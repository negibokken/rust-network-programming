use std::net::Ipv4Addr;
use std::sync::{Mutex, RwLock};
use std::{collections::HashMap, default::default};

use ipnetwork::Ipv4Network;
use pnet::packet::PrimitiveValues;
use pnet::util::MacAddr;
use rusqlite::Connection;

use crate::database;
use crate::util;

const OP: usize = 0;
const XID: usize = 4;
const SECS: usize = 8;
const CHADDR: usize = 28;
const SNAME: usize = 44;
pub const OPTIONS: usize = 236;

const DHCP_MINIMUM_SIZE: usize = 237;
const OPTION_END: u8 = 255;

pub struct DhcpPacket {
    buffer: Vec<u8>,
}

impl DhcpPacket {
    pub fn new(buf: Vec<u8>) -> Option<DhcpPacket> {
        if buf.len() > DHCP_MINIMUM_SIZE {
            return Some(DhcpPacket { buffer: buf });
        }
        None
    }
}

impl DhcpPacket {
    pub fn get_op(&self) -> u8 {
        self.buffer[OP]
    }

    pub fn get_options(&self) -> &[u8] {
        &self.buffer[OPTIONS..]
    }

    pub fn get_xid(&self) -> &[u8] {
        &self.buffer[XID..SECS]
    }

    pub fn get_chaddr(&self) -> MacAddr {
        let b = &self.buffer[CHADDR..SNAME];
        MacAddr::new(b[0], b[1], b[2], b[3], b[4], b[5])
    }
    pub fn get_option(&self, option_code: u8) -> Option<Vec<u8>> {
        let mut index: usize = 4;
        let options = self.get_options();
        while options[index] != OPTION_END {
            if options[index] == option_code {
                let len = options[index + 1];
                let buf_index = index + 2;
                let v = options[buf_index..buf_index + len as usize].to_vec();
                return Some(v);
            } else if options[index] == 0 {
                index += 1;
            } else {
                index += 1;
                let len = options[index];
                index += 1;
                index += len as usize;
            }
        }
        None
    }
}

pub struct DhcpServer {
    addres_pool: RwLock<Vec<Ipv4Addr>>,
    pub db_connection: Mutex<Connection>,
    pub network_address: Ipv4Network,
    pub server_address: Ipv4Addr,
    pub default_gateway: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub dns_server: Ipv4Addr,
    pub lease_time: Vec<u8>,
}

impl DhcpServer {
    pub fn new() -> Result<DhcpServer, failure::Error> {
        let env = util::load_env();
        let static_addresses = util::obtain_static_addresses(&env)?;

        let network_addr_with_prefix: Ipv4Network = Ipv4Network::new(
            static_addresses["network_addr"],
            ipnetwork::ipv4_mask_to_prefix(static_addresses["subnet_mask"])?,
        )?;

        let con = Connection::open("dhcp.db")?;

        let addr_pool = Self::init_address_pool(&con, &static_addresses, network_addr_with_prefix)?;
        info!(
            "There are {} addresses in the address pool",
            addr_pool.len(),
        );

        let lease_time = util::make_big_endian_vec_from_u32(
            env.get("LEASE_TIME").expect("Missing lease_time").parse()?,
        )?;

        Ok(DhcpServer {
            addres_pool: RwLock::new(addr_pool),
            db_connection: Mutex::new(con),
            network_address: network_addr_with_prefix,
            server_address: static_addresses["dhcp_server_addr"],
            default_gateway: static_addresses["default_gatway"],
            subnet_mask: static_addresses["subnet_mask"],
            dns_server: static_addresses["dns_server"],
            lease_time,
        })
    }

    fn init_address_pool(
        con: &Connection,
        static_addresses: &HashMap<String, Ipv4Addr>,
        network_addr_with_prefix: Ipv4Network,
    ) -> Result<Vec<Ipv4Addr>, failure::Error> {
        let network_addr = static_addresses.get("network_addr").unwrap();
        let default_gateway = static_addresses.get("default_gateway").unwrap();
        let dhcp_server_addr = static_addresses.get("dhcp_server_addr").unwrap();
        let dns_server_addr = static_addresses.get("dns_server_addr").unwrap();
        let broadcast = network_addr_with_prefix.broadcast();

        let mut used_ip_addrs = database::select_addresses(con, Some(0))?;

        used_ip_addrs.push(*network_addr);
        used_ip_addrs.push(*default_gateway);
        used_ip_addrs.push(*dhcp_server_addr);
        used_ip_addrs.push(*dns_server_addr);
        used_ip_addrs.push(broadcast);

        let mut addr_pool: Vec<Ipv4Addr> = network_addr_with_prefix
            .iter()
            .filter(|addr| !used_ip_addrs.contains(addr))
            .collect();

        addr_pool.reverse();

        Ok(addr_pool)
    }
}
