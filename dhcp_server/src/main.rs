use byteorder::{BigEndian, ByteOrder};
use dhcp::{DhcpPacket, DhcpServer};
use env_logger;
use pnet::util::MacAddr;
use std::{
    env,
    net::{Ipv4Addr, UdpSocket},
    sync::Arc,
    thread,
};

#[macro_use]
extern crate log;

mod database;
mod dhcp;
mod util;

const HTYP_ETHER: u8 = 1;

const DHCP_SIZE: usize = 400;

const DHCPDISCOVER: u8 = 1;
const DHCPOFFER: u8 = 2;
const DHCPREQUEST: u8 = 3;
const DHCPACK: u8 = 5;
const DHCPNAK: u8 = 6;
const DHCPRELEASE: u8 = 7;

const BOOTREQUEST: u8 = 1;
const BOOTREPLY: u8 = 2;

enum Code {
    MessageType = 53,
    IpAddressLeaseTime = 51,
    ServerIdentifier = 54,
    RequestedIpAddress = 50,
    SubnetMask = 1,
    Router = 5,
    DNS = 6,
    End = 255,
}

fn main() {
    env::set_var("RUST_LOG", "debug");
    env_logger::init();

    let server_socket = UdpSocket::bind("0.0.0.0:67").expect("Failed to bind socket");
    server_socket.set_broadcast(true).unwrap();

    let dhcp_server = Arc::new(
        DhcpServer::new().unwrap_or_else(|e| panic!("Failed to start dhcp server. {:?}", e)),
    );

    loop {
        let mut recv_buf = [0u8; 1024];
        match server_socket.recv_from(&mut recv_buf) {
            Ok((size, src)) => {
                debug!("received data from {}, size: {}", src, size);
                let client_socket = server_socket
                    .try_clone()
                    .expect("Failed to create client socket");
                let cloned_dhcp_server = dhcp_server.clone();

                thread::spawn(move || {
                    if let Some(dhcp_packet) = DhcpPacket::new(recv_buf[..size].to_vec()) {
                        if dhcp_packet.get_op() != BOOTREQUEST {
                            return;
                        }
                        if let Err(e) =
                            dhcp_handler(&dhcp_packet, &client_socket, cloned_dhcp_server)
                        {
                            error!("{}", e)
                        }
                    }
                });
            }
            Err(e) => {
                error!("Could not recieve a datagram: {}", e);
            }
        }
    }
}

fn dhcp_handler(
    packet: &DhcpPacket,
    soc: &UdpSocket,
    dhcp_server: Arc<DhcpServer>,
) -> Result<(), failure::Error> {
    let message = packet
        .get_option(Code::MessageType as u8)
        .ok_or_else(|| failure::err_msg("specified option was not found"))?;
    let message_type = message[0];
    let transaction_id = BigEndian::read_u32(packet.get_xid());
    let client_macaddr = packet.get_chaddr();

    match message_type {
        DHCPDISCOVER => dhcp_discover_message_handler(transaction_id, dhcp_server, &packet, soc),
        DHCPREQUEST => match packet.get_option(Code::ServerIdentifier as u8) {
            Some(server_id) => dhcp_request_message_handler_responded_to_offer(
                transaction_id,
                dhcp_server,
                &packet,
                client_macaddr,
                soc,
                server_id,
            ),
            None => dhcp_request_message_handler_to_reallocate(
                transaction_id,
                dhcp_server,
                &packet,
                client_macaddr,
                soc,
            ),
        },
        DHCPRELEASE => {
            dhcp_release_message_handler(transaction_id, dhcp_server, &packet, client_macaddr)
        }
        _ => Err(failure::format_err!(
            "{:x}: received unimplemented message, message_type: {}",
            transaction_id,
            message_type,
        )),
    }
}

fn dhcp_discover_message_handler(
    xid: u32,
    dhcp_server: Arc<DhcpServer>,
    received_packet: &DhcpPacket,
    soc: &UdpSocket,
) -> Result<(), failure::Error> {
    info!("{:x}: recieved DHCPDISCOVER", xid);

    let ip_to_be_leased = select_lease_ip(&dhcp_server, &received_packet)?;

    let dhcp_packet = make_dhcp_packet(&received_packet, &dhcp_server, DHCPOFFER, ip_to_be_leased)?;
    util::send_dhcp_broadcast_response(soc, dhcp_packet.get_buffer())?;
    info!("{:x}: sent DHCPOFFER", xid);
    Ok(())
}

fn dhcp_request_message_handler_responded_to_offer(
    xid: u32,
    dhcp_server: Arc<DhcpServer>,
    received_packet: &DhcpPacket,
    client_macaddr: MacAddr,
    soc: &UdpSocket,
    server_id: Vec<u8>,
) -> Result<(), failure::Error> {
    info!("{:x}: received DHCPREQUEST with server_id", xid);

    let server_ip = util::u8_to_ipv4addr(&server_id)
        .ok_or_else(|| failure::err_msg("Failed to convert ip addr."))?;

    if server_ip != dhcp_server.server_address {
        info!("Client has chosen anoher dhcp server.");
        return Ok(());
    }

    let ip_bin = received_packet
        .get_option(Code::RequestedIpAddress as u8)
        .unwrap();

    let ip_to_be_leased = util::u8_to_ipv4addr(&ip_bin)
        .ok_or_else(|| failure::err_msg("Failed to convert ip addr."))?;

    let mut con = dhcp_server.db_connection.lock().unwrap();
    let count = {
        let tx = con.transaction()?;
        let count = database::count_records_by_mac_addr(&tx, client_macaddr)?;
        match count {
            0 => database::insert_entry(&tx, client_macaddr, ip_to_be_leased)?,
            _ => database::update_entry(&tx, client_macaddr, ip_to_be_leased, 0)?,
        }

        let dhcp_packet =
            make_dhcp_packet(&received_packet, &dhcp_server, DHCPACK, ip_to_be_leased)?;
        util::send_dhcp_broadcast_response(soc, dhcp_packet.get_buffer())?;
        info!("{:x}: sent DHCPACK", xid);

        tx.commit()?;
        count
    };

    debug!("{:x}: leased address: {}", xid, ip_to_be_leased);
    match count {
        0 => debug!("{:x}: inserted into DB", xid),
        _ => debug!("{:x}: updated DB", xid),
    }
    Ok(())
}

fn dhcp_request_message_handler_to_reallocate(
    xid: u32,
    dhcp_server: Arc<DhcpServer>,
    received_packet: &DhcpPacket,
    client_macaddr: MacAddr,
    soc: &UdpSocket,
) -> Result<(), failure::Error> {
    info!("{:x}: received DHCPREQUEST without server_id", xid);

    if let Some(requested_ip) = received_packet.get_option(Code::RequestedIpAddress as u8) {
        debug!("client is in INIT-REBOOT");
        let requested_ip = util::u8_to_ipv4addr(&requested_ip)
            .ok_or_else(|| failure::err_msg("Failed to convert ip addr."))?;
        let con = dhcp_server.db_connection.lock().unwrap();
        match database::select_entry(&con, client_macaddr)? {
            Some(ip) => {
                if ip == requested_ip && dhcp_server.network_address.contains(ip) {
                    let dhcp_packet =
                        make_dhcp_packet(&received_packet, &dhcp_server, DHCPACK, ip)?;
                    util::send_dhcp_broadcast_response(soc, dhcp_packet.get_buffer())?;
                    info!("{:x}: sent DHCPACK", xid);
                    Ok(())
                } else {
                    let dhcp_packet = make_dhcp_packet(
                        &received_packet,
                        &dhcp_server,
                        DHCPNAK,
                        "0.0.0.0".parse()?,
                    )?;
                    util::send_dhcp_broadcast_response(soc, dhcp_packet.get_buffer())?;
                    info!("{:x}: sent DHCPACK", xid);
                    Ok(())
                }
            }
            None => Ok(()),
        }
    } else {
        debug!("client is in RENEWING or REBINDING");

        let ip_from_client = received_packet.get_ciaddr();
        if !dhcp_server.network_address.contains(ip_from_client) {
            return Err(failure::err_msg(
                "Invalid ciaddr. Mismatched network address.",
            ));
        }
        let dhcp_packet = make_dhcp_packet(
            &received_packet,
            &dhcp_server,
            DHCPACK,
            received_packet.get_ciaddr(),
        )?;
        util::send_dhcp_broadcast_response(soc, dhcp_packet.get_buffer())?;
        info!("{:x}: sent DHCPACK", xid);
        Ok(())
    }
}

fn select_lease_ip(
    dhcp_server: &Arc<DhcpServer>,
    received_packet: &DhcpPacket,
) -> Result<Ipv4Addr, failure::Error> {
    {
        let con = dhcp_server.db_connection.lock().unwrap();
        if let Some(ip_from_used) = database::select_entry(&con, received_packet.get_chaddr())? {
            if dhcp_server.network_address.contains(ip_from_used)
                && util::is_ipaddr_available(ip_from_used).is_ok()
            {
                return Ok(ip_from_used);
            }
        }
    }

    if let Some(ip_to_be_leased) =
        obtain_available_ip_from_requested_option(dhcp_server, &received_packet)
    {
        return Ok(ip_to_be_leased);
    }

    while let Some(ip_addr) = dhcp_server.pick_available_ip() {
        if util::is_ipaddr_available(ip_addr).is_ok() {
            return Ok(ip_addr);
        }
    }
    Err(failure::err_msg("Could not obtain available ip address"))
}

fn make_dhcp_packet(
    received_packet: &DhcpPacket,
    dhcp_server: &Arc<DhcpServer>,
    message_type: u8,
    ip_to_be_leased: Ipv4Addr,
) -> Result<DhcpPacket, failure::Error> {
    let buffer = vec![0u8; DHCP_SIZE];
    let mut dhcp_packet = DhcpPacket::new(buffer).unwrap();

    dhcp_packet.set_op(BOOTREPLY);
    dhcp_packet.set_htype(HTYP_ETHER);
    dhcp_packet.set_hlen(6);
    dhcp_packet.set_xid(received_packet.get_xid());

    if message_type == DHCPACK {
        dhcp_packet.set_ciaddr(received_packet.get_ciaddr());
    }
    dhcp_packet.set_yiaddr(ip_to_be_leased);
    dhcp_packet.set_flags(received_packet.get_flags());
    dhcp_packet.set_giaddr(received_packet.get_giaddr());
    dhcp_packet.set_chaddr(received_packet.get_chaddr());

    let mut cursor = dhcp::OPTIONS;
    dhcp_packet.set_magic_cookie(&mut cursor);
    dhcp_packet.set_option(
        &mut cursor,
        Code::MessageType as u8,
        1,
        Some(&[message_type]),
    );
    dhcp_packet.set_option(
        &mut cursor,
        Code::IpAddressLeaseTime as u8,
        4,
        Some(&dhcp_server.lease_time),
    );
    dhcp_packet.set_option(
        &mut cursor,
        Code::ServerIdentifier as u8,
        4,
        Some(&dhcp_server.server_address.octets()),
    );
    dhcp_packet.set_option(
        &mut cursor,
        Code::SubnetMask as u8,
        4,
        Some(&dhcp_server.subnet_mask.octets()),
    );
    dhcp_packet.set_option(
        &mut cursor,
        Code::Router as u8,
        4,
        Some(&dhcp_server.default_gateway.octets()),
    );
    dhcp_packet.set_option(
        &mut cursor,
        Code::DNS as u8,
        4,
        Some(&dhcp_server.dns_server.octets()),
    );

    dhcp_packet.set_option(&mut cursor, Code::End as u8, 0, None);
    Ok(dhcp_packet)
}

fn dhcp_release_message_handler(
    xid: u32,
    dhcp_server: Arc<DhcpServer>,
    received_packet: &DhcpPacket,
    client_macaddr: MacAddr,
) -> Result<(), failure::Error> {
    info!("{:x} received DHCPRELEASE", xid);

    let mut con = dhcp_server.db_connection.lock().unwrap();
    let tx = con.transaction()?;
    database::delete_entry(&tx, client_macaddr)?;
    tx.commit()?;

    debug!("{:x}: deleted from DB", xid);
    dhcp_server.release_address(received_packet.get_ciaddr());
    Ok(())
}

fn obtain_available_ip_from_requested_option(
    dhcp_server: &Arc<DhcpServer>,
    received_packet: &DhcpPacket,
) -> Option<Ipv4Addr> {
    let ip = received_packet.get_option(Code::RequestedIpAddress as u8)?;
    let requested_ip = util::u8_to_ipv4addr(&ip)?;
    let ip_from_pool = dhcp_server.pick_specified_ip(requested_ip)?;

    if util::is_ipaddr_available(ip_from_pool).is_ok() {
        return Some(requested_ip);
    }
    None
}
