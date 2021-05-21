use byteorder::{BigEndian, ByteOrder};
use dhcp::{DhcpPacket, DhcpServer};
use env_logger;
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

const BOOTREQUEST: u8 = 1;

enum Code {
    MessageType = 53,
    ServerIdentifier = 54,
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
        DHCPRELEASE => {}
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
}
