use pcap::{Device, Capture};
use std::convert::TryInto;
use chrono::Local;

fn main() {
    let main_device = Device::lookup().unwrap().unwrap();
    let mut cap = Capture::from_device(main_device).unwrap()
        .promisc(true)
        .open().unwrap();

    while let Ok(packet) = cap.next_packet() {
        let ether_type = u16::from_be_bytes(packet[12..14].try_into().unwrap());
        let ip_packet = &packet[14..];

        match ether_type {

            // IPv4 protocol
            0x0800 => {
                let protocol = ip_packet[9];

                match protocol {
                    6 => {
                        // TCP protocol
                        let dest_port = u16::from_be_bytes([ip_packet[2], ip_packet[3]]);
                        if dest_port == 80 || dest_port == 443 {
                            // HTTP or HTTPS traffic
                            println!("————————————————————————————————");
                            process_packet(&packet, "IPv4", protocol, dest_port);
                        }
                    }

                    1 => {
                        println!("————————————————————————————————");
                        // ICMP protocol
                        process_packet(&packet, "IPv4", protocol, 0);
                    }
                    _ => {}
                }
            }

            // IPv6 protocol
            0x86DD => {
                let next_header = ip_packet[6];

                match next_header {
                    6 => {
                        // TCP protocol
                        let dest_port = u16::from_be_bytes([ip_packet[38], ip_packet[39]]);
                        if dest_port == 80 || dest_port == 443 {
                            println!("————————————————————————————————");
                            // HTTP or HTTPS traffic
                            process_packet(&packet, "IPv6", next_header, dest_port);
                        }
                    }
                    _ => {}
                }
            }

            0x0806 => {
                // println!("————————————————————————————————");
                // ARP protocol
                // process_packet(&packet, "ARP", 0, 0);
            }
            _ => {}
        }
    }
}

fn process_packet(packet: &[u8], ip_version: &str, protocol: u8, dest_port: u16) {
    let current_time = Local::now();
    let formatted_time = current_time.format("%I:%M:%S %p").to_string();

    println!();
    println!("Received Packet at {}", formatted_time);
    println!("IP Version: {}", ip_version);
    println!("Protocol: {}", protocol);
    println!("Destination Port: {}", dest_port);
    println!();

    match protocol {
        6 => {
            // TCP protocol
            if dest_port == 80 {
                println!("🔵 HTTP Packet");
                let tcp_payload = &packet[14..];
                if tcp_payload.len() > 0 {
                    if let Ok(http_request) = std::str::from_utf8(tcp_payload) {
                        if let Some(http_method) = http_request.split_whitespace().next() {
                            println!("🟠");
                            println!("HTTP Method: {}", http_method);
                            println!("HTTP Request: {}", http_request.trim());
                        }
                    }
                }

            } else if dest_port == 443 {
                println!("🟢 HTTPS Packet (Encrypted)");

            } else {
                println!("Other TCP Packet");
            }
        }

        1 => {
            // ICMP protocol
            println!("🟣 ICMP Packet");
        }

        _ => {}
    }

    match ip_version {

        "IPv4" => {
            let source_ip = &packet[26..30];
            let dest_ip = &packet[30..34];

            println!("Source IP: {}.{}.{}.{}", source_ip[0], source_ip[1], source_ip[2], source_ip[3]);
            println!("Destination IP: {}.{}.{}.{}", dest_ip[0], dest_ip[1], dest_ip[2], dest_ip[3]);
            println!();
            println!("{:?}", packet);
            println!();
        }

        "IPv6" => {
            let source_ip = &packet[22..38];
            let dest_ip = &packet[38..54];

            println!("Source IP: {:x?}", source_ip);
            println!("Destination IP: {:x?}", dest_ip);
        }

        _ => {}
    }
}

