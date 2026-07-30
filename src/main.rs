use pcap::Capture;
use std::env;
use std::net::Ipv4Addr;
use std::process;

// Format slice of 6 bytes into colon-separated MAC address string
fn format_mac(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<String>>()
        .join(":")
}

// Translate IPv4 protocol number to human-readable string
fn protocol_name(proto: u8) -> &'static str {
    match proto {
        1 => "ICMP (Control Message)",
        2 => "IGMP",
        6 => "TCP (Transmission Control Protocol)",
        17 => "UDP (User Datagram Protocol)",
        41 => "IPv6 Encapsulation",
        89 => "OSPF",
        _ => "Other / Unknown",
    }
}

// Translate common port numbers to service names
fn port_service(port: u16) -> &'static str {
    match port {
        20 | 21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        67 | 68 => "DHCP",
        80 => "HTTP",
        123 => "NTP",
        143 => "IMAP",
        443 => "HTTPS",
        3306 => "MySQL",
        5432 => "PostgreSQL",
        8080 => "HTTP-Proxy",
        _ => "Custom/Dynamic",
    }
}

// Parse TCP flags byte into human-readable representation
fn parse_tcp_flags(flags: u8) -> String {
    let mut active = Vec::new();
    if flags & 0x01 != 0 { active.push("FIN"); }
    if flags & 0x02 != 0 { active.push("SYN"); }
    if flags & 0x04 != 0 { active.push("RST"); }
    if flags & 0x08 != 0 { active.push("PSH"); }
    if flags & 0x10 != 0 { active.push("ACK"); }
    if flags & 0x20 != 0 { active.push("URG"); }

    if active.is_empty() {
        "NONE".to_string()
    } else {
        active.join(" | ")
    }
}

// Translate ICMP Type code
fn icmp_type_name(icmp_type: u8) -> &'static str {
    match icmp_type {
        0 => "Echo Reply (Ping Response)",
        3 => "Destination Unreachable",
        5 => "Redirect",
        8 => "Echo Request (Ping Query)",
        11 => "Time Exceeded",
        _ => "Other ICMP Type",
    }
}

// Print formatted Hex Dump with ASCII view (first N bytes)
fn print_hex_dump(data: &[u8], max_bytes: usize) {
    let len = data.len().min(max_bytes);
    let slice = &data[..len];
    println!("  Raw Hex Dump (first {} bytes):", len);

    for (idx, chunk) in slice.chunks(16).enumerate() {
        let hex_str = chunk
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<String>>()
            .join(" ");

        let ascii_str: String = chunk
            .iter()
            .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
            .collect();

        println!("    {:04X}:  {:47}  |{}|", idx * 16, hex_str, ascii_str);
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut interface_name = String::new();
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--interface" || args[i] == "-i" {
            if i + 1 < args.len() {
                interface_name = args[i + 1].clone();
                i += 1;
            }
        }
        i += 1;
    }

    if interface_name.is_empty() {
        eprintln!("Error: No network interface specified.");
        eprintln!("Usage: packet-sniffer-engine --interface <INTERFACE>");
        process::exit(1);
    }

    println!("Listening on interface: {}...", interface_name);

    let mut cap = match Capture::from_device(interface_name.as_str()) {
        Ok(device) => match device.promisc(true).immediate_mode(true).open() {
            Ok(cap) => cap,
            Err(e) => {
                eprintln!("Failed to open device '{}': {}", interface_name, e);
                process::exit(1);
            }
        },
        Err(e) => {
            eprintln!("Failed to find device '{}': {}", interface_name, e);
            process::exit(1);
        }
    };

    let mut packet_count: u64 = 0;

    while let Ok(packet) = cap.next_packet() {
        packet_count += 1;
        let data = packet.data;
        println!("\n==================================================");
        println!("  Packet #{} (Total Bytes: {})", packet_count, data.len());
        println!("==================================================");

        // --- LAYER 2: ETHERNET HEADER ---
        if data.len() >= 14 {
            let dst_mac = &data[0..6];
            let src_mac = &data[6..12];
            let mut ether_type = u16::from_be_bytes([data[12], data[13]]);
            let mut ip_start = 14;

            // Check for 802.1Q VLAN Tag (0x8100)
            if ether_type == 0x8100 && data.len() >= 18 {
                ether_type = u16::from_be_bytes([data[16], data[17]]);
                ip_start = 18;
            }

            let eth_desc = match ether_type {
                0x0800 => "IPv4 (0x0800)",
                0x86DD => "IPv6 (0x86DD)",
                0x0806 => "ARP (0x0806)",
                0x8100 => "VLAN (0x8100)",
                _ => "Other Protocol",
            };

            println!("  [Layer 2 - Ethernet Header]");
            println!("    Destination MAC : {}", format_mac(dst_mac));
            println!("    Source MAC      : {}", format_mac(src_mac));
            println!("    EtherType       : 0x{:04X} -> {}", ether_type, eth_desc);

            // --- LAYER 3: IPv4 HEADER ---
            if ether_type == 0x0800 && data.len() >= ip_start + 20 {
                let version = data[ip_start] >> 4;
                let ihl = data[ip_start] & 0x0F;
                let ihl_bytes = (ihl * 4) as usize;
                let total_length = u16::from_be_bytes([data[ip_start + 2], data[ip_start + 3]]);
                let ttl = data[ip_start + 8];
                let protocol = data[ip_start + 9];

                let src_ip = Ipv4Addr::new(
                    data[ip_start + 12],
                    data[ip_start + 13],
                    data[ip_start + 14],
                    data[ip_start + 15],
                );
                let dst_ip = Ipv4Addr::new(
                    data[ip_start + 16],
                    data[ip_start + 17],
                    data[ip_start + 18],
                    data[ip_start + 19],
                );

                println!("  [Layer 3 - IPv4 Header]");
                println!("    IP Version      : IPv{}", version);
                println!("    Header Length   : {} bytes (IHL: {})", ihl_bytes, ihl);
                println!("    Total Length    : {} bytes", total_length);
                println!("    TTL (Hop Limit) : {}", ttl);
                println!("    Protocol        : {} ({})", protocol_name(protocol), protocol);
                println!("    Source IP       : {}", src_ip);
                println!("    Destination IP  : {}", dst_ip);

                // --- LAYER 4: TRANSPORT LAYER PARSING ---
                let l4_start = ip_start + ihl_bytes;

                if protocol == 6 && data.len() >= l4_start + 20 {
                    // TCP Header Parsing
                    let src_port = u16::from_be_bytes([data[l4_start], data[l4_start + 1]]);
                    let dst_port = u16::from_be_bytes([data[l4_start + 2], data[l4_start + 3]]);
                    let seq_num = u32::from_be_bytes([
                        data[l4_start + 4],
                        data[l4_start + 5],
                        data[l4_start + 6],
                        data[l4_start + 7],
                    ]);
                    let ack_num = u32::from_be_bytes([
                        data[l4_start + 8],
                        data[l4_start + 9],
                        data[l4_start + 10],
                        data[l4_start + 11],
                    ]);
                    let tcp_offset = (data[l4_start + 12] >> 4) * 4;
                    let flags = data[l4_start + 13];

                    println!("  [Layer 4 - TCP Header]");
                    println!(
                        "    Source Port     : {} ({})",
                        src_port,
                        port_service(src_port)
                    );
                    println!(
                        "    Destination Port: {} ({})",
                        dst_port,
                        port_service(dst_port)
                    );
                    println!("    Sequence Num    : {}", seq_num);
                    println!("    Ack Num         : {}", ack_num);
                    println!("    Header Length   : {} bytes", tcp_offset);
                    println!("    Control Flags   : [ {} ] (0x{:02X})", parse_tcp_flags(flags), flags);

                } else if protocol == 17 && data.len() >= l4_start + 8 {
                    // UDP Header Parsing
                    let src_port = u16::from_be_bytes([data[l4_start], data[l4_start + 1]]);
                    let dst_port = u16::from_be_bytes([data[l4_start + 2], data[l4_start + 3]]);
                    let udp_len = u16::from_be_bytes([data[l4_start + 4], data[l4_start + 5]]);
                    let checksum = u16::from_be_bytes([data[l4_start + 6], data[l4_start + 7]]);

                    println!("  [Layer 4 - UDP Header]");
                    println!(
                        "    Source Port     : {} ({})",
                        src_port,
                        port_service(src_port)
                    );
                    println!(
                        "    Destination Port: {} ({})",
                        dst_port,
                        port_service(dst_port)
                    );
                    println!("    UDP Length      : {} bytes", udp_len);
                    println!("    Checksum        : 0x{:04X}", checksum);

                } else if protocol == 1 && data.len() >= l4_start + 4 {
                    // ICMP Header Parsing
                    let icmp_type = data[l4_start];
                    let icmp_code = data[l4_start + 1];
                    let checksum = u16::from_be_bytes([data[l4_start + 2], data[l4_start + 3]]);

                    println!("  [Layer 4 - ICMP Header]");
                    println!("    Type            : {} ({})", icmp_type, icmp_type_name(icmp_type));
                    println!("    Code            : {}", icmp_code);
                    println!("    Checksum        : 0x{:04X}", checksum);
                }
            } else if ether_type == 0x0806 {
                println!("  [Layer 3 - ARP Protocol]");
            } else if ether_type == 0x86DD {
                println!("  [Layer 3 - IPv6 Protocol]");
            }
        } else {
            println!("  [Warning: Packet size smaller than 14 bytes]");
        }

        print_hex_dump(data, 64);
    }
}
