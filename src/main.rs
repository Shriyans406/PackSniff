use pcap::Capture;
use std::env;
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::process;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq)]
enum PacketFilter {
    None,
    Protocol(u8),
    Port(u16),
    Ip(Ipv4Addr),
}

fn format_mac(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<String>>()
        .join(":")
}

fn protocol_name(proto: u8) -> &'static str {
    match proto {
        1 => "ICMP",
        2 => "IGMP",
        6 => "TCP",
        17 => "UDP",
        41 => "IPv6-Encaps",
        89 => "OSPF",
        _ => "OTHER",
    }
}

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
        _ => "CUSTOM",
    }
}

fn parse_tcp_flags(flags: u8) -> String {
    let mut active = Vec::new();
    if flags & 0x01 != 0 { active.push("FIN"); }
    if flags & 0x02 != 0 { active.push("SYN"); }
    if flags & 0x04 != 0 { active.push("RST"); }
    if flags & 0x08 != 0 { active.push("PSH"); }
    if flags & 0x10 != 0 { active.push("ACK"); }
    if flags & 0x20 != 0 { active.push("URG"); }
    if active.is_empty() { "NONE".to_string() } else { active.join("|") }
}

fn icmp_type_name(icmp_type: u8) -> &'static str {
    match icmp_type {
        0 => "Echo Reply",
        3 => "Dst Unreachable",
        5 => "Redirect",
        8 => "Echo Request",
        11 => "Time Exceeded",
        _ => "ICMP Other",
    }
}

fn hex_encode(data: &[u8], max_bytes: usize) -> String {
    let len = data.len().min(max_bytes);
    data[..len].iter().map(|b| format!("{:02X}", b)).collect::<Vec<String>>().join(" ")
}

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

fn safe_println(msg: &str) {
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    if writeln!(handle, "{}", msg).is_err() {
        process::exit(0);
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut interface_name = String::new();
    let mut filter = PacketFilter::None;
    let mut json_mode = false;
    let mut save_path: Option<String> = None;
    let mut read_path: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--interface" | "-i" => {
                if i + 1 < args.len() {
                    interface_name = args[i + 1].clone();
                    i += 1;
                }
            }
            "--json" | "-j" => {
                json_mode = true;
            }
            "--save" | "-s" => {
                if i + 1 < args.len() {
                    save_path = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "--read" | "-r" => {
                if i + 1 < args.len() {
                    read_path = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "--filter" | "-f" => {
                if i + 1 < args.len() {
                    let filter_type = args[i + 1].to_lowercase();
                    i += 1;
                    match filter_type.as_str() {
                        "tcp" => filter = PacketFilter::Protocol(6),
                        "udp" => filter = PacketFilter::Protocol(17),
                        "icmp" => filter = PacketFilter::Protocol(1),
                        "port" => {
                            if i + 1 < args.len() {
                                if let Ok(port) = args[i + 1].parse::<u16>() {
                                    filter = PacketFilter::Port(port);
                                    i += 1;
                                } else {
                                    eprintln!("Error: Invalid port number '{}'", args[i + 1]);
                                    process::exit(1);
                                }
                            } else {
                                eprintln!("Error: '--filter port' requires a port number argument.");
                                process::exit(1);
                            }
                        }
                        "ip" => {
                            if i + 1 < args.len() {
                                if let Ok(ip) = Ipv4Addr::from_str(&args[i + 1]) {
                                    filter = PacketFilter::Ip(ip);
                                    i += 1;
                                } else {
                                    eprintln!("Error: Invalid IP address '{}'", args[i + 1]);
                                    process::exit(1);
                                }
                            } else {
                                eprintln!("Error: '--filter ip' requires an IP address argument.");
                                process::exit(1);
                            }
                        }
                        _ => {
                            eprintln!("Error: Unknown filter mode '{}'. Options: tcp, udp, icmp, port <PORT>, ip <IP>", filter_type);
                            process::exit(1);
                        }
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }

    if read_path.is_none() && interface_name.is_empty() {
        eprintln!("Error: No network interface or PCAP file specified.");
        eprintln!("Usage: packet-sniffer-engine [--interface <INTERFACE> | --read <FILE.pcap>] [--save <FILE.pcap>] [--json]");
        process::exit(1);
    }

    // Open Live Capture or Offline PCAP file
    let mut cap_live: Option<Capture<pcap::Active>> = None;
    let mut cap_offline: Option<Capture<pcap::Offline>> = None;

    if let Some(ref r_path) = read_path {
        if !json_mode {
            println!("Reading offline PCAP file: {}...", r_path);
        }
        match Capture::from_file(r_path) {
            Ok(c) => cap_offline = Some(c),
            Err(e) => {
                eprintln!("Failed to open PCAP file '{}': {}", r_path, e);
                process::exit(1);
            }
        }
    } else {
        if !json_mode {
            println!("Listening on interface: {}...", interface_name);
        }
        match Capture::from_device(interface_name.as_str()) {
            Ok(device) => match device.promisc(true).immediate_mode(true).open() {
                Ok(c) => cap_live = Some(c),
                Err(e) => {
                    eprintln!("Failed to open device '{}': {}", interface_name, e);
                    process::exit(1);
                }
            },
            Err(e) => {
                eprintln!("Failed to find device '{}': {}", interface_name, e);
                process::exit(1);
            }
        }
    }

    if !json_mode {
        match &filter {
            PacketFilter::None => println!("Active Filter: NONE (Capturing All Packets)"),
            PacketFilter::Protocol(p) => println!("Active Filter: PROTOCOL -> {} ({})", protocol_name(*p), p),
            PacketFilter::Port(p) => println!("Active Filter: PORT -> {}", p),
            PacketFilter::Ip(ip) => println!("Active Filter: IP ADDRESS -> {}", ip),
        }
        if let Some(ref s_path) = save_path {
            println!("Saving live capture to PCAP file: {}...", s_path);
        }
    }

    // Initialize Savefile if --save is passed in live capture mode
    let mut savefile = if let (Some(ref s_path), Some(ref mut c_live)) = (&save_path, &mut cap_live) {
        match c_live.savefile(s_path) {
            Ok(sf) => Some(sf),
            Err(e) => {
                eprintln!("Failed to create savefile '{}': {}", s_path, e);
                process::exit(1);
            }
        }
    } else {
        None
    };

    let mut packet_count: u64 = 0;
    let mut matched_count: u64 = 0;

    let mut get_next_packet = || -> Option<pcap::Packet> {
        if let Some(ref mut c_live) = cap_live {
            c_live.next_packet().ok().map(|p| p.to_owned())
        } else if let Some(ref mut c_off) = cap_offline {
            c_off.next_packet().ok().map(|p| p.to_owned())
        } else {
            None
        }
    };

    while let Some(packet) = get_next_packet() {
        packet_count += 1;
        let data = packet.data;

        // Save raw packet to PCAP file if saving enabled
        if let Some(ref mut sf) = savefile {
            sf.write(&packet);
        }

        if data.len() >= 14 {
            let dst_mac = &data[0..6];
            let src_mac = &data[6..12];
            let mut ether_type = u16::from_be_bytes([data[12], data[13]]);
            let mut ip_start = 14;

            if ether_type == 0x8100 && data.len() >= 18 {
                ether_type = u16::from_be_bytes([data[16], data[17]]);
                ip_start = 18;
            }

            let mut matches_filter = false;
            let mut src_ip_opt = None;
            let mut dst_ip_opt = None;
            let mut protocol_opt = None;
            let mut src_port_opt = None;
            let mut dst_port_opt = None;
            let mut ttl_opt = None;
            let mut l4_info = String::new();

            if ether_type == 0x0800 && data.len() >= ip_start + 20 {
                let ihl = data[ip_start] & 0x0F;
                let ihl_bytes = (ihl * 4) as usize;
                let protocol = data[ip_start + 9];
                let ttl = data[ip_start + 8];
                protocol_opt = Some(protocol);
                ttl_opt = Some(ttl);

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
                src_ip_opt = Some(src_ip);
                dst_ip_opt = Some(dst_ip);

                let l4_start = ip_start + ihl_bytes;

                if protocol == 6 && data.len() >= l4_start + 14 {
                    let src_port = u16::from_be_bytes([data[l4_start], data[l4_start + 1]]);
                    let dst_port = u16::from_be_bytes([data[l4_start + 2], data[l4_start + 3]]);
                    let flags = data[l4_start + 13];
                    src_port_opt = Some(src_port);
                    dst_port_opt = Some(dst_port);
                    l4_info = format!("Flags: [{}]", parse_tcp_flags(flags));
                } else if protocol == 17 && data.len() >= l4_start + 8 {
                    let src_port = u16::from_be_bytes([data[l4_start], data[l4_start + 1]]);
                    let dst_port = u16::from_be_bytes([data[l4_start + 2], data[l4_start + 3]]);
                    let udp_len = u16::from_be_bytes([data[l4_start + 4], data[l4_start + 5]]);
                    src_port_opt = Some(src_port);
                    dst_port_opt = Some(dst_port);
                    l4_info = format!("Len: {}B", udp_len);
                } else if protocol == 1 && data.len() >= l4_start + 4 {
                    let icmp_type = data[l4_start];
                    let icmp_code = data[l4_start + 1];
                    l4_info = format!("Type {} ({}) Code {}", icmp_type, icmp_type_name(icmp_type), icmp_code);
                }
            }

            match &filter {
                PacketFilter::None => matches_filter = true,
                PacketFilter::Protocol(proto) => {
                    if let Some(p) = protocol_opt {
                        if p == *proto { matches_filter = true; }
                    }
                }
                PacketFilter::Port(port) => {
                    if let (Some(sp), Some(dp)) = (src_port_opt, dst_port_opt) {
                        if sp == *port || dp == *port { matches_filter = true; }
                    }
                }
                PacketFilter::Ip(ip) => {
                    if let (Some(sip), Some(dip)) = (src_ip_opt, dst_ip_opt) {
                        if sip == *ip || dip == *ip { matches_filter = true; }
                    }
                }
            }

            if !matches_filter {
                continue;
            }

            matched_count += 1;

            if json_mode {
                let proto_str = match protocol_opt {
                    Some(p) => protocol_name(p),
                    None => match ether_type {
                        0x0806 => "ARP",
                        0x86DD => "IPv6",
                        _ => "ETH",
                    },
                };

                let src_ip_str = src_ip_opt.map(|ip| ip.to_string()).unwrap_or_else(|| format_mac(src_mac));
                let dst_ip_str = dst_ip_opt.map(|ip| ip.to_string()).unwrap_or_else(|| format_mac(dst_mac));
                let hex_str = hex_encode(data, 32);

                let json_line = format!(
                    "{{\"id\":{},\"captured\":{},\"len\":{},\"proto\":\"{}\",\"src\":\"{}\",\"dst\":\"{}\",\"src_port\":{},\"dst_port\":{},\"ttl\":{},\"l4_info\":\"{}\",\"src_mac\":\"{}\",\"dst_mac\":\"{}\",\"hex\":\"{}\"}}",
                    matched_count,
                    packet_count,
                    data.len(),
                    proto_str,
                    src_ip_str,
                    dst_ip_str,
                    src_port_opt.map(|p| p.to_string()).unwrap_or_else(|| "null".to_string()),
                    dst_port_opt.map(|p| p.to_string()).unwrap_or_else(|| "null".to_string()),
                    ttl_opt.map(|t| t.to_string()).unwrap_or_else(|| "null".to_string()),
                    l4_info.replace('"', "\\\""),
                    format_mac(src_mac),
                    format_mac(dst_mac),
                    hex_str
                );

                safe_println(&json_line);
            } else {
                let eth_desc = match ether_type {
                    0x0800 => "IPv4 (0x0800)",
                    0x86DD => "IPv6 (0x86DD)",
                    0x0806 => "ARP (0x0806)",
                    0x8100 => "VLAN (0x8100)",
                    _ => "Other Protocol",
                };

                println!("\n==================================================");
                println!("  Matched Packet #{} (Captured Total: {}, Bytes: {})", matched_count, packet_count, data.len());
                println!("==================================================");

                println!("  [Layer 2 - Ethernet Header]");
                println!("    Destination MAC : {}", format_mac(dst_mac));
                println!("    Source MAC      : {}", format_mac(src_mac));
                println!("    EtherType       : 0x{:04X} -> {}", ether_type, eth_desc);

                if ether_type == 0x0800 && data.len() >= ip_start + 20 {
                    let version = data[ip_start] >> 4;
                    let ihl = data[ip_start] & 0x0F;
                    let ihl_bytes = (ihl * 4) as usize;
                    let total_length = u16::from_be_bytes([data[ip_start + 2], data[ip_start + 3]]);
                    let ttl = data[ip_start + 8];
                    let protocol = protocol_opt.unwrap();

                    println!("  [Layer 3 - IPv4 Header]");
                    println!("    IP Version      : IPv{}", version);
                    println!("    Header Length   : {} bytes (IHL: {})", ihl_bytes, ihl);
                    println!("    Total Length    : {} bytes", total_length);
                    println!("    TTL (Hop Limit) : {}", ttl);
                    println!("    Protocol        : {} ({})", protocol_name(protocol), protocol);
                    println!("    Source IP       : {}", src_ip_opt.unwrap());
                    println!("    Destination IP  : {}", dst_ip_opt.unwrap());

                    let l4_start = ip_start + ihl_bytes;

                    if protocol == 6 && data.len() >= l4_start + 20 {
                        let src_port = src_port_opt.unwrap();
                        let dst_port = dst_port_opt.unwrap();
                        let flags = data[l4_start + 13];

                        println!("  [Layer 4 - TCP Header]");
                        println!("    Source Port     : {} ({})", src_port, port_service(src_port));
                        println!("    Destination Port: {} ({})", dst_port, port_service(dst_port));
                        println!("    Control Flags   : [ {} ] (0x{:02X})", parse_tcp_flags(flags), flags);
                    } else if protocol == 17 && data.len() >= l4_start + 8 {
                        let src_port = src_port_opt.unwrap();
                        let dst_port = dst_port_opt.unwrap();
                        println!("  [Layer 4 - UDP Header]");
                        println!("    Source Port     : {} ({})", src_port, port_service(src_port));
                        println!("    Destination Port: {} ({})", dst_port, port_service(dst_port));
                    } else if protocol == 1 && data.len() >= l4_start + 4 {
                        let icmp_type = data[l4_start];
                        let icmp_code = data[l4_start + 1];
                        println!("  [Layer 4 - ICMP Header]");
                        println!("    Type            : {} ({})", icmp_type, icmp_type_name(icmp_type));
                        println!("    Code            : {}", icmp_code);
                    }
                }
                print_hex_dump(data, 64);
            }
        }
    }

    if !json_mode {
        println!("\n[+] Finished processing packets. Matched: {}, Total Processed: {}", matched_count, packet_count);
    }
}
