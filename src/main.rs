use pcap::Capture;
use std::env;
use std::process;

// Format slice of bytes into space-separated HEX string
fn format_mac(bytes: &[u8]) -> String {
    bytes.iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<String>>()
        .join(":")
}

// Print formatted Hex Dump with ASCII view (first N bytes)
fn print_hex_dump(data: &[u8], max_bytes: usize) {
    let len = data.len().min(max_bytes);
    let slice = &data[..len];
    println!("  Raw Hex Dump (first {} bytes):", len);

    for (idx, chunk) in slice.chunks(16).enumerate() {
        let hex_str = chunk.iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<String>>()
            .join(" ");

        let ascii_str: String = chunk.iter()
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
        println!("  Packet #{} (Length: {} bytes)", packet_count, data.len());
        println!("==================================================");

        // Ethernet Header requires at least 14 bytes
        if data.len() >= 14 {
            let dst_mac = &data[0..6];
            let src_mac = &data[6..12];
            let ether_type = u16::from_be_bytes([data[12], data[13]]);

            let eth_desc = match ether_type {
                0x0800 => "IPv4 (0x0800)",
                0x86DD => "IPv6 (0x86DD)",
                0x0806 => "ARP (0x0806)",
                _ => "Unknown / Other",
            };

            println!("  [Ethernet Header]");
            println!("    Destination MAC : {}", format_mac(dst_mac));
            println!("    Source MAC      : {}", format_mac(src_mac));
            println!("    EtherType       : 0x{:04X} -> {}", ether_type, eth_desc);
        }

        print_hex_dump(data, 64);
    }
}
