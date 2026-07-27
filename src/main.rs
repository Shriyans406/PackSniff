use pcap::Capture;
use std::env;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();
    
    // Simple argument parsing for --interface <IFACE>
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

    // Open network interface in promiscuous mode with immediate mode enabled
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

    // Loop forever capturing live packets
    while let Ok(packet) = cap.next_packet() {
        packet_count += 1;
        println!("Captured packet #{}: {} bytes", packet_count, packet.header.len);
    }
}
