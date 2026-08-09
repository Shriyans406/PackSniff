use pcap::Capture;
use std::env;
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::process;
use std::str::FromStr;
use std::collections::HashMap;

// --- ADVANCED PACKET FILTERING AST DATA STRUCTURES ---

#[derive(Debug, Clone, PartialEq)]
pub enum SizeOp {
    Equal,
    GreaterThan,
    GreaterThanOrEqual,
    LessThan,
    LessThanOrEqual,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FilterCondition {
    Protocol(u8),
    SrcIp(Ipv4Addr),
    DstIp(Ipv4Addr),
    Ip(Ipv4Addr),
    SrcPort(u16),
    DstPort(u16),
    Port(u16),
    PacketSize(SizeOp, usize),
}

#[derive(Debug, Clone, PartialEq)]
pub enum FilterExpr {
    Any,
    Match(FilterCondition),
    And(Box<FilterExpr>, Box<FilterExpr>),
    Or(Box<FilterExpr>, Box<FilterExpr>),
    Not(Box<FilterExpr>),
}

impl FilterExpr {
    pub fn matches(
        &self,
        pkt_size: usize,
        _eth_type: u16,
        src_ip: Option<Ipv4Addr>,
        dst_ip: Option<Ipv4Addr>,
        proto: Option<u8>,
        src_port: Option<u16>,
        dst_port: Option<u16>,
    ) -> bool {
        match self {
            FilterExpr::Any => true,
            FilterExpr::Not(sub) => !sub.matches(pkt_size, _eth_type, src_ip, dst_ip, proto, src_port, dst_port),
            FilterExpr::And(left, right) => {
                left.matches(pkt_size, _eth_type, src_ip, dst_ip, proto, src_port, dst_port)
                    && right.matches(pkt_size, _eth_type, src_ip, dst_ip, proto, src_port, dst_port)
            }
            FilterExpr::Or(left, right) => {
                left.matches(pkt_size, _eth_type, src_ip, dst_ip, proto, src_port, dst_port)
                    || right.matches(pkt_size, _eth_type, src_ip, dst_ip, proto, src_port, dst_port)
            }
            FilterExpr::Match(cond) => match cond {
                FilterCondition::Protocol(p) => proto == Some(*p),
                FilterCondition::SrcIp(ip) => src_ip == Some(*ip),
                FilterCondition::DstIp(ip) => dst_ip == Some(*ip),
                FilterCondition::Ip(ip) => src_ip == Some(*ip) || dst_ip == Some(*ip),
                FilterCondition::SrcPort(p) => src_port == Some(*p),
                FilterCondition::DstPort(p) => dst_port == Some(*p),
                FilterCondition::Port(p) => src_port == Some(*p) || dst_port == Some(*p),
                FilterCondition::PacketSize(op, val) => match op {
                    SizeOp::Equal => pkt_size == *val,
                    SizeOp::GreaterThan => pkt_size > *val,
                    SizeOp::GreaterThanOrEqual => pkt_size >= *val,
                    SizeOp::LessThan => pkt_size < *val,
                    SizeOp::LessThanOrEqual => pkt_size <= *val,
                },
            },
        }
    }
}

impl std::fmt::Display for FilterExpr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FilterExpr::Any => write!(f, "NONE (Capturing All Traffic)"),
            FilterExpr::Match(cond) => match cond {
                FilterCondition::Protocol(p) => write!(f, "proto == {}", protocol_name(*p)),
                FilterCondition::SrcIp(ip) => write!(f, "src_ip == {}", ip),
                FilterCondition::DstIp(ip) => write!(f, "dst_ip == {}", ip),
                FilterCondition::Ip(ip) => write!(f, "host == {}", ip),
                FilterCondition::SrcPort(p) => write!(f, "sport == {}", p),
                FilterCondition::DstPort(p) => write!(f, "dport == {}", p),
                FilterCondition::Port(p) => write!(f, "port == {}", p),
                FilterCondition::PacketSize(op, sz) => match op {
                    SizeOp::Equal => write!(f, "size == {}B", sz),
                    SizeOp::GreaterThan => write!(f, "size > {}B", sz),
                    SizeOp::GreaterThanOrEqual => write!(f, "size >= {}B", sz),
                    SizeOp::LessThan => write!(f, "size < {}B", sz),
                    SizeOp::LessThanOrEqual => write!(f, "size <= {}B", sz),
                },
            },
            FilterExpr::And(left, right) => write!(f, "({} AND {})", left, right),
            FilterExpr::Or(left, right) => write!(f, "({} OR {})", left, right),
            FilterExpr::Not(sub) => write!(f, "NOT ({})", sub),
        }
    }
}


#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct FlowKey {
    pub ip_a: Ipv4Addr,
    pub port_a: u16,
    pub ip_b: Ipv4Addr,
    pub port_b: u16,
    pub protocol: u8,
}

impl FlowKey {
    pub fn canonical(src_ip: Ipv4Addr, src_port: u16, dst_ip: Ipv4Addr, dst_port: u16, proto: u8) -> (Self, bool) {
        if (src_ip, src_port) <= (dst_ip, dst_port) {
            (
                FlowKey { ip_a: src_ip, port_a: src_port, ip_b: dst_ip, port_b: dst_port, protocol: proto },
                true, // Forward direction
            )
        } else {
            (
                FlowKey { ip_a: dst_ip, port_a: dst_port, ip_b: src_ip, port_b: src_port, protocol: proto },
                false, // Reverse direction
            )
        }
    }
}

#[derive(Debug, Clone)]
pub struct FlowStats {
    pub pkts_fwd: u64,
    pub pkts_rev: u64,
    pub bytes_fwd: u64,
    pub bytes_rev: u64,
    pub first_seen: std::time::Instant,
    pub last_seen: std::time::Instant,
    pub tcp_state: String,
}

// --- LEXER & PARSER FOR FILTER EXPRESSIONS ---

#[derive(Debug, Clone, PartialEq)]
enum Token {
    LParen,
    RParen,
    And,
    Or,
    Not,
    Word(String),
}

fn tokenize(input: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();

    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
            continue;
        }

        if c == '(' {
            tokens.push(Token::LParen);
            chars.next();
        } else if c == ')' {
            tokens.push(Token::RParen);
            chars.next();
        } else if c == '!' {
            tokens.push(Token::Not);
            chars.next();
        } else if c == '&' {
            chars.next();
            if chars.peek() == Some(&'&') {
                chars.next();
            }
            tokens.push(Token::And);
        } else if c == '|' {
            chars.next();
            if chars.peek() == Some(&'|') {
                chars.next();
            }
            tokens.push(Token::Or);
        } else {
            let mut word = String::new();
            while let Some(&ch) = chars.peek() {
                if ch.is_whitespace() || ch == '(' || ch == ')' || ch == '!' {
                    break;
                }
                word.push(ch);
                chars.next();
            }

            if !word.is_empty() {
                let lower = word.to_lowercase();
                if lower == "and" {
                    tokens.push(Token::And);
                } else if lower == "or" {
                    tokens.push(Token::Or);
                } else if lower == "not" {
                    tokens.push(Token::Not);
                } else {
                    tokens.push(Token::Word(word));
                }
            }
        }
    }
    tokens
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self {
        Parser { tokens, pos: 0 }
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn next_token(&mut self) -> Option<Token> {
        if self.pos < self.tokens.len() {
            let tok = self.tokens[self.pos].clone();
            self.pos += 1;
            Some(tok)
        } else {
            None
        }
    }

    fn parse_expr(&mut self) -> Result<FilterExpr, String> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Result<FilterExpr, String> {
        let mut left = self.parse_and()?;
        while let Some(Token::Or) = self.peek() {
            self.next_token();
            let right = self.parse_and()?;
            left = FilterExpr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<FilterExpr, String> {
        let mut left = self.parse_not()?;
        loop {
            if let Some(Token::And) = self.peek() {
                self.next_token();
                let right = self.parse_not()?;
                left = FilterExpr::And(Box::new(left), Box::new(right));
            } else if self.is_primary_start() {
                // Implicit AND e.g. "tcp port 443"
                let right = self.parse_not()?;
                left = FilterExpr::And(Box::new(left), Box::new(right));
            } else {
                break;
            }
        }
        Ok(left)
    }

    fn is_primary_start(&self) -> bool {
        match self.peek() {
            Some(Token::LParen) | Some(Token::Not) | Some(Token::Word(_)) => true,
            _ => false,
        }
    }

    fn parse_not(&mut self) -> Result<FilterExpr, String> {
        if let Some(Token::Not) = self.peek() {
            self.next_token();
            let expr = self.parse_not()?;
            Ok(FilterExpr::Not(Box::new(expr)))
        } else {
            self.parse_primary()
        }
    }

    fn parse_primary(&mut self) -> Result<FilterExpr, String> {
        match self.next_token() {
            Some(Token::LParen) => {
                let expr = self.parse_expr()?;
                match self.next_token() {
                    Some(Token::RParen) => Ok(expr),
                    _ => Err("Expected closing parenthesis ')'".to_string()),
                }
            }
            Some(Token::Word(w)) => {
                let lower = w.to_lowercase();
                match lower.as_str() {
                    "tcp" => Ok(FilterExpr::Match(FilterCondition::Protocol(6))),
                    "udp" => Ok(FilterExpr::Match(FilterCondition::Protocol(17))),
                    "icmp" => Ok(FilterExpr::Match(FilterCondition::Protocol(1))),
                    "src" | "src_ip" | "srcip" => {
                        let ip_str = self.expect_word("Expected IP address after 'src'")?;
                        let ip = Ipv4Addr::from_str(&ip_str)
                            .map_err(|_| format!("Invalid IPv4 address '{}' after 'src'", ip_str))?;
                        Ok(FilterExpr::Match(FilterCondition::SrcIp(ip)))
                    }
                    "dst" | "dst_ip" | "dstip" => {
                        let ip_str = self.expect_word("Expected IP address after 'dst'")?;
                        let ip = Ipv4Addr::from_str(&ip_str)
                            .map_err(|_| format!("Invalid IPv4 address '{}' after 'dst'", ip_str))?;
                        Ok(FilterExpr::Match(FilterCondition::DstIp(ip)))
                    }
                    "ip" | "host" => {
                        let ip_str = self.expect_word("Expected IP address after 'ip'")?;
                        let ip = Ipv4Addr::from_str(&ip_str)
                            .map_err(|_| format!("Invalid IPv4 address '{}' after 'ip'", ip_str))?;
                        Ok(FilterExpr::Match(FilterCondition::Ip(ip)))
                    }
                    "sport" | "src_port" | "srcport" => {
                        let p_str = self.expect_word("Expected port number after 'sport'")?;
                        let p = p_str.parse::<u16>()
                            .map_err(|_| format!("Invalid port number '{}' after 'sport'", p_str))?;
                        Ok(FilterExpr::Match(FilterCondition::SrcPort(p)))
                    }
                    "dport" | "dst_port" | "dstport" => {
                        let p_str = self.expect_word("Expected port number after 'dport'")?;
                        let p = p_str.parse::<u16>()
                            .map_err(|_| format!("Invalid port number '{}' after 'dport'", p_str))?;
                        Ok(FilterExpr::Match(FilterCondition::DstPort(p)))
                    }
                    "port" => {
                        let p_str = self.expect_word("Expected port number after 'port'")?;
                        let p = p_str.parse::<u16>()
                            .map_err(|_| format!("Invalid port number '{}' after 'port'", p_str))?;
                        Ok(FilterExpr::Match(FilterCondition::Port(p)))
                    }
                    "size" | "len" => {
                        let (op, sz_str) = self.parse_size_op_and_val()?;
                        let val = sz_str.parse::<usize>()
                            .map_err(|_| format!("Invalid packet size number '{}'", sz_str))?;
                        Ok(FilterExpr::Match(FilterCondition::PacketSize(op, val)))
                    }
                    _ => {
                        if let Ok(ip) = Ipv4Addr::from_str(&w) {
                            Ok(FilterExpr::Match(FilterCondition::Ip(ip)))
                        } else if let Ok(p) = w.parse::<u16>() {
                            Ok(FilterExpr::Match(FilterCondition::Port(p)))
                        } else {
                            Err(format!("Unknown filter token '{}'", w))
                        }
                    }
                }
            }
            Some(tok) => Err(format!("Unexpected token '{:?}'", tok)),
            None => Err("Unexpected end of filter expression".to_string()),
        }
    }

    fn expect_word(&mut self, err_msg: &str) -> Result<String, String> {
        match self.next_token() {
            Some(Token::Word(w)) => Ok(w),
            _ => Err(err_msg.to_string()),
        }
    }

    fn parse_size_op_and_val(&mut self) -> Result<(SizeOp, String), String> {
        let first_word = self.expect_word("Expected size operator or number after 'size'")?;
        match first_word.as_str() {
            ">" => {
                let val_str = self.expect_word("Expected number after 'size >'")?;
                Ok((SizeOp::GreaterThan, val_str))
            }
            ">=" => {
                let val_str = self.expect_word("Expected number after 'size >='")?;
                Ok((SizeOp::GreaterThanOrEqual, val_str))
            }
            "<" => {
                let val_str = self.expect_word("Expected number after 'size <'")?;
                Ok((SizeOp::LessThan, val_str))
            }
            "<=" => {
                let val_str = self.expect_word("Expected number after 'size <='")?;
                Ok((SizeOp::LessThanOrEqual, val_str))
            }
            "==" | "=" => {
                let val_str = self.expect_word("Expected number after 'size =='")?;
                Ok((SizeOp::Equal, val_str))
            }
            other => {
                if other.starts_with(">=") {
                    Ok((SizeOp::GreaterThanOrEqual, other[2..].to_string()))
                } else if other.starts_with("<=") {
                    Ok((SizeOp::LessThanOrEqual, other[2..].to_string()))
                } else if other.starts_with('>') {
                    Ok((SizeOp::GreaterThan, other[1..].to_string()))
                } else if other.starts_with('<') {
                    Ok((SizeOp::LessThan, other[1..].to_string()))
                } else if other.starts_with("==") {
                    Ok((SizeOp::Equal, other[2..].to_string()))
                } else if other.starts_with('=') {
                    Ok((SizeOp::Equal, other[1..].to_string()))
                } else {
                    Ok((SizeOp::Equal, other.to_string()))
                }
            }
        }
    }
}

pub fn parse_filter(input: &str) -> Result<FilterExpr, String> {
    let input_trimmed = input.trim();
    if input_trimmed.is_empty() {
        return Ok(FilterExpr::Any);
    }
    let tokens = tokenize(input_trimmed);
    if tokens.is_empty() {
        return Ok(FilterExpr::Any);
    }
    let mut parser = Parser::new(tokens);
    let expr = parser.parse_expr()?;
    if parser.pos < parser.tokens.len() {
        return Err(format!("Unexpected extra token '{:?}' in filter expression", parser.tokens[parser.pos]));
    }
    Ok(expr)
}

// --- CLI HELP & PRINT UTILITIES ---

fn print_help() {
    println!(
        r#"
================================================================================
  🛡️  PACKSNIFF RUST ENGINE — COMMAND LINE INTERFACE & HELP
================================================================================

USAGE:
    packet-sniffer-engine [OPTIONS]

CAPTURE SOURCE OPTIONS (Required):
    --interface, -i <NAME>   Specify active network interface to capture live (e.g. enp0s3)
    --read, -r <FILE.pcap>   Read and replay offline PCAP capture file

OUTPUT FORMAT OPTIONS:
    --json, -j               Output line-delimited JSON stream for TUI presenter
    --save, -s <FILE.pcap>   Save raw live captured packets to a PCAP file
    --flows                  Print stateful connection / flow analysis summary table on exit

FILTERING OPTIONS:
    --filter, -f <EXPR>      Apply advanced packet filter expression:
                             - tcp / udp / icmp           Isolate specific protocol
                             - src <IP> / dst <IP>        Isolate source/destination IPv4
                             - sport <P> / dport <P>      Isolate source/destination Port
                             - port <P> / ip <ADDR>       Isolate general Port / IPv4
                             - size > <N> / size < <N>    Isolate packets by size threshold
                             - COMBINATIONS: "tcp and port 443", "udp and dport 53", "src 10.0.2.15"

MISCELLANEOUS:
    --help, -h               Display this help banner and exit

EXAMPLES:
    packet-sniffer-engine --interface enp0s3 --filter "tcp and port 443"
    packet-sniffer-engine --interface enp0s3 --filter "udp and port 53" --json
    packet-sniffer-engine --interface enp0s3 --filter "src 10.0.2.15 and size > 100"
    packet-sniffer-engine --read capture.pcap --filter "port 80 or port 443"
==============================================================================="#
    );
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

fn format_bytes_rust(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
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

// --- MAIN ENGINE FUNCTION ---

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut interface_name = String::new();
    let mut filter_expr = FilterExpr::Any;
    let mut json_mode = false;
    let mut flow_mode = false;
    let mut save_path: Option<String> = None;
    let mut read_path: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                print_help();
                process::exit(0);
            }
            "--flows" => {
                flow_mode = true;
            }
            "--interface" | "-i" => {
                if i + 1 < args.len() {
                    interface_name = args[i + 1].clone();
                    i += 1;
                } else {
                    eprintln!("[!] Error: Option '--interface' requires an interface name argument.");
                    process::exit(1);
                }
            }
            "--json" | "-j" => {
                json_mode = true;
            }
            "--save" | "-s" => {
                if i + 1 < args.len() {
                    save_path = Some(args[i + 1].clone());
                    i += 1;
                } else {
                    eprintln!("[!] Error: Option '--save' requires a file path argument.");
                    process::exit(1);
                }
            }
            "--read" | "-r" => {
                if i + 1 < args.len() {
                    read_path = Some(args[i + 1].clone());
                    i += 1;
                } else {
                    eprintln!("[!] Error: Option '--read' requires a PCAP file path argument.");
                    process::exit(1);
                }
            }
            "--filter" | "-f" => {
                if i + 1 < args.len() {
                    let mut filter_raw = args[i + 1].clone();
                    i += 1;
                    // Handle multi-token positional flags like "--filter port 443" or "--filter ip 8.8.8.8"
                    if (filter_raw.to_lowercase() == "port" || filter_raw.to_lowercase() == "ip"
                        || filter_raw.to_lowercase() == "src" || filter_raw.to_lowercase() == "dst"
                        || filter_raw.to_lowercase() == "sport" || filter_raw.to_lowercase() == "dport"
                        || filter_raw.to_lowercase() == "size") && i < args.len()
                    {
                        filter_raw.push(' ');
                        filter_raw.push_str(&args[i]);
                        i += 1;
                    }

                    match parse_filter(&filter_raw) {
                        Ok(e) => filter_expr = e,
                        Err(err) => {
                            eprintln!("[!] Error parsing filter expression '{}': {}", filter_raw, err);
                            process::exit(1);
                        }
                    }
                } else {
                    eprintln!("[!] Error: Option '--filter' requires a filter expression argument.");
                    process::exit(1);
                }
            }
            _ => {}
        }
        i += 1;
    }

    if read_path.is_none() && interface_name.is_empty() {
        eprintln!("[!] Error: No network interface or PCAP file specified.");
        eprintln!("Run 'packet-sniffer-engine --help' for complete usage instructions.");
        process::exit(1);
    }

    let mut cap_live: Option<Capture<pcap::Active>> = None;
    let mut cap_offline: Option<Capture<pcap::Offline>> = None;

    if let Some(ref r_path) = read_path {
        if !json_mode {
            println!("[+] Opening offline PCAP file: {}...", r_path);
        }
        match Capture::from_file(r_path) {
            Ok(c) => cap_offline = Some(c),
            Err(e) => {
                eprintln!("[!] Failed to open PCAP file '{}': {}", r_path, e);
                process::exit(1);
            }
        }
    } else {
        if !json_mode {
            println!("[+] Opening live interface: {}...", interface_name);
        }
        match Capture::from_device(interface_name.as_str()) {
            Ok(device) => match device.promisc(true).immediate_mode(true).open() {
                Ok(c) => cap_live = Some(c),
                Err(e) => {
                    eprintln!("[!] Failed to open device '{}': {}", interface_name, e);
                    process::exit(1);
                }
            },
            Err(e) => {
                eprintln!("[!] Failed to find device '{}': {}", interface_name, e);
                process::exit(1);
            }
        }
    }

    if !json_mode {
        println!("[+] Active Filter: {}", filter_expr);
        if let Some(ref s_path) = save_path {
            println!("[+] Saving live capture to PCAP file: {}...", s_path);
        }
    }

    let mut savefile = if let Some(ref s_path) = save_path {
        if let Some(ref mut c_live) = cap_live {
            match c_live.savefile(s_path) {
                Ok(sf) => Some(sf),
                Err(e) => {
                    eprintln!("[!] Failed to create savefile '{}': {}", s_path, e);
                    process::exit(1);
                }
            }
        } else if let Some(ref mut c_off) = cap_offline {
            match c_off.savefile(s_path) {
                Ok(sf) => Some(sf),
                Err(e) => {
                    eprintln!("[!] Failed to create savefile '{}': {}", s_path, e);
                    process::exit(1);
                }
            }
        } else {
            None
        }
    } else {
        None
    };

    let mut packet_count: u64 = 0;
    let mut matched_count: u64 = 0;
    let mut flows: HashMap<FlowKey, FlowStats> = HashMap::new();

    loop {
        let (data_bytes, save_pkt) = if let Some(ref mut c_live) = cap_live {
            match c_live.next_packet() {
                Ok(packet) => {
                    let b = packet.data.to_vec();
                    (b, Some(packet))
                }
                Err(_) => break,
            }
        } else if let Some(ref mut c_off) = cap_offline {
            match c_off.next_packet() {
                Ok(packet) => {
                    let b = packet.data.to_vec();
                    (b, Some(packet))
                }
                Err(_) => break,
            }
        } else {
            break;
        };

        packet_count += 1;
        let data = &data_bytes[..];

        if let Some(ref mut sf) = savefile {
            if let Some(ref pkt) = save_pkt {
                sf.write(pkt);
            }
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

            // EVALUATE ADVANCED FILTER AST
            let matches = filter_expr.matches(
                data.len(),
                ether_type,
                src_ip_opt,
                dst_ip_opt,
                protocol_opt,
                src_port_opt,
                dst_port_opt,
            );

            if !matches {
                continue;
            }

            matched_count += 1;

            if let (Some(s_ip), Some(d_ip), Some(s_port), Some(d_port), Some(proto)) =
                (src_ip_opt, dst_ip_opt, src_port_opt, dst_port_opt, protocol_opt)
            {
                let (key, is_fwd) = FlowKey::canonical(s_ip, s_port, d_ip, d_port, proto);
                let now = std::time::Instant::now();
                let entry = flows.entry(key).or_insert_with(|| FlowStats {
                    pkts_fwd: 0,
                    pkts_rev: 0,
                    bytes_fwd: 0,
                    bytes_rev: 0,
                    first_seen: now,
                    last_seen: now,
                    tcp_state: if proto == 6 { "SYN_SENT".to_string() } else { "ACTIVE".to_string() },
                });

                entry.last_seen = now;
                if is_fwd {
                    entry.pkts_fwd += 1;
                    entry.bytes_fwd += data.len() as u64;
                } else {
                    entry.pkts_rev += 1;
                    entry.bytes_rev += data.len() as u64;
                }

                if proto == 6 {
                    if l4_info.contains("RST") {
                        entry.tcp_state = "RESET".to_string();
                    } else if l4_info.contains("FIN") {
                        entry.tcp_state = "FIN_WAIT".to_string();
                    } else if l4_info.contains("ACK") && entry.tcp_state == "SYN_SENT" {
                        entry.tcp_state = "ESTABLISHED".to_string();
                    }
                }
            }

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
        if flow_mode || !flows.is_empty() {
            println!("\n====================================================================================================");
            println!("  🔗 PACKSNIFF STATEFUL FLOW TRACKER — CONNECTION CONVERSATIONS ({})", flows.len());
            println!("====================================================================================================");
            println!("{:<48} {:<16} {:<24} {:<10} {:<12}", "FLOW 5-TUPLE", "PKTS (Tx/Rx)", "BYTES (Tx/Rx)", "DURATION", "STATE");
            println!("----------------------------------------------------------------------------------------------------");
            for (key, stat) in &flows {
                let duration_sec = stat.last_seen.duration_since(stat.first_seen).as_secs_f64();
                let proto_str = protocol_name(key.protocol);
                let svc_a = port_service(key.port_a);
                let svc_b = port_service(key.port_b);
                let svc_name = if svc_a != "CUSTOM" {
                    svc_a
                } else if svc_b != "CUSTOM" {
                    svc_b
                } else {
                    proto_str
                };

                let flow_str = format!("{}:{} -> {}:{} ({})", key.ip_a, key.port_a, key.ip_b, key.port_b, svc_name);
                let total_pkts = stat.pkts_fwd + stat.pkts_rev;
                let pkts_str = format!("{} ({} / {})", total_pkts, stat.pkts_fwd, stat.pkts_rev);
                let total_bytes = stat.bytes_fwd + stat.bytes_rev;
                let bytes_str = format!("{} ({} / {})", format_bytes_rust(total_bytes), format_bytes_rust(stat.bytes_fwd), format_bytes_rust(stat.bytes_rev));
                let dur_str = format!("{:.1}s", duration_sec);
                println!("{:<48} {:<16} {:<24} {:<10} {:<12}", flow_str, pkts_str, bytes_str, dur_str, stat.tcp_state);
            }
            println!("====================================================================================================");
        }
    }
}

// --- UNIT TESTS ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_filter_simple() {
        assert_eq!(parse_filter("tcp").unwrap(), FilterExpr::Match(FilterCondition::Protocol(6)));
        assert_eq!(parse_filter("udp").unwrap(), FilterExpr::Match(FilterCondition::Protocol(17)));
        assert_eq!(parse_filter("icmp").unwrap(), FilterExpr::Match(FilterCondition::Protocol(1)));
    }

    #[test]
    fn test_parse_filter_ip_and_ports() {
        let ip = Ipv4Addr::new(192, 168, 1, 10);
        assert_eq!(parse_filter("src 192.168.1.10").unwrap(), FilterExpr::Match(FilterCondition::SrcIp(ip)));
        assert_eq!(parse_filter("dst 192.168.1.10").unwrap(), FilterExpr::Match(FilterCondition::DstIp(ip)));
        assert_eq!(parse_filter("port 443").unwrap(), FilterExpr::Match(FilterCondition::Port(443)));
        assert_eq!(parse_filter("sport 80").unwrap(), FilterExpr::Match(FilterCondition::SrcPort(80)));
        assert_eq!(parse_filter("dport 53").unwrap(), FilterExpr::Match(FilterCondition::DstPort(53)));
    }

    #[test]
    fn test_parse_filter_size() {
        assert_eq!(parse_filter("size > 100").unwrap(), FilterExpr::Match(FilterCondition::PacketSize(SizeOp::GreaterThan, 100)));
        assert_eq!(parse_filter("size <= 500").unwrap(), FilterExpr::Match(FilterCondition::PacketSize(SizeOp::LessThanOrEqual, 500)));
    }

    #[test]
    fn test_parse_filter_combinations() {
        let expr = parse_filter("tcp and port 443").unwrap();
        assert_eq!(
            expr,
            FilterExpr::And(
                Box::new(FilterExpr::Match(FilterCondition::Protocol(6))),
                Box::new(FilterExpr::Match(FilterCondition::Port(443)))
            )
        );

        let expr_not = parse_filter("not icmp").unwrap();
        assert_eq!(
            expr_not,
            FilterExpr::Not(Box::new(FilterExpr::Match(FilterCondition::Protocol(1))))
        );
    }

    #[test]
    fn test_filter_evaluation() {
        let expr = parse_filter("tcp and port 443").unwrap();
        let src_ip = Some(Ipv4Addr::new(10, 0, 2, 15));
        let dst_ip = Some(Ipv4Addr::new(8, 8, 8, 8));

        // Matches HTTPS TCP packet
        assert!(expr.matches(100, 0x0800, src_ip, dst_ip, Some(6), Some(50000), Some(443)));
        // Fails UDP packet on port 443
        assert!(!expr.matches(100, 0x0800, src_ip, dst_ip, Some(17), Some(50000), Some(443)));
        // Fails TCP packet on port 80
        assert!(!expr.matches(100, 0x0800, src_ip, dst_ip, Some(6), Some(50000), Some(80)));
    }

    #[test]
    fn test_flow_canonical_key() {
        let ip1 = Ipv4Addr::new(192, 168, 1, 5);
        let ip2 = Ipv4Addr::new(142, 250, 80, 14);
        let (key1, is_fwd1) = FlowKey::canonical(ip1, 52143, ip2, 443, 6);
        let (key2, is_fwd2) = FlowKey::canonical(ip2, 443, ip1, 52143, 6);

        assert_eq!(key1, key2);
        assert_ne!(is_fwd1, is_fwd2);
    }
}
