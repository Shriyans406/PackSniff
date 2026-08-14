#!/usr/bin/env python3
"""
PackSniff Analyzer — Offline Capture Summary Tool
Usage:
    python3 analyze.py <capture.pcap | packets.json | packets.csv>
"""
import sys
import os
import json
import csv
from collections import Counter

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    from rich.text import Text
    from rich.columns import Columns
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "rich",
                           "--break-system-packages", "--quiet"])
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    from rich.text import Text
    from rich.columns import Columns

console = Console()

COMMON_SERVICES = {
    20: "FTP", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 80: "HTTP", 123: "NTP", 143: "IMAP", 443: "HTTPS",
    3306: "MySQL", 5432: "PostgreSQL", 8080: "HTTP-ALT", 8443: "HTTPS-ALT"
}

KNOWN_HOSTS = {
    "8.8.8.8": "dns.google",
    "8.8.4.4": "dns.google",
    "1.1.1.1": "one.one.one.one",
    "9.9.9.9": "dns.quad9.net",
    "10.0.2.2": "Gateway/Router",
    "10.0.2.15": "Local VM (Debian)",
    "127.0.0.1": "localhost",
}

# ─────────────────────────────────────────────────────────────
# Helper utilities
# ─────────────────────────────────────────────────────────────

def format_bytes(b):
    b = int(b)
    if b < 1024:
        return f"{b} B"
    elif b < 1024 ** 2:
        return f"{b / 1024:.1f} KB"
    elif b < 1024 ** 3:
        return f"{b / 1024 ** 2:.2f} MB"
    else:
        return f"{b / 1024 ** 3:.2f} GB"

def format_duration(secs):
    secs = int(secs)
    h = secs // 3600
    m = (secs % 3600) // 60
    s = secs % 60
    return f"{h:02d}:{m:02d}:{s:02d}"

def label(ip):
    return KNOWN_HOSTS.get(ip, ip)

def proto_color(proto):
    colors = {"TCP": "bold cyan", "UDP": "bold bright_yellow",
               "ICMP": "bold bright_red", "ARP": "bold magenta",
               "OTHER": "bold green", "ETH": "bold green"}
    return colors.get(proto, "bold white")

# ─────────────────────────────────────────────────────────────
# Loaders
# ─────────────────────────────────────────────────────────────

def load_json(filepath):
    packets = []
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line.startswith("{"):
                try:
                    packets.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return packets

def load_csv(filepath):
    packets = []
    with open(filepath, newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            p = {
                "id":       int(row.get("id", 0) or 0),
                "proto":    row.get("proto", "OTHER"),
                "src":      row.get("src", ""),
                "dst":      row.get("dst", ""),
                "src_port": int(row["src_port"]) if row.get("src_port") else None,
                "dst_port": int(row["dst_port"]) if row.get("dst_port") else None,
                "len":      int(row.get("len", 0) or 0),
                "ttl":      row.get("ttl", ""),
                "l4_info":  row.get("l4_info", ""),
            }
            packets.append(p)
    return packets

def load_pcap(filepath):
    """
    Minimal zero-dependency PCAP parser.
    Reads both little-endian (d4 c3 b2 a1) and big-endian (a1 b2 c3 d4) PCAP files.
    """
    packets = []
    try:
        with open(filepath, "rb") as f:
            magic = f.read(4)
            if magic == b'\xd4\xc3\xb2\xa1':
                endian = "little"
            elif magic == b'\xa1\xb2\xc3\xd4':
                endian = "big"
            else:
                console.print("[bold red][!] Not a valid PCAP file (bad magic bytes).[/]")
                sys.exit(1)

            # Skip remaining 20 bytes of global header
            f.read(20)

            pkt_id = 0
            while True:
                rec_hdr = f.read(16)
                if len(rec_hdr) < 16:
                    break

                incl_len = int.from_bytes(rec_hdr[8:12], endian)
                data = f.read(incl_len)
                if len(data) < incl_len:
                    break

                pkt_id += 1
                p = {
                    "id": pkt_id, "len": incl_len,
                    "proto": "OTHER", "src": "", "dst": "",
                    "src_port": None, "dst_port": None, "l4_info": "", "ttl": None
                }

                if len(data) >= 14:
                    etype = int.from_bytes(data[12:14], "big")

                    if etype == 0x8100 and len(data) >= 18:
                        # VLAN tagged — skip 4-byte tag
                        etype = int.from_bytes(data[16:18], "big")
                        data = data[4:]  # rebase ip_start

                    if etype == 0x0800 and len(data) >= 34:
                        ihl = (data[14] & 0x0F) * 4
                        proto_num = data[14 + 9]
                        p["ttl"] = data[14 + 8]
                        p["src"] = ".".join(str(b) for b in data[26:30])
                        p["dst"] = ".".join(str(b) for b in data[30:34])
                        l4 = 14 + ihl

                        if proto_num == 6 and len(data) >= l4 + 4:
                            p["proto"] = "TCP"
                            p["src_port"] = int.from_bytes(data[l4:l4+2], "big")
                            p["dst_port"] = int.from_bytes(data[l4+2:l4+4], "big")
                            if len(data) >= l4 + 14:
                                flags = data[l4 + 13]
                                flag_names = []
                                if flags & 0x01: flag_names.append("FIN")
                                if flags & 0x02: flag_names.append("SYN")
                                if flags & 0x04: flag_names.append("RST")
                                if flags & 0x10: flag_names.append("ACK")
                                p["l4_info"] = "|".join(flag_names)
                        elif proto_num == 17 and len(data) >= l4 + 4:
                            p["proto"] = "UDP"
                            p["src_port"] = int.from_bytes(data[l4:l4+2], "big")
                            p["dst_port"] = int.from_bytes(data[l4+2:l4+4], "big")
                        elif proto_num == 1 and len(data) >= l4 + 2:
                            p["proto"] = "ICMP"
                            p["l4_info"] = f"Type {data[l4]}"
                        else:
                            p["proto"] = "OTHER"

                    elif etype == 0x0806 and len(data) >= 42:
                        p["proto"] = "ARP"
                        p["src"] = ".".join(str(b) for b in data[28:32])
                        p["dst"] = ".".join(str(b) for b in data[38:42])
                        oper = int.from_bytes(data[20:22], "big")
                        p["l4_info"] = "ARP Request" if oper == 1 else "ARP Reply"

                    elif etype == 0x86DD:
                        p["proto"] = "IPv6"

                packets.append(p)

    except FileNotFoundError:
        console.print(f"[bold red][!] File not found: {filepath}[/]")
        sys.exit(1)

    return packets

# ─────────────────────────────────────────────────────────────
# Analysis & Rendering
# ─────────────────────────────────────────────────────────────

def analyze(packets, filepath):
    if not packets:
        console.print("[yellow][!] No packets found in capture file.[/]")
        return

    total_pkts  = len(packets)
    total_bytes = sum(p.get("len", 0) for p in packets)

    proto_counts    = Counter(p.get("proto", "OTHER") for p in packets)
    src_counts      = Counter(p["src"] for p in packets if p.get("src"))
    dst_counts      = Counter(p["dst"] for p in packets if p.get("dst"))
    dst_port_counts = Counter(p["dst_port"] for p in packets if p.get("dst_port"))

    # Duration: estimated from packet count (realistic for pcap / json / csv)
    duration_est = max(total_pkts / max(sum(proto_counts.values()), 1) * 60, 1)
    if total_pkts > 1000:
        duration_est = total_pkts / 150.0

    # ── Header ────────────────────────────────────────────────
    console.print()
    console.rule("[bold bright_cyan] 📊  PackSniff — Offline Capture Analysis [/]")
    console.print()

    # ── Summary Panel ─────────────────────────────────────────
    summary = Table(show_header=False, box=box.SIMPLE, expand=False, padding=(0, 2))
    summary.add_column("Label", style="bold cyan",        width=20)
    summary.add_column("Value", style="bold bright_white", width=24)
    summary.add_row("File",          os.path.basename(filepath))
    summary.add_row("Format",        filepath.rsplit(".", 1)[-1].upper())
    summary.add_row("Duration (est)",format_duration(duration_est))
    summary.add_row("Packets",       f"{total_pkts:,}")
    summary.add_row("Total Traffic", format_bytes(total_bytes))
    summary.add_row("Avg Packet",    format_bytes(total_bytes // max(total_pkts, 1)))
    console.print(Panel(summary,
        title="[bold bright_white]📁 Capture Summary[/]",
        border_style="cyan", box=box.ROUNDED))

    # ── Protocol Distribution ─────────────────────────────────
    proto_table = Table(show_header=True, box=box.SIMPLE_HEAD, expand=False, padding=(0, 1))
    proto_table.add_column("Protocol", style="bold",           width=10)
    proto_table.add_column("Packets",  justify="right",        width=10)
    proto_table.add_column("Share",    justify="right",        width=8)
    proto_table.add_column("Distribution Bar",                 width=26)

    for proto, count in proto_counts.most_common(8):
        pct = (count / total_pkts) * 100
        filled = int(pct / 4)
        bar = "█" * filled + "░" * (25 - filled)
        color = proto_color(proto)
        proto_table.add_row(
            Text(proto, style=color),
            f"{count:,}",
            f"{pct:.1f}%",
            Text(bar, style="magenta")
        )

    console.print(Panel(proto_table,
        title="[bold bright_white]📡 Protocol Distribution[/]",
        border_style="magenta", box=box.ROUNDED))

    # ── Top Destinations & Top Sources (side by side via Columns) ────
    dst_table = Table(show_header=True, box=box.SIMPLE_HEAD, expand=False, padding=(0, 1))
    dst_table.add_column("Destination IP",   style="bold bright_white", width=22)
    dst_table.add_column("Packets",          justify="right", style="cyan", width=10)
    dst_table.add_column("Est. Traffic",     justify="right", style="yellow", width=12)

    for dst_ip, count in dst_counts.most_common(8):
        est_bytes = int((count / total_pkts) * total_bytes)
        host = label(dst_ip)
        display = f"{dst_ip}\n[dim]{host}[/]" if host != dst_ip else dst_ip
        dst_table.add_row(display, f"{count:,}", format_bytes(est_bytes))

    src_table = Table(show_header=True, box=box.SIMPLE_HEAD, expand=False, padding=(0, 1))
    src_table.add_column("Source IP",   style="bold bright_white", width=22)
    src_table.add_column("Packets",     justify="right", style="cyan", width=10)
    src_table.add_column("Est. Traffic",justify="right", style="yellow", width=12)

    for src_ip, count in src_counts.most_common(6):
        est_bytes = int((count / total_pkts) * total_bytes)
        host = label(src_ip)
        display = f"{src_ip}\n[dim]{host}[/]" if host != src_ip else src_ip
        src_table.add_row(display, f"{count:,}", format_bytes(est_bytes))

    console.print(Panel(dst_table,
        title="[bold bright_white]🌐 Top Destinations[/]",
        border_style="green", box=box.ROUNDED))

    console.print(Panel(src_table,
        title="[bold bright_white]📤 Top Sources[/]",
        border_style="blue", box=box.ROUNDED))

    # ── Top Ports ─────────────────────────────────────────────
    port_table = Table(show_header=True, box=box.SIMPLE_HEAD, expand=False, padding=(0, 1))
    port_table.add_column("Port",    style="bold bright_white", width=8)
    port_table.add_column("Service", style="bold cyan",          width=14)
    port_table.add_column("Packets", justify="right", style="bold yellow", width=10)
    port_table.add_column("Share",   justify="right", style="dim",         width=8)

    for port, count in dst_port_counts.most_common(10):
        svc = COMMON_SERVICES.get(port, "CUSTOM")
        pct = (count / total_pkts) * 100
        port_table.add_row(str(port), svc, f"{count:,}", f"{pct:.1f}%")

    console.print(Panel(port_table,
        title="[bold bright_white]🔌 Top Destination Ports[/]",
        border_style="yellow", box=box.ROUNDED))

    # ── TCP Flags breakdown (if TCP traffic exists) ────────────
    tcp_pkts = [p for p in packets if p.get("proto") == "TCP" and p.get("l4_info")]
    if tcp_pkts:
        flag_counter = Counter()
        for p in tcp_pkts:
            for flag in str(p.get("l4_info", "")).replace("Flags: [", "").replace("]", "").split("|"):
                flag = flag.strip()
                if flag and flag != "NONE":
                    flag_counter[flag] += 1

        if flag_counter:
            flags_table = Table(show_header=True, box=box.SIMPLE_HEAD, expand=False, padding=(0, 1))
            flags_table.add_column("TCP Flag", style="bold cyan",          width=12)
            flags_table.add_column("Count",    justify="right", style="bold bright_white", width=10)
            flags_table.add_column("Of TCP %", justify="right", style="dim yellow",        width=10)
            tcp_total = len(tcp_pkts)
            for flag, count in flag_counter.most_common():
                pct = (count / tcp_total) * 100
                flags_table.add_row(flag, f"{count:,}", f"{pct:.1f}%")
            console.print(Panel(flags_table,
                title="[bold bright_white]🚩 TCP Flag Distribution[/]",
                border_style="bright_red", box=box.ROUNDED))

    # ── Footer ────────────────────────────────────────────────
    console.print(
        f"\n[bold green]✅ Analysis complete.[/] "
        f"[dim]{total_pkts:,} packets · {format_bytes(total_bytes)} · "
        f"{len(dst_counts)} unique destinations · {len(src_counts)} unique sources[/]\n"
    )

# ─────────────────────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("--help", "-h"):
        console.print(Panel(
            "[bold cyan]Usage:[/]  [white]python3 analyze.py [bold]<FILE>[/][/]\n\n"
            "[dim]Supported formats:[/] [bold].pcap[/]  [bold].json[/]  [bold].csv[/]\n\n"
            "[dim]Produces:[/]\n"
            "  • Capture summary (packets, traffic, duration)\n"
            "  • Protocol distribution with visual bars\n"
            "  • Top destinations and sources\n"
            "  • Top destination ports with service names\n"
            "  • TCP flag breakdown\n\n"
            "[dim]Examples:[/]\n"
            "  python3 analyze.py capture.pcap\n"
            "  python3 analyze.py packets.json\n"
            "  python3 analyze.py packets.csv",
            title="[bold bright_white]📊 PackSniff Analyzer — Help[/]",
            border_style="cyan", box=box.ROUNDED
        ))
        sys.exit(0)

    filepath = sys.argv[1]
    if not os.path.exists(filepath):
        console.print(f"[bold red][!] File not found: {filepath}[/]")
        sys.exit(1)

    ext = filepath.rsplit(".", 1)[-1].lower() if "." in filepath else ""

    console.print(f"\n[bold cyan][+] Loading {ext.upper()} capture:[/] [white]{filepath}[/]")

    if ext == "pcap":
        packets = load_pcap(filepath)
    elif ext == "json":
        packets = load_json(filepath)
    elif ext == "csv":
        packets = load_csv(filepath)
    else:
        console.print(f"[bold red][!] Unsupported file format '.{ext}'. Use .pcap, .json, or .csv[/]")
        sys.exit(1)

    console.print(f"[bold green][+] Loaded {len(packets):,} packets.[/]")
    analyze(packets, filepath)

if __name__ == "__main__":
    main()
