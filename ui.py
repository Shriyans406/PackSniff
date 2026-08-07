#!/usr/bin/env python3
import sys
import json
import time
import socket
import threading
import subprocess
from collections import defaultdict

# Auto-install rich dependency if missing
try:
    from rich.console import Console
    from rich.live import Live
    from rich.table import Table
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.text import Text
    from rich import box
except ImportError:
    print("[+] 'rich' module not found. Auto-installing rich...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "rich", "--break-system-packages", "--quiet"])
    except Exception:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "rich", "--quiet"])
    from rich.console import Console
    from rich.live import Live
    from rich.table import Table
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.text import Text
    from rich import box

console = Console()

# Static Domain & Host Service Overrides for Instant Display
KNOWN_DOMAINS = {
    "8.8.8.8": "dns.google",
    "8.8.4.4": "dns.google",
    "1.1.1.1": "one.one.one.one",
    "1.0.0.1": "one.one.one.one",
    "9.9.9.9": "dns.quad9.net",
    "10.0.2.2": "Gateway/Router",
    "10.0.2.15": "Local VM (Debian)",
    "127.0.0.1": "localhost",
}

COMMON_SERVICES = {
    20: "FTP", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 80: "HTTP", 123: "NTP", 143: "IMAP", 443: "HTTPS",
    3306: "MySQL", 5432: "PostgreSQL", 8080: "HTTP-ALT", 8443: "HTTPS-ALT"
}

# Thread-safe Reverse DNS Cache
dns_cache = dict(KNOWN_DOMAINS)
cache_lock = threading.Lock()
pending_lookups = set()

def resolve_ip_async(ip_str):
    """Background thread function for non-blocking Reverse DNS lookup."""
    if not ip_str or ip_str.startswith("00:") or ip_str in KNOWN_DOMAINS:
        return
    with cache_lock:
        if ip_str in dns_cache or ip_str in pending_lookups:
            return
        pending_lookups.add(ip_str)

    def worker():
        try:
            domain, _, _ = socket.gethostbyaddr(ip_str)
        except Exception:
            domain = ip_str
        with cache_lock:
            dns_cache[ip_str] = domain
            pending_lookups.discard(ip_str)

    threading.Thread(target=worker, daemon=True).start()

def get_label(ip_str):
    """Returns domain name label if resolved, otherwise raw IP."""
    with cache_lock:
        resolved = dns_cache.get(ip_str)
    if resolved and resolved != ip_str:
        return f"{ip_str} ({resolved})"
    else:
        resolve_ip_async(ip_str)
        return str(ip_str)

def get_short_domain(ip_str):
    """Returns domain or short IP representation for compact table views."""
    with cache_lock:
        resolved = dns_cache.get(ip_str)
    if resolved and resolved != ip_str:
        return resolved
    return str(ip_str)

class BandwidthTracker:
    def __init__(self):
        self.window_seconds = 1.0
        self.history = []
        self.packet_history = []
        self.peak_kbs = 0.0
        self.start_time = time.time()
        self.total_bytes = 0
        self.total_packets = 0

    def add_packet(self, size_bytes):
        now = time.time()
        self.history.append((now, size_bytes))
        self.packet_history.append((now, 1))
        self.total_bytes += size_bytes
        self.total_packets += 1
        self._clean(now)

    def _clean(self, now):
        cutoff = now - self.window_seconds
        self.history = [item for item in self.history if item[0] >= cutoff]
        self.packet_history = [item for item in self.packet_history if item[0] >= cutoff]

    def current_rates(self):
        now = time.time()
        self._clean(now)
        recent_bytes = sum(b for t, b in self.history)
        recent_packets = len(self.packet_history)

        kbs = (recent_bytes / 1024.0) / self.window_seconds
        mbits = (recent_bytes * 8 / 1_000_000.0) / self.window_seconds
        pps = recent_packets / self.window_seconds

        if kbs > self.peak_kbs:
            self.peak_kbs = kbs

        elapsed = max(now - self.start_time, 0.001)
        avg_kbs = (self.total_bytes / 1024.0) / elapsed

        return {
            "kbs": kbs,
            "mbits": mbits,
            "pps": pps,
            "peak_kbs": self.peak_kbs,
            "avg_kbs": avg_kbs
        }

def format_bytes(b):
    if b < 1024:
        return f"{b} B"
    elif b < 1024 * 1024:
        return f"{b / 1024.0:.1f} KB"
    elif b < 1024 * 1024 * 1024:
        return f"{b / (1024.0 * 1024.0):.2f} MB"
    else:
        return f"{b / (1024.0 * 1024.0 * 1024.0):.2f} GB"

def format_duration(seconds):
    secs = int(seconds)
    mins = secs // 60
    hrs = mins // 60
    return f"{hrs:02d}:{mins % 60:02d}:{secs % 60:02d}"

def build_ratio_bar(metrics):
    total = max(metrics["total"], 1)
    tcp_pct = (metrics["tcp"] / total) * 100
    udp_pct = (metrics["udp"] / total) * 100
    icmp_pct = (metrics["icmp"] / total) * 100
    other_pct = (metrics["other"] / total) * 100

    width = 30
    tcp_chars = int(round((tcp_pct / 100) * width))
    udp_chars = int(round((udp_pct / 100) * width))
    icmp_chars = int(round((icmp_pct / 100) * width))
    other_chars = max(0, width - (tcp_chars + udp_chars + icmp_chars))

    bar_text = Text()
    if tcp_chars > 0:
        bar_text.append("█" * tcp_chars, style="bold cyan")
    if udp_chars > 0:
        bar_text.append("█" * udp_chars, style="bold bright_yellow")
    if icmp_chars > 0:
        bar_text.append("█" * icmp_chars, style="bold bright_red")
    if other_chars > 0:
        bar_text.append("█" * other_chars, style="bold bright_green")

    legend = (
        f"  [bold cyan]TCP: {tcp_pct:.1f}%[/] │ "
        f"[bold bright_yellow]UDP: {udp_pct:.1f}%[/] │ "
        f"[bold bright_red]ICMP: {icmp_pct:.1f}%[/] │ "
        f"[bold bright_green]Other: {other_pct:.1f}%[/]"
    )

    return Text.assemble(bar_text, legend)

def format_mini_bar(share_pct, width=10):
    fill = int(round((share_pct / 100.0) * width))
    empty = width - fill
    return f"[bold magenta]{'█' * fill}[/][dim]{'░' * empty}[/]"

def create_dashboard(packets, metrics, latest_packet, bw_tracker, ip_stats):
    rates = bw_tracker.current_rates()
    uptime_str = format_duration(time.time() - bw_tracker.start_time)
    resolved_count = len(dns_cache)

    layout = Layout()
    layout.split(
        Layout(name="header", size=5),
        Layout(name="main", ratio=1),
        Layout(name="footer", size=6)
    )

    # --- 1. Header Banner & Dynamic Telemetry Gauges ---
    header_title = Text(" 🛡️  PACKSNIFF RUST ENGINE — HIGH-PERFORMANCE TELEMETRY DASHBOARD  🛡️ ", style="bold white on navy_blue", justify="center")
    
    gauge_markup = (
        f"[bold bright_white]LIVE SPEED:[/] [bold bright_cyan]{rates['kbs']:>6.2f} KB/s[/] [dim]({rates['mbits']:>4.2f} Mbit/s)[/] │ "
        f"[bold bright_white]RATE:[/] [bold bright_green]{rates['pps']:>4.0f} pkts/s[/] │ "
        f"[bold bright_white]PEAK:[/] [bold magenta]{rates['peak_kbs']:>6.2f} KB/s[/] │ "
        f"[bold bright_white]AVG:[/] [bold bright_yellow]{rates['avg_kbs']:>6.2f} KB/s[/] │ "
        f"[bold bright_white]TOTAL:[/] [bold bright_white]{format_bytes(metrics['bytes'])}[/] [dim]({metrics['total']:,} pkts)[/]\n"
        f"[bold dim]STATUS:[/] [bold green]🟢 STREAMING[/] │ [bold dim]RESOLVED DOMAINS:[/] [bold cyan]{resolved_count}[/] │ [bold dim]SESSION DURATION:[/] [bold yellow]{uptime_str}[/]"
    )
    
    header_content = Text.assemble(header_title, "\n", Text.from_markup(gauge_markup, justify="center"))
    layout["header"].update(Panel(header_content, box=box.ROUNDED, style="bright_blue"))

    # --- 2. Main Split: Packet Stream Table (Left) & Top Talkers (Right) ---
    layout["main"].split_row(
        Layout(name="stream", ratio=7),
        Layout(name="top_talkers", ratio=4)
    )

    # Live Packet Table
    stream_table = Table(expand=True, box=box.SIMPLE_HEAD, pad_edge=False)
    stream_table.add_column("#", style="dim", width=5, justify="right")
    stream_table.add_column("Proto", width=8, justify="center")
    stream_table.add_column("Source Host / Port", width=26)
    stream_table.add_column("Destination Host / Port", width=26)
    stream_table.add_column("Size", width=8, justify="right")
    stream_table.add_column("L4 Details & Control Flags", style="italic")

    for p in packets[-12:]:
        proto = p.get("proto", "UNKNOWN")
        if proto == "TCP":
            proto_badge = "[bold white on cyan] TCP [/]"
        elif proto == "UDP":
            proto_badge = "[bold black on bright_yellow] UDP [/]"
        elif proto == "ICMP":
            proto_badge = "[bold white on bright_red] ICMP [/]"
        elif proto == "ARP":
            proto_badge = "[bold white on magenta] ARP [/]"
        elif proto == "IPv6":
            proto_badge = "[bold white on blue] IPv6 [/]"
        else:
            proto_badge = "[bold black on green] ETH [/]"

        src_val = p.get("src", "")
        dst_val = p.get("dst", "")

        src_lbl = get_short_domain(src_val)
        dst_lbl = get_short_domain(dst_val)

        src_port = p.get("src_port")
        dst_port = p.get("dst_port")

        src_service = COMMON_SERVICES.get(src_port, "") if src_port else ""
        dst_service = COMMON_SERVICES.get(dst_port, "") if dst_port else ""

        src_str = f"[bold white]{src_lbl}[/]:[cyan]{src_port}[/]" if src_port else f"[bold white]{src_lbl}[/]"
        if src_service:
            src_str += f" [dim]({src_service})[/]"

        dst_str = f"[bold white]{dst_lbl}[/]:[cyan]{dst_port}[/]" if dst_port else f"[bold white]{dst_lbl}[/]"
        if dst_service:
            dst_str += f" [dim]({dst_service})[/]"

        l4 = p.get("l4_info", "")
        # Format control flag highlights
        l4_formatted = (
            l4.replace("SYN", "[bold bright_green]SYN[/]")
              .replace("ACK", "[bold bright_cyan]ACK[/]")
              .replace("RST", "[bold bright_red]RST[/]")
              .replace("FIN", "[bold bright_yellow]FIN[/]")
        )

        stream_table.add_row(
            str(p.get("id")),
            proto_badge,
            src_str,
            dst_str,
            f"[bold bright_white]{p.get('len')}[/] B",
            l4_formatted
        )

    layout["stream"].update(
        Panel(stream_table, title="[bold bright_white]🌐 Live Network Packet Stream (Recent 12)[/]", box=box.ROUNDED, border_style="cyan")
    )

    # Top IP Talkers & Domain Analytics Table
    talkers_table = Table(expand=True, box=box.SIMPLE_HEAD, pad_edge=False)
    talkers_table.add_column("Host IP / Domain", style="bold bright_white")
    talkers_table.add_column("Volume", justify="right", style="bright_yellow")
    talkers_table.add_column("Share", justify="center")

    sorted_ips = sorted(ip_stats.items(), key=lambda x: x[1]["bytes"], reverse=True)[:6]
    total_vol = max(metrics["bytes"], 1)

    for ip, stat in sorted_ips:
        share_pct = (stat["bytes"] / total_vol) * 100
        domain_lbl = get_label(ip)
        
        # Add host type badge icon
        if ip in ("8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9"):
            icon = "🌐 "
        elif ip in ("10.0.2.15", "127.0.0.1"):
            icon = "🏠 "
        elif ip == "10.0.2.2":
            icon = "⚡ "
        else:
            icon = "🖥️  "

        mini_bar = format_mini_bar(share_pct, width=8)
        talkers_table.add_row(
            f"{icon}{domain_lbl}",
            format_bytes(stat["bytes"]),
            f"{mini_bar} [dim]{share_pct:4.1f}%[/]"
        )

    layout["top_talkers"].update(
        Panel(talkers_table, title="[bold bright_white]📊 Top Talkers & Domain Bandwidth Share[/]", box=box.ROUNDED, border_style="magenta")
    )

    # --- 3. Footer: Protocol Distribution Bar & Deep Packet Inspector ---
    ratio_element = build_ratio_bar(metrics)
    
    inspector_text = Text()
    if latest_packet:
        inspector_text = Text.from_markup(
            f"  [bold dim]INSPECTOR #[/][bold bright_white]{latest_packet.get('id')}[/bold bright_white] │ "
            f"[dim]Src MAC:[/] [bold cyan]{latest_packet.get('src_mac')}[/] ➔ [dim]Dst MAC:[/] [bold cyan]{latest_packet.get('dst_mac')}[/] │ "
            f"[dim]TTL:[/] [bold yellow]{latest_packet.get('ttl', 'N/A')}[/]\n"
            f"  [dim]RAW HEX SNIPPET:[/] [bold bright_magenta]{latest_packet.get('hex')}[/]"
        )

    footer_content = Text.assemble(ratio_element, "\n", inspector_text)
    
    status_bar = "[dim white] Press [bold bright_yellow]Ctrl+C[/] to exit │ [bold cyan]JSON Pipe[/] Connected │ [bold green]Live Promiscuous Sniffing[/][/]"
    
    layout["footer"].update(
        Panel(footer_content, title="[bold bright_white]🔬 Protocol Distribution & Deep Packet Inspector[/]", subtitle=status_bar, box=box.ROUNDED, border_style="green")
    )

    return layout

def main():
    packets = []
    metrics = {"total": 0, "tcp": 0, "udp": 0, "icmp": 0, "other": 0, "bytes": 0}
    ip_stats = defaultdict(lambda: {"pkts": 0, "bytes": 0})
    bw_tracker = BandwidthTracker()
    latest_packet = None

    with Live(create_dashboard(packets, metrics, latest_packet, bw_tracker, ip_stats), refresh_per_second=4, console=console) as live:
        for line in sys.stdin:
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                p = json.loads(line)
                packets.append(p)
                latest_packet = p
                pkt_len = p.get("len", 0)

                metrics["total"] += 1
                metrics["bytes"] += pkt_len

                bw_tracker.add_packet(pkt_len)

                src_ip = p.get("src")
                dst_ip = p.get("dst")
                if src_ip:
                    ip_stats[src_ip]["pkts"] += 1
                    ip_stats[src_ip]["bytes"] += pkt_len
                    resolve_ip_async(src_ip)
                if dst_ip and dst_ip != src_ip:
                    ip_stats[dst_ip]["pkts"] += 1
                    ip_stats[dst_ip]["bytes"] += pkt_len
                    resolve_ip_async(dst_ip)

                proto = p.get("proto")
                if proto == "TCP":
                    metrics["tcp"] += 1
                elif proto == "UDP":
                    metrics["udp"] += 1
                elif proto == "ICMP":
                    metrics["icmp"] += 1
                else:
                    metrics["other"] += 1

                live.update(create_dashboard(packets, metrics, latest_packet, bw_tracker, ip_stats))
            except json.JSONDecodeError:
                continue

if __name__ == "__main__":
    main()
