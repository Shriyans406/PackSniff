#!/usr/bin/env python3
import sys
import json
import time
import subprocess
from collections import defaultdict

# Ensure rich module is present
try:
    from rich.console import Console
    from rich.live import Live
    from rich.table import Table
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.text import Text
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

console = Console()

class BandwidthTracker:
    def __init__(self):
        self.window_seconds = 1.0
        self.history = []  # list of (timestamp, byte_count)
        self.packet_history = []  # list of (timestamp, 1)
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

def build_ratio_bar(metrics):
    total = max(metrics["total"], 1)
    tcp_pct = (metrics["tcp"] / total) * 100
    udp_pct = (metrics["udp"] / total) * 100
    icmp_pct = (metrics["icmp"] / total) * 100
    other_pct = (metrics["other"] / total) * 100

    width = 36
    tcp_chars = int(round((tcp_pct / 100) * width))
    udp_chars = int(round((udp_pct / 100) * width))
    icmp_chars = int(round((icmp_pct / 100) * width))
    other_chars = max(0, width - (tcp_chars + udp_chars + icmp_chars))

    bar_text = Text()
    if tcp_chars > 0:
        bar_text.append("█" * tcp_chars, style="cyan")
    if udp_chars > 0:
        bar_text.append("█" * udp_chars, style="yellow")
    if icmp_chars > 0:
        bar_text.append("█" * icmp_chars, style="red")
    if other_chars > 0:
        bar_text.append("█" * other_chars, style="green")

    legend = (
        f"  [cyan]TCP: {tcp_pct:.1f}%[/cyan] | "
        f"[yellow]UDP: {udp_pct:.1f}%[/yellow] | "
        f"[red]ICMP: {icmp_pct:.1f}%[/red] | "
        f"[green]Other: {other_pct:.1f}%[/green]"
    )

    return Text.assemble(bar_text, legend)

def create_dashboard(packets, metrics, latest_packet, bw_tracker, ip_stats):
    rates = bw_tracker.current_rates()

    layout = Layout()
    layout.split(
        Layout(name="header", size=4),
        Layout(name="main", ratio=1),
        Layout(name="footer", size=5)
    )

    # 1. Header Banner & Dynamic Bandwidth Gauge
    header_title = Text(" 🛡️  PACKSNIFF RUST ENGINE — LIVE PACKET & BANDWIDTH DASHBOARD 🛡️ \n", style="bold white on blue", justify="center")
    gauge_str = (
        f"[bold white]Speed:[/bold white] [bold cyan]{rates['kbs']:.2f} KB/s[/bold cyan] ({rates['mbits']:.2f} Mbit/s)  |  "
        f"[bold white]Rate:[/bold white] [bold green]{rates['pps']:.0f} pkts/s[/bold green]  |  "
        f"[bold white]Peak:[/bold white] [magenta]{rates['peak_kbs']:.2f} KB/s[/magenta]  |  "
        f"[bold white]Avg:[/bold white] [yellow]{rates['avg_kbs']:.2f} KB/s[/yellow]  |  "
        f"[bold white]Total Volume:[/bold white] {format_bytes(metrics['bytes'])}"
    )
    header_content = Text.assemble(header_title, Text.from_markup(gauge_str, justify="center"))
    layout["header"].update(Panel(header_content, style="blue"))

    # 2. Main Content Split: Stream (Left) & Top IP Talkers (Right)
    layout["main"].split_row(
        Layout(name="stream", ratio=2),
        Layout(name="top_talkers", ratio=1)
    )

    # Stream Table
    stream_table = Table(expand=True, box=None)
    stream_table.add_column("#", style="dim", width=5)
    stream_table.add_column("Proto", width=7, justify="center")
    stream_table.add_column("Source IP / Port", width=21)
    stream_table.add_column("Destination IP / Port", width=21)
    stream_table.add_column("Size", width=8, justify="right")
    stream_table.add_column("Details", style="italic")

    for p in packets[-12:]:
        proto = p.get("proto", "UNKNOWN")
        if proto == "TCP":
            proto_style = "bold cyan"
        elif proto == "UDP":
            proto_style = "bold yellow"
        elif proto == "ICMP":
            proto_style = "bold red"
        else:
            proto_style = "bold green"

        src_str = f"{p.get('src')}:{p.get('src_port')}" if p.get('src_port') else str(p.get('src'))
        dst_str = f"{p.get('dst')}:{p.get('dst_port')}" if p.get('dst_port') else str(p.get('dst'))

        stream_table.add_row(
            str(p.get("id")),
            f"[{proto_style}]{proto}[/{proto_style}]",
            src_str,
            dst_str,
            f"{p.get('len')} B",
            p.get("l4_info", "")
        )
    layout["stream"].update(Panel(stream_table, title="[bold white]Live Packet Stream (Recent 12)[/bold white]", border_style="cyan"))

    # Top IP Talkers Table
    talkers_table = Table(expand=True, box=None)
    talkers_table.add_column("Host IP Address", style="bold white")
    talkers_table.add_column("Packets", justify="right")
    talkers_table.add_column("Volume", justify="right")
    talkers_table.add_column("Share", justify="right", style="cyan")

    sorted_ips = sorted(ip_stats.items(), key=lambda x: x[1]["bytes"], reverse=True)[:5]
    total_vol = max(metrics["bytes"], 1)

    for ip, stat in sorted_ips:
        share_pct = (stat["bytes"] / total_vol) * 100
        talkers_table.add_row(
            ip,
            str(stat["pkts"]),
            format_bytes(stat["bytes"]),
            f"{share_pct:.1f}%"
        )
    layout["top_talkers"].update(Panel(talkers_table, title="[bold white]Top IP Talkers (Top 5)[/bold white]", border_style="magenta"))

    # 3. Footer: Protocol Ratio Bar & Packet Inspector
    ratio_element = build_ratio_bar(metrics)
    latest_info = ""
    if latest_packet:
        latest_info = (
            f"  [dim]Latest #[/dim][bold]{latest_packet.get('id')}[/bold]: "
            f"MAC [bold]{latest_packet.get('src_mac')}[/bold] -> [bold]{latest_packet.get('dst_mac')}[/bold] | "
            f"Hex: [magenta]{latest_packet.get('hex')}[/magenta]"
        )

    footer_content = Text.assemble(ratio_element, "\n", Text.from_markup(latest_info))
    layout["footer"].update(Panel(footer_content, title="[bold white]Protocol Ratio Distribution & Packet Inspector[/bold white]", border_style="green"))

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
                if dst_ip and dst_ip != src_ip:
                    ip_stats[dst_ip]["pkts"] += 1
                    ip_stats[dst_ip]["bytes"] += pkt_len

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
