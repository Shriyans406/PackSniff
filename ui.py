#!/usr/bin/env python3
import sys
import json
import subprocess

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

def create_dashboard(packets, metrics, latest_packet):
    layout = Layout()
    layout.split(
        Layout(name="header", size=3),
        Layout(name="main", ratio=1),
        Layout(name="footer", size=6)
    )

    # 1. Header Banner
    header_text = Text(
        " 🛡️  PACKSNIFF RUST ENGINE — LIVE PACKET STREAM & TUI DASHBOARD 🛡️ ",
        style="bold white on blue",
        justify="center"
    )
    layout["header"].update(Panel(header_text, style="blue"))

    # 2. Packets Table
    table = Table(expand=True, box=None)
    table.add_column("#", style="dim", width=6)
    table.add_column("Proto", width=8, justify="center")
    table.add_column("Source IP / Port", width=24)
    table.add_column("Destination IP / Port", width=24)
    table.add_column("Size", width=8, justify="right")
    table.add_column("Layer 4 Details / Info", style="italic")

    for p in packets[-15:]:
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

        table.add_row(
            str(p.get("id")),
            f"[{proto_style}]{proto}[/{proto_style}]",
            src_str,
            dst_str,
            f"{p.get('len')} B",
            p.get("l4_info", "")
        )

    layout["main"].update(Panel(table, title="[bold white]Live Packet Stream (Recent 15)[/bold white]", border_style="cyan"))

    # 3. Footer Inspector & Metrics Summary
    stats_str = (
        f"[bold white]Total Filtered Packets:[/bold white] {metrics['total']}  |  "
        f"[cyan]TCP:[/cyan] {metrics['tcp']}  |  "
        f"[yellow]UDP:[/yellow] {metrics['udp']}  |  "
        f"[red]ICMP:[/red] {metrics['icmp']}  |  "
        f"[green]Other:[/green] {metrics['other']}  |  "
        f"[bold white]Total Bytes:[/bold white] {metrics['bytes']} B"
    )

    latest_info = ""
    if latest_packet:
        latest_info = (
            f"\n[dim]Latest Packet #{latest_packet.get('id')}:[/dim] "
            f"MAC [bold]{latest_packet.get('src_mac')}[/bold] -> [bold]{latest_packet.get('dst_mac')}[/bold] | "
            f"Hex: [magenta]{latest_packet.get('hex')}[/magenta]"
        )

    footer_content = stats_str + latest_info
    layout["footer"].update(Panel(footer_content, title="[bold white]Metrics & Detail Inspector[/bold white]", border_style="green"))

    return layout

def main():
    packets = []
    metrics = {"total": 0, "tcp": 0, "udp": 0, "icmp": 0, "other": 0, "bytes": 0}
    latest_packet = None

    with Live(create_dashboard(packets, metrics, latest_packet), refresh_per_second=4, console=console) as live:
        for line in sys.stdin:
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                p = json.loads(line)
                packets.append(p)
                latest_packet = p

                metrics["total"] += 1
                metrics["bytes"] += p.get("len", 0)

                proto = p.get("proto")
                if proto == "TCP":
                    metrics["tcp"] += 1
                elif proto == "UDP":
                    metrics["udp"] += 1
                elif proto == "ICMP":
                    metrics["icmp"] += 1
                else:
                    metrics["other"] += 1

                live.update(create_dashboard(packets, metrics, latest_packet))
            except json.JSONDecodeError:
                continue

if __name__ == "__main__":
    main()
