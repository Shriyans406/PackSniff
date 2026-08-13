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

MAC_VENDORS = {
    "08:00:27": "Oracle VirtualBox",
    "00:05:69": "VMware",
    "00:0C:29": "VMware",
    "00:50:56": "VMware",
    "52:54:00": "QEMU/KVM",
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "00:1A:11": "Google",
    "F4:F5:DB": "Google",
    "00:03:93": "Apple",
    "AC:BC:32": "Apple",
    "00:15:5D": "Microsoft Hyper-V",
    "00:1B:21": "Intel",
    "00:1E:67": "Intel",
    "3C:D9:2B": "HP",
    "70:85:C2": "Asus",
    "E0:D5:5E": "Cisco",
}

def get_mac_vendor(mac_str):
    if not mac_str or mac_str == "00:00:00:00:00:00" or mac_str == "FF:FF:FF:FF:FF:FF":
        return "Broadcast/Unknown"
    prefix = mac_str.upper()[:8]
    return MAC_VENDORS.get(prefix, "Generic Vendor")


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

class AnomalyDetector:
    def __init__(self):
        # Track (src_ip -> set of (dst_port, timestamp))
        self.port_scan_tracker = defaultdict(list)
        # Track (src_ip -> count of SYN packets)
        self.syn_tracker = defaultdict(list)
        # Suspicious port definitions
        self.suspicious_ports = {23: "TELNET (Unencrypted)", 4444: "Metasploit Shell", 31337: "Back Orifice", 6667: "IRC Traffic"}
        # List of active alerts: {"level": "WARNING", "msg": "...", "time": timestamp}
        self.alerts = []

    def inspect(self, p, current_pps, current_kbs):
        now = time.time()
        src_ip = p.get("src")
        dst_ip = p.get("dst")
        dst_port = p.get("dst_port")
        proto = p.get("proto")
        l4_info = p.get("l4_info", "")

        # 1. Traffic Burst / High Rate Detection
        if current_pps > 300:
            self._add_alert("WARNING", f"High Packet Rate Detected: {current_pps:.0f} pkts/sec")
        if current_kbs > 2048:  # > 2 MB/s
            self._add_alert("WARNING", f"Traffic Volume Burst Detected: {current_kbs/1024:.2f} MB/s")

        if not src_ip or not dst_port:
            return

        # 2. Port Scan Detection (10+ distinct ports in 5 seconds)
        self.port_scan_tracker[src_ip].append((dst_port, now))
        # Clean old entries (> 5 seconds)
        self.port_scan_tracker[src_ip] = [item for item in self.port_scan_tracker[src_ip] if now - item[1] <= 5.0]
        distinct_ports = {item[0] for item in self.port_scan_tracker[src_ip]}
        if len(distinct_ports) >= 10:
            self._add_alert(
                "CRITICAL",
                f"Possible Port Scan from {src_ip}! {len(distinct_ports)} ports contacted ({len(self.port_scan_tracker[src_ip])} attempts)"
            )

        # 3. SYN Flood Detection
        if proto == "TCP" and "SYN" in l4_info and "ACK" not in l4_info:
            self.syn_tracker[src_ip].append(now)
            self.syn_tracker[src_ip] = [t for t in self.syn_tracker[src_ip] if now - t <= 3.0]
            if len(self.syn_tracker[src_ip]) >= 25:
                self._add_alert("CRITICAL", f"Excessive Connection Attempts / SYN Flood from {src_ip} ({len(self.syn_tracker[src_ip])} SYNs/3s)")

        # 4. Suspicious / Unexpected Port Detection
        if dst_port in self.suspicious_ports:
            self._add_alert("WARNING", f"Suspicious Port Activity: {src_ip} ➔ {dst_ip}:{dst_port} ({self.suspicious_ports[dst_port]})")

    def _add_alert(self, level, msg):
        now_str = time.strftime("%H:%M:%S")
        full_msg = f"[{now_str}] {msg}"
        # Deduplicate recent identical alerts
        if not self.alerts or self.alerts[-1]["msg"] != full_msg:
            self.alerts.append({"level": level, "msg": full_msg, "time": time.time()})
            if len(self.alerts) > 10:
                self.alerts.pop(0)

    def get_recent_alerts(self, limit=4):
        return self.alerts[-limit:]

class DeviceTracker:
    def __init__(self):
        # ip -> {mac, hostname, vendor, pkts, bytes, first_seen, last_seen, is_arp}
        self.devices = {}

    def update(self, p):
        src_ip = p.get("src")
        src_mac = p.get("src_mac")
        dst_ip = p.get("dst")
        dst_mac = p.get("dst_mac")
        pkt_len = p.get("len", 0)
        proto = p.get("proto")
        now = time.time()

        # Handle Source Device
        if src_ip and src_mac and not src_ip.startswith("00:"):
            if src_ip not in self.devices:
                self.devices[src_ip] = {
                    "ip": src_ip,
                    "mac": src_mac,
                    "vendor": get_mac_vendor(src_mac),
                    "pkts": 0,
                    "bytes": 0,
                    "first_seen": now,
                    "last_seen": now,
                    "proto_last": proto
                }
            d = self.devices[src_ip]
            d["mac"] = src_mac
            d["vendor"] = get_mac_vendor(src_mac)
            d["pkts"] += 1
            d["bytes"] += pkt_len
            d["last_seen"] = now
            d["proto_last"] = proto

        # Handle Destination Device (for Local IPs)
        if dst_ip and dst_mac and not dst_ip.startswith("00:") and dst_mac != "FF:FF:FF:FF:FF:FF":
            if dst_ip not in self.devices:
                self.devices[dst_ip] = {
                    "ip": dst_ip,
                    "mac": dst_mac,
                    "vendor": get_mac_vendor(dst_mac),
                    "pkts": 0,
                    "bytes": 0,
                    "first_seen": now,
                    "last_seen": now,
                    "proto_last": proto
                }
            d = self.devices[dst_ip]
            d["last_seen"] = now

    def get_discovered_devices(self):
        return sorted(self.devices.values(), key=lambda x: x["last_seen"], reverse=True)


class FlowTracker:
    def __init__(self):
        self.flows = {}

    def update(self, p):
        src_ip = p.get("src")
        dst_ip = p.get("dst")
        src_port = p.get("src_port")
        dst_port = p.get("dst_port")
        proto = p.get("proto", "OTHER")
        length = p.get("len", 0)
        l4_info = p.get("l4_info", "")

        if not src_ip or not dst_ip or src_port is None or dst_port is None:
            return

        if (src_ip, src_port) <= (dst_ip, dst_port):
            key = (src_ip, src_port, dst_ip, dst_port, proto)
            is_fwd = True
        else:
            key = (dst_ip, dst_port, src_ip, src_port, proto)
            is_fwd = False

        now = time.time()
        if key not in self.flows:
            initial_state = "SYN_SENT" if "SYN" in l4_info else ("ESTABLISHED" if proto == "TCP" else "ACTIVE")
            self.flows[key] = {
                "start": now,
                "last": now,
                "pkts_fwd": 0, "pkts_rev": 0,
                "bytes_fwd": 0, "bytes_rev": 0,
                "state": initial_state,
                "src_ip": key[0], "src_port": key[1],
                "dst_ip": key[2], "dst_port": key[3],
                "proto": proto
            }

        f = self.flows[key]
        f["last"] = now
        if is_fwd:
            f["pkts_fwd"] += 1
            f["bytes_fwd"] += length
        else:
            f["pkts_rev"] += 1
            f["bytes_rev"] += length

        if proto == "TCP":
            if "RST" in l4_info:
                f["state"] = "RESET"
            elif "FIN" in l4_info:
                f["state"] = "FIN_WAIT"
            elif "ACK" in l4_info and f["state"] == "SYN_SENT":
                f["state"] = "ESTABLISHED"

    def get_recent_flows(self, limit=4):
        sorted_flows = sorted(self.flows.values(), key=lambda x: x["last"], reverse=True)
        return sorted_flows[:limit]

def format_mini_bar(share_pct, width=10):
    fill = int(round((share_pct / 100.0) * width))
    empty = width - fill
    return f"[bold magenta]{'█' * fill}[/][dim]{'░' * empty}[/]"

def create_dashboard(packets, metrics, latest_packet, bw_tracker, src_ip_stats, dst_ip_stats, port_stats, flow_tracker, anomaly_detector, device_tracker):
    rates = bw_tracker.current_rates()
    uptime_str = format_duration(time.time() - bw_tracker.start_time)
    resolved_count = len(dns_cache)
    active_flows_count = len(flow_tracker.flows)

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
        f"[bold bright_white]ACTIVE FLOWS:[/] [bold bright_yellow]{active_flows_count}[/] │ "
        f"[bold bright_white]TOTAL:[/] [bold bright_white]{format_bytes(metrics['bytes'])}[/] [dim]({metrics['total']:,} pkts)[/]\n"
        f"[bold dim]STATUS:[/] [bold green]🟢 STREAMING[/] │ [bold dim]RESOLVED DOMAINS:[/] [bold cyan]{resolved_count}[/] │ [bold dim]SESSION DURATION:[/] [bold yellow]{uptime_str}[/]"
    )
    
    header_content = Text.assemble(header_title, "\n", Text.from_markup(gauge_markup, justify="center"))
    layout["header"].update(Panel(header_content, box=box.ROUNDED, style="bright_blue"))

    # --- 2. Main Split: Packet Stream (Left) & Right Side (Stats + Alerts + Flows) ---
    layout["main"].split_row(
        Layout(name="stream", ratio=7),
        Layout(name="right_side", ratio=5)
    )

    layout["right_side"].split(
        Layout(name="stats", ratio=2),
        Layout(name="devices", ratio=2),
        Layout(name="alerts", ratio=2),
        Layout(name="flows", ratio=2)
    )

    # Live Packet Table
    stream_table = Table(expand=True, box=box.SIMPLE_HEAD, pad_edge=False)
    stream_table.add_column("#", style="dim", width=5, justify="right")
    stream_table.add_column("Proto", width=8, justify="center")
    stream_table.add_column("Source Host / Port", width=24)
    stream_table.add_column("Destination Host / Port", width=24)
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

    # Phase 13 - Protocol Statistics Dashboard
    stats_table = Table(expand=True, box=box.SIMPLE_HEAD, pad_edge=False, show_header=False)
    stats_table.add_column("Category", style="bold cyan")
    stats_table.add_column("Value", style="bold bright_white")
    
    total_pkts = max(metrics["total"], 1)
    
    # 1. Global Stats
    stats_table.add_row("[yellow]Packets[/]", f"{metrics['total']:,}")
    stats_table.add_row("[yellow]Traffic[/]", f"{format_bytes(metrics['bytes'])}")
    stats_table.add_row("[yellow]Packets/sec[/]", f"{rates['pps']:.0f}")
    stats_table.add_row("[yellow]Bytes/sec[/]", f"{format_bytes(rates['kbs'] * 1024)}/s")
    
    # 2. Protocol Distribution
    stats_table.add_row("[magenta]TCP[/]", f"{(metrics['tcp'] / total_pkts) * 100:.1f}%")
    stats_table.add_row("[magenta]UDP[/]", f"{(metrics['udp'] / total_pkts) * 100:.1f}%")
    stats_table.add_row("[magenta]ICMP[/]", f"{(metrics['icmp'] / total_pkts) * 100:.1f}%")

    # 3. Top Ports
    sorted_ports = sorted(port_stats.items(), key=lambda x: x[1], reverse=True)[:2]
    for port, count in sorted_ports:
        svc = COMMON_SERVICES.get(port, "CUSTOM")
        stats_table.add_row(f"[green]Port {port} ({svc})[/]", f"{count:,} pkts")
        
    # 4. Top Source / Dest IPs
    sorted_src = sorted(src_ip_stats.items(), key=lambda x: x[1]["pkts"], reverse=True)[:1]
    sorted_dst = sorted(dst_ip_stats.items(), key=lambda x: x[1]["pkts"], reverse=True)[:1]
    
    for ip, stat in sorted_src:
        stats_table.add_row(f"[blue]Src: {get_short_domain(ip)}[/]", f"{stat['pkts']:,} pkts")
    for ip, stat in sorted_dst:
        stats_table.add_row(f"[red]Dst: {get_short_domain(ip)}[/]", f"{stat['pkts']:,} pkts")

    layout["stats"].update(
        Panel(stats_table, title="[bold bright_white]📈 NETWORK STATISTICS[/]", box=box.ROUNDED, border_style="magenta")
    )

    # Phase 15 - Local Network Devices Panel
    devices_table = Table(expand=True, box=box.SIMPLE_HEAD, pad_edge=False)
    devices_table.add_column("IP Address", style="bold bright_cyan", width=15)
    devices_table.add_column("MAC Address", style="bold yellow", width=18)
    devices_table.add_column("Host / Description", style="bold bright_white", width=22)
    devices_table.add_column("MAC Vendor", style="magenta", width=18)

    for dev in device_tracker.get_discovered_devices()[:3]:
        ip = dev["ip"]
        mac = dev["mac"]
        host = get_short_domain(ip)
        vendor = dev["vendor"]
        devices_table.add_row(ip, mac, host, vendor)

    layout["devices"].update(
        Panel(devices_table, title="[bold bright_white]🖥️  LOCAL NETWORK DEVICES (Phase 15)[/]", box=box.ROUNDED, border_style="cyan")
    )

    # Phase 14 - Security & Anomaly Alerts Panel
    alerts_table = Table(expand=True, box=box.SIMPLE_HEAD, pad_edge=False, show_header=False)
    alerts_table.add_column("Level", width=12, justify="center")
    alerts_table.add_column("Alert Details", style="bold bright_white")

    recent_alerts = anomaly_detector.get_recent_alerts(3)
    if not recent_alerts:
        alerts_table.add_row("[bold green]  OK  [/]", "[dim green]No security anomalies detected. System operating normally.[/]")
    else:
        for alert in recent_alerts:
            if alert["level"] == "CRITICAL":
                lvl_badge = "[bold white on red] CRITICAL [/]"
            else:
                lvl_badge = "[bold black on yellow] WARNING  [/]"
            alerts_table.add_row(lvl_badge, alert["msg"])

    layout["alerts"].update(
        Panel(alerts_table, title="[bold bright_white]🚨 SECURITY & ANOMALY ALERTS (Phase 14)[/]", box=box.ROUNDED, border_style="red")
    )

    # Active Flow Conversations Panel
    flows_table = Table(expand=True, box=box.SIMPLE_HEAD, pad_edge=False)
    flows_table.add_column("Flow 5-Tuple", style="bold bright_white")
    flows_table.add_column("Pkts (Tx/Rx)", justify="right", style="cyan")
    flows_table.add_column("Volume (Tx/Rx)", justify="right", style="yellow")
    flows_table.add_column("Dur", justify="right", style="green")
    flows_table.add_column("State", justify="center")

    for f in flow_tracker.get_recent_flows(4):
        s_lbl = get_short_domain(f["src_ip"])
        d_lbl = get_short_domain(f["dst_ip"])
        s_svc = COMMON_SERVICES.get(f["src_port"], "")
        d_svc = COMMON_SERVICES.get(f["dst_port"], "")
        svc_str = f" ({d_svc})" if d_svc else (f" ({s_svc})" if s_svc else f" ({f['proto']})")
        flow_name = f"{s_lbl}:{f['src_port']}➔{d_lbl}:{f['dst_port']}{svc_str}"
        
        total_pkts = f["pkts_fwd"] + f["pkts_rev"]
        pkts_str = f"{total_pkts} ({f['pkts_fwd']}/{f['pkts_rev']})"
        
        total_bytes = f["bytes_fwd"] + f["bytes_rev"]
        vol_str = f"{format_bytes(total_bytes)} ({format_bytes(f['bytes_fwd'])}/{format_bytes(f['bytes_rev'])})"
        
        dur = f"{f['last'] - f['start']:.1f}s"
        
        st = f["state"]
        if st == "ESTABLISHED":
            badge = "[bold green]ESTAB[/]"
        elif st == "SYN_SENT":
            badge = "[bold yellow]SYN[/]"
        elif st == "RESET":
            badge = "[bold red]RESET[/]"
        elif st == "FIN_WAIT":
            badge = "[bold magenta]FIN[/]"
        else:
            badge = "[bold cyan]ACTV[/]"

        flows_table.add_row(
            flow_name,
            pkts_str,
            vol_str,
            dur,
            badge
        )

    layout["flows"].update(
        Panel(flows_table, title="[bold bright_white]🔗 Active Flow Conversations (Phase 12)[/]", box=box.ROUNDED, border_style="yellow")
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
    
    status_bar = "[dim white] Press [bold bright_yellow]Ctrl+C[/] to exit │ [bold cyan]JSON Pipe[/] Connected │ [bold green]Live Flow Telemetry[/][/]"
    
    layout["footer"].update(
        Panel(footer_content, title="[bold bright_white]🔬 Protocol Distribution & Deep Packet Inspector[/]", subtitle=status_bar, box=box.ROUNDED, border_style="green")
    )

    return layout

def main():
    packets = []
    metrics = {"total": 0, "tcp": 0, "udp": 0, "icmp": 0, "other": 0, "bytes": 0}
    src_ip_stats = defaultdict(lambda: {"pkts": 0, "bytes": 0})
    dst_ip_stats = defaultdict(lambda: {"pkts": 0, "bytes": 0})
    port_stats = defaultdict(int)

    bw_tracker = BandwidthTracker()
    flow_tracker = FlowTracker()
    anomaly_detector = AnomalyDetector()
    device_tracker = DeviceTracker()
    latest_packet = None

    with Live(create_dashboard(packets, metrics, latest_packet, bw_tracker, src_ip_stats, dst_ip_stats, port_stats, flow_tracker, anomaly_detector, device_tracker), refresh_per_second=4, console=console) as live:
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
                flow_tracker.update(p)
                device_tracker.update(p)

                rates = bw_tracker.current_rates()
                anomaly_detector.inspect(p, rates['pps'], rates['kbs'])

                src_ip = p.get("src")
                dst_ip = p.get("dst")
                if src_ip:
                    src_ip_stats[src_ip]["pkts"] += 1
                    src_ip_stats[src_ip]["bytes"] += pkt_len
                    resolve_ip_async(src_ip)
                if dst_ip and dst_ip != src_ip:
                    dst_ip_stats[dst_ip]["pkts"] += 1
                    dst_ip_stats[dst_ip]["bytes"] += pkt_len
                    resolve_ip_async(dst_ip)

                src_port = p.get("src_port")
                dst_port = p.get("dst_port")
                if src_port:
                    port_stats[src_port] += 1
                if dst_port:
                    port_stats[dst_port] += 1

                proto = p.get("proto")
                if proto == "TCP":
                    metrics["tcp"] += 1
                elif proto == "UDP":
                    metrics["udp"] += 1
                elif proto == "ICMP":
                    metrics["icmp"] += 1
                else:
                    metrics["other"] += 1

                live.update(create_dashboard(packets, metrics, latest_packet, bw_tracker, src_ip_stats, dst_ip_stats, port_stats, flow_tracker, anomaly_detector, device_tracker))
            except json.JSONDecodeError:
                continue

if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError, SystemExit):
        sys.exit(0)

