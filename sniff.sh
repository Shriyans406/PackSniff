#!/bin/bash

# --- PRE-FLIGHT DEPENDENCY CHECK ---
check_dependencies() {
    if ! command -v cargo &> /dev/null; then
        echo "[!] Error: Cargo (Rust compiler package manager) is not installed or not in PATH."
        echo "    Install Rust: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
        exit 1
    fi

    if ! command -v python3 &> /dev/null; then
        echo "[!] Error: Python 3 is not installed or not in PATH."
        echo "    Install Python 3: sudo apt install python3 python3-pip"
        exit 1
    fi
}

show_help() {
    echo "================================================================================"
    echo "  🛡️  PACKSNIFF SHELL WRAPPER — HELP & USAGE MENU"
    echo "================================================================================"
    echo ""
    echo "USAGE:"
    echo "  sudo ./sniff.sh [INTERFACE] [OPTIONS]"
    echo "  ./sniff.sh --read <FILE.pcap> [OPTIONS]"
    echo ""
    echo "OPTIONS:"
    echo "  --ui                   Launch live Python Rich TUI telemetry dashboard"
    echo "  --flows                Display stateful connection flow analysis summary"
    echo "  --devices              Display local network devices inventory on exit"
    echo "  --output, -o <FILE>    Export packets to .pcap / .json / .csv (auto-detected by extension)"
    echo "  --read, -r <FILE.pcap> Replay saved PCAP capture file offline"
    echo "  --save, -s <FILE.pcap> Save live captured traffic to PCAP file"
    echo "  --filter, -f <EXPR>    Advanced filter (e.g. \"tcp and port 443\", \"src 10.0.2.15\")"
    echo "  --help, -h             Show this help screen"
    echo ""
    echo "EXAMPLES:"
    echo "  sudo ./sniff.sh enp0s3 --ui"
    echo "  sudo ./sniff.sh enp0s3 --filter \"tcp and port 443\" --ui"
    echo "  sudo ./sniff.sh enp0s3 --filter \"udp and port 53\" --ui"
    echo "  sudo ./sniff.sh enp0s3 --filter \"src 10.0.2.15\""
    echo "  sudo ./sniff.sh enp0s3 --filter \"size > 100\""
    echo "  ./sniff.sh --read traffic.pcap --filter \"tcp and port 443\" --ui"
    echo "================================================================================"
    exit 0
}

check_dependencies

UI_MODE=false
READ_MODE=false
ARGS=()

i=1
while [ $i -le $# ]; do
    arg="${!i}"
    if [ "$arg" == "--help" ] || [ "$arg" == "-h" ]; then
        show_help
    elif [ "$arg" == "--ui" ]; then
        UI_MODE=true
    elif [ "$arg" == "--read" ] || [ "$arg" == "-r" ]; then
        READ_MODE=true
        ARGS+=("$arg")
        i=$((i+1))
        if [ $i -le $# ]; then
            ARGS+=("${!i}")
        fi
    else
        ARGS+=("$arg")
    fi
    i=$((i+1))
done

# Root privilege validation for live packet capture
if [ "$READ_MODE" = false ] && [ "$EUID" -ne 0 ]; then
    echo "[!] Error: Live packet sniffing requires root privileges."
    echo "    Please run with: sudo ./sniff.sh [INTERFACE] [OPTIONS]"
    exit 1
fi

# Detect network interface if not reading offline PCAP file
INTERFACE=""
if [ "$READ_MODE" = false ]; then
    if [ -n "${ARGS[0]}" ] && [[ "${ARGS[0]}" != --* ]]; then
        INTERFACE="${ARGS[0]}"
        ARGS=("${ARGS[@]:1}")
    else
        INTERFACE=$(ip link show | grep -E "^[0-9]" | awk -F': ' '{print $2}' | grep -v "^lo$" | head -1)
    fi

    if [ -z "$INTERFACE" ]; then
        echo "[!] Error: Could not detect an active network interface."
        echo "    Specify interface explicitly: sudo ./sniff.sh enp0s3"
        exit 1
    fi
fi

# Cleanup trap restoring promiscuous mode safely
cleanup() {
    trap - INT TERM EXIT
    if [ "$READ_MODE" = false ] && [ -n "$INTERFACE" ]; then
        echo ""
        echo "[+] Restoring interface state..."
        ip link set "$INTERFACE" promisc off &> /dev/null
        echo "[+] Interface $INTERFACE promiscuous mode disabled. Sniffer stopped safely."
    fi
    exit 0
}

trap cleanup INT TERM EXIT

# Enable promiscuous mode for live capture
if [ "$READ_MODE" = false ]; then
    echo "[+] Enabling promiscuous mode on $INTERFACE..."
    ip link set "$INTERFACE" promisc on
fi

# Execute Pipeline
if [ "$READ_MODE" = true ]; then
    if [ "$UI_MODE" = true ]; then
        echo "[+] Replaying PCAP file in Python Rich UI..."
        cargo run --quiet -- --json "${ARGS[@]}" | python3 ui.py
    else
        echo "[+] Reading offline PCAP file..."
        cargo run --quiet -- "${ARGS[@]}"
    fi
else
    if [ "$UI_MODE" = true ]; then
        echo "[+] Launching PackSniff Rust Engine with Python Rich UI..."
        cargo run --quiet -- --interface "$INTERFACE" --json "${ARGS[@]}" | python3 ui.py
    else
        echo "[+] Building and starting Rust packet engine on $INTERFACE..."
        cargo run --quiet -- --interface "$INTERFACE" "${ARGS[@]}"
    fi
fi
