#!/bin/bash

# 1. Check for root privileges
if [ "$EUID" -ne 0 ]; then
    echo "[!] Error: Packet sniffing requires root privileges. Please run with sudo!"
    exit 1
fi

# 2. Auto-detect active network interface if not specified
INTERFACE=""
if [ -n "$1" ] && [[ "$1" != --* ]]; then
    INTERFACE="$1"
    shift
else
    INTERFACE=$(ip link show | grep -E "^[0-9]" | awk -F': ' '{print $2}' | grep -v "^lo$" | head -1)
fi

if [ -z "$INTERFACE" ]; then
    echo "[!] Error: Could not detect an active network interface."
    exit 1
fi

echo "[+] Target network interface: $INTERFACE"

# 3. Setup cleanup trap function for Ctrl+C / Exit
cleanup() {
    echo ""
    echo "[+] Disabling promiscuous mode on $INTERFACE..."
    ip link set "$INTERFACE" promisc off
    echo "[+] Interface $INTERFACE restored. Sniffer stopped safely."
    exit 0
}

trap cleanup INT TERM EXIT

# 4. Turn on promiscuous mode
echo "[+] Enabling promiscuous mode on $INTERFACE..."
ip link set "$INTERFACE" promisc on

# 5. Build and run Rust engine with all passed filter arguments
echo "[+] Building and starting Rust packet engine..."
cargo run --quiet -- --interface "$INTERFACE" "$@"
