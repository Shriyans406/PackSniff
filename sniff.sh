#!/bin/bash

# 1. Check for root privileges
if [ "$EUID" -ne 0 ]; then
    echo "[!] Error: Packet sniffing requires root privileges. Please run with sudo!"
    exit 1
fi

# 2. Check for --ui flag
UI_MODE=false
ARGS=()

for arg in "$@"; do
    if [ "$arg" == "--ui" ]; then
        UI_MODE=true
    else
        ARGS+=("$arg")
    fi
done

# 3. Detect interface
INTERFACE=""
if [ -n "${ARGS[0]}" ] && [[ "${ARGS[0]}" != --* ]]; then
    INTERFACE="${ARGS[0]}"
    ARGS=("${ARGS[@]:1}")
else
    INTERFACE=$(ip link show | grep -E "^[0-9]" | awk -F': ' '{print $2}' | grep -v "^lo$" | head -1)
fi

if [ -z "$INTERFACE" ]; then
    echo "[!] Error: Could not detect an active network interface."
    exit 1
fi

# 4. Setup cleanup trap function
cleanup() {
    echo ""
    echo "[+] Disabling promiscuous mode on $INTERFACE..."
    ip link set "$INTERFACE" promisc off
    echo "[+] Interface $INTERFACE restored. Sniffer stopped safely."
    exit 0
}

trap cleanup INT TERM EXIT

# 5. Enable promiscuous mode
echo "[+] Enabling promiscuous mode on $INTERFACE..."
ip link set "$INTERFACE" promisc on

# 6. Execute Engine
if [ "$UI_MODE" = true ]; then
    echo "[+] Launching PackSniff Rust Engine with Python Rich UI..."
    cargo run --quiet -- --interface "$INTERFACE" --json "${ARGS[@]}" | python3 ui.py
else
    echo "[+] Building and starting Rust packet engine..."
    cargo run --quiet -- --interface "$INTERFACE" "${ARGS[@]}"
fi
