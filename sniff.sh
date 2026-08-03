#!/bin/bash

UI_MODE=false
READ_MODE=false
ARGS=()

i=1
while [ $i -le $# ]; do
    arg="${!i}"
    if [ "$arg" == "--ui" ]; then
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

if [ "$READ_MODE" = false ] && [ "$EUID" -ne 0 ]; then
    echo "[!] Error: Live packet sniffing requires root privileges. Please run with sudo!"
    exit 1
fi

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
        exit 1
    fi
fi

cleanup() {
    if [ "$READ_MODE" = false ] && [ -n "$INTERFACE" ]; then
        echo ""
        echo "[+] Disabling promiscuous mode on $INTERFACE..."
        ip link set "$INTERFACE" promisc off
        echo "[+] Interface $INTERFACE restored. Sniffer stopped safely."
    fi
    exit 0
}

trap cleanup INT TERM EXIT

if [ "$READ_MODE" = false ]; then
    echo "[+] Enabling promiscuous mode on $INTERFACE..."
    ip link set "$INTERFACE" promisc on
fi

if [ "$READ_MODE" = true ]; then
    if [ "$UI_MODE" = true ]; then
        echo "[+] Replaying PCAP file in Python Rich UI with Domain Labels..."
        cargo run --quiet -- --json "${ARGS[@]}" | python3 ui.py
    else
        echo "[+] Reading offline PCAP file..."
        cargo run --quiet -- "${ARGS[@]}"
    fi
else
    if [ "$UI_MODE" = true ]; then
        echo "[+] Launching PackSniff Rust Engine with Domain Labels..."
        cargo run --quiet -- --interface "$INTERFACE" --json "${ARGS[@]}" | python3 ui.py
    else
        echo "[+] Building and starting Rust packet engine..."
        cargo run --quiet -- --interface "$INTERFACE" "${ARGS[@]}"
    fi
fi
