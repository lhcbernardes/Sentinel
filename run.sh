#!/bin/bash

# Sentinel-RS Run Script
# Usage: ./run.sh [mac|linux|windows]

PLATFORM="${1:-mac}"

case "$PLATFORM" in
    mac)
        echo "Detected macOS - Using interface en0"
        INTERFACE="en0"
        ;;
    linux)
        echo "Detected Linux - Using interface eth0"
        INTERFACE="eth0"
        ;;
    windows)
        echo "Para Windows, use: run.bat"
        exit 1
        ;;
    *)
        echo "Usage: ./run.sh [mac|linux]"
        echo "  mac  - for macOS (interface: en0)"
        echo "  linux - for Linux (interface: eth0)"
        exit 1
        ;;
esac

echo "Starting Sentinel-RS..."
echo "Web Interface: http://localhost:8080"
echo ""

# Verifica se precisa de sudo para captura de pacotes
if [ "$EUID" -ne 0 ]; then
    echo "Note: Running without sudo - packet capture may not work"
    echo "Use: sudo -E ./run.sh $PLATFORM for full functionality"
    echo ""
fi

export INTERFACE
cargo run