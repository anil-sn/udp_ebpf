#!/bin/bash
# Quick setup script for test dependencies

echo "Installing test dependencies for XDP VXLAN Pipeline..."

# Install system dependencies required for Scapy
echo "Installing system dependencies (tcpdump, libpcap-dev)..."
if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update && sudo apt-get install -y tcpdump libpcap-dev python3-pip
elif command -v yum >/dev/null 2>&1; then
    sudo yum install -y tcpdump libpcap-devel python3-pip
elif command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y tcpdump libpcap-devel python3-pip
else
    echo "Cannot detect package manager. Please install tcpdump and libpcap-dev manually."
fi

# Install hping3
echo "Installing hping3..."
if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get install -y hping3
elif command -v yum >/dev/null 2>&1; then
    sudo yum install -y hping3
elif command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y hping3
else
    echo "Cannot detect package manager. Please install hping3 manually."
fi

# Install scapy - try system package first, then pip
echo "Installing scapy..."
echo "Trying system package (python3-scapy)..."
if sudo apt-get install -y python3-scapy 2>/dev/null; then
    echo "✓ Scapy installed via system package"
else
    echo "System package not available, installing via pip..."
    # Install for system-wide use (needed for root access)
    sudo pip3 install scapy
    echo "✓ Scapy installed via pip (system-wide)"
fi

echo ""
echo "Dependencies installed. You can now run:"
echo "  sudo ./test_framework.sh"
echo ""
echo "Note: Tests require root privileges for XDP operations and network access."