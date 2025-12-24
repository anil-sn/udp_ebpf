#!/bin/bash
# Quick setup script for test dependencies

echo "Installing test dependencies..."

# Install hping3
echo "Installing hping3..."
if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update && sudo apt-get install -y hping3
elif command -v yum >/dev/null 2>&1; then
    sudo yum install -y hping3
elif command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y hping3
else
    echo "Cannot detect package manager. Please install hping3 manually."
fi

# Install scapy
echo "Installing scapy..."
pip3 install scapy

echo "Dependencies installed. You can now run:"
echo "  sudo ./test_framework.sh"