#!/bin/bash

# Simple VXLAN Packet Test - Send on eth5 and monitor on ens6
# Run this script to send the packet and monitor both interfaces

echo "🚀 Starting VXLAN Packet Test"
echo "=================================="

# Check if interfaces exist
if ! ip link show ens5 >/dev/null 2>&1; then
    echo "❌ Interface ens5 not found"
    echo "Available interfaces:"
    ip link show | grep -E "^[0-9]+:" | cut -d: -f2 | sed 's/^ *//'
    exit 1
fi

if ! ip link show ens6 >/dev/null 2>&1; then
    echo "❌ Interface ens6 not found"
    echo "Available interfaces:"
    ip link show | grep -E "^[0-9]+:" | cut -d: -f2 | sed 's/^ *//'
    exit 1
fi

# Make sure XDP program is loaded (if needed)
echo "📡 Checking XDP program status..."
if command -v bpftool >/dev/null 2>&1; then
    echo "Current XDP programs:"
    sudo bpftool net show
fi

# Start monitoring in background
echo "🔍 Starting packet capture on ens6..."
sudo tcpdump -i ens6 -n -X -w /tmp/ens6_capture.pcap &
TCPDUMP_PID=$!

# Give tcpdump time to start
sleep 1

# Send the packet
echo "📦 Sending VXLAN packet on ens5..."
sudo python3 send_vxlan_packet.py ens5

# Wait a moment for packet processing
sleep 2

# Stop monitoring
echo "⏹️  Stopping capture..."
sudo kill $TCPDUMP_PID 2>/dev/null

# Show results
echo "📊 Results:"
echo "=================================="
echo "Capture saved to: /tmp/ens6_capture.pcap"

if [ -f /tmp/ens6_capture.pcap ]; then
    echo "📈 Packets captured on ens6:"
    sudo tcpdump -r /tmp/ens6_capture.pcap -n -c 5 2>/dev/null || echo "No packets captured"
    echo ""
    echo "📄 Full capture analysis:"
    echo "  sudo tcpdump -r /tmp/ens6_capture.pcap -n -X"
else
    echo "❌ No capture file generated"
fi

echo ""
echo "🔍 To monitor live traffic:"
echo "  Terminal 1: sudo tcpdump -i ens5 -n -X"  
echo "  Terminal 2: sudo tcpdump -i ens6 -n -X"
echo "  Terminal 3: sudo python3 send_vxlan_packet.py ens5"