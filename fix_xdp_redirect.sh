#!/bin/bash
# Fix XDP Redirect - Force packets to exit via ens6
# This script reloads the XDP program with correct ens6 redirect configuration

set -e

echo "🔧 XDP Redirect Fix - Force ens6 Egress"
echo "========================================"

# Get current directory (should be in ebpf project)
if [ ! -f "src/vxlan_pipeline.bpf.c" ]; then
    echo "❌ Error: Must run from ebpf project root directory"
    exit 1
fi

# Source environment configuration
if [ -f ".env" ]; then
    source .env
    echo "✅ Configuration loaded from .env"
else
    echo "❌ Error: .env file not found"
    exit 1
fi

# Verify interfaces exist
if ! ip link show $INTERFACE >/dev/null 2>&1; then
    echo "❌ Error: Interface $INTERFACE not found"
    exit 1
fi

if ! ip link show $TARGET_INTERFACE >/dev/null 2>&1; then
    echo "❌ Error: Target interface $TARGET_INTERFACE not found"
    exit 1
fi

# Get interface indices
INTERFACE_INDEX=$(ip link show $INTERFACE | head -1 | cut -d: -f1)
TARGET_INDEX=$(ip link show $TARGET_INTERFACE | head -1 | cut -d: -f1)

echo "📋 Interface Configuration:"
echo "   Source: $INTERFACE (index: $INTERFACE_INDEX)"
echo "   Target: $TARGET_INTERFACE (index: $TARGET_INDEX)"

# Stop existing XDP program
echo "🛑 Stopping existing XDP program..."
sudo pkill -f vxlan_loader 2>/dev/null || true
sleep 2

# Detach any existing XDP programs
sudo ip link set $INTERFACE xdp off 2>/dev/null || true

# Build with latest changes
echo "🔨 Building XDP program..."
cd src
make clean >/dev/null 2>&1
make all >/dev/null 2>&1
cd ..

# Start XDP program with explicit target interface
echo "🚀 Starting XDP program with ens6 redirect..."
sudo ./src/vxlan_loader \
    -i $INTERFACE \
    -t $TARGET_INTERFACE \
    -a $NAT_IP \
    -p $NAT_PORT \
    -s $SOURCE_PORT \
    -v &

XDP_PID=$!
echo "   XDP Program PID: $XDP_PID"

# Wait for program to initialize
sleep 3

# Verify XDP is loaded
if ! sudo bpftool prog show | grep -q xdp; then
    echo "❌ Error: XDP program not loaded"
    exit 1
fi

echo "✅ XDP program loaded with ens6 redirect configuration"

# Test packet flow
echo ""
echo "🧪 Testing packet flow (10 seconds)..."
echo "   Looking for packets on $TARGET_INTERFACE..."

# Monitor both interfaces
timeout 10s sudo tcpdump -i any -n "host $NAT_IP" 2>/dev/null | grep -E "(ens5|ens6|br0)" | head -5 || true

echo ""
echo "🎯 XDP Redirect Fix Complete!"
echo "   If packets still appear on ens5, check XDP program logs"
echo "   Monitor with: sudo bpftool prog tracelog"

# Keep XDP running in background
echo "   XDP program running in background (PID: $XDP_PID)"
echo "   To stop: sudo kill $XDP_PID"