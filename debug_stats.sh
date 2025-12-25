#!/bin/bash
# XDP VXLAN Pipeline - Statistics Diagnostic Tool

echo "XDP VXLAN Pipeline - Statistics Diagnostic"
echo "=========================================="

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root (use sudo)"
    exit 1
fi

# Check if vxlan_loader is running
if pgrep -f "vxlan_loader" > /dev/null; then
    echo "✓ vxlan_loader is running"
    
    # Show process info
    echo ""
    echo "Process Information:"
    ps aux | grep vxlan_loader | grep -v grep
    
    # Check XDP attachment
    echo ""
    echo "XDP Program Status:"
    ip link show | grep -E "(lo|ens[0-9]):" -A1 | grep -E "(UP|xdp)"
    
else
    echo "⚠️ vxlan_loader is not running"
    echo ""
    echo "To start the pipeline:"
    echo "  cd /path/to/project && ./xdp.sh start"
fi

echo ""
echo "Recent log entries:"
if [ -f "/tmp/vxlan_loader.log" ]; then
    echo "--- /tmp/vxlan_loader.log (last 10 lines) ---"
    tail -10 /tmp/vxlan_loader.log
else
    echo "No log file found at /tmp/vxlan_loader.log"
fi

echo ""
echo "Tips for debugging statistics issues:"
echo "  1. Ensure eBPF program is built: cd src && make clean && make"
echo "  2. Check XDP support: ethtool -i <interface> | grep driver"
echo "  3. Verify permissions: XDP requires root privileges"
echo "  4. Check dmesg for kernel messages: dmesg | tail -20"