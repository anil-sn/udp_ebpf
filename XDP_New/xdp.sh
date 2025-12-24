#!/bin/bash
# Simple XDP VXLAN Pipeline Control
# Usage: ./xdp.sh [start|stop|status|monitor|clean]

INTERFACE="ens4"
TARGET_INTERFACE="ens5"
NAT_IP="10.2.41.17"
NAT_PORT="8081"
SOURCE_PORT="42844"

start() {
    echo "Starting XDP VXLAN Pipeline..."
    
    # Check if already running
    PID=$(pgrep -f vxlan_loader | head -1)
    if [ -n "$PID" ]; then
        echo "ERROR: Pipeline already running (PID: $PID)"
        echo "Run './xdp.sh stop' first"
        exit 1
    fi
    
    # Clean up any orphaned XDP programs first
    if ip link show $INTERFACE 2>/dev/null | grep -q xdp; then
        echo "Cleaning up orphaned XDP program..."
        sudo ip link set $INTERFACE xdp off 2>/dev/null || true
        sleep 1
    fi
    
    # Start in background with proper terminal handling
    nohup sudo ./vxlan_loader -i $INTERFACE -t $TARGET_INTERFACE \
        -a $NAT_IP -p $NAT_PORT -s $SOURCE_PORT -I 5 \
        </dev/null >/dev/null 2>&1 &
    
    sleep 3
    
    PID=$(pgrep -f vxlan_loader | head -1)
    if [ -n "$PID" ]; then
        echo "SUCCESS: Pipeline started (PID: $PID)"
        echo "Interface: $INTERFACE -> $TARGET_INTERFACE"
        echo "NAT Rule: port $SOURCE_PORT -> $NAT_IP:$NAT_PORT"
        echo ""
    else
        echo "ERROR: Failed to start pipeline"
        echo "Try: sudo ./vxlan_loader -i $INTERFACE -t $TARGET_INTERFACE -a $NAT_IP -p $NAT_PORT -s $SOURCE_PORT -v"
        exit 1
    fi
}

stop() {
    echo "Stopping XDP VXLAN Pipeline..."
    
    PID=$(pgrep -f vxlan_loader | head -1)
    if [ -z "$PID" ]; then
        echo "Pipeline not running"
        
        # Clean up any orphaned XDP programs
        if ip link show $INTERFACE 2>/dev/null | grep -q xdp; then
            echo "Cleaning up orphaned XDP program..."
            sudo ip link set $INTERFACE xdp off 2>/dev/null || true
        fi
        return 0
    fi
    
    # Send SIGTERM for graceful shutdown
    sudo kill -TERM $PID 2>/dev/null
    
    # Wait up to 5 seconds for graceful shutdown
    for i in {1..5}; do
        if ! pgrep -f vxlan_loader > /dev/null; then
            echo "Pipeline stopped successfully"
            return 0
        fi
        sleep 1
    done
    
    # Force kill if still running
    echo "Forcing shutdown..."
    sudo pkill -KILL -f vxlan_loader 2>/dev/null || true
    sudo ip link set $INTERFACE xdp off 2>/dev/null || true
    echo "Pipeline stopped"
}

status() {
    echo "XDP VXLAN Pipeline Status"
    echo "========================="
    
    PID=$(pgrep -f vxlan_loader | head -1)
    if [ -n "$PID" ]; then
        echo "Status: RUNNING (PID: $PID)"
        
        # Check XDP attachment
        if ip link show $INTERFACE 2>/dev/null | grep -q xdp; then
            echo "XDP Program: Attached to $INTERFACE"
        else
            echo "XDP Program: Not attached"
        fi
        
        # Show basic stats
        echo ""
        echo "Quick Stats:"
        RX_BEFORE=$(cat /sys/class/net/$INTERFACE/statistics/rx_packets 2>/dev/null || echo "0")
        sleep 1
        RX_AFTER=$(cat /sys/class/net/$INTERFACE/statistics/rx_packets 2>/dev/null || echo "0")
        PPS=$((RX_AFTER - RX_BEFORE))
        echo "   Packet Rate: $PPS pps"
        
        if [ $PPS -ge 1000 ]; then
            echo "   Performance: Active traffic"
        elif [ $PPS -gt 0 ]; then
            echo "   Performance: Low traffic"
        else
            echo "   Performance: No traffic"
        fi
        
    else
        echo "Status: STOPPED"
        
        if ip link show $INTERFACE 2>/dev/null | grep -q xdp; then
            echo "XDP Program: Orphaned (needs cleanup)"
        else
            echo "XDP Program: Clean"
        fi
    fi
    
    echo ""
    echo "Configuration:"
    echo "  Interface: $INTERFACE → $TARGET_INTERFACE"  
    echo "  NAT Rule: port $SOURCE_PORT → $NAT_IP:$NAT_PORT"
}

monitor() {
    echo "Simple Monitoring (Press Ctrl+C to stop)"
    echo "======================================="
    
    if ! pgrep -f vxlan_loader > /dev/null; then
        echo "ERROR: Pipeline not running. Start it first: ./xdp.sh start"
        exit 1
    fi
    
    echo "Time     | PPS    | Status"
    echo "---------|--------|--------"
    
    while true; do
        RX_BEFORE=$(cat /sys/class/net/$INTERFACE/statistics/rx_packets 2>/dev/null || echo "0")
        sleep 2
        RX_AFTER=$(cat /sys/class/net/$INTERFACE/statistics/rx_packets 2>/dev/null || echo "0")
        PPS=$(( (RX_AFTER - RX_BEFORE) / 2 ))
        
        TIME=$(date +%H:%M:%S)
        
        if [ $PPS -ge 85000 ]; then
            STATUS="EXCELLENT"
        elif [ $PPS -ge 50000 ]; then
            STATUS="GOOD"
        elif [ $PPS -gt 0 ]; then
            STATUS="LOW"
        else
            STATUS="IDLE"
        fi
        
        printf "%s | %-6d | %s\n" "$TIME" "$PPS" "$STATUS"
    done
}

clean() {
    echo "Cleaning up XDP VXLAN Pipeline..."
    
    # Stop any running processes
    PID=$(pgrep -f vxlan_loader | head -1)
    if [ -n "$PID" ]; then
        echo "Stopping pipeline process..."
        sudo pkill -TERM -f vxlan_loader 2>/dev/null
        sleep 2
        sudo pkill -KILL -f vxlan_loader 2>/dev/null || true
    fi
    
    # Remove XDP programs
    if ip link show $INTERFACE 2>/dev/null | grep -q xdp; then
        echo "Detaching XDP program from $INTERFACE..."
        sudo ip link set $INTERFACE xdp off 2>/dev/null || true
    fi
    
    echo "✅ Cleanup complete"
}

# Main command handling
case "${1:-status}" in
    "start")
        start
        ;;
    "stop")
        stop
        ;;
    "status"|"")
        status
        ;;
    "monitor")
        monitor
        ;;
    "clean")
        clean
        ;;
    "restart")
        stop
        sleep 1
        start
        ;;
    *)
        echo "Usage: $0 [start|stop|status|monitor|clean|restart]"
        echo ""
        echo "Commands:"
        echo "  start    - Start XDP pipeline"
        echo "  stop     - Stop XDP pipeline"  
        echo "  status   - Show current status (default)"
        echo "  monitor  - Live monitoring"
        echo "  clean    - Force cleanup"
        echo "  restart  - Stop and start"
        exit 1
        ;;
esac