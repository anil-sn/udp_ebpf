#!/bin/bash
# Simple XDP VXLAN Pipeline Control
# Usage: ./xdp.sh [start|stop|status|monitor|clean]

INTERFACE="ens4"
TARGET_INTERFACE="ens5"
NAT_IP="10.2.41.17"
NAT_PORT="8081"
SOURCE_PORT="42844"

# Visual Configuration
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

start() {
    echo -e "${BLUE}Starting XDP VXLAN Pipeline...${NC}"
    
    # Check if already running
    PID=$(pgrep -f vxlan_loader | head -1)
    if [ -n "$PID" ]; then
        echo -e "${RED}✗ ERROR: Pipeline already running (PID: $PID)${NC}"
        echo "Run './xdp.sh stop' first"
        exit 1
    fi
    
    # Clean up any orphaned XDP programs first
    if ip link show $INTERFACE 2>/dev/null | grep -q xdp; then
        echo -e "${YELLOW}Warning: Cleaning up orphaned XDP program...${NC}"
        sudo ip link set $INTERFACE xdp off 2>/dev/null || true
        sleep 1
    fi
    
    # Start in background
    nohup sudo ./vxlan_loader -i $INTERFACE -t $TARGET_INTERFACE \
        -a $NAT_IP -p $NAT_PORT -s $SOURCE_PORT -I 5 \
        </dev/null >/dev/null 2>&1 &
    
    sleep 2
    
    PID=$(pgrep -f vxlan_loader | head -1)
    if [ -n "$PID" ]; then
        echo -e "${GREEN}✓ SUCCESS: Pipeline started (PID: $PID)${NC}"
        status  # Call status to show the dashboard immediately
    else
        echo -e "${RED}✗ ERROR: Failed to start pipeline${NC}"
        echo "Try running manually to debug:"
        echo "sudo ./vxlan_loader -i $INTERFACE -t $TARGET_INTERFACE -a $NAT_IP -p $NAT_PORT -s $SOURCE_PORT -v"
        exit 1
    fi
}

stop() {
    echo -e "${BLUE}Stopping XDP VXLAN Pipeline...${NC}"
    
    PID=$(pgrep -f vxlan_loader | head -1)
    if [ -z "$PID" ]; then
        # Check for orphans even if process is dead
        if ip link show $INTERFACE 2>/dev/null | grep -q xdp; then
            echo -e "${YELLOW}Cleaning up orphaned XDP hook...${NC}"
            sudo ip link set $INTERFACE xdp off 2>/dev/null || true
            echo -e "${GREEN}✓ Cleanup complete${NC}"
        else
            echo "Pipeline is not running."
        fi
        return 0
    fi
    
    # Graceful kill
    sudo kill -TERM $PID 2>/dev/null
    
    # Wait loop
    for i in {1..5}; do
        if ! pgrep -f vxlan_loader > /dev/null; then
            echo -e "${GREEN}✓ Pipeline stopped successfully${NC}"
            return 0
        fi
        sleep 1
    done
    
    # Force kill
    echo -e "${RED}Forcing shutdown...${NC}"
    sudo pkill -KILL -f vxlan_loader 2>/dev/null || true
    sudo ip link set $INTERFACE xdp off 2>/dev/null || true
    echo -e "${GREEN}✓ Pipeline stopped${NC}"
}

status() {
    # CLEAR SCREEN for clean output
    clear
    
    echo -e "${CYAN}=======================================${NC}"
    echo -e "${CYAN}      XDP VXLAN PIPELINE STATUS        ${NC}"
    echo -e "${CYAN}=======================================${NC}"
    
    PID=$(pgrep -f vxlan_loader | head -1)
    
    if [ -n "$PID" ]; then
        echo -e "Service:  ${GREEN}● RUNNING${NC} (PID: $PID)"
        
        # Check XDP attachment
        if ip link show $INTERFACE 2>/dev/null | grep -q xdp; then
            echo -e "XDP Hook: ${GREEN}✓ ATTACHED${NC} ($INTERFACE)"
        else
            echo -e "XDP Hook: ${RED}✗ DETACHED${NC} (Warning)"
        fi
        
        echo ""
        echo -e "${BLUE}Configuration:${NC}"
        echo "---------------------------------------"
        printf "Inbound:  %-10s (Port %s)\n" "$INTERFACE" "$SOURCE_PORT"
        printf "Outbound: %-10s -> %s:%s\n" "$TARGET_INTERFACE" "$NAT_IP" "$NAT_PORT"
        echo "---------------------------------------"
        
        # Calculate Stats
        echo ""
        echo -e "${BLUE}Current Traffic Load:${NC}"
        RX_BEFORE=$(cat /sys/class/net/$INTERFACE/statistics/rx_packets 2>/dev/null || echo "0")
        sleep 1
        RX_AFTER=$(cat /sys/class/net/$INTERFACE/statistics/rx_packets 2>/dev/null || echo "0")
        PPS=$((RX_AFTER - RX_BEFORE))
        
        if [ $PPS -ge 1000 ]; then
             echo -e "Rate:     ${GREEN}$PPS pps${NC} (Active)"
        elif [ $PPS -gt 0 ]; then
             echo -e "Rate:     ${YELLOW}$PPS pps${NC} (Low)"
        else
             echo -e "Rate:     ${RED}0 pps${NC} (Idle)"
        fi
        
    else
        echo -e "Service:  ${RED}● STOPPED${NC}"
        if ip link show $INTERFACE 2>/dev/null | grep -q xdp; then
            echo -e "XDP Hook: ${YELLOW}⚠ ORPHANED${NC} (Run './xdp.sh clean')"
        else
            echo -e "XDP Hook: ${GREEN}✓ CLEAN${NC}"
        fi
    fi
    echo ""
}

monitor() {
    # Check if running first
    if ! pgrep -f vxlan_loader > /dev/null; then
        echo -e "${RED}ERROR: Pipeline is not running.${NC}"
        exit 1
    fi

    clear
    echo -e "${BLUE}Starting Live Monitor (Ctrl+C to stop)${NC}"
    echo -e "Time      |    PPS | Status"
    echo "--------------------------------"
    
    while true; do
        RX_BEFORE=$(cat /sys/class/net/$INTERFACE/statistics/rx_packets 2>/dev/null || echo "0")
        sleep 2
        RX_AFTER=$(cat /sys/class/net/$INTERFACE/statistics/rx_packets 2>/dev/null || echo "0")
        
        # Calculate approximate PPS over 2 seconds
        PPS=$(( (RX_AFTER - RX_BEFORE) / 2 ))
        
        TIME=$(date +%H:%M:%S)
        
        if [ $PPS -ge 85000 ]; then
            COLOR=$GREEN
            STATUS="HIGH"
        elif [ $PPS -ge 1000 ]; then
            COLOR=$CYAN
            STATUS="GOOD"
        elif [ $PPS -gt 0 ]; then
            COLOR=$YELLOW
            STATUS="LOW "
        else
            COLOR=$RED
            STATUS="IDLE"
        fi
        
        # Print formatted row
        printf "%s | ${COLOR}%6d${NC} | ${COLOR}%s${NC}\n" "$TIME" "$PPS" "$STATUS"
    done
}

clean() {
    echo -e "${BLUE}Resetting XDP Environment...${NC}"
    
    # Stop processes
    sudo pkill -TERM -f vxlan_loader 2>/dev/null
    sudo pkill -KILL -f vxlan_loader 2>/dev/null || true
    
    # Remove XDP links
    sudo ip link set $INTERFACE xdp off 2>/dev/null || true
    
    sleep 1
    echo -e "${GREEN}✓ System Cleaned & Reset${NC}"
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
    "clean"|"reset")
        clean
        ;;
    "restart")
        stop
        sleep 1
        start
        ;;
    *)
        echo "Usage: $0 [start|stop|status|monitor|clean|restart]"
        exit 1
        ;;
esac