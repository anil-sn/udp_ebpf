#!/bin/bash
# Simple XDP VXLAN Pipeline Control

# --- CONFIGURATION ---
INTERFACE="ens4"
TARGET_INTERFACE="ens5"
NAT_IP="10.2.41.17"
NAT_PORT="8081"
SOURCE_PORT="42844"

# --- VISUALS ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# FIX TERMINAL STATE (Prevents stair-stepping output)
stty sane

start() {
    echo -e "${BLUE}Starting XDP VXLAN Pipeline...${NC}"
    
    # Check if already running
    PID=$(pgrep -f vxlan_loader | head -1)
    if [ -n "$PID" ]; then
        echo -e "${RED}ERROR: Pipeline already running (PID: $PID)${NC}"
        echo "Run './xdp.sh stop' first"
        exit 1
    fi
    
    # Cleanup orphans
    if ip link show $INTERFACE 2>/dev/null | grep -q xdp; then
        echo "Cleaning up orphaned XDP program..."
        sudo ip link set $INTERFACE xdp off 2>/dev/null || true
    fi
    
    # Start background process
    nohup sudo ./vxlan_loader -i $INTERFACE -t $TARGET_INTERFACE \
        -a $NAT_IP -p $NAT_PORT -s $SOURCE_PORT -I 5 \
        </dev/null >/dev/null 2>&1 &
    
    sleep 2
    
    PID=$(pgrep -f vxlan_loader | head -1)
    if [ -n "$PID" ]; then
        echo -e "${GREEN}SUCCESS: Pipeline started (PID: $PID)${NC}"
        status
    else
        echo -e "${RED}ERROR: Failed to start pipeline${NC}"
        exit 1
    fi
}

stop() {
    echo -e "${BLUE}Stopping Pipeline...${NC}"
    
    PID=$(pgrep -f vxlan_loader | head -1)
    if [ -z "$PID" ]; then
        # Just clean interface if process is dead
        sudo ip link set $INTERFACE xdp off 2>/dev/null || true
        echo "Pipeline was not running."
        return 0
    fi
    
    # Kill process
    sudo kill -TERM $PID 2>/dev/null
    
    for i in {1..3}; do
        if ! pgrep -f vxlan_loader > /dev/null; then
            break
        fi
        sleep 1
    done
    
    # Force kill if needed
    sudo pkill -KILL -f vxlan_loader 2>/dev/null || true
    sudo ip link set $INTERFACE xdp off 2>/dev/null || true
    
    echo -e "${GREEN}Stopped and Detached.${NC}"
}

status() {
    clear
    echo -e "${CYAN}--- XDP VXLAN STATUS ---${NC}"
    
    PID=$(pgrep -f vxlan_loader | head -1)
    
    if [ -n "$PID" ]; then
        echo -e "Service:  ${GREEN}RUNNING${NC} (PID: $PID)"
        
        if ip link show $INTERFACE 2>/dev/null | grep -q xdp; then
            echo -e "XDP Hook: ${GREEN}ATTACHED${NC} ($INTERFACE)"
        else
            echo -e "XDP Hook: ${RED}DETACHED${NC} (Error)"
        fi
        
        echo ""
        echo -e "${BLUE}Configuration:${NC}"
        # Using simple echo to avoid printf formatting issues
        echo "  Inbound:  $INTERFACE (Port $SOURCE_PORT)"
        echo "  Outbound: $TARGET_INTERFACE -> $NAT_IP:$NAT_PORT"
        
        echo ""
        echo -e "${BLUE}Traffic:${NC}"
        RX1=$(cat /sys/class/net/$INTERFACE/statistics/rx_packets 2>/dev/null || echo "0")
        sleep 1
        RX2=$(cat /sys/class/net/$INTERFACE/statistics/rx_packets 2>/dev/null || echo "0")
        PPS=$((RX2 - RX1))
        
        if [ $PPS -gt 0 ]; then
             echo -e "  Rate:     ${GREEN}$PPS pps${NC}"
        else
             echo -e "  Rate:     ${YELLOW}0 pps${NC} (Idle)"
        fi
        
    else
        echo -e "Service:  ${RED}STOPPED${NC}"
        echo -e "XDP Hook: $(ip link show $INTERFACE 2>/dev/null | grep -q xdp && echo "${YELLOW}ORPHANED${NC}" || echo "${GREEN}CLEAN${NC}")"
    fi
    echo ""
}

monitor() {
    if ! pgrep -f vxlan_loader > /dev/null; then
        echo -e "${RED}Start pipeline first!${NC}"
        exit 1
    fi

    clear
    echo -e "${BLUE}Live Monitor (Ctrl+C to stop)${NC}"
    printf "%-10s | %-10s | %s\n" "TIME" "PPS" "STATUS"
    echo "-----------------------------------"
    
    while true; do
        RX1=$(cat /sys/class/net/$INTERFACE/statistics/rx_packets 2>/dev/null || echo "0")
        sleep 2
        RX2=$(cat /sys/class/net/$INTERFACE/statistics/rx_packets 2>/dev/null || echo "0")
        PPS=$(( (RX2 - RX1) / 2 ))
        TIME=$(date +%H:%M:%S)
        
        if [ $PPS -ge 1000 ]; then
            COLOR=$GREEN; STAT="ACTIVE"
        elif [ $PPS -gt 0 ]; then
            COLOR=$YELLOW; STAT="LOW"
        else
            COLOR=$RED; STAT="IDLE"
        fi
        
        printf "%s | ${COLOR}%-10d${NC} | ${COLOR}%s${NC}\n" "$TIME" "$PPS" "$STAT"
    done
}

clean() {
    sudo pkill -KILL -f vxlan_loader 2>/dev/null
    sudo ip link set $INTERFACE xdp off 2>/dev/null || true
    echo -e "${GREEN}Environment Reset.${NC}"
}

case "${1:-status}" in
    "start") start ;;
    "stop") stop ;;
    "status") status ;;
    "monitor") monitor ;;
    "clean") clean ;;
    "restart") stop; sleep 1; start ;;
    *) echo "Usage: $0 [start|stop|status|monitor|clean|restart]" ;;
esac