#!/bin/bash
# Simple XDP VXLAN Pipeline Control

# --- LOAD ENVIRONMENT CONFIGURATION ---
# Check if .env file exists and source it
if [ -f "$(dirname "$0")/.env" ]; then
    source "$(dirname "$0")/.env"
    echo "Configuration loaded from .env file"
else
    echo "Warning: .env file not found, using defaults"
    # Fallback defaults if .env is missing
    INTERFACE="ens4"
    TARGET_INTERFACE="ens5"
    NAT_IP="10.2.41.17"
    NAT_PORT="8081"
    SOURCE_PORT="42844"
    STATS_INTERVAL="5"
    LOG_FILE="/tmp/vxlan_loader.log"
    ENABLE_COLORS="true"
fi

# --- VISUALS ---
# Only set colors if enabled in config
if [ "$ENABLE_COLORS" = "true" ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    NC='\033[0m' # No Color
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    CYAN=''
    NC=''
fi

# Helper to force TTY fix
fix_terminal() {
    stty sane 2>/dev/null
    # Specifically fix the staircase effect (newline issue)
    stty opost onlcr 2>/dev/null
    # Force immediate terminal reset
    printf "\r\033[0m" # Carriage return + color reset
    tput cnorm 2>/dev/null # Show cursor
    tput sgr0 2>/dev/null # Reset all attributes
}

start() {
    fix_terminal
    echo -e "${BLUE}Starting XDP VXLAN Pipeline...${NC}"
    
    # Check if running with more robust detection
    EXISTING_PID=$(pgrep -f "vxlan_loader.*-i.*$INTERFACE" | head -1)
    if [ -n "$EXISTING_PID" ]; then
        echo -e "${RED}ERROR: Pipeline already running (PID: $EXISTING_PID)${NC}"
        echo -e "${YELLOW}Use './xdp.sh stop' first${NC}"
        return 1
    fi
    
    # Clean orphans
    echo -e "${YELLOW}Cleaning any orphaned XDP programs...${NC}"
    sudo ip link set $INTERFACE xdp off 2>/dev/null || true
    
    # Set MTU to safe value for XDP (max 3498, use 3000 for safety)
    echo -e "${YELLOW}Configuring interface MTU for XDP...${NC}"
    sudo ip link set $INTERFACE mtu 3000
    
    # Start background process with comprehensive redirection
    echo -e "${BLUE}Launching vxlan_loader...${NC}"
    # Change to src directory where .bpf.o file is located and fix log path
    cd src
    nohup sudo ./vxlan_loader -i $INTERFACE -t $TARGET_INTERFACE \
        -a $NAT_IP -p $NAT_PORT -s $SOURCE_PORT -I $STATS_INTERVAL \
        </dev/null >"$LOG_FILE" 2>&1 &
    cd ..
    
    # Give more time for startup
    sleep 3
    
    # Verify startup with specific pattern match
    NEW_PID=$(pgrep -f "vxlan_loader.*-i.*$INTERFACE" | head -1)
    if [ -n "$NEW_PID" ]; then
        echo -e "${GREEN}SUCCESS: Pipeline started (PID: $NEW_PID)${NC}"
        echo -e "${GREEN}Log file: $LOG_FILE${NC}"
        
        # Load IP allowlist after successful pipeline start
        echo -e "${BLUE}Loading IP allowlist...${NC}"
        cd src
        if sudo python3 load_ip_allowlist.py ip_allowlist.json > /dev/null 2>&1; then
            echo -e "${GREEN}IP allowlist loaded successfully${NC}"
        else
            echo -e "${YELLOW}Warning: Failed to load IP allowlist${NC}"
        fi
        cd ..
        
        sleep 1
        fix_terminal
    else
        echo -e "${RED}ERROR: Failed to start pipeline${NC}"
        echo -e "${YELLOW}Check log: cat $LOG_FILE${NC}"
        fix_terminal
        exit 1
    fi
}

stop() {
    fix_terminal
    echo -e "${BLUE}Stopping Pipeline...${NC}"
    
    # Kill process if exists
    if pgrep -f "vxlan_loader" > /dev/null; then
        sudo pkill -TERM -f "vxlan_loader" 2>/dev/null || true
        fix_terminal  # Immediate fix after pkill
        
        # Wait loop
        for i in {1..3}; do
            pgrep -f "vxlan_loader" > /dev/null || break
            sleep 1
        done
        
        # Force kill
        sudo pkill -KILL -f "vxlan_loader" 2>/dev/null || true
        fix_terminal  # Immediate fix after force kill
    fi

    # Clean interface - use xdpgeneric since that's the mode we load in
    sudo ip link set $INTERFACE xdpgeneric off 2>/dev/null || true
    
    fix_terminal  # Final terminal fix
    echo -e "${GREEN}Stopped and Detached.${NC}"
    fix_terminal
}

clean() {
    # Aggressive cleanup
    sudo pkill -KILL -f "vxlan_loader" 2>/dev/null || true
    fix_terminal  # Immediate fix after pkill
    
    sudo ip link set $INTERFACE xdpgeneric off 2>/dev/null || true
    
    # FIX TERMINAL NOW because the kill might have left it raw
    fix_terminal
    
    echo -e "${GREEN}Environment Reset.${NC}"
    fix_terminal  # Final fix
}

status() {
    fix_terminal
    clear
    echo -e "${CYAN}--- XDP VXLAN STATUS ---${NC}"
    
    PID=$(pgrep -f "vxlan_loader" | head -1)
    
    if [ -n "$PID" ]; then
        echo -e "Service:  ${GREEN}RUNNING${NC} (PID: $PID)"
        
        if ip link show $INTERFACE 2>/dev/null | grep -q xdp; then
            echo -e "XDP Hook: ${GREEN}ATTACHED${NC} ($INTERFACE)"
        else
            echo -e "XDP Hook: ${RED}DETACHED${NC} (Error)"
        fi
        
        echo ""
        echo -e "${BLUE}Configuration:${NC}"
        echo "  Inbound:  $INTERFACE (Port $SOURCE_PORT)"
        echo "  Outbound: $TARGET_INTERFACE -> $NAT_IP:$NAT_PORT"
        
        echo ""
        echo -e "${BLUE}Traffic Load:${NC}"
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
        STATUS_LINK=$(ip link show $INTERFACE 2>/dev/null | grep -q xdp && echo "${YELLOW}ORPHANED${NC}" || echo "${GREEN}CLEAN${NC}")
        echo -e "XDP Hook: $STATUS_LINK"
    fi
    echo ""
}

monitor() {
    if ! pgrep -f "vxlan_loader" > /dev/null; then
        echo -e "${RED}Start pipeline first!${NC}"
        exit 1
    fi
    
    fix_terminal
    clear
    echo -e "${BLUE}Live Monitor (Ctrl+C to stop)${NC}"
    printf "%-10s | %-10s | %s\n" "TIME" "PPS" "STATUS"
    echo "-----------------------------------"
    
    # Set trap for Ctrl+C
    trap 'fix_terminal; echo; exit 0' INT
    
    while true; do
        RX1=$(cat /sys/class/net/$INTERFACE/statistics/rx_packets 2>/dev/null || echo "0")
        sleep 2
        RX2=$(cat /sys/class/net/$INTERFACE/statistics/rx_packets 2>/dev/null || echo "0")
        PPS=$(( (RX2 - RX1) / 2 ))
        TIME=$(date +%H:%M:%S)
        
        # Use performance threshold from config
        if [ $PPS -ge ${TARGET_PPS:-85000} ]; then
            COLOR=$GREEN; STAT="OPTIMAL"
        elif [ $PPS -ge ${PERFORMANCE_THRESHOLD:-60000} ]; then
            COLOR=$YELLOW; STAT="GOOD"
        elif [ $PPS -gt 0 ]; then
            COLOR=$YELLOW; STAT="LOW"
        else
            COLOR=$RED; STAT="IDLE"
        fi
        
        printf "%s | ${COLOR}%-10d${NC} | ${COLOR}%s${NC}\n" "$TIME" "$PPS" "$STAT"
    done
}

# Ensure terminal is fixed on exit
trap fix_terminal EXIT

case "${1:-status}" in
    "start") start ;;
    "stop") stop ;;
    "status") status ;;
    "monitor") monitor ;;
    "clean") clean ;;
    "restart") stop; sleep 1; start ;;
    *) echo "Usage: $0 [start|stop|status|monitor|clean|restart]" ;;
esac