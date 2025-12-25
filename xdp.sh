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
    
    # Configure queue count for AWS ENA XDP compatibility (max half of available)
    echo -e "${YELLOW}Configuring interface queues for XDP...${NC}"
    sudo ethtool -L $INTERFACE combined 4
    
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
        
        # Validate critical BPF maps
        echo -e "${BLUE}Validating BPF maps...${NC}"
        
        # Check NAT map
        NAT_ENTRIES=$(sudo bpftool map dump name nat_map 2>/dev/null | grep -c "key")
        if [ "$NAT_ENTRIES" -gt 0 ]; then
            echo -e "${GREEN}✓ NAT map: $NAT_ENTRIES rules loaded${NC}"
            sudo bpftool map dump name nat_map | head -10
        else
            echo -e "${RED}✗ NAT map: Empty or missing${NC}"
        fi
        
        # Check IP allowlist
        IP_ENTRIES=$(sudo bpftool map dump name ip_allowlist 2>/dev/null | grep -c "key")
        if [ "$IP_ENTRIES" -gt 0 ]; then
            echo -e "${GREEN}✓ IP allowlist: $IP_ENTRIES IPs loaded${NC}"
        else
            echo -e "${RED}✗ IP allowlist: Empty or missing${NC}"
        fi
        
        # Check stats map
        if sudo bpftool map show name stats_map > /dev/null 2>&1; then
            echo -e "${GREEN}✓ Stats map: Available${NC}"
        else
            echo -e "${RED}✗ Stats map: Missing${NC}"
        fi
        
        # Start packet injector for userspace packet processing
        echo -e "${BLUE}Starting packet injector...${NC}"
        cd src
        nohup sudo ./packet_injector vxlan_pipeline.bpf.o $TARGET_INTERFACE \
            </dev/null >"/tmp/packet_injector.log" 2>&1 &
        cd ..
        
        # Wait a moment for packet_injector startup
        sleep 2
        
        # Verify packet_injector startup
        INJECTOR_PID=$(pgrep -f "packet_injector.*-i.*$TARGET_INTERFACE" | head -1)
        if [ -n "$INJECTOR_PID" ]; then
            echo -e "${GREEN}✓ Packet injector started (PID: $INJECTOR_PID)${NC}"
            echo -e "${GREEN}Log file: /tmp/packet_injector.log${NC}"
        else
            echo -e "${YELLOW}Warning: Packet injector failed to start${NC}"
            echo -e "${YELLOW}Check log: cat /tmp/packet_injector.log${NC}"
        fi
        
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
    
    # Kill vxlan_loader process if exists
    if pgrep -f "vxlan_loader" > /dev/null; then
        echo -e "${YELLOW}Stopping vxlan_loader...${NC}"
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
        echo -e "${GREEN}✓ vxlan_loader stopped${NC}"
    fi
    
    # Kill packet_injector process if exists
    if pgrep -f "packet_injector" > /dev/null; then
        echo -e "${YELLOW}Stopping packet_injector...${NC}"
        sudo pkill -TERM -f "packet_injector" 2>/dev/null || true
        fix_terminal  # Immediate fix after pkill
        
        # Wait loop
        for i in {1..3}; do
            pgrep -f "packet_injector" > /dev/null || break
            sleep 1
        done
        
        # Force kill
        sudo pkill -KILL -f "packet_injector" 2>/dev/null || true
        fix_terminal  # Immediate fix after force kill
        echo -e "${GREEN}✓ packet_injector stopped${NC}"
    fi

    # Clean interface - use xdpgeneric since that's the mode we load in
    sudo ip link set $INTERFACE xdpgeneric off 2>/dev/null || true
    
    # COMPREHENSIVE BPF CLEANUP: Remove orphaned programs and maps
    echo -e "${YELLOW}Cleaning up BPF programs and maps...${NC}"
    
    # First, detach any remaining XDP programs from interfaces
    sudo ip link set $INTERFACE xdp off 2>/dev/null || true
    sudo ip link set $TARGET_INTERFACE xdp off 2>/dev/null || true
    
    # Remove any pinned BPF objects (maps/programs) that might keep references
    if [ -d "/sys/fs/bpf" ]; then
        sudo find /sys/fs/bpf -name "*vxlan*" -delete 2>/dev/null || true
        sudo find /sys/fs/bpf -name "*nat_map*" -delete 2>/dev/null || true
        sudo find /sys/fs/bpf -name "*stats_map*" -delete 2>/dev/null || true
    fi
    
    # Force cleanup of any remaining file descriptors by restarting systemd-resolved
    # (this helps clean up any lingering BPF references)
    sudo systemctl restart systemd-resolved 2>/dev/null || true
    
    # Wait a moment for kernel garbage collection
    sleep 2
    
    fix_terminal  # Final terminal fix
    echo -e "${GREEN}Stopped and Detached.${NC}"
    fix_terminal
}

clean() {
    # Aggressive cleanup of both processes
    echo -e "${YELLOW}Cleaning up all processes...${NC}"
    sudo pkill -KILL -f "vxlan_loader" 2>/dev/null || true
    sudo pkill -KILL -f "packet_injector" 2>/dev/null || true
    fix_terminal  # Immediate fix after pkill
    
    # Comprehensive interface and BPF cleanup
    sudo ip link set $INTERFACE xdpgeneric off 2>/dev/null || true
    
    # COMPLETE BPF CLEANUP: Remove all orphaned programs and maps
    echo -e "${YELLOW}Performing complete BPF cleanup...${NC}"
    
    # Force detach from all interfaces
    sudo ip link set $INTERFACE xdp off 2>/dev/null || true
    sudo ip link set $TARGET_INTERFACE xdp off 2>/dev/null || true
    
    # Remove pinned BPF objects that might hold references
    if [ -d "/sys/fs/bpf" ]; then
        echo "Cleaning pinned BPF objects..."
        sudo find /sys/fs/bpf -name "*vxlan*" -delete 2>/dev/null || true
        sudo find /sys/fs/bpf -name "*nat_map*" -delete 2>/dev/null || true
        sudo find /sys/fs/bpf -name "*stats_map*" -delete 2>/dev/null || true
        sudo find /sys/fs/bpf -name "*ip_allowlist*" -delete 2>/dev/null || true
        sudo find /sys/fs/bpf -name "*packet_ringbuf*" -delete 2>/dev/null || true
    fi
    
    # Clear any cgroup BPF programs if attached (comprehensive cleanup)
    sudo bpftool cgroup list 2>/dev/null | grep -i vxlan | while read line; do
        cgroup_path=$(echo "$line" | awk '{print $1}')
        if [ -n "$cgroup_path" ]; then
            echo "Detaching from cgroup: $cgroup_path"
            sudo bpftool cgroup detach "$cgroup_path" ingress 2>/dev/null || true
            sudo bpftool cgroup detach "$cgroup_path" egress 2>/dev/null || true
        fi
    done 2>/dev/null || true
    
    # Wait for kernel garbage collection
    sleep 3
    
    # Verify cleanup
    remaining=$(sudo bpftool prog show 2>/dev/null | grep -c "vxlan_pipeline_main" 2>/dev/null || echo "0")
    remaining=$(echo "$remaining" | tail -1 | tr -d '\n')  # Ensure single line, no newlines
    if [ "$remaining" -eq "0" ] 2>/dev/null; then
        echo -e "${GREEN}✓ All BPF programs cleaned up${NC}"
    else
        echo -e "${YELLOW}Warning: $remaining BPF programs may still be loaded${NC}"
    fi
    
    # FIX TERMINAL NOW because the kill might have left it raw
    fix_terminal
    
    echo -e "${GREEN}Environment Reset - All processes and BPF programs cleaned.${NC}"
    fix_terminal  # Final fix
}

status() {
    fix_terminal
    clear
    echo -e "${CYAN}--- XDP VXLAN PIPELINE STATUS ---${NC}"
    
    # Check vxlan_loader
    LOADER_PID=$(pgrep -f "vxlan_loader" | head -1)
    
    if [ -n "$LOADER_PID" ]; then
        echo -e "vxlan_loader: ${GREEN}RUNNING${NC} (PID: $LOADER_PID)"
        
        if ip link show $INTERFACE 2>/dev/null | grep -q xdp; then
            echo -e "XDP Hook:     ${GREEN}ATTACHED${NC} ($INTERFACE)"
        else
            echo -e "XDP Hook:     ${RED}DETACHED${NC} (Error)"
        fi
    else
        echo -e "vxlan_loader: ${RED}STOPPED${NC}"
        echo -e "XDP Hook:     ${RED}DETACHED${NC}"
    fi
    
    # Check packet_injector
    INJECTOR_PID=$(pgrep -f "packet_injector" | head -1)
    
    if [ -n "$INJECTOR_PID" ]; then
        echo -e "packet_injector: ${GREEN}RUNNING${NC} (PID: $INJECTOR_PID)"
    else
        echo -e "packet_injector: ${RED}STOPPED${NC}"
    fi
    
    if [ -n "$LOADER_PID" ]; then
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

# Stats function to display BPF maps and program statistics
stats() {
    echo -e "${GREEN}XDP VXLAN Pipeline Statistics${NC}"
    echo "=============================="
    
    # Check if programs are loaded
    XDP_PROGS=$(sudo bpftool prog list 2>/dev/null | grep -c "vxlan_pipeline_main" || echo "0")
    if [ "$XDP_PROGS" -eq "0" ]; then
        echo -e "${RED}✗ No XDP programs loaded${NC}"
        return 1
    fi
    
    echo -e "${GREEN}✓ XDP Programs: $XDP_PROGS loaded${NC}"
    
    # Show program details
    echo -e "\n${YELLOW}Program Details:${NC}"
    sudo bpftool prog list | grep -A1 -B1 "vxlan_pipeline_main" | head -10
    
    # Stats map
    echo -e "\n${YELLOW}Packet Statistics:${NC}"
    if sudo bpftool map show name stats_map > /dev/null 2>&1; then
        sudo bpftool map dump name stats_map 2>/dev/null || echo "No statistics available yet"
    else
        echo "Stats map not found"
    fi
    
    # NAT map
    echo -e "\n${YELLOW}NAT Rules:${NC}"
    if sudo bpftool map show name nat_map > /dev/null 2>&1; then
        NAT_COUNT=$(sudo bpftool map dump name nat_map 2>/dev/null | grep -c "key" || echo "0")
        echo "Active NAT rules: $NAT_COUNT"
        if [ "$NAT_COUNT" -gt "0" ]; then
            sudo bpftool map dump name nat_map | head -5
        fi
    else
        echo "NAT map not found"
    fi
    
    # IP allowlist
    echo -e "\n${YELLOW}IP Allowlist:${NC}"
    if sudo bpftool map show name ip_allowlist > /dev/null 2>&1; then
        IP_COUNT=$(sudo bpftool map dump name ip_allowlist 2>/dev/null | grep -c "key" || echo "0")
        echo "Allowed IPs: $IP_COUNT"
    else
        echo "IP allowlist map not found"
    fi
    
    # Interface statistics
    echo -e "\n${YELLOW}Interface Statistics ($INTERFACE):${NC}"
    if [ -f "/sys/class/net/$INTERFACE/statistics/rx_packets" ]; then
        RX_PACKETS=$(cat /sys/class/net/$INTERFACE/statistics/rx_packets 2>/dev/null || echo "0")
        TX_PACKETS=$(cat /sys/class/net/$INTERFACE/statistics/tx_packets 2>/dev/null || echo "0")
        RX_BYTES=$(cat /sys/class/net/$INTERFACE/statistics/rx_bytes 2>/dev/null || echo "0")
        TX_BYTES=$(cat /sys/class/net/$INTERFACE/statistics/tx_bytes 2>/dev/null || echo "0")
        
        echo "RX: $RX_PACKETS packets ($RX_BYTES bytes)"
        echo "TX: $TX_PACKETS packets ($TX_BYTES bytes)"
    else
        echo "Interface statistics not available"
    fi
    
    # Process status
    echo -e "\n${YELLOW}Process Status:${NC}"
    LOADER_PID=$(pgrep -f "vxlan_loader" 2>/dev/null || echo "")
    INJECTOR_PID=$(pgrep -f "packet_injector" 2>/dev/null || echo "")
    
    if [ -n "$LOADER_PID" ]; then
        echo -e "${GREEN}✓ vxlan_loader: Running (PID: $LOADER_PID)${NC}"
    else
        echo -e "${RED}✗ vxlan_loader: Not running${NC}"
    fi
    
    if [ -n "$INJECTOR_PID" ]; then
        echo -e "${GREEN}✓ packet_injector: Running (PID: $INJECTOR_PID)${NC}"
    else
        echo -e "${YELLOW}◦ packet_injector: Not running${NC}"
    fi
}

# Ensure terminal is fixed on exit
trap fix_terminal EXIT

case "${1:-status}" in
    "start") start ;;
    "stop") stop ;;
    "status") status ;;
    "stats") stats ;;
    "monitor") monitor ;;
    "clean") clean ;;
    "restart") stop; sleep 1; start ;;
    *) echo "Usage: $0 [start|stop|status|stats|monitor|clean|restart]" ;;
esac