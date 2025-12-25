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

# Helper to convert integer IP to dotted decimal notation
int_to_ip() {
    local ip_int="$1"
    printf "%d.%d.%d.%d" \
        $((ip_int & 0xFF)) \
        $(((ip_int >> 8) & 0xFF)) \
        $(((ip_int >> 16) & 0xFF)) \
        $(((ip_int >> 24) & 0xFF))
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

# Stats function to display basic packet statistics only
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
    
    # Basic packet statistics only
    echo -e "\n${YELLOW}Packet Statistics:${NC}"
    if sudo bpftool map show name stats_map > /dev/null 2>&1; then
        STATS_JSON=$(sudo bpftool map dump name stats_map 2>/dev/null)
        if [ -n "$STATS_JSON" ]; then
            # Extract totals
            TOTAL_RX=$(echo "$STATS_JSON" | jq -r 'first(.[] | select(.name == "stats_map")) | .elements[] | select(.key == 0) | .values | map(.value) | add // 0' 2>/dev/null || echo "0")
            TOTAL_PROCESSED=$(echo "$STATS_JSON" | jq -r 'first(.[] | select(.name == "stats_map")) | .elements[] | select(.key == 1) | .values | map(.value) | add // 0' 2>/dev/null || echo "0")
            TOTAL_DROPPED=$(echo "$STATS_JSON" | jq -r 'first(.[] | select(.name == "stats_map")) | .elements[] | select(.key == 4) | .values | map(.value) | add // 0' 2>/dev/null || echo "0")
            TOTAL_VXLAN=$(echo "$STATS_JSON" | jq -r 'first(.[] | select(.name == "stats_map")) | .elements[] | select(.key == 5) | .values | map(.value) | add // 0' 2>/dev/null || echo "0")
            TOTAL_NAT=$(echo "$STATS_JSON" | jq -r 'first(.[] | select(.name == "stats_map")) | .elements[] | select(.key == 6) | .values | map(.value) | add // 0' 2>/dev/null || echo "0")
            TOTAL_BYTES=$(echo "$STATS_JSON" | jq -r 'first(.[] | select(.name == "stats_map")) | .elements[] | select(.key == 8) | .values | map(.value) | add // 0' 2>/dev/null || echo "0")
            
            # Format bytes
            if [ "$TOTAL_BYTES" -gt 1073741824 ]; then
                BYTES_FMT=$(echo "$TOTAL_BYTES" | awk '{printf "%.2f GB", $1/1073741824}')
            elif [ "$TOTAL_BYTES" -gt 1048576 ]; then
                BYTES_FMT=$(echo "$TOTAL_BYTES" | awk '{printf "%.2f MB", $1/1048576}')
            elif [ "$TOTAL_BYTES" -gt 1024 ]; then
                BYTES_FMT=$(echo "$TOTAL_BYTES" | awk '{printf "%.2f KB", $1/1024}')
            else
                BYTES_FMT="${TOTAL_BYTES} bytes"
            fi
            
            # Calculate drop rate
            if [ "$TOTAL_RX" -gt 0 ]; then
                DROP_RATE=$(echo "$TOTAL_DROPPED $TOTAL_RX" | awk '{printf "%.3f%%", ($1/$2)*100}')
            else
                DROP_RATE="0.000%"
            fi
            
            echo "┌─────────────────────────────────────────┐"
            echo "│             Packet Counters             │"
            echo "├─────────────────────────────────────────┤"
            echo "│ Total Received:        $(printf "%'d" "$TOTAL_RX" 2>/dev/null || echo "$TOTAL_RX")"
            echo "│ Total Processed:       $(printf "%'d" "$TOTAL_PROCESSED" 2>/dev/null || echo "$TOTAL_PROCESSED")"
            echo "│ Total Dropped:         $(printf "%'d" "$TOTAL_DROPPED" 2>/dev/null || echo "$TOTAL_DROPPED") ($DROP_RATE)"
            echo "│ VXLAN Processed:       $(printf "%'d" "$TOTAL_VXLAN" 2>/dev/null || echo "$TOTAL_VXLAN")"
            echo "│ NAT Applied:           $(printf "%'d" "$TOTAL_NAT" 2>/dev/null || echo "$TOTAL_NAT")"
            echo "│ Total Bytes:           $BYTES_FMT"
            echo "└─────────────────────────────────────────┘"
        else
            echo "No statistics available yet"
        fi
    else
        echo "Stats map not found"
    fi
    
    # Process status
    echo -e "\n${YELLOW}Process Status:${NC}"
    if pgrep -f "vxlan_loader" > /dev/null; then
        VXLAN_PIDS=$(pgrep -f "vxlan_loader" | tr '\n' ' ')
        echo -e "${GREEN}✓ vxlan_loader: Running (PID: ${VXLAN_PIDS%% })${NC}"
    else
        echo -e "${RED}✗ vxlan_loader: Not running${NC}"
    fi
    
    if pgrep -f "packet_injector" > /dev/null; then
        INJECTOR_PIDS=$(pgrep -f "packet_injector" | tr '\n' ' ')
        echo -e "${GREEN}✓ packet_injector: Running (PID: ${INJECTOR_PIDS%% })${NC}"
    else
        echo -e "${RED}✗ packet_injector: Not running${NC}"
    fi
}

# Comprehensive info function with all eBPF details formatted as tables
info() {
    echo -e "${GREEN}XDP VXLAN Pipeline - Debug Information${NC}"
    echo "======================================="
    
    # XDP Programs Summary
    echo -e "\n${YELLOW}=== XDP PROGRAM STATUS ===${NC}"
    XDP_PROGS=$(sudo bpftool prog list 2>/dev/null | grep -c "vxlan_pipeline_main" || echo "0")
    if [ "$XDP_PROGS" -gt "0" ]; then
        echo -e "${GREEN}✓ Active XDP Programs: $XDP_PROGS${NC}"
        
        echo -e "\n┌─────────────────────────────────────────────────────────────────────┐"
        echo -e "│                         XDP Program Details                         │"
        echo -e "├──────┬─────────┬────────────────┬─────────┬──────────┬─────────────┤"
        echo -e "│  ID  │   Tag   │     Size       │  Maps   │   PID    │   Status    │"
        echo -e "├──────┼─────────┼────────────────┼─────────┼──────────┼─────────────┤"
        
        # Parse XDP program details
        sudo bpftool prog list 2>/dev/null | grep "vxlan_pipeline_main" | while read -r line; do
            PROG_ID=$(echo "$line" | awk '{print $1}' | tr -d ':')
            TAG=$(echo "$line" | grep -o 'tag [a-f0-9]*' | cut -d' ' -f2)
            SIZE=$(echo "$line" | grep -o 'xlated [0-9]*B' | cut -d' ' -f2 || echo "N/A")
            
            # Count maps by parsing map_ids
            MAP_IDS_RAW=$(echo "$line" | grep -o 'map_ids [0-9,]*' | cut -d' ' -f2)
            if [ -n "$MAP_IDS_RAW" ]; then
                MAP_COUNT=$(echo "$MAP_IDS_RAW" | tr ',' '\n' | wc -l)
            else
                MAP_COUNT=0
            fi
            
            # Get process info - extract just the process name
            PID_INFO=$(echo "$line" | sed -n 's/.*pids \([^(]*\).*/\1/p' | tr -d ' ' || echo "N/A")
            
            printf "│ %4s │ %7s │ %14s │ %7d │ %8s │ %-11s │\n" \
                "$PROG_ID" "${TAG:0:7}" "${SIZE:-N/A}" "$MAP_COUNT" "${PID_INFO:-N/A}" "Active"
        done
        echo -e "└──────┴─────────┴────────────────┴─────────┴──────────┴─────────────┘"
    else
        echo -e "${RED}✗ No XDP programs loaded${NC}"
    fi
    
    # Network Interface Attachment
    echo -e "\n${YELLOW}=== NETWORK ATTACHMENT ===${NC}"
    ATTACHMENT=$(sudo bpftool net list 2>/dev/null | grep -E '^xdp:|^tc:')
    if [ -n "$ATTACHMENT" ]; then
        echo "$ATTACHMENT"
    else
        echo "No XDP programs attached to interfaces"
    fi
    
    # NAT Rules Table
    echo -e "\n${YELLOW}=== NAT CONFIGURATION ===${NC}"
    
    # Try to get NAT data and check if any maps have elements
    NAT_HAS_DATA=false
    NAT_ENTRIES_FILE=$(mktemp)
    
    sudo bpftool map dump name nat_map 2>/dev/null | jq -r '.[] | select(.elements != null) | select((.elements | length) > 0) | .elements[] | [.key.src_port, .value.target_ip, .value.target_port] | @csv' 2>/dev/null > "$NAT_ENTRIES_FILE"
    
    if [ -s "$NAT_ENTRIES_FILE" ]; then
        NAT_HAS_DATA=true
        NAT_COUNT=$(wc -l < "$NAT_ENTRIES_FILE")
        echo "Active NAT Rules: $NAT_COUNT"
        echo ""
        echo "┌─────────────┬─────────────────┬──────────────┬────────────────────┐"
        echo "│ Source Port │   Target IP     │ Target Port  │      Status        │"
        echo "├─────────────┼─────────────────┼──────────────┼────────────────────┤"
        
        while IFS=',' read -r src_port target_ip_int target_port; do
            # Remove quotes from CSV output
            src_port=$(echo "$src_port" | tr -d '"')
            target_ip_int=$(echo "$target_ip_int" | tr -d '"')
            target_port=$(echo "$target_port" | tr -d '"')
            
            if [ -n "$src_port" ] && [ -n "$target_ip_int" ] && [ -n "$target_port" ]; then
                TARGET_IP=$(int_to_ip "$target_ip_int")
                printf "│    %5d    │ %15s │    %6d    │       Active       │\n" \
                    "$src_port" "$TARGET_IP" "$target_port"
            fi
        done < "$NAT_ENTRIES_FILE"
        echo "└─────────────┴─────────────────┴──────────────┴────────────────────┘"
    fi
    
    rm -f "$NAT_ENTRIES_FILE"
    
    if [ "$NAT_HAS_DATA" = false ]; then
        echo "No NAT rules configured"
    fi
    
    # IP Allowlist Table
    echo -e "\n${YELLOW}=== IP ALLOWLIST ===${NC}"
    IP_DATA=$(sudo bpftool map dump name ip_allowlist 2>/dev/null)
    
    if [ -n "$IP_DATA" ]; then
        # Extract IP entries from any map that has elements
        IP_ENTRIES=$(echo "$IP_DATA" | jq -r '.[] | select(.elements != null and (.elements | length) > 0) | .elements[].key' 2>/dev/null)
        
        if [ -n "$IP_ENTRIES" ]; then
            IP_COUNT=$(echo "$IP_ENTRIES" | wc -l)
            echo "Allowed IP Addresses: $IP_COUNT total"
            echo ""
            echo "┌─────────────────┬────────────────────────────────────────────────┐"
            echo "│   IP Address    │                   Status                       │"
            echo "├─────────────────┼────────────────────────────────────────────────┤"
            
            # Show first 20 IPs to keep output manageable
            echo "$IP_ENTRIES" | head -20 | while read -r ip_int; do
                if [ -n "$ip_int" ]; then
                    IP_ADDR=$(int_to_ip "$ip_int")
                    printf "│ %15s │                    Allowed                     │\n" "$IP_ADDR"
                fi
            done
            
            if [ "$IP_COUNT" -gt 20 ]; then
                printf "│       ...       │              ... (%d more IPs)                │\n" $((IP_COUNT - 20))
            fi
            echo "└─────────────────┴────────────────────────────────────────────────┘"
        else
            echo "No IPs in allowlist"
        fi
    else
        echo "IP allowlist map not accessible"
    fi
    
    # BPF Maps Summary
    echo -e "\n${YELLOW}=== BPF MAPS SUMMARY ===${NC}"
    echo "┌─────────────────┬─────┬──────────┬─────────┬─────────────────────────┐"
    echo "│   Map Name      │ ID  │   Type   │ Elements│         Purpose         │"
    echo "├─────────────────┼─────┼──────────┼─────────┼─────────────────────────┤"
    
    sudo bpftool map list 2>/dev/null | grep -E "(nat_map|stats_map|ip_allowlist|redirect_map|interface_map)" | while read -r line; do
        MAP_ID=$(echo "$line" | awk '{print $1}' | tr -d ':')
        MAP_TYPE=$(echo "$line" | awk '{print $2}')
        MAP_NAME=$(echo "$line" | grep -o 'name [^ ]*' | cut -d' ' -f2)
        
        # Get element count - try different approaches
        if [ "$MAP_TYPE" = "hash" ]; then
            # For hash maps, count actual key-value pairs
            ELEMENTS=$(sudo bpftool map dump id "$MAP_ID" 2>/dev/null | jq -r 'if type == "array" then [.[] | select(.elements != null) | .elements | length] | add // 0 else 0 end' 2>/dev/null || echo "0")
        elif [ "$MAP_TYPE" = "array" ] || [ "$MAP_TYPE" = "percpu_array" ]; then
            # For arrays, count non-zero entries
            ELEMENTS=$(sudo bpftool map dump id "$MAP_ID" 2>/dev/null | jq -r 'if type == "array" then [.[] | select(.elements != null) | .elements | length] | add // 0 else 0 end' 2>/dev/null || echo "0")
        else
            ELEMENTS="0"
        fi
        
        # Set purpose
        case "$MAP_NAME" in
            "nat_map") PURPOSE="NAT rule storage" ;;
            "stats_map") PURPOSE="Packet statistics" ;;
            "ip_allowlist") PURPOSE="IP access control" ;;
            "redirect_map") PURPOSE="Interface redirect" ;;
            "interface_map") PURPOSE="Interface info" ;;
            *) PURPOSE="Unknown" ;;
        esac
        
        printf "│ %-15s │ %3s │ %-8s │ %7s │ %-23s │\n" \
            "$MAP_NAME" "$MAP_ID" "$MAP_TYPE" "$ELEMENTS" "$PURPOSE"
    done
    echo "└─────────────────┴─────┴──────────┴─────────┴─────────────────────────┘"
    
    # Per-CPU Statistics
    echo -e "\n${YELLOW}=== PER-CPU PACKET STATISTICS ===${NC}"
    STATS_DATA=$(sudo bpftool map dump name stats_map 2>/dev/null)
    if [ -n "$STATS_DATA" ]; then
        echo "┌─────┬─────────────┬─────────────┬─────────────┬─────────────┬─────────────┐"
        echo "│ CPU │ RX Packets  │  Processed  │   Dropped   │    VXLAN    │ NAT Applied │"
        echo "├─────┼─────────────┼─────────────┼─────────────┼─────────────┼─────────────┤"
        
        # Get the first stats map that has data
        FIRST_MAP_WITH_DATA=$(echo "$STATS_DATA" | jq -r '[.[] | select(.elements != null and (.elements | length) > 0)] | first | .id' 2>/dev/null)
        
        if [ -n "$FIRST_MAP_WITH_DATA" ] && [ "$FIRST_MAP_WITH_DATA" != "null" ]; then
            for cpu in 0 1 2 3 4 5 6 7; do
                CPU_RX=$(echo "$STATS_DATA" | jq -r ".[] | select(.id == $FIRST_MAP_WITH_DATA) | .elements[] | select(.key == 0) | .values[] | select(.cpu == $cpu) | .value // 0" 2>/dev/null || echo "0")
                CPU_PROC=$(echo "$STATS_DATA" | jq -r ".[] | select(.id == $FIRST_MAP_WITH_DATA) | .elements[] | select(.key == 1) | .values[] | select(.cpu == $cpu) | .value // 0" 2>/dev/null || echo "0")
                CPU_DROP=$(echo "$STATS_DATA" | jq -r ".[] | select(.id == $FIRST_MAP_WITH_DATA) | .elements[] | select(.key == 4) | .values[] | select(.cpu == $cpu) | .value // 0" 2>/dev/null || echo "0")
                CPU_VXLAN=$(echo "$STATS_DATA" | jq -r ".[] | select(.id == $FIRST_MAP_WITH_DATA) | .elements[] | select(.key == 5) | .values[] | select(.cpu == $cpu) | .value // 0" 2>/dev/null || echo "0")
                CPU_NAT=$(echo "$STATS_DATA" | jq -r ".[] | select(.id == $FIRST_MAP_WITH_DATA) | .elements[] | select(.key == 6) | .values[] | select(.cpu == $cpu) | .value // 0" 2>/dev/null || echo "0")
            
                if [ "$CPU_RX" -gt 0 ] || [ "$CPU_PROC" -gt 0 ] || [ "$CPU_DROP" -gt 0 ] || [ "$CPU_VXLAN" -gt 0 ] || [ "$CPU_NAT" -gt 0 ]; then
                    printf "│  %d  │ %11s │ %11s │ %11s │ %11s │ %11s │\n" "$cpu" \
                        "$(printf "%'d" "$CPU_RX" 2>/dev/null || echo "$CPU_RX")" \
                        "$(printf "%'d" "$CPU_PROC" 2>/dev/null || echo "$CPU_PROC")" \
                        "$(printf "%'d" "$CPU_DROP" 2>/dev/null || echo "$CPU_DROP")" \
                        "$(printf "%'d" "$CPU_VXLAN" 2>/dev/null || echo "$CPU_VXLAN")" \
                        "$(printf "%'d" "$CPU_NAT" 2>/dev/null || echo "$CPU_NAT")"
                fi
            done
        fi
        echo "└─────┴─────────────┴─────────────┴─────────────┴─────────────┴─────────────┘"
    else
        echo "No statistics available"
    fi
    
    # Interface Statistics
    echo -e "\n${YELLOW}=== INTERFACE STATISTICS ===${NC}"
    echo "┌─────────────┬─────────────────┬─────────────────┬─────────────────┬─────────────────┐"
    echo "│ Interface   │   RX Packets    │    RX Bytes     │   TX Packets    │    TX Bytes     │"
    echo "├─────────────┼─────────────────┼─────────────────┼─────────────────┼─────────────────┤"
    
    for iface in "$INTERFACE" "$TARGET_INTERFACE"; do
        if [ -f "/sys/class/net/$iface/statistics/rx_packets" ]; then
            RX_PACKETS=$(cat "/sys/class/net/$iface/statistics/rx_packets" 2>/dev/null || echo "0")
            TX_PACKETS=$(cat "/sys/class/net/$iface/statistics/tx_packets" 2>/dev/null || echo "0")
            RX_BYTES=$(cat "/sys/class/net/$iface/statistics/rx_bytes" 2>/dev/null || echo "0")
            TX_BYTES=$(cat "/sys/class/net/$iface/statistics/tx_bytes" 2>/dev/null || echo "0")
            
            # Format bytes in human readable format
            if [ "$RX_BYTES" -gt 1073741824 ]; then
                RX_FMT=$(echo "$RX_BYTES" | awk '{printf "%.1f GB", $1/1073741824}')
            elif [ "$RX_BYTES" -gt 1048576 ]; then
                RX_FMT=$(echo "$RX_BYTES" | awk '{printf "%.1f MB", $1/1048576}')
            else
                RX_FMT=$(echo "$RX_BYTES" | awk '{printf "%.1f KB", $1/1024}')
            fi
            
            if [ "$TX_BYTES" -gt 1073741824 ]; then
                TX_FMT=$(echo "$TX_BYTES" | awk '{printf "%.1f GB", $1/1073741824}')
            elif [ "$TX_BYTES" -gt 1048576 ]; then
                TX_FMT=$(echo "$TX_BYTES" | awk '{printf "%.1f MB", $1/1048576}')
            else
                TX_FMT=$(echo "$TX_BYTES" | awk '{printf "%.1f KB", $1/1024}')
            fi
            
            printf "│ %-11s │ %15s │ %15s │ %15s │ %15s │\n" \
                "$iface" \
                "$(printf "%'d" "$RX_PACKETS" 2>/dev/null || echo "$RX_PACKETS")" \
                "$RX_FMT" \
                "$(printf "%'d" "$TX_PACKETS" 2>/dev/null || echo "$TX_PACKETS")" \
                "$TX_FMT"
        fi
    done
    echo "└─────────────┴─────────────────┴─────────────────┴─────────────────┴─────────────────┘"
    
    # Process Status
    echo -e "\n${YELLOW}=== PROCESS STATUS ===${NC}"
    echo "┌─────────────────┬─────────────┬─────────────────┬────────────────────────┐"
    echo "│    Process      │   Status    │      PID(s)     │        Command         │"
    echo "├─────────────────┼─────────────┼─────────────────┼────────────────────────┤"
    
    # vxlan_loader status
    LOADER_PIDS=$(pgrep -f "vxlan_loader" 2>/dev/null | tr '\n' ',' | sed 's/,$//')
    if [ -n "$LOADER_PIDS" ]; then
        LOADER_CMD=$(ps -p "$(echo "$LOADER_PIDS" | cut -d',' -f1)" -o args= 2>/dev/null | cut -c1-22)
        printf "│ vxlan_loader    │ ${GREEN}%-11s${NC} │ %-15s │ %-22s │\n" "Running" "$LOADER_PIDS" "$LOADER_CMD"
    else
        printf "│ vxlan_loader    │ ${RED}%-11s${NC} │ %-15s │ %-22s │\n" "Stopped" "N/A" "Not running"
    fi
    
    # packet_injector status
    INJECTOR_PIDS=$(pgrep -f "packet_injector" 2>/dev/null | tr '\n' ',' | sed 's/,$//')
    if [ -n "$INJECTOR_PIDS" ]; then
        INJECTOR_CMD=$(ps -p "$(echo "$INJECTOR_PIDS" | cut -d',' -f1)" -o args= 2>/dev/null | cut -c1-22)
        printf "│ packet_injector │ ${GREEN}%-11s${NC} │ %-15s │ %-22s │\n" "Running" "$INJECTOR_PIDS" "$INJECTOR_CMD"
    else
        printf "│ packet_injector │ ${YELLOW}%-11s${NC} │ %-15s │ %-22s │\n" "Stopped" "N/A" "Not running"
    fi
    
    echo "└─────────────────┴─────────────┴─────────────────┴────────────────────────┘"

}

# Test function for end-to-end packet tracing
test() {
    echo -e "${GREEN}XDP VXLAN Pipeline End-to-End Testing${NC}"
    echo "======================================"
    
    # Check if pipeline is running
    XDP_PROGS=$(sudo bpftool prog list 2>/dev/null | grep -c "vxlan_pipeline_main" || echo "0")
    if [ "$XDP_PROGS" -eq "0" ]; then
        echo -e "${RED}✗ XDP pipeline not running. Start with: ./xdp.sh start${NC}"
        return 1
    fi
    
    echo -e "${GREEN}✓ XDP pipeline is running${NC}"
    
    # Create test output directory
    TEST_DIR="/tmp/xdp_test_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$TEST_DIR"
    echo -e "${YELLOW}Test outputs will be saved to: $TEST_DIR${NC}"
    
    # Get baseline statistics
    echo -e "\n${YELLOW}Capturing baseline statistics...${NC}"
    ./xdp.sh stats > "$TEST_DIR/stats_before.txt" 2>/dev/null
    
    # Extract baseline counters for comparison
    BASELINE_RX=$(sudo bpftool map dump name stats_map 2>/dev/null | jq -r 'first(.[] | select(.name == "stats_map")) | .elements[] | select(.key == 0) | .values | map(.value) | add // 0' 2>/dev/null || echo "0")
    BASELINE_VXLAN=$(sudo bpftool map dump name stats_map 2>/dev/null | jq -r 'first(.[] | select(.name == "stats_map")) | .elements[] | select(.key == 5) | .values | map(.value) | add // 0' 2>/dev/null || echo "0")
    BASELINE_NAT=$(sudo bpftool map dump name stats_map 2>/dev/null | jq -r 'first(.[] | select(.name == "stats_map")) | .elements[] | select(.key == 6) | .values | map(.value) | add // 0' 2>/dev/null || echo "0")
    
    echo "Baseline - RX: $BASELINE_RX, VXLAN: $BASELINE_VXLAN, NAT: $BASELINE_NAT"
    
    # Enable debug logging temporarily
    ORIGINAL_DEBUG=$(grep "DEBUG_LEVEL=" .env | cut -d'=' -f2 | tr -d '"')
    echo -e "\n${YELLOW}Enabling debug logging (level 3)...${NC}"
    sed -i 's/DEBUG_LEVEL=".*"/DEBUG_LEVEL="3"/' .env
    
    # Start packet captures
    echo -e "\n${YELLOW}Starting packet captures...${NC}"
    
    # Ingress capture (VXLAN traffic on ens5)
    echo "Capturing ingress VXLAN traffic..."
    sudo tcpdump -i "$INTERFACE" "port 4789" -w "$TEST_DIR/ingress_vxlan.pcap" -c 50 &
    INGRESS_PID=$!
    
    # Egress capture (processed traffic on ens6)  
    echo "Capturing egress traffic..."
    sudo tcpdump -i "$TARGET_INTERFACE" -w "$TEST_DIR/egress.pcap" -c 50 &
    EGRESS_PID=$!
    
    # BPF trace capture
    echo "Starting BPF trace logging..."
    sudo cat /sys/kernel/debug/tracing/trace_pipe | grep -E "(vxlan|nat|trace)" > "$TEST_DIR/bpf_trace.log" &
    TRACE_PID=$!
    
    echo -e "\n${GREEN}✓ Monitoring started${NC}"
    echo "┌─────────────────────────────────────────────────┐"
    echo "│                 LIVE MONITORING                 │"
    echo "├─────────────────────────────────────────────────┤"
    echo "│ Ingress (ens5):    Capturing VXLAN (port 4789) │"
    echo "│ Egress (ens6):     Capturing processed traffic │"  
    echo "│ BPF Traces:        Kernel debug logs           │"
    echo "│ Statistics:        Real-time counters          │"
    echo "└─────────────────────────────────────────────────┘"
    
    # Monitor for specified duration
    TEST_DURATION=30
    echo -e "\n${YELLOW}Monitoring for $TEST_DURATION seconds...${NC}"
    echo "Waiting for real VXLAN packets (you can send traffic now)..."
    
    for i in $(seq 1 $TEST_DURATION); do
        # Show current statistics every 5 seconds
        if [ $((i % 5)) -eq 0 ]; then
            CURRENT_RX=$(sudo bpftool map dump name stats_map 2>/dev/null | jq -r 'first(.[] | select(.name == "stats_map")) | .elements[] | select(.key == 0) | .values | map(.value) | add // 0' 2>/dev/null || echo "0")
            CURRENT_VXLAN=$(sudo bpftool map dump name stats_map 2>/dev/null | jq -r 'first(.[] | select(.name == "stats_map")) | .elements[] | select(.key == 5) | .values | map(.value) | add // 0' 2>/dev/null || echo "0")
            CURRENT_NAT=$(sudo bpftool map dump name stats_map 2>/dev/null | jq -r 'first(.[] | select(.name == "stats_map")) | .elements[] | select(.key == 6) | .values | map(.value) | add // 0' 2>/dev/null || echo "0")
            
            NEW_RX=$((CURRENT_RX - BASELINE_RX))
            NEW_VXLAN=$((CURRENT_VXLAN - BASELINE_VXLAN))
            NEW_NAT=$((CURRENT_NAT - BASELINE_NAT))
            
            printf "\r[%02d/%02d] New packets - RX: %d, VXLAN: %d, NAT: %d" $i $TEST_DURATION $NEW_RX $NEW_VXLAN $NEW_NAT
        else
            printf "\r[%02d/%02d] Monitoring..." $i $TEST_DURATION
        fi
        sleep 1
    done
    
    echo -e "\n\n${YELLOW}Stopping captures...${NC}"
    
    # Stop all captures gracefully
    sudo kill -TERM $INGRESS_PID 2>/dev/null || true
    sudo kill -TERM $EGRESS_PID 2>/dev/null || true  
    sudo kill -TERM $TRACE_PID 2>/dev/null || true
    
    # Wait for captures to finish
    wait $INGRESS_PID 2>/dev/null || true
    wait $EGRESS_PID 2>/dev/null || true
    
    # Get final statistics
    echo "Capturing final statistics..."
    ./xdp.sh stats > "$TEST_DIR/stats_after.txt" 2>/dev/null
    
    # Restore original debug level
    sed -i "s/DEBUG_LEVEL=\".*\"/DEBUG_LEVEL=\"$ORIGINAL_DEBUG\"/" .env
    
    # Analysis and results
    echo -e "\n${GREEN}Test Results Analysis${NC}"
    echo "===================="
    
    # Calculate packet deltas
    FINAL_RX=$(sudo bpftool map dump name stats_map 2>/dev/null | jq -r 'first(.[] | select(.name == "stats_map")) | .elements[] | select(.key == 0) | .values | map(.value) | add // 0' 2>/dev/null || echo "0")
    FINAL_VXLAN=$(sudo bpftool map dump name stats_map 2>/dev/null | jq -r 'first(.[] | select(.name == "stats_map")) | .elements[] | select(.key == 5) | .values | map(.value) | add // 0' 2>/dev/null || echo "0")
    FINAL_NAT=$(sudo bpftool map dump name stats_map 2>/dev/null | jq -r 'first(.[] | select(.name == "stats_map")) | .elements[] | select(.key == 6) | .values | map(.value) | add // 0' 2>/dev/null || echo "0")
    
    TOTAL_NEW_RX=$((FINAL_RX - BASELINE_RX))
    TOTAL_NEW_VXLAN=$((FINAL_VXLAN - BASELINE_VXLAN))
    TOTAL_NEW_NAT=$((FINAL_NAT - BASELINE_NAT))
    
    echo "Packets processed during test:"
    echo "  Total RX:        $TOTAL_NEW_RX packets"
    echo "  VXLAN processed: $TOTAL_NEW_VXLAN packets"
    echo "  NAT applied:     $TOTAL_NEW_NAT packets"
    
    # Check capture files
    echo -e "\nCapture file analysis:"
    if [ -f "$TEST_DIR/ingress_vxlan.pcap" ]; then
        INGRESS_COUNT=$(tcpdump -r "$TEST_DIR/ingress_vxlan.pcap" 2>/dev/null | wc -l)
        echo "  Ingress VXLAN:   $INGRESS_COUNT packets captured"
    fi
    
    if [ -f "$TEST_DIR/egress.pcap" ]; then
        EGRESS_COUNT=$(tcpdump -r "$TEST_DIR/egress.pcap" 2>/dev/null | wc -l)
        echo "  Egress packets:  $EGRESS_COUNT packets captured"
    fi
    
    # Show trace log summary
    if [ -f "$TEST_DIR/bpf_trace.log" ]; then
        TRACE_LINES=$(wc -l < "$TEST_DIR/bpf_trace.log")
        echo "  BPF trace logs:  $TRACE_LINES lines captured"
    fi
    
    echo -e "\n${GREEN}✓ Test completed successfully!${NC}"
    echo -e "${YELLOW}Test outputs saved in: $TEST_DIR${NC}"
    echo ""
    echo "Available files:"
    echo "  • ingress_vxlan.pcap - Raw VXLAN packets from ens5"
    echo "  • egress.pcap       - Processed packets to ens6"
    echo "  • bpf_trace.log     - Kernel BPF debug traces"
    echo "  • stats_before.txt  - Statistics before test"
    echo "  • stats_after.txt   - Statistics after test"
    echo ""
    echo "Analysis commands:"
    echo "  tcpdump -r $TEST_DIR/ingress_vxlan.pcap -vvn"
    echo "  tcpdump -r $TEST_DIR/egress.pcap -vvn"
    echo "  diff $TEST_DIR/stats_before.txt $TEST_DIR/stats_after.txt"
}

# Ensure terminal is fixed on exit
trap fix_terminal EXIT

case "${1:-status}" in
    "start") start ;;
    "stop") stop ;;
    "status") status ;;
    "stats") stats ;;
    "info") info ;;
    "test") test ;;
    "monitor") monitor ;;
    "clean") clean ;;
    "restart") stop; sleep 1; start ;;
    *) echo "Usage: $0 [start|stop|status|stats|info|test|monitor|clean|restart]" ;;
esac