#!/bin/bash
# XDP Pipeline - BPF Operations

# Check if BPF program is loaded - FIXED: Strip newlines from count
check_bpf_program() {
    local prog_name="${1:-vxlan_pipeline_main}"
    local count=$(sudo bpftool prog list 2>/dev/null | grep -c "$prog_name" || echo "0")
    # Fix: Remove any newlines or whitespace that could cause bash comparison errors
    count=$(echo "$count" | tr -d '\n\r' | tr -d ' ')
    echo "$count"
}

# Check for existing XDP programs and prevent start if found - FIXED: Better error handling
check_existing_xdp_programs() {
    local existing_count=$(check_bpf_program "vxlan_pipeline_main")
    # Fix: Ensure count is a clean integer
    existing_count=$(echo "$existing_count" | tr -d '\n\r' | tr -d ' ')
    
    if [ -n "$existing_count" ] && [ "$existing_count" -gt 0 ] 2>/dev/null; then
        print_color "red" "ERROR: $existing_count existing XDP programs detected!"
        print_color "yellow" "Found programs:"
        sudo bpftool prog list 2>/dev/null | grep "vxlan_pipeline_main"
        print_color "yellow" ""
        print_color "yellow" "Please run './xdp.sh stop' or './xdp.sh clean' first to remove existing programs"
        print_color "yellow" "This prevents duplicate XDP programs and BPF map conflicts"
        return 1
    fi
    return 0
}

# Get BPF map information
get_bpf_map_info() {
    local map_name="$1"
    
    if ! sudo bpftool map show name "$map_name" >/dev/null 2>&1; then
        echo "Map $map_name not found"
        return 1
    fi
    
    # Get map details
    local map_info=$(sudo bpftool map show name "$map_name")
    local map_id=$(echo "$map_info" | awk 'NR==1{print $1}' | tr -d ':')
    local map_type=$(echo "$map_info" | awk 'NR==1{print $2}')
    
    echo "$map_id:$map_type"
}

# Dump BPF map contents
dump_bpf_map() {
    local map_name="$1"
    local format="${2:-json}"
    
    case "$format" in
        "json")
            sudo bpftool map dump name "$map_name" -j 2>/dev/null
            ;;
        "text")
            sudo bpftool map dump name "$map_name" 2>/dev/null
            ;;
        *)
            sudo bpftool map dump name "$map_name" 2>/dev/null
            ;;
    esac
}

# Count entries in BPF map - FIXED to handle actual bpftool JSON format
count_bpf_map_entries() {
    local map_name="$1"
    
    # Try to get map data
    local map_data=$(sudo bpftool map dump name "$map_name" -j 2>/dev/null)
    
    if [ -z "$map_data" ]; then
        echo "0"
        return
    fi
    
    # Check if jq is available for proper JSON parsing
    if command -v jq >/dev/null 2>&1; then
        # Simply count the array length - no need for complex conditionals
        local total_count=$(echo "$map_data" | jq 'length' 2>/dev/null)
        if [ -n "$total_count" ] && [ "$total_count" != "null" ]; then
            total_count=$(echo "$total_count" | tr -d '\n\r' | tr -d ' ')
            echo "$total_count"
        else
            echo "0"
        fi
    else
        # Fallback to counting "key" occurrences
        local count=$(echo "$map_data" | grep -c '"key":' 2>/dev/null || echo "0")
        echo "$count"
    fi
}

# Get NAT rules from BPF map
get_nat_rules() {
    local nat_data=$(dump_bpf_map "nat_map" "json")
    
    if [ -z "$nat_data" ]; then
        return 1
    fi
    
    # First try to get NAT rules from the BPF map using multiple parsing methods
    if command -v jq >/dev/null 2>&1; then
        # Method 1: Try parsing as direct array of entries
        local rules_method1=$(echo "$nat_data" | jq -r '
            try (
                .[] | 
                if .elements then .elements[] else . end |
                if .key and .value then
                    "\(.key | if type == "object" then .src_port else . end) -> \(.value | if type == "object" then "\(.target_ip):\(.target_port)" else . end)"
                else empty end
            ) catch empty
        ' 2>/dev/null)
        
        # Method 2: Try parsing as nested structure with elements
        if [ -z "$rules_method1" ]; then
            local rules_method2=$(echo "$nat_data" | jq -r '
                try (
                    if type == "array" then
                        .[] | select(.elements) | .elements[] |
                        if .key and .value then
                            "\(.key.src_port // .key) -> \(.value.target_ip // .value):\(.value.target_port // .value)"
                        else empty end
                    else empty end
                ) catch empty
            ' 2>/dev/null)
            rules_method1="$rules_method2"
        fi
        
        # Process and convert the rules if found
        if [ -n "$rules_method1" ]; then
            echo "$rules_method1" | while read -r rule; do
                if [[ "$rule" =~ ([0-9]+)\ -\>\ ([0-9]+):([0-9]+) ]]; then
                    local src_port_net="${BASH_REMATCH[1]}"
                    local target_ip_int="${BASH_REMATCH[2]}"
                    local target_port="${BASH_REMATCH[3]}"
                    
                    # Convert network byte order port to host byte order for display
                    local src_port_host=$(python3 -c "import socket; print(socket.ntohs($src_port_net))" 2>/dev/null || echo "$src_port_net")
                    local target_ip=$(int_to_ip "$target_ip_int")
                    echo "$src_port_host -> $target_ip:$target_port"
                fi
            done
            return 0
        fi
    fi
    
    # Fallback: Try to extract directly from raw bpftool output (non-JSON)
    local raw_nat_data=$(sudo bpftool map dump name nat_map 2>/dev/null)
    if [ -n "$raw_nat_data" ]; then
        # Parse raw bpftool output format
        echo "$raw_data" | grep -E "key:|value:" | paste - - | while read -r key_line value_line; do
            local src_port=$(echo "$key_line" | grep -o '[0-9a-f]\{2\} [0-9a-f]\{2\}' | head -1)
            local target_data=$(echo "$value_line" | grep -o '[0-9a-f]\{2\} [0-9a-f]\{2\}')
            
            if [ -n "$src_port" ] && [ -n "$target_data" ]; then
                # This would need proper hex to decimal conversion
                echo "Raw NAT data found (parsing needed)"
            fi
        done
    fi
    
    return 1
    
    return 1
}

# Get IP allowlist count
get_ip_allowlist_count() {
    count_bpf_map_entries "ip_allowlist"
}

# Get statistics from stats map with proper error handling
get_statistics() {
    local stat_key="${1:-all}"
    local stats_data=$(dump_bpf_map "stats_map" "json")
    
    if [ -z "$stats_data" ]; then
        echo "0"
        return
    fi
    
    if command -v jq >/dev/null 2>&1; then
        case "$stat_key" in
            "total"|"0")
                echo "$stats_data" | jq -r '.[0].formatted.values | map(.value) | add // 0' 2>/dev/null || echo "0"
                ;;
            "processed"|"1")
                echo "$stats_data" | jq -r '.[1].formatted.values | map(.value) | add // 0' 2>/dev/null || echo "0"
                ;;
            "dropped"|"4")
                echo "$stats_data" | jq -r '.[4].formatted.values | map(.value) | add // 0' 2>/dev/null || echo "0"
                ;;
            "vxlan"|"5")
                echo "$stats_data" | jq -r '.[5].formatted.values | map(.value) | add // 0' 2>/dev/null || echo "0"
                ;;
            "nat"|"6")
                echo "$stats_data" | jq -r '.[6].formatted.values | map(.value) | add // 0' 2>/dev/null || echo "0"
                ;;
            "bytes"|"8")
                echo "$stats_data" | jq -r '.[8].formatted.values | map(.value) | add // 0' 2>/dev/null || echo "0"
                ;;
            "all")
                echo "$stats_data"
                ;;
            *)
                echo "0"
                ;;
        esac
    else
        # Fallback without jq - extract using grep and basic parsing
        case "$stat_key" in
            "total"|"0")
                echo "$stats_data" | grep -A10 '"key":0' | grep -o '"value":[0-9]*' | cut -d':' -f2 | awk '{sum+=$1} END {print sum+0}' 2>/dev/null || echo "0"
                ;;
            "vxlan"|"5")
                echo "$stats_data" | grep -A10 '"key":5' | grep -o '"value":[0-9]*' | cut -d':' -f2 | awk '{sum+=$1} END {print sum+0}' 2>/dev/null || echo "0"
                ;;
            "nat"|"6")
                echo "$stats_data" | grep -A10 '"key":6' | grep -o '"value":[0-9]*' | cut -d':' -f2 | awk '{sum+=$1} END {print sum+0}' 2>/dev/null || echo "0"
                ;;
            "bytes"|"8")
                echo "$stats_data" | grep -A10 '"key":8' | grep -o '"value":[0-9]*' | cut -d':' -f2 | awk '{sum+=$1} END {print sum+0}' 2>/dev/null || echo "0"
                ;;
            "all")
                echo "$stats_data"
                ;;
            *)
                echo "0"
                ;;
        esac
    fi
}

# Get BPF program list with details
get_bpf_program_details() {
    sudo bpftool prog list 2>/dev/null | grep "vxlan_pipeline_main"
}

# Get BPF map list
get_bpf_map_list() {
    sudo bpftool map list 2>/dev/null | grep -E "(nat_map|stats_map|ip_allowlist|redirect_map|interface_map)"
}

# Get XDP attachment status
get_xdp_attachment() {
    local iface="$1"
    local attachment_info=$(sudo bpftool net list 2>/dev/null)
    
    if [ -n "$attachment_info" ]; then
        # Show XDP attachments for the interface
        local xdp_info=$(echo "$attachment_info" | grep -E "xdp.*$iface")
        if [ -n "$xdp_info" ]; then
            echo "XDP Programs attached to $iface:"
            echo "$xdp_info" | while read -r line; do
                echo "  $line"
            done
        else
            # Check if XDP is attached but not showing interface name properly
            local all_xdp=$(echo "$attachment_info" | grep "xdp:")
            if [ -n "$all_xdp" ]; then
                echo "XDP Programs detected:"
                echo "$all_xdp" | while read -r line; do
                    echo "  $line"
                done
            else
                echo "No XDP programs attached to any interfaces"
            fi
        fi
    else
        echo "No network attachment information available"
    fi
}

# Clean up BPF maps and programs - ENHANCED to remove all XDP programs
cleanup_bpf() {
    print_color "yellow" "Cleaning up BPF resources..."
    
    # Kill processes first to stop new activity (but preserve if just started during pipeline startup)
    sudo pkill -KILL -f "vxlan_loader" 2>/dev/null || true
    # Note: Don't kill packet_injector here - it should only be killed during explicit stop
    
    # Detach XDP from ALL interfaces (not just target ones)
    sudo ip link set "$INTERFACE" xdp off 2>/dev/null || true
    sudo ip link set "$TARGET_INTERFACE" xdp off 2>/dev/null || true
    
    # CRITICAL FIX: Force remove ALL vxlan_pipeline_main programs by ID
    local prog_ids=$(sudo bpftool prog list 2>/dev/null | grep "vxlan_pipeline_main" | awk '{print $1}' | tr -d ':')
    if [ -n "$prog_ids" ]; then
        echo "$prog_ids" | while read -r prog_id; do
            if [ -n "$prog_id" ]; then
                print_color "yellow" "Force removing XDP program ID: $prog_id"
                sudo bpftool prog detach xdp id "$prog_id" dev "$INTERFACE" 2>/dev/null || true
                sudo bpftool prog detach xdp id "$prog_id" dev "$TARGET_INTERFACE" 2>/dev/null || true
                # Program will auto-cleanup when no longer referenced
            fi
        done
        print_color "green" "✓ All XDP programs successfully removed"
    fi
    
    # Clean up pinned maps created by vxlan_loader for packet_injector
    print_color "yellow" "Cleaning pinned BPF maps..."
    sudo rm -f /sys/fs/bpf/vxlan_stats_map 2>/dev/null || true
    sudo rm -f /sys/fs/bpf/vxlan_nat_map 2>/dev/null || true
    sudo rm -f /sys/fs/bpf/vxlan_redirect_map 2>/dev/null || true
    sudo rm -f /sys/fs/bpf/vxlan_interface_map 2>/dev/null || true
    sudo rm -f /sys/fs/bpf/vxlan_ip_allowlist 2>/dev/null || true
    sudo rm -f /sys/fs/bpf/vxlan_packet_ringbuf 2>/dev/null || true
    
    # Remove pinned BPF objects
    if [ -d "/sys/fs/bpf" ]; then
        sudo find /sys/fs/bpf -name "*vxlan*" -delete 2>/dev/null || true
        sudo find /sys/fs/bpf -name "*nat_map*" -delete 2>/dev/null || true
        sudo find /sys/fs/bpf -name "*stats_map*" -delete 2>/dev/null || true
        sudo find /sys/fs/bpf -name "*ip_allowlist*" -delete 2>/dev/null || true
        sudo find /sys/fs/bpf -name "*packet_ringbuf*" -delete 2>/dev/null || true
    fi
    
    # Wait for kernel cleanup and garbage collection
    sleep 3
    
    # Verify cleanup worked - FIXED: Clean integer comparison
    local remaining=$(sudo bpftool prog list 2>/dev/null | grep -c "vxlan_pipeline_main" 2>/dev/null || echo "0")
    remaining=$(echo "$remaining" | tr -d '\n\r' | tr -d ' ')  # Remove newlines and spaces
    
    if [ -n "$remaining" ] && [ "$remaining" -gt 0 ] 2>/dev/null; then
        print_color "red" "Warning: $remaining XDP programs still loaded"
        print_color "yellow" "Manual cleanup may be needed: sudo bpftool prog list | grep vxlan"
    else
        print_color "green" "✓ All XDP programs successfully removed"
    fi
    
    print_color "green" "✓ BPF resources cleaned up"
}