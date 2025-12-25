#!/bin/bash
# XDP Pipeline - BPF Operations

# Check if BPF program is loaded
check_bpf_program() {
    local prog_name="${1:-vxlan_pipeline_main}"
    local count=$(sudo bpftool prog list 2>/dev/null | grep -c "$prog_name" || echo "0")
    echo "$count"
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

# Count entries in BPF map - Fixed to handle multiple maps with same name
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
        # Count entries across ALL maps with this name (sum all non-empty maps)
        local total_count=$(echo "$map_data" | jq -r 'if (type == "array") then [.[] | select(.elements != null and (.elements | length) > 0) | .elements | length] | add // 0 else 0 end' 2>/dev/null || echo "0")
        echo "$total_count"
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
    
    # Parse JSON output using jq if available - fixed to handle multiple maps
    if command -v jq >/dev/null 2>&1; then
        # Check if any map has entries (handle multiple maps with same name)
        local has_entries=$(echo "$nat_data" | jq -r 'if (type == "array") then ([.[] | select(.elements != null and (.elements | length) > 0)] | length > 0) else false end' 2>/dev/null)
        
        if [ "$has_entries" = "true" ]; then
            # Get entries from all maps that have data, format as "src_port -> target_ip:target_port"
            echo "$nat_data" | jq -r '.[] | select(.elements != null and (.elements | length) > 0) | .elements[] | (.key.src_port // .key) as $src | (.value.target_ip // 0) as $ip | (.value.target_port // .value) as $port | "\($src) -> \($ip):\($port)"' 2>/dev/null
            return 0
        fi
    else
        fi
    else
        # Fallback to text parsing - extract individual components
        local src_ports=$(echo "$nat_data" | grep -o '"src_port":[0-9]*' | cut -d':' -f2)
        local target_ips=$(echo "$nat_data" | grep -o '"target_ip":[0-9]*' | cut -d':' -f2)
        local target_ports=$(echo "$nat_data" | grep -o '"target_port":[0-9]*' | cut -d':' -f2)
        
        if [ -n "$src_ports" ]; then
            paste <(echo "$src_ports") <(echo "$target_ips") <(echo "$target_ports") | while read -r src_port target_ip_int target_port; do
                if [ -n "$src_port" ] && [ -n "$target_ip_int" ] && [ -n "$target_port" ]; then
                    local target_ip=$(int_to_ip "$target_ip_int")
                    echo "$src_port -> $target_ip:$target_port"
                fi
            done
        fi
    fi
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
                echo "$stats_data" | jq -r 'if (type == "array" and length > 0 and .[0].elements != null) then ([.[0].elements[] | select(.key == 0) | .values[] | .value] | add // 0) else 0 end' 2>/dev/null || echo "0"
                ;;
            "processed"|"1")
                echo "$stats_data" | jq -r 'if (type == "array" and length > 0 and .[0].elements != null) then ([.[0].elements[] | select(.key == 1) | .values[] | .value] | add // 0) else 0 end' 2>/dev/null || echo "0"
                ;;
            "dropped"|"4")
                echo "$stats_data" | jq -r 'if (type == "array" and length > 0 and .[0].elements != null) then ([.[0].elements[] | select(.key == 4) | .values[] | .value] | add // 0) else 0 end' 2>/dev/null || echo "0"
                ;;
            "vxlan"|"5")
                echo "$stats_data" | jq -r 'if (type == "array" and length > 0 and .[0].elements != null) then ([.[0].elements[] | select(.key == 5) | .values[] | .value] | add // 0) else 0 end' 2>/dev/null || echo "0"
                ;;
            "nat"|"6")
                echo "$stats_data" | jq -r 'if (type == "array" and length > 0 and .[0].elements != null) then ([.[0].elements[] | select(.key == 6) | .values[] | .value] | add // 0) else 0 end' 2>/dev/null || echo "0"
                ;;
            "bytes"|"8")
                echo "$stats_data" | jq -r 'if (type == "array" and length > 0 and .[0].elements != null) then ([.[0].elements[] | select(.key == 8) | .values[] | .value] | add // 0) else 0 end' 2>/dev/null || echo "0"
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
    sudo bpftool net list 2>/dev/null | grep -E "^xdp:" | grep "$iface"
}

# Clean up BPF maps and programs
cleanup_bpf() {
    print_color "yellow" "Cleaning up BPF resources..."
    
    # Detach XDP from interfaces
    sudo ip link set "$INTERFACE" xdp off 2>/dev/null || true
    sudo ip link set "$TARGET_INTERFACE" xdp off 2>/dev/null || true
    
    # Remove pinned BPF objects
    if [ -d "/sys/fs/bpf" ]; then
        sudo find /sys/fs/bpf -name "*vxlan*" -delete 2>/dev/null || true
        sudo find /sys/fs/bpf -name "*nat_map*" -delete 2>/dev/null || true
        sudo find /sys/fs/bpf -name "*stats_map*" -delete 2>/dev/null || true
        sudo find /sys/fs/bpf -name "*ip_allowlist*" -delete 2>/dev/null || true
        sudo find /sys/fs/bpf -name "*packet_ringbuf*" -delete 2>/dev/null || true
    fi
    
    # Kill any remaining processes
    sudo pkill -KILL -f "vxlan_loader" 2>/dev/null || true
    sudo pkill -KILL -f "packet_injector" 2>/dev/null || true
    
    # Wait for kernel cleanup
    sleep 2
    
    print_color "green" "✓ BPF resources cleaned up"
}