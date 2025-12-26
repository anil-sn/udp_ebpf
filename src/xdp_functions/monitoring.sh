#!/bin/bash
# XDP Pipeline - Monitoring Functions

# Show real-time statistics
show_statistics() {
    fix_terminal
    
    print_color "green" "XDP VXLAN Pipeline Statistics"
    echo "=============================="
    
    # Check if pipeline is running
    local prog_count=$(check_bpf_program)
    if [ "$prog_count" -eq 0 ]; then
        print_color "red" "✗ No XDP programs loaded"
        return 1
    fi
    
    print_color "green" "✓ XDP Programs: $prog_count loaded"
    
    # Get and display statistics
    echo ""
    print_color "yellow" "Packet Statistics:"
    
    if sudo bpftool map show name stats_map >/dev/null 2>&1; then
        # Get key statistics
        local total_rx=$(get_statistics "total")
        local total_processed=$(get_statistics "processed")
        local total_dropped=$(get_statistics "dropped")
        local total_vxlan=$(get_statistics "vxlan")
        local total_nat=$(get_statistics "nat")
        local total_bytes=$(get_statistics "bytes")
        
        # Format bytes
        local bytes_fmt=$(format_bytes "$total_bytes")
        
        # Calculate drop rate
        local drop_rate="0.000%"
        if [ "$total_rx" -gt 0 ]; then
            drop_rate=$(echo "$total_dropped $total_rx" | awk '{printf "%.3f%%", ($1/$2)*100}')
        fi
        
        echo "┌─────────────────────────────────────────┐"
        echo "│             Packet Counters             │"
        echo "├─────────────────────────────────────────┤"
        printf "│ Total Received:        %16s │\n" "$(format_number "$total_rx")"
        printf "│ Total Processed:       %16s │\n" "$(format_number "$total_processed")"
        printf "│ Total Dropped:         %16s │\n" "$(format_number "$total_dropped") ($drop_rate)"
        printf "│ VXLAN Processed:       %16s │\n" "$(format_number "$total_vxlan")"
        printf "│ NAT Applied:           %16s │\n" "$(format_number "$total_nat")"
        printf "│ Total Bytes:           %16s │\n" "$bytes_fmt"
        echo "└─────────────────────────────────────────┘"
    else
        print_color "yellow" "Stats map not found"
    fi
    
    # Process status
    echo ""
    print_color "yellow" "Process Status:"
    
    if pgrep -f "vxlan_loader" >/dev/null; then
        local loader_pids=$(pgrep -f "vxlan_loader" | tr '\n' ' ')
        print_color "green" "✓ vxlan_loader: Running (PID: ${loader_pids%% })"
    else
        print_color "red" "✗ vxlan_loader: Not running"
    fi
    
    if pgrep -f "packet_injector" >/dev/null; then
        local injector_pids=$(pgrep -f "packet_injector" | tr '\n' ' ')
        print_color "green" "✓ packet_injector: Running (PID: ${injector_pids%% })"
    else
        print_color "red" "✗ packet_injector: Not running"
    fi
}

# Monitor pipeline in real-time
monitor_pipeline() {
    if ! pgrep -f "vxlan_loader" >/dev/null; then
        print_color "red" "Pipeline not running. Start with: ./xdp.sh start"
        exit 1
    fi
    
    fix_terminal
    clear
    
    print_color "blue" "Live Monitor (Ctrl+C to stop)"
    printf "%-10s | %-10s | %s\n" "TIME" "PPS" "STATUS"
    echo "-----------------------------------"
    
    # Set trap for Ctrl+C
    trap 'fix_terminal; echo; exit 0' INT
    
    local last_rx=""
    
    while true; do
        local rx1=$(cat "/sys/class/net/$INTERFACE/statistics/rx_packets" 2>/dev/null || echo "0")
        sleep 2
        local rx2=$(cat "/sys/class/net/$INTERFACE/statistics/rx_packets" 2>/dev/null || echo "0")
        local pps=$(( (rx2 - rx1) / 2 ))
        local time=$(date +%H:%M:%S)
        
        # Use performance threshold from config
        if [ "$pps" -ge "${TARGET_PPS:-85000}" ]; then
            local color="green"; local stat="OPTIMAL"
        elif [ "$pps" -ge "${PERFORMANCE_THRESHOLD:-60000}" ]; then
            local color="yellow"; local stat="GOOD"
        elif [ "$pps" -gt 0 ]; then
            local color="yellow"; local stat="LOW"
        else
            local color="red"; local stat="IDLE"
        fi
        
        case "$color" in
            "green") printf "%s | \033[0;32m%-10d\033[0m | \033[0;32m%s\033[0m\n" "$time" "$pps" "$stat" ;;
            "yellow") printf "%s | \033[1;33m%-10d\033[0m | \033[1;33m%s\033[0m\n" "$time" "$pps" "$stat" ;;
            "red") printf "%s | \033[0;31m%-10d\033[0m | \033[0;31m%s\033[0m\n" "$time" "$pps" "$stat" ;;
        esac
    done
}

# Show pipeline status
show_pipeline_status() {
    fix_terminal
    clear
    
    print_color "cyan" "--- XDP VXLAN PIPELINE STATUS ---"
    echo ""
    
    # Check vxlan_loader
    local loader_pid=$(pgrep -f "vxlan_loader" | head -1)
    
    if [ -n "$loader_pid" ]; then
        print_color "green" "vxlan_loader: RUNNING (PID: $loader_pid)"
        
        if check_xdp_attached "$INTERFACE"; then
            print_color "green" "XDP Hook:     ATTACHED ($INTERFACE)"
        else
            print_color "red" "XDP Hook:     DETACHED (Error)"
        fi
    else
        print_color "red" "vxlan_loader: STOPPED"
        print_color "red" "XDP Hook:     DETACHED"
    fi
    
    # Check packet_injector
    local injector_pid=$(pgrep -f "packet_injector" | head -1)
    
    if [ -n "$injector_pid" ]; then
        print_color "green" "packet_injector: RUNNING (PID: $injector_pid)"
    else
        print_color "red" "packet_injector: STOPPED"
    fi
    
    if [ -n "$loader_pid" ]; then
        echo ""
        print_color "blue" "Configuration:"
        echo "  Inbound:  $INTERFACE (Port $SOURCE_PORT)"
        echo "  Outbound: $TARGET_INTERFACE -> $NAT_IP:$NAT_PORT"
        
        echo ""
        print_color "blue" "Traffic Load:"
        local rx1=$(cat "/sys/class/net/$INTERFACE/statistics/rx_packets" 2>/dev/null || echo "0")
        sleep 1
        local rx2=$(cat "/sys/class/net/$INTERFACE/statistics/rx_packets" 2>/dev/null || echo "0")
        local pps=$((rx2 - rx1))
        
        if [ "$pps" -gt 0 ]; then
             print_color "green" "  Rate:     $pps pps"
        else
             print_color "yellow" "  Rate:     0 pps (Idle)"
        fi
    else
        print_color "red" "Service:  STOPPED"
        local status_link
        if check_xdp_attached "$INTERFACE"; then
            status_link="ORPHANED"
        else
            status_link="CLEAN"
        fi
        echo "XDP Hook: $status_link"
    fi
    echo ""
}

# Show comprehensive pipeline information - Fixed version
show_detailed_info() {
    fix_terminal
    
    print_color "green" "XDP VXLAN Pipeline - Debug Information"
    echo "======================================="
    
    # XDP Programs Summary
    echo ""
    print_color "yellow" "=== XDP PROGRAM STATUS ==="
    local prog_count=$(check_bpf_program)
    
    if [ "$prog_count" -gt 0 ]; then
        print_color "green" "✓ Active XDP Programs: $prog_count"
        echo ""
        
        echo "┌─────────────────────────────────────────────────────────────────────┐"
        echo "│                         XDP Program Details                         │"
        echo "├──────┬─────────┬────────────────┬─────────┬──────────┬─────────────┤"
        echo "│  ID  │   Tag   │     Size       │  Maps   │   PID    │   Status    │"
        echo "├──────┼─────────┼────────────────┼─────────┼──────────┼─────────────┤"
        
        # Parse XDP program details
        get_bpf_program_details | while IFS= read -r line; do
            local prog_id=$(echo "$line" | awk '{print $1}' | tr -d ':')
            local tag=$(echo "$line" | grep -o 'tag [a-f0-9]*' | cut -d' ' -f2 | head -1)
            
            # Extract size (xlated bytes)
            local size=$(echo "$line" | grep -o 'xlated [0-9]*B' | cut -d' ' -f2 | head -1)
            [ -z "$size" ] && size="N/A"
            
            # Count maps by parsing map_ids
            local map_ids_raw=$(echo "$line" | grep -o 'map_ids [0-9,]*' | cut -d' ' -f2)
            local map_count=0
            if [ -n "$map_ids_raw" ]; then
                map_count=$(echo "$map_ids_raw" | tr ',' '\n' | wc -l)
            fi
            
            # Extract process name from pids line
            local pid_info=$(echo "$line" | grep -o 'pids [^(]*' | cut -d' ' -f2- | head -1)
            if [ -z "$pid_info" ] || [ "$pid_info" = "systemd(1)" ]; then
                pid_info="kernel"
            fi
            
            printf "│ %4s │ %7s │ %14s │ %7d │ %8s │ %-11s │\n" \
                "$prog_id" "${tag:0:7}" "$size" "$map_count" "${pid_info}" "Active"
        done
        echo "└──────┴─────────┴────────────────┴─────────┴──────────┴─────────────┘"
    else
        print_color "red" "✗ No XDP programs loaded"
    fi
    
    # Network Interface Attachment
    echo ""
    print_color "yellow" "=== NETWORK ATTACHMENT ==="
    local attachment=$(get_xdp_attachment "$INTERFACE")
    if [ -n "$attachment" ]; then
        echo "$attachment"
    else
        echo "No XDP programs attached to interfaces"
    fi
    
    # NAT Rules Table
    echo ""
    print_color "yellow" "=== NAT CONFIGURATION ==="
    
    # First check if nat_map exists and has entries
    local nat_map_exists=$(sudo bpftool map show name nat_map 2>/dev/null)
    if [ -z "$nat_map_exists" ]; then
        echo "NAT map not found"
        return
    fi
    
    local nat_entries=$(count_bpf_map_entries "nat_map")
    echo "NAT map entries: $nat_entries"
    
    if [ "$nat_entries" -gt 0 ]; then
        # Try to get formatted rules
        local nat_rules=$(get_nat_rules 2>/dev/null)
        local nat_count=0
        
        if [ -n "$nat_rules" ] && [ "$nat_rules" != "" ]; then
            nat_count=$(echo "$nat_rules" | grep -c "->")
        fi
        
        if [ "$nat_count" -gt 0 ]; then
            echo "Active NAT Rules: $nat_count"
            echo ""
            echo "┌─────────────┬─────────────────┬──────────────┬────────────────────┐"
            echo "│ Source Port │   Target IP     │ Target Port  │      Status        │"
            echo "├─────────────┼─────────────────┼──────────────┼────────────────────┤"
            
            echo "$nat_rules" | while IFS= read -r rule; do
                if [[ "$rule" =~ ([0-9]+)\ -\>\ ([0-9.]+):([0-9]+) ]]; then
                    local src_port="${BASH_REMATCH[1]}"
                    local target_ip="${BASH_REMATCH[2]}"
                    local target_port="${BASH_REMATCH[3]}"
                    printf "│    %5d    │ %15s │    %6d    │       Active       │\n" \
                        "$src_port" "$target_ip" "$target_port"
                fi
            done
            echo "└─────────────┴─────────────────┴──────────────┴────────────────────┘"
        else
            # Debug: Show raw NAT map content for troubleshooting
            echo "NAT rules parsing failed. Debug information:"
            echo ""
            echo "Raw NAT map dump (first few lines):"
            local raw_nat=$(sudo bpftool map dump name nat_map 2>/dev/null | head -10)
            if [ -n "$raw_nat" ]; then
                echo "$raw_nat"
            else
                echo "Failed to dump NAT map"
            fi
            
            echo ""
            echo "JSON NAT map dump (first 500 chars):"
            local json_nat=$(dump_bpf_map "nat_map" "json" 2>/dev/null)
            if [ -n "$json_nat" ]; then
                echo "$json_nat" | cut -c1-500
                if [ ${#json_nat} -gt 500 ]; then
                    echo "... (truncated)"
                fi
            else
                echo "Failed to get JSON dump"
            fi
        fi
    else
        echo "No NAT rules configured (empty map)"
    fi
    
    # IP Allowlist Table
    echo ""
    print_color "yellow" "=== IP ALLOWLIST ==="
    local ip_count=$(get_ip_allowlist_count)
    
    if [ "$ip_count" -gt 0 ]; then
        echo "Allowed IP Addresses: $ip_count total"
        
        # Show sample IPs if available
        local ip_data=$(dump_bpf_map "ip_allowlist" "json")
        if [ -n "$ip_data" ] && command -v jq >/dev/null 2>&1; then
            echo ""
            echo "┌─────────────────┬────────────────────────────────────────────────┐"
            echo "│   IP Address    │                   Status                       │"
            echo "├─────────────────┼────────────────────────────────────────────────┤"
            
            # Show first 15 IPs to keep output manageable - handle multiple maps
            local ip_entries=$(echo "$ip_data" | jq -r 'if (type == "array") then [.[] | select(.elements != null and (.elements | length) > 0) | .elements[].key] else [] end | sort | .[:15] | .[]' 2>/dev/null)
            
            if [ -n "$ip_entries" ]; then
                local displayed_count=0
                echo "$ip_entries" | while read -r ip_int; do
                    if [ -n "$ip_int" ] && [[ "$ip_int" =~ ^[0-9]+$ ]]; then
                        local ip_addr=$(int_to_ip "$ip_int")
                        printf "│ %15s │                    Allowed                     │\n" "$ip_addr"
                        ((displayed_count++))
                        # Break after 15 to avoid too much output
                        [ $displayed_count -ge 15 ] && break
                    fi
                done
                
                if [ "$ip_count" -gt 15 ]; then
                    printf "│       ...       │              ... (%d more IPs)                │\n" $((ip_count - 15))
                fi
            fi
            echo "└─────────────────┴────────────────────────────────────────────────┘"
        fi
    else
        echo "No IPs in allowlist"
    fi
    
    # BPF Maps Summary
    echo ""
    print_color "yellow" "=== BPF MAPS SUMMARY ==="
    echo "┌─────────────────┬─────┬──────────┬─────────┬─────────────────────────┐"
    echo "│   Map Name      │ ID  │   Type   │ Elements│         Purpose         │"
    echo "├─────────────────┼─────┼──────────┼─────────┼─────────────────────────┤"
    
    get_bpf_map_list | while IFS= read -r line; do
        local map_id=$(echo "$line" | awk '{print $1}' | tr -d ':')
        local map_type=$(echo "$line" | awk '{print $2}')
        local map_name=$(echo "$line" | grep -o 'name [^ ]*' | cut -d' ' -f2)
        
        # Get element count
        local elements=$(count_bpf_map_entries "$map_name")
        
        # Set purpose
        local purpose
        case "$map_name" in
            "nat_map") purpose="NAT rule storage" ;;
            "stats_map") purpose="Packet statistics" ;;
            "ip_allowlist") purpose="IP access control" ;;
            "redirect_map") purpose="Interface redirect" ;;
            "interface_map") purpose="Interface info" ;;
            *) purpose="Unknown" ;;
        esac
        
        printf "│ %-15s │ %3s │ %-8s │ %7s │ %-23s │\n" \
            "$map_name" "$map_id" "$map_type" "$elements" "$purpose"
    done
    echo "└─────────────────┴─────┴──────────┴─────────┴─────────────────────────┘"
    
    # Interface Statistics
    echo ""
    print_color "yellow" "=== INTERFACE STATISTICS ==="
    show_interface_info "$INTERFACE" "$TARGET_INTERFACE"
    
    # Process Status
    echo ""
    print_color "yellow" "=== PROCESS STATUS ==="
    echo "┌─────────────────┬─────────────┬─────────────────┬────────────────────────┐"
    echo "│    Process      │   Status    │      PID(s)     │        Command         │"
    echo "├─────────────────┼─────────────┼─────────────────┼────────────────────────┤"
    
    # vxlan_loader status
    local loader_pids=$(pgrep -f "vxlan_loader" 2>/dev/null | tr '\n' ',' | sed 's/,$//')
    if [ -n "$loader_pids" ]; then
        local loader_cmd=$(ps -p "$(echo "$loader_pids" | cut -d',' -f1)" -o args= 2>/dev/null | cut -c1-22)
        printf "│ vxlan_loader    │ \033[0;32m%-11s\033[0m │ %-15s │ %-22s │\n" "Running" "$loader_pids" "$loader_cmd"
    else
        printf "│ vxlan_loader    │ \033[0;31m%-11s\033[0m │ %-15s │ %-22s │\n" "Stopped" "N/A" "Not running"
    fi
    
    # packet_injector status
    local injector_pids=$(pgrep -f "packet_injector" 2>/dev/null | tr '\n' ',' | sed 's/,$//')
    if [ -n "$injector_pids" ]; then
        local injector_cmd=$(ps -p "$(echo "$injector_pids" | cut -d',' -f1)" -o args= 2>/dev/null | cut -c1-22)
        printf "│ packet_injector │ \033[0;32m%-11s\033[0m │ %-15s │ %-22s │\n" "Running" "$injector_pids" "$injector_cmd"
    else
        printf "│ packet_injector │ \033[1;33m%-11s\033[0m │ %-15s │ %-22s │\n" "Stopped" "N/A" "Not running"
    fi
    
    echo "└─────────────────┴─────────────┴─────────────────┴────────────────────────┘"
    
    # Dynamic Scaling Status
    echo ""
    print_color "yellow" "=== DYNAMIC SCALING STATUS ==="
    
    # Source the dynamic scaling script to get scaling status
    if [ -f "$SCRIPT_DIR/xdp_functions/dynamic_scaling.sh" ]; then
        local scaling_status=$("$SCRIPT_DIR/xdp_functions/dynamic_scaling.sh" status 2>/dev/null)
        if [ $? -eq 0 ] && [ -n "$scaling_status" ]; then
            echo "$scaling_status"
        else
            echo "Dynamic scaling information not available"
        fi
    else
        echo "Dynamic scaling module not found"
    fi
}