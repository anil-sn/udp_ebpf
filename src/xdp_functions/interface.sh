#!/bin/bash
# XDP Pipeline - Network Interface Operations

# Check if interface exists with improved validation
check_interface_exists() {
    local iface="$1"
    
    if [ -z "$iface" ]; then
        print_color "red" "ERROR: Interface name cannot be empty"
        return 1
    fi
    
    if ! ip link show "$iface" >/dev/null 2>&1; then
        print_color "red" "ERROR: Network interface '$iface' not found"
        return 1
    fi
    
    return 0
}

# Get interface statistics
get_interface_stats() {
    local iface="$1"
    
    if ! check_interface_exists "$iface"; then
        echo "0:0:0:0:0:0:0:0:0:0"
        return 1
    fi
    
    # Read statistics from sysfs
    local rx_packets=$(cat "/sys/class/net/$iface/statistics/rx_packets" 2>/dev/null || echo "0")
    local tx_packets=$(cat "/sys/class/net/$iface/statistics/tx_packets" 2>/dev/null || echo "0")
    local rx_bytes=$(cat "/sys/class/net/$iface/statistics/rx_bytes" 2>/dev/null || echo "0")
    local tx_bytes=$(cat "/sys/class/net/$iface/statistics/tx_bytes" 2>/dev/null || echo "0")
    local rx_dropped=$(cat "/sys/class/net/$iface/statistics/rx_dropped" 2>/dev/null || echo "0")
    local tx_dropped=$(cat "/sys/class/net/$iface/statistics/tx_dropped" 2>/dev/null || echo "0")
    local rx_errors=$(cat "/sys/class/net/$iface/statistics/rx_errors" 2>/dev/null || echo "0")
    local tx_errors=$(cat "/sys/class/net/$iface/statistics/tx_errors" 2>/dev/null || echo "0")
    local rx_missed=$(cat "/sys/class/net/$iface/statistics/rx_missed_errors" 2>/dev/null || echo "0")
    local tx_carrier=$(cat "/sys/class/net/$iface/statistics/tx_carrier_errors" 2>/dev/null || echo "0")
    
    echo "$rx_packets:$tx_packets:$rx_bytes:$tx_bytes:$rx_dropped:$tx_dropped:$rx_errors:$tx_errors:$rx_missed:$tx_carrier"
}

# Enhanced PPS monitoring for three interfaces: incoming, target, and ipsec
monitor_interface_pps() {
    local incoming_iface="${INTERFACE:-ens5}"
    local target_iface="${TARGET_INTERFACE:-tap0}"
    local ipsec_iface="ipsec0"
    local interval="${1:-1}"
    local duration="${2:-0}"  # 0 = infinite
    
    print_color "cyan" "🔍 TRIPLE INTERFACE PPS MONITOR"
    print_color "blue" "Incoming: $incoming_iface | Target: $target_iface | IPSec: $ipsec_iface | Interval: ${interval}s"
    echo ""
    
    # Storage for previous statistics
    local -A prev_stats
    local start_time=$(date +%s)
    local iterations=0
    
    # Initial readings
    local incoming_stats=$(get_interface_stats "$incoming_iface")
    local target_stats=$(get_interface_stats "$target_iface")
    local ipsec_stats=$(get_interface_stats "$ipsec_iface")
    
    prev_stats["incoming_rx"]=$(echo "$incoming_stats" | cut -d: -f1)
    prev_stats["incoming_tx"]=$(echo "$incoming_stats" | cut -d: -f2)
    prev_stats["target_rx"]=$(echo "$target_stats" | cut -d: -f1)
    prev_stats["target_tx"]=$(echo "$target_stats" | cut -d: -f2)
    prev_stats["ipsec_rx"]=$(echo "$ipsec_stats" | cut -d: -f1)
    prev_stats["ipsec_tx"]=$(echo "$ipsec_stats" | cut -d: -f2)
    prev_stats["incoming_rx_dropped"]=$(echo "$incoming_stats" | cut -d: -f5)
    prev_stats["incoming_tx_dropped"]=$(echo "$incoming_stats" | cut -d: -f6)
    prev_stats["target_rx_dropped"]=$(echo "$target_stats" | cut -d: -f5)
    prev_stats["target_tx_dropped"]=$(echo "$target_stats" | cut -d: -f6)
    prev_stats["ipsec_rx_dropped"]=$(echo "$ipsec_stats" | cut -d: -f5)
    prev_stats["ipsec_tx_dropped"]=$(echo "$ipsec_stats" | cut -d: -f6)
    prev_stats["incoming_rx_errors"]=$(echo "$incoming_stats" | cut -d: -f7)
    prev_stats["incoming_tx_errors"]=$(echo "$incoming_stats" | cut -d: -f8)
    prev_stats["target_rx_errors"]=$(echo "$target_stats" | cut -d: -f7)
    prev_stats["target_tx_errors"]=$(echo "$target_stats" | cut -d: -f8)
    prev_stats["ipsec_rx_errors"]=$(echo "$ipsec_stats" | cut -d: -f7)
    prev_stats["ipsec_tx_errors"]=$(echo "$ipsec_stats" | cut -d: -f8)
    prev_stats["incoming_rx_missed"]=$(echo "$incoming_stats" | cut -d: -f9)
    prev_stats["target_rx_missed"]=$(echo "$target_stats" | cut -d: -f9)
    prev_stats["ipsec_rx_missed"]=$(echo "$ipsec_stats" | cut -d: -f9)
    
    # Initialize tracking variables for enhanced monitoring
    local -A max_pps peak_errors total_packets
    local iteration_count=0
    local alert_threshold_pps=5000
    local alert_threshold_errors=1000
    
    # Enhanced header with color coding and statistics
    echo ""
    print_color "cyan" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_color "yellow" "                                    🚀 ENHANCED NETWORK PERFORMANCE MONITOR 🚀"
    print_color "cyan" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    # Interface status summary
    print_color "blue" "📊 INTERFACE OVERVIEW:"
    printf "   %-8s: %s (Input Traffic)\n" "$incoming_iface" "$(print_color 'green' '●') ACTIVE"
    printf "   %-8s: %s (Processed Traffic)\n" "$target_iface" "$(print_color 'green' '●') ACTIVE"  
    printf "   %-8s: %s (IPSec Tunnel)\n" "$ipsec_iface" "$(print_color 'yellow' '●') MONITORING"
    echo ""
    
    # Enhanced table header with visual separators
    print_color "cyan" "┌─────────┬─────────────────────────────────────────────┬─────────────────────────────────────────────┬─────────────────────────────────────────────┐"
    printf "│%-8s │ %-43s │ %-43s │ %-43s │\n" "" "$(print_color 'green' "🔄 $incoming_iface (INGRESS)")" "$(print_color 'blue' "⚡ $target_iface (PROCESSING)")" "$(print_color 'yellow' "🔒 $ipsec_iface (SECURITY)")"
    print_color "cyan" "├─────────┼─────────────────────────────────────────────┼─────────────────────────────────────────────┼─────────────────────────────────────────────┤"
    printf "│%-8s │ %-13s %-13s %-13s │ %-13s %-13s %-13s │ %-13s %-13s %-13s │\n" \
        "TIME" "RX-PPS" "TX-PPS" "ERRORS/s" "RX-PPS" "TX-PPS" "ERRORS/s" "RX-PPS" "TX-PPS" "ERRORS/s"
    print_color "cyan" "├─────────┼─────────────────────────────────────────────┼─────────────────────────────────────────────┼─────────────────────────────────────────────┤"
    
    # Set trap for Ctrl+C
    trap 'print_color "yellow" "\n📊 PPS monitoring stopped"; return 0' INT
    
    while true; do
        sleep "$interval"
        iterations=$((iterations + 1))
        iteration_count=$((iteration_count + 1))
        
        # Get current statistics
        incoming_stats=$(get_interface_stats "$incoming_iface")
        target_stats=$(get_interface_stats "$target_iface")
        ipsec_stats=$(get_interface_stats "$ipsec_iface")
        
        # Parse current values - packets
        local incoming_rx=$(echo "$incoming_stats" | cut -d: -f1)
        local incoming_tx=$(echo "$incoming_stats" | cut -d: -f2)
        local target_rx=$(echo "$target_stats" | cut -d: -f1)
        local target_tx=$(echo "$target_stats" | cut -d: -f2)
        local ipsec_rx=$(echo "$ipsec_stats" | cut -d: -f1)
        local ipsec_tx=$(echo "$ipsec_stats" | cut -d: -f2)
        
        # Parse current values - drops and errors
        local incoming_rx_dropped=$(echo "$incoming_stats" | cut -d: -f5)
        local incoming_tx_dropped=$(echo "$incoming_stats" | cut -d: -f6)
        local target_rx_dropped=$(echo "$target_stats" | cut -d: -f5)
        local target_tx_dropped=$(echo "$target_stats" | cut -d: -f6)
        local ipsec_rx_dropped=$(echo "$ipsec_stats" | cut -d: -f5)
        local ipsec_tx_dropped=$(echo "$ipsec_stats" | cut -d: -f6)
        local incoming_rx_errors=$(echo "$incoming_stats" | cut -d: -f7)
        local incoming_tx_errors=$(echo "$incoming_stats" | cut -d: -f8)
        local target_rx_errors=$(echo "$target_stats" | cut -d: -f7)
        local target_tx_errors=$(echo "$target_stats" | cut -d: -f8)
        local ipsec_rx_errors=$(echo "$ipsec_stats" | cut -d: -f7)
        local ipsec_tx_errors=$(echo "$ipsec_stats" | cut -d: -f8)
        local incoming_rx_missed=$(echo "$incoming_stats" | cut -d: -f9)
        local target_rx_missed=$(echo "$target_stats" | cut -d: -f9)
        local ipsec_rx_missed=$(echo "$ipsec_stats" | cut -d: -f9)
        
        # Calculate PPS
        local incoming_rx_pps=$(( (incoming_rx - prev_stats["incoming_rx"]) / interval ))
        local incoming_tx_pps=$(( (incoming_tx - prev_stats["incoming_tx"]) / interval ))
        local target_rx_pps=$(( (target_rx - prev_stats["target_rx"]) / interval ))
        local target_tx_pps=$(( (target_tx - prev_stats["target_tx"]) / interval ))
        local ipsec_rx_pps=$(( (ipsec_rx - prev_stats["ipsec_rx"]) / interval ))
        local ipsec_tx_pps=$(( (ipsec_tx - prev_stats["ipsec_tx"]) / interval ))
        
        # Calculate Error/Drop rates
        local incoming_err_rate=$(( (incoming_rx_dropped + incoming_tx_dropped + incoming_rx_errors + incoming_tx_errors + incoming_rx_missed - prev_stats["incoming_rx_dropped"] - prev_stats["incoming_tx_dropped"] - prev_stats["incoming_rx_errors"] - prev_stats["incoming_tx_errors"] - prev_stats["incoming_rx_missed"]) / interval ))
        local target_err_rate=$(( (target_rx_dropped + target_tx_dropped + target_rx_errors + target_tx_errors + target_rx_missed - prev_stats["target_rx_dropped"] - prev_stats["target_tx_dropped"] - prev_stats["target_rx_errors"] - prev_stats["target_tx_errors"] - prev_stats["target_rx_missed"]) / interval ))
        local ipsec_err_rate=$(( (ipsec_rx_dropped + ipsec_tx_dropped + ipsec_rx_errors + ipsec_tx_errors + ipsec_rx_missed - prev_stats["ipsec_rx_dropped"] - prev_stats["ipsec_tx_dropped"] - prev_stats["ipsec_rx_errors"] - prev_stats["ipsec_tx_errors"] - prev_stats["ipsec_rx_missed"]) / interval ))
        
        # Track maximums for summary
        [[ $incoming_rx_pps -gt ${max_pps["incoming_rx"]:-0} ]] && max_pps["incoming_rx"]=$incoming_rx_pps
        [[ $target_rx_pps -gt ${max_pps["target_rx"]:-0} ]] && max_pps["target_rx"]=$target_rx_pps
        [[ $ipsec_err_rate -gt ${peak_errors["ipsec"]:-0} ]] && peak_errors["ipsec"]=$ipsec_err_rate
        
        # Color-coded formatting based on thresholds
        local timestamp=$(date +"%H:%M:%S")
        
        # Format PPS with color coding
        local incoming_rx_fmt=$(format_pps_with_color $incoming_rx_pps)
        local incoming_tx_fmt=$(format_pps_with_color $incoming_tx_pps)
        local target_rx_fmt=$(format_pps_with_color $target_rx_pps)
        local target_tx_fmt=$(format_pps_with_color $target_tx_pps)
        local ipsec_rx_fmt=$(format_pps_with_color $ipsec_rx_pps)
        local ipsec_tx_fmt=$(format_pps_with_color $ipsec_tx_pps)
        
        # Format errors with color coding
        local incoming_err_fmt=$(format_errors_with_color $incoming_err_rate)
        local target_err_fmt=$(format_errors_with_color $target_err_rate)
        local ipsec_err_fmt=$(format_errors_with_color $ipsec_err_rate)
        
        # Enhanced display with color coding and status indicators
        printf "│%-8s │ %s %s %s │ %s %s %s │ %s %s %s │\n" \
            "$timestamp" \
            "$(printf "%-13s" "$incoming_rx_fmt")" "$(printf "%-13s" "$incoming_tx_fmt")" "$(printf "%-13s" "$incoming_err_fmt")" \
            "$(printf "%-13s" "$target_rx_fmt")" "$(printf "%-13s" "$target_tx_fmt")" "$(printf "%-13s" "$target_err_fmt")" \
            "$(printf "%-13s" "$ipsec_rx_fmt")" "$(printf "%-13s" "$ipsec_tx_fmt")" "$(printf "%-13s" "$ipsec_err_fmt")"
        
        # Show alert summary every 10 iterations
        if [[ $((iteration_count % 10)) -eq 0 ]]; then
            show_alert_summary $incoming_rx_pps $target_rx_pps $ipsec_err_rate
        fi
        
        # Update previous values - packets
        prev_stats["incoming_rx"]=$incoming_rx
        prev_stats["incoming_tx"]=$incoming_tx
        prev_stats["target_rx"]=$target_rx
        prev_stats["target_tx"]=$target_tx
        prev_stats["ipsec_rx"]=$ipsec_rx
        prev_stats["ipsec_tx"]=$ipsec_tx
        
        # Update previous values - errors and drops
        prev_stats["incoming_rx_dropped"]=$incoming_rx_dropped
        prev_stats["incoming_tx_dropped"]=$incoming_tx_dropped
        prev_stats["target_rx_dropped"]=$target_rx_dropped
        prev_stats["target_tx_dropped"]=$target_tx_dropped
        prev_stats["ipsec_rx_dropped"]=$ipsec_rx_dropped
        prev_stats["ipsec_tx_dropped"]=$ipsec_tx_dropped
        prev_stats["incoming_rx_errors"]=$incoming_rx_errors
        prev_stats["incoming_tx_errors"]=$incoming_tx_errors
        prev_stats["target_rx_errors"]=$target_rx_errors
        prev_stats["target_tx_errors"]=$target_tx_errors
        prev_stats["ipsec_rx_errors"]=$ipsec_rx_errors
        prev_stats["ipsec_tx_errors"]=$ipsec_tx_errors
        prev_stats["incoming_rx_missed"]=$incoming_rx_missed
        prev_stats["target_rx_missed"]=$target_rx_missed
        prev_stats["ipsec_rx_missed"]=$ipsec_rx_missed
        
        # Check duration limit
        if [ "$duration" -gt 0 ]; then
            local elapsed=$(( $(date +%s) - start_time ))
            if [ "$elapsed" -ge "$duration" ]; then
                break
            fi
        fi
    done
    
    print_color "green" "✓ PPS monitoring completed ($iterations samples)"
}

# Single interface PPS monitoring (for individual interface monitoring)
monitor_interface_pps_single() {
    local interface="${1:-ens5}"
    local interval="${2:-1}"
    local duration="${3:-0}"  # 0 = infinite
    
    if ! check_interface_exists "$interface"; then
        print_color "red" "ERROR: Interface $interface does not exist"
        return 1
    fi
    
    print_color "cyan" "📊 SINGLE INTERFACE PPS MONITOR: $interface"
    print_color "blue" "Interval: ${interval}s | Press Ctrl+C to stop"
    echo ""
    
    local prev_rx=0
    local prev_tx=0
    local start_time=$(date +%s)
    local iterations=0
    
    # Initial reading
    local stats=$(get_interface_stats "$interface")
    prev_rx=$(echo "$stats" | cut -d: -f1)
    prev_tx=$(echo "$stats" | cut -d: -f2)
    
    # Header
    printf "%-8s | %-15s | %-15s | %-12s\n" "TIME" "RX PPS" "TX PPS" "TOTAL PPS"
    printf "%-8s | %-15s | %-15s | %-12s\n" "--------" "---------------" "---------------" "------------"
    
    # Set trap for Ctrl+C
    trap 'print_color "yellow" "\n📊 PPS monitoring stopped"; return 0' INT
    
    while true; do
        sleep "$interval"
        iterations=$((iterations + 1))
        
        # Get current statistics
        stats=$(get_interface_stats "$interface")
        local curr_rx=$(echo "$stats" | cut -d: -f1)
        local curr_tx=$(echo "$stats" | cut -d: -f2)
        
        # Calculate PPS
        local rx_pps=$(( (curr_rx - prev_rx) / interval ))
        local tx_pps=$(( (curr_tx - prev_tx) / interval ))
        local total_pps=$((rx_pps + tx_pps))
        
        # Display with color coding
        local timestamp=$(date +"%H:%M:%S")
        if [ "$total_pps" -gt 50000 ]; then
            printf "\033[32m%-8s | %'10d pps | %'10d pps | %'9d pps\033[0m\n" \
                "$timestamp" "$rx_pps" "$tx_pps" "$total_pps"
        elif [ "$total_pps" -gt 10000 ]; then
            printf "\033[33m%-8s | %'10d pps | %'10d pps | %'9d pps\033[0m\n" \
                "$timestamp" "$rx_pps" "$tx_pps" "$total_pps"
        else
            printf "%-8s | %'10d pps | %'10d pps | %'9d pps\n" \
                "$timestamp" "$rx_pps" "$tx_pps" "$total_pps"
        fi
        
        # Update previous values
        prev_rx=$curr_rx
        prev_tx=$curr_tx
        
        # Check duration limit
        if [ "$duration" -gt 0 ]; then
            local elapsed=$(( $(date +%s) - start_time ))
            if [ "$elapsed" -ge "$duration" ]; then
                break
            fi
        fi
    done
    
    print_color "green" "✓ PPS monitoring completed ($iterations samples)"
}

# Configure interface for XDP with enhanced validation
configure_interface() {
    local iface="$1"
    
    if ! check_interface_exists "$iface"; then
        return 1
    fi
    
    print_color "blue" "Configuring interface $iface for XDP..."
    
    # Check if interface is up
    if ! ip link show "$iface" | grep -q "state UP"; then
        print_color "yellow" "WARNING: Interface $iface is down, attempting to bring up..."
        if ! sudo ip link set "$iface" up; then
            print_color "red" "ERROR: Failed to bring up interface $iface"
            return 1
        fi
        sleep 2  # Allow interface to stabilize
    fi
    
    # Set MTU for XDP compatibility (with validation)
    local current_mtu=$(cat "/sys/class/net/$iface/mtu" 2>/dev/null || echo "0")
    local target_mtu=3000
    
    if [ "$current_mtu" -ne "$target_mtu" ]; then
        if sudo ip link set "$iface" mtu "$target_mtu" 2>/dev/null; then
            print_color "green" "  SUCCESS: MTU updated: $current_mtu -> $target_mtu"
        else
            print_color "yellow" "  WARNING: Could not set MTU on $iface (current: $current_mtu)"
        fi
    else
        print_color "green" "  SUCCESS: MTU already optimal ($target_mtu)"
    fi
    
    # Configure queue count for AWS ENA (with current state check)
    local current_queues=$(ethtool -l "$iface" 2>/dev/null | grep "Combined:" | tail -1 | awk '{print $2}' || echo "1")
    local target_queues=4
    
    if [ -n "$current_queues" ] && [ "$current_queues" -ne "$target_queues" ]; then
        if sudo ethtool -L "$iface" combined "$target_queues" 2>/dev/null; then
            print_color "green" "  SUCCESS: Queue config updated: $current_queues -> $target_queues combined"
        else
            print_color "yellow" "  WARNING: Could not configure queues on $iface (keeping $current_queues)"
        fi
    else
        print_color "green" "  SUCCESS: Queue configuration optimal ($current_queues queues)"
    fi
    
    return 0
    
    # Disable offload features for better XDP performance
    sudo ethtool -K "$iface" gro off 2>/dev/null || true
    sudo ethtool -K "$iface" lro off 2>/dev/null || true
    sudo ethtool -K "$iface" gso off 2>/dev/null || true
    
    print_color "green" "✓ Interface $iface configured"
}

# Check interface XDP support
check_xdp_support() {
    local iface="$1"
    
    if ! command -v xdp-loader >/dev/null 2>&1; then
        print_color "yellow" "⚠ xdp-loader not installed, skipping XDP feature check"
        return 0
    fi
    
    local features=$(sudo xdp-loader features "$iface" 2>/dev/null)
    
    if echo "$features" | grep -q "NETDEV_XDP_ACT_BASIC:.*yes"; then
        print_color "green" "✓ Interface $iface supports XDP"
        return 0
    else
        print_color "yellow" "⚠ Interface $iface has limited XDP support"
        echo "$features"
        return 1
    fi
}

# Get interface IP address
get_interface_ip() {
    local iface="$1"
    ip -4 addr show "$iface" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1
}

# Get interface MAC address
get_interface_mac() {
    local iface="$1"
    ip link show "$iface" | grep -oP '(?<=link/ether\s)[0-9a-f:]+' | head -1
}

# Check if XDP is attached to interface
check_xdp_attached() {
    local iface="$1"
    ip link show "$iface" 2>/dev/null | grep -q "xdp"
}

# Reset interface to defaults
reset_interface() {
    local iface="$1"
    
    print_color "blue" "Resetting interface $iface to defaults..."
    
    # Re-enable offload features
    sudo ethtool -K "$iface" gro on 2>/dev/null || true
    sudo ethtool -K "$iface" gso on 2>/dev/null || true
    
    # Reset MTU to default
    sudo ip link set "$iface" mtu 1500 2>/dev/null || true
    
    print_color "green" "✓ Interface $iface reset"
}

# Get interface status
get_interface_status() {
    local iface="$1"
    
    if ! check_interface_exists "$iface"; then
        echo "not_found"
        return 1
    fi
    
    local status=$(cat "/sys/class/net/$iface/operstate" 2>/dev/null || echo "unknown")
    echo "$status"
}

# Display interface information table
show_interface_info() {
    local interfaces=("$@")
    
    echo "┌─────────────┬─────────────────┬─────────────────┬─────────────────┬─────────────────┐"
    echo "│ Interface   │   RX Packets    │    RX Bytes     │   TX Packets    │    TX Bytes     │"
    echo "├─────────────┼─────────────────┼─────────────────┼─────────────────┼─────────────────┤"
    
    for iface in "${interfaces[@]}"; do
        if check_interface_exists "$iface"; then
            local stats=$(get_interface_stats "$iface")
            local rx_packets=$(echo "$stats" | cut -d: -f1)
            local tx_packets=$(echo "$stats" | cut -d: -f2)
            local rx_bytes=$(echo "$stats" | cut -d: -f3)
            local tx_bytes=$(echo "$stats" | cut -d: -f4)
            
            # Format bytes in human readable format
            local rx_fmt=$(format_bytes "$rx_bytes")
            local tx_fmt=$(format_bytes "$tx_bytes")
            
            printf "│ %-11s │ %15s │ %15s │ %15s │ %15s │\n" \
                "$iface" \
                "$(format_number "$rx_packets")" \
                "$rx_fmt" \
                "$(format_number "$tx_packets")" \
                "$tx_fmt"
        else
            printf "│ %-11s │ %15s │ %15s │ %15s │ %15s │\n" \
                "$iface" "Not Found" "N/A" "N/A" "N/A"
        fi
    done
    echo "└─────────────┴─────────────────┴─────────────────┴─────────────────┴─────────────────┘"
}

# Helper function for color-coded PPS formatting
format_pps_with_color() {
    local pps=$1
    if [[ $pps -gt 2000 ]]; then
        print_color 'green' "${pps} pps"
    elif [[ $pps -gt 1000 ]]; then
        print_color 'yellow' "${pps} pps"
    elif [[ $pps -gt 0 ]]; then
        print_color 'white' "${pps} pps"
    else
        print_color 'gray' "${pps} pps"
    fi
}

# Helper function for color-coded error formatting
format_errors_with_color() {
    local errors=$1
    if [[ $errors -gt 2000 ]]; then
        print_color 'red' "🚨 ${errors}"
    elif [[ $errors -gt 1000 ]]; then
        print_color 'yellow' "⚠️  ${errors}"
    elif [[ $errors -gt 0 ]]; then
        print_color 'orange' "${errors} err"
    else
        print_color 'green' "✓ ${errors}"
    fi
}

# Helper function for alert summary
show_alert_summary() {
    local incoming_pps=$1
    local target_pps=$2
    local ipsec_errors=$3
    
    # Show alerts if thresholds exceeded
    if [[ $ipsec_errors -gt 2000 ]]; then
        print_color "red" "├─ 🚨 CRITICAL: IPSec interface showing ${ipsec_errors} errors/sec - Check tunnel status! ─┤"
    elif [[ $incoming_pps -gt 3000 ]] || [[ $target_pps -gt 3000 ]]; then
        print_color "yellow" "├─ ⚡ HIGH LOAD: Traffic exceeding 3K pps - Monitor for saturation ─┤"
    fi
}