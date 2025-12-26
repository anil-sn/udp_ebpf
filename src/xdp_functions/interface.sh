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
        echo "0:0:0:0:0:0"
        return 1
    fi
    
    # Read statistics from sysfs
    local rx_packets=$(cat "/sys/class/net/$iface/statistics/rx_packets" 2>/dev/null || echo "0")
    local tx_packets=$(cat "/sys/class/net/$iface/statistics/tx_packets" 2>/dev/null || echo "0")
    local rx_bytes=$(cat "/sys/class/net/$iface/statistics/rx_bytes" 2>/dev/null || echo "0")
    local tx_bytes=$(cat "/sys/class/net/$iface/statistics/tx_bytes" 2>/dev/null || echo "0")
    local rx_dropped=$(cat "/sys/class/net/$iface/statistics/rx_dropped" 2>/dev/null || echo "0")
    local tx_dropped=$(cat "/sys/class/net/$iface/statistics/tx_dropped" 2>/dev/null || echo "0")
    
    echo "$rx_packets:$tx_packets:$rx_bytes:$tx_bytes:$rx_dropped:$tx_dropped"
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