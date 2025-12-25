#!/bin/bash
# XDP Pipeline - Network Interface Operations

# Check if interface exists
check_interface_exists() {
    local iface="$1"
    ip link show "$iface" >/dev/null 2>&1
    return $?
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

# Configure interface for XDP
configure_interface() {
    local iface="$1"
    
    print_color "blue" "Configuring interface $iface for XDP..."
    
    # Set MTU for XDP compatibility
    if sudo ip link set "$iface" mtu 3000 2>/dev/null; then
        print_color "green" "  ✓ MTU set to 3000"
    else
        print_color "yellow" "  ⚠ Could not set MTU on $iface"
    fi
    
    # Configure queue count for AWS ENA
    if sudo ethtool -L "$iface" combined 4 2>/dev/null; then
        print_color "green" "  ✓ Queues configured (4 combined)"
    else
        print_color "yellow" "  ⚠ Could not configure queues on $iface"
    fi
    
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