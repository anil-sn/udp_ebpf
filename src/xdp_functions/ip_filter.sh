#!/bin/bash
# IP Filtering Control Functions

enable_ip_filtering() {
    print_color "blue" "Enabling IP allowlist filtering..."
    
    # Check if BPF program is loaded
    if ! bpftool map show name ip_filter_config >/dev/null 2>&1; then
        print_color "red" "✗ XDP program not loaded. Please start pipeline first."
        return 1
    fi
    
    # Set config flag to 1 (enabled)
    if bpftool map update name ip_filter_config key hex 00 00 00 00 value hex 01; then
        print_color "green" "✓ IP filtering ENABLED"
        echo "  - Only IPs in allowlist will be allowed through"
        
        # Show current allowlist size
        local count=$(bpftool map dump name ip_allowlist 2>/dev/null | grep -c "key" || echo "0")
        echo "  - Current allowlist contains: $count IPs"
        
        if [ "$count" -eq 0 ]; then
            print_color "yellow" "⚠ Warning: Allowlist is empty - all packets will be dropped"
            echo "    Use: ./xdp.sh ips reload  # to load IPs from JSON"
        fi
    else
        print_color "red" "✗ Failed to enable IP filtering"
        return 1
    fi
}

disable_ip_filtering() {
    print_color "blue" "Disabling IP allowlist filtering..."
    
    # Check if BPF program is loaded
    if ! bpftool map show name ip_filter_config >/dev/null 2>&1; then
        print_color "red" "✗ XDP program not loaded. Please start pipeline first."
        return 1
    fi
    
    # Set config flag to 0 (disabled)
    if bpftool map update name ip_filter_config key hex 00 00 00 00 value hex 00; then
        print_color "green" "✓ IP filtering DISABLED"
        echo "  - All IP addresses will be allowed through"
        echo "  - Allowlist is ignored but preserved"
    else
        print_color "red" "✗ Failed to disable IP filtering"
        return 1
    fi
}

show_ip_filtering_status() {
    print_color "blue" "=== IP Filtering Status ==="
    
    # Check if BPF program is loaded
    if ! bpftool map show name ip_filter_config >/dev/null 2>&1; then
        print_color "red" "Status: NOT AVAILABLE"
        echo "  - XDP program not loaded"
        echo "  - Run './xdp.sh start' to load pipeline"
        return 1
    fi
    
    # Get current config value
    local status_output=$(bpftool map lookup name ip_filter_config key hex 00 00 00 00 2>/dev/null)
    local status=$(echo "$status_output" | grep -o "value.*" | grep -o "[0-9a-f][0-9a-f]" | tail -1)
    
    if [ "$status" = "01" ]; then
        print_color "green" "Status: ENABLED ✓"
        echo "  - IP allowlist filtering is ACTIVE"
        echo "  - Only allowlisted IPs can pass through"
        
        # Show allowlist statistics
        local count=$(bpftool map dump name ip_allowlist 2>/dev/null | grep -c "key" || echo "0")
        echo "  - Allowlist size: $count IPs"
        
        # Show recent statistics
        if command -v python3 >/dev/null 2>&1 && [ -f "src/xdp_functions/analyze_stats.py" ]; then
            echo "  - Recent allowlist activity:"
            python3 src/xdp_functions/analyze_stats.py --compact 2>/dev/null | grep -E "(Allowlist|IP)" || echo "    (no recent activity data)"
        fi
        
        if [ "$count" -eq 0 ]; then
            print_color "yellow" "  ⚠ WARNING: Allowlist is empty - all packets will be DROPPED"
        fi
        
    elif [ "$status" = "00" ]; then
        print_color "yellow" "Status: DISABLED"
        echo "  - IP filtering is INACTIVE"  
        echo "  - ALL IP addresses are allowed through"
        echo "  - Allowlist is preserved but ignored"
        
        local count=$(bpftool map dump name ip_allowlist 2>/dev/null | grep -c "key" || echo "0")
        echo "  - Allowlist size (ignored): $count IPs"
        
    else
        print_color "red" "Status: UNKNOWN/ERROR"
        echo "  - Unable to determine filtering status"
        echo "  - Raw status: $status"
        return 1
    fi
    
    # Show control commands
    echo ""
    echo "Control commands:"
    echo "  ./xdp.sh filter enable     # Enable IP filtering"
    echo "  ./xdp.sh filter disable    # Disable IP filtering"
    echo "  ./xdp.sh ips reload        # Reload allowlist from JSON"
}

initialize_ip_filter_config() {
    print_color "blue" "Initializing IP filter configuration..."
    
    # Default to enabled for backward compatibility
    bpftool map update name ip_filter_config key hex 00 00 00 00 value hex 01 2>/dev/null
    
    if [ $? -eq 0 ]; then
        print_color "green" "✓ IP filtering initialized (default: ENABLED)"
    else
        print_color "yellow" "⚠ Could not initialize IP filter config (will use BPF program default)"
    fi
}