#!/bin/bash
# XDP Pipeline - Main Control Functions

# Start the pipeline with enhanced error handling
start_pipeline() {
    fix_terminal
    
    print_color "blue" "Starting XDP VXLAN Pipeline..."
    
    # Pre-flight checks
    if ! validate_configuration; then
        print_color "red" "ERROR: Configuration validation failed"
        return 1
    fi
    
    # Check if already running
    if pgrep -f "vxlan_loader.*-i.*$INTERFACE" >/dev/null; then
        local pid=$(pgrep -f "vxlan_loader.*-i.*$INTERFACE" | head -1)
        print_color "red" "ERROR: Pipeline already running (PID: $pid)"
        print_color "yellow" "INFO: Use './xdp.sh stop' first"
        return 1
    fi
    
    # CRITICAL: Check for existing XDP programs to prevent duplicates
    if ! check_existing_xdp_programs; then
        return 1
    fi
    
    # Clean orphans with retry mechanism
    print_color "yellow" "Cleaning any orphaned XDP programs..."
    if ! retry_operation 3 1 "XDP cleanup" sudo ip link set "$INTERFACE" xdp off; then
        print_color "yellow" "WARNING: Could not clean XDP programs (may not exist)"
    fi
    
    # Configure interfaces with validation
    if ! configure_interface "$INTERFACE"; then
        print_color "red" "ERROR: Failed to configure interface $INTERFACE"
        return 1
    fi
    
    # FORCE 8 QUEUES FOR MAXIMUM PERFORMANCE (DEFAULT BEHAVIOR)
    print_color "blue" "Configuring network for maximum performance..."
    local current_queues=$(ethtool -l "$INTERFACE" 2>/dev/null | grep "Combined:" | tail -1 | awk '{print $2}')
    local max_queues=$(ethtool -l "$INTERFACE" 2>/dev/null | grep "Combined:" | head -1 | awk '{print $2}')
    
    if [ -n "$current_queues" ] && [ -n "$max_queues" ] && [ "$current_queues" -lt 8 ] && [ "$max_queues" -ge 8 ]; then
        print_color "yellow" "Scaling network queues: $current_queues → 8 (safe method)"
        
        # Use safe method only - never bring interface down to avoid SSH disconnection
        if sudo ethtool -L "$INTERFACE" combined 8 2>/dev/null; then
            print_color "green" "✓ Successfully scaled to 8 queues"
            sleep 1  # Brief pause for queue initialization
        else
            print_color "yellow" "⚠ Queue scaling failed (AWS ENA limitation), continuing with $current_queues queues"
            print_color "blue" "Note: Will still optimize for 8-core packet processing"
        fi
    else
        if [ "$current_queues" -ge 8 ]; then
            print_color "green" "✓ Already using 8 queues"
        else
            print_color "yellow" "⚠ Cannot scale to 8 queues (max available: $max_queues)"
            print_color "blue" "Note: Will still optimize for 8-core packet processing"
        fi
    fi
    
    # Start background process with comprehensive redirection
    print_color "blue" "Launching vxlan_loader..."
    
    # Change to src directory where .bpf.o file is located
    cd "$SCRIPT_DIR" || {
        print_color "red" "Failed to change to src directory"
        return 1
    }
    
    nohup sudo ./vxlan_loader -i "$INTERFACE" -t "$TARGET_INTERFACE" \
        -a "$NAT_IP" -p "$NAT_PORT" -s "$SOURCE_PORT" -I "$STATS_INTERVAL" \
        </dev/null >"$LOG_FILE" 2>&1 &
    
    local loader_pid=$!
    
    # Give time for startup
    sleep 3
    
    # Verify startup with specific pattern match
    if wait_for_process "vxlan_loader.*-i.*$INTERFACE" 5; then
        local new_pid=$(pgrep -f "vxlan_loader.*-i.*$INTERFACE" | head -1)
        print_color "green" "SUCCESS: Pipeline started (PID: $new_pid)"
        print_color "green" "Log file: $LOG_FILE"
        
        # Load IP allowlist after successful pipeline start
        print_color "blue" "Loading IP allowlist..."
        if [ -f "ip_allowlist.json" ]; then
            if sudo python3 load_ip_allowlist.py ip_allowlist.json >/dev/null 2>&1; then
                print_color "green" "IP allowlist loaded successfully"
            else
                print_color "yellow" "Warning: Failed to load IP allowlist"
            fi
        else
            print_color "yellow" "Warning: ip_allowlist.json not found"
        fi
        
        # Allow time for vxlan_loader to fully initialize NAT rules and maps
        print_color "blue" "Waiting for BPF map initialization..."
        sleep 3
        
        # Validate critical BPF maps
        print_color "blue" "Validating BPF maps..."
        
        # Check NAT map
        local nat_entries=$(count_bpf_map_entries "nat_map")
        if [ "$nat_entries" -gt 0 ]; then
            print_color "green" "✓ NAT map: $nat_entries rules loaded"
            # Show the NAT rule details for debugging (simplified to avoid pipe issues)
            local nat_rule=$(get_nat_rules | head -n1)
            if [ -n "$nat_rule" ]; then
                echo "$nat_rule"
            fi
        else
            print_color "red" "✗ NAT map: Empty or missing"
            # Debug: Show available BPF maps for troubleshooting
            print_color "yellow" "Debug: Available BPF maps with 'nat' in name:"
            sudo bpftool map list 2>/dev/null | grep nat || echo "  No nat maps found"
        fi
        
        # Check IP allowlist
        print_color "blue" "Checking IP allowlist..."
        local ip_entries=$(count_bpf_map_entries "ip_allowlist")
        if [ "$ip_entries" -gt 0 ]; then
            print_color "green" "✓ IP allowlist: $ip_entries IPs loaded"
        else
            print_color "red" "✗ IP allowlist: Empty or missing"
            # Debug: Show available BPF maps for troubleshooting
            print_color "yellow" "Debug: Available BPF maps with 'allowlist' in name:"
            sudo bpftool map list 2>/dev/null | grep allowlist || echo "  No allowlist maps found"
        fi
        
        # Check stats map
        print_color "blue" "Checking stats map..."
        if sudo bpftool map show name stats_map >/dev/null 2>&1; then
            print_color "green" "✓ Stats map: Available"
        else
            print_color "red" "✗ Stats map: Missing"
        fi
        
        # Re-enable packet_injector for userspace packet processing
        print_color "blue" "Starting optimized packet injectors..."
        
        # packet_injector provides essential userspace packet processing
        # Start multiple instances for maximum CPU utilization
        if [ -f "vxlan_pipeline.bpf.o" ]; then
            print_color "blue" "Starting 8 packet_injector instances for maximum performance..."
            
            # Kill any existing injectors first
            sudo pkill -f "packet_injector" 2>/dev/null || true
            sleep 1
            
            # Start 8 packet injector instances with CPU affinity
            for ((cpu=0; cpu<8; cpu++)); do
                nohup taskset -c "$cpu" sudo ./packet_injector vxlan_pipeline.bpf.o "$TARGET_INTERFACE" \
                    </dev/null >"/tmp/packet_injector_cpu${cpu}.log" 2>&1 &
                sleep 0.2  # Small delay between starts
            done
            
            # Wait for all injectors to start
            sleep 3
            
            # Verify packet_injector startup and set CPU affinity
            local injector_count=$(pgrep -f "packet_injector.*vxlan_pipeline" | wc -l)
            if [ "$injector_count" -gt 0 ]; then
                print_color "green" "✓ Started $injector_count packet_injector instances"
                
                # Set CPU affinity for worker processes
                local cpu=0
                pgrep -f "packet_injector.*vxlan_pipeline" | while read pid; do
                    sudo taskset -cp "$cpu" "$pid" >/dev/null 2>&1
                    cpu=$(((cpu + 1) % 8))
                done
                
                print_color "green" "✓ CPU affinity optimized for all injector processes"
            else
                print_color "yellow" "Warning: No packet injector processes started"
                print_color "yellow" "Check logs: ls /tmp/packet_injector_cpu*.log"
            fi
        else
            print_color "yellow" "Warning: vxlan_pipeline.bpf.o not found, skipping packet injector"
        fi
        
        sleep 1
        fix_terminal
        return 0
    else
        print_color "red" "ERROR: Failed to start pipeline"
        print_color "yellow" "Check log: cat $LOG_FILE"
        fix_terminal
        return 1
    fi
}

# Stop the pipeline
stop_pipeline() {
    fix_terminal
    
    print_color "blue" "Stopping Pipeline..."
    
    # Kill vxlan_loader process if exists
    if pgrep -f "vxlan_loader" >/dev/null; then
        print_color "yellow" "Stopping vxlan_loader..."
        sudo pkill -TERM -f "vxlan_loader" 2>/dev/null || true
        fix_terminal
        
        # Wait loop
        for i in {1..3}; do
            pgrep -f "vxlan_loader" >/dev/null || break
            sleep 1
        done
        
        # Force kill
        sudo pkill -KILL -f "vxlan_loader" 2>/dev/null || true
        fix_terminal
        print_color "green" "✓ vxlan_loader stopped"
    fi
    
    # Kill packet_injector process if exists
    if pgrep -f "packet_injector" >/dev/null; then
        print_color "yellow" "Stopping packet_injector..."
        sudo pkill -TERM -f "packet_injector" 2>/dev/null || true
        fix_terminal
        
        # Wait loop
        for i in {1..3}; do
            pgrep -f "packet_injector" >/dev/null || break
            sleep 1
        done
        
        # Force kill
        sudo pkill -KILL -f "packet_injector" 2>/dev/null || true
        fix_terminal
        print_color "green" "✓ packet_injector stopped"
    fi
    
    # Clean interface - use xdpgeneric since that's the mode we load in
    sudo ip link set "$INTERFACE" xdpgeneric off 2>/dev/null || true
    
    # Clean up BPF resources
    cleanup_bpf
    
    fix_terminal
    print_color "green" "Stopped and Detached."
    fix_terminal
}

# Clean up pipeline
cleanup_pipeline() {
    fix_terminal
    
    print_color "yellow" "Cleaning up all processes..."
    sudo pkill -KILL -f "vxlan_loader" 2>/dev/null || true
    sudo pkill -KILL -f "packet_injector" 2>/dev/null || true
    fix_terminal
    
    # Comprehensive interface and BPF cleanup
    sudo ip link set "$INTERFACE" xdpgeneric off 2>/dev/null || true
    
    # Complete BPF cleanup
    print_color "yellow" "Performing complete BPF cleanup..."
    cleanup_bpf
    
    # Clear any cgroup BPF programs if attached
    sudo bpftool cgroup list 2>/dev/null | grep -i vxlan | while read -r line; do
        local cgroup_path=$(echo "$line" | awk '{print $1}')
        if [ -n "$cgroup_path" ]; then
            echo "Detaching from cgroup: $cgroup_path"
            sudo bpftool cgroup detach "$cgroup_path" ingress 2>/dev/null || true
            sudo bpftool cgroup detach "$cgroup_path" egress 2>/dev/null || true
        fi
    done 2>/dev/null || true
    
    # Wait for kernel garbage collection
    sleep 3
    
    # Verify cleanup
    local remaining=$(check_bpf_program)
    if [ "$remaining" -eq 0 ]; then
        print_color "green" "✓ All BPF programs cleaned up"
    else
        print_color "yellow" "Warning: $remaining BPF programs may still be loaded"
    fi
    
    print_color "green" "Pipeline cleanup completed"
}

# Enhanced cleanup function with comprehensive resource cleanup  
cleanup_pipeline() {
    fix_terminal
    
    print_color "blue" "Performing comprehensive pipeline cleanup..."
    
    # Stop all processes first
    stop_pipeline
    
    # Clean up BPF maps and programs
    print_color "yellow" "Cleaning BPF resources..."
    
    # Remove pinned maps
    local bpf_fs_maps=("/sys/fs/bpf/vxlan_stats_map" "/sys/fs/bpf/vxlan_nat_map" "/sys/fs/bpf/vxlan_redirect_map")
    for map_path in "${bpf_fs_maps[@]}"; do
        if [ -e "$map_path" ]; then
            sudo rm -f "$map_path" && print_color "green" "  SUCCESS: Removed $map_path"
        fi
    done
    
    # Clean up log files
    print_color "yellow" "Cleaning log files..."
    if [ -f "$LOG_FILE" ]; then
        sudo rm -f "$LOG_FILE" && print_color "green" "  SUCCESS: Removed log file: $LOG_FILE"
    fi
    
    # Clean temporary test directories
    print_color "yellow" "Cleaning temporary files..."
    sudo rm -rf /tmp/xdp_test_* 2>/dev/null && print_color "green" "  SUCCESS: Removed test directories"
    sudo rm -rf /tmp/vxlan_* 2>/dev/null && print_color "green" "  SUCCESS: Removed temporary files"
    
    # Reset interface configurations (optional)
    if [ "${1:-}" = "--reset-interfaces" ]; then
        print_color "yellow" "Resetting interface configurations..."
        reset_interface_config "$INTERFACE"
        reset_interface_config "$TARGET_INTERFACE"
    fi
    
    print_color "green" "Comprehensive cleanup completed"
}

# Reset interface configuration to defaults
reset_interface_config() {
    local iface="$1"
    
    if ! check_interface_exists "$iface" 2>/dev/null; then
        return 0
    fi
    
    print_color "blue" "Resetting configuration for $iface..."
    
    # Reset MTU to default (1500)
    sudo ip link set "$iface" mtu 1500 2>/dev/null && print_color "green" "  SUCCESS: Reset MTU to 1500"
    
    # Reset queue configuration to single queue
    sudo ethtool -L "$iface" combined 1 2>/dev/null && print_color "green" "  SUCCESS: Reset to single queue"
    
    return 0
    # Clean up log files
    rm -f "$LOG_FILE" 2>/dev/null || true
    rm -f "/tmp/packet_injector.log" 2>/dev/null || true
    
    # Reset interface settings
    reset_interface "$INTERFACE" 2>/dev/null || true
    
    fix_terminal
    print_color "green" "Environment Reset - All processes and BPF programs cleaned."
    fix_terminal
}