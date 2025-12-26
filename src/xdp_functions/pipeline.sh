#!/bin/bash
# XDP Pipeline - Main Control Functions

# Start the pipeline
start_pipeline() {
    fix_terminal
    
    print_color "blue" "Starting XDP VXLAN Pipeline..."
    
    # Check if already running
    if pgrep -f "vxlan_loader.*-i.*$INTERFACE" >/dev/null; then
        local pid=$(pgrep -f "vxlan_loader.*-i.*$INTERFACE" | head -1)
        print_color "red" "ERROR: Pipeline already running (PID: $pid)"
        print_color "yellow" "Use './xdp.sh stop' first"
        return 1
    fi
    
    # CRITICAL: Check for existing XDP programs to prevent duplicates
    if ! check_existing_xdp_programs; then
        return 1
    fi
    
    # Clean orphans
    print_color "yellow" "Cleaning any orphaned XDP programs..."
    sudo ip link set "$INTERFACE" xdp off 2>/dev/null || true
    
    # Configure interfaces
    configure_interface "$INTERFACE"
    
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
            # Show the NAT rule details for debugging
            get_nat_rules | head -3
        else
            print_color "red" "✗ NAT map: Empty or missing"
            # Debug: Show available BPF maps for troubleshooting
            print_color "yellow" "Debug: Available BPF maps with 'nat' in name:"
            sudo bpftool map list 2>/dev/null | grep nat || echo "  No nat maps found"
        fi
        
        # Check IP allowlist
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
        if sudo bpftool map show name stats_map >/dev/null 2>&1; then
            print_color "green" "✓ Stats map: Available"
        else
            print_color "red" "✗ Stats map: Missing"
        fi
        
        # Re-enable packet_injector for userspace packet processing
        print_color "blue" "Starting packet injector..."
        
        # packet_injector provides essential userspace packet processing
        # It accesses BPF maps but doesn't load duplicate XDP programs
        if [ -f "vxlan_pipeline.bpf.o" ]; then
            print_color "blue" "Note: packet_injector provides essential userspace packet processing"
            
            # Start packet_injector - uses .bpf.o for map access only
            nohup sudo ./packet_injector vxlan_pipeline.bpf.o "$TARGET_INTERFACE" \
                </dev/null >"/tmp/packet_injector.log" 2>&1 &
            
            # Wait longer for packet_injector startup (needs time to initialize workers, memory pools)
            sleep 5
            
            # Verify packet_injector startup
            if pgrep -f "packet_injector" >/dev/null; then
                local injector_pid=$(pgrep -f "packet_injector" | head -1)
                print_color "green" "✓ Packet injector started (PID: $injector_pid)"
                print_color "green" "Log file: /tmp/packet_injector.log"
            else
                print_color "yellow" "Warning: Packet injector failed to start"
                print_color "yellow" "Check log: cat /tmp/packet_injector.log"
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
    
    # Clean up log files
    rm -f "$LOG_FILE" 2>/dev/null || true
    rm -f "/tmp/packet_injector.log" 2>/dev/null || true
    
    # Reset interface settings
    reset_interface "$INTERFACE" 2>/dev/null || true
    
    fix_terminal
    print_color "green" "Environment Reset - All processes and BPF programs cleaned."
    fix_terminal
}