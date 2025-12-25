#!/bin/bash
# XDP Pipeline - Testing Functions

# Run end-to-end test
run_end_to_end_test() {
    fix_terminal
    
    print_color "green" "XDP VXLAN Pipeline End-to-End Testing"
    echo "======================================"
    
    # Check if pipeline is running
    local prog_count=$(check_bpf_program)
    if [ "$prog_count" -eq 0 ]; then
        print_color "red" "✗ XDP pipeline not running. Start with: ./xdp.sh start"
        return 1
    fi
    
    print_color "green" "✓ XDP pipeline is running"
    
    # Create test output directory
    local test_dir="/tmp/xdp_test_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$test_dir"
    print_color "yellow" "Test outputs will be saved to: $test_dir"
    
    # Get baseline statistics
    echo ""
    print_color "yellow" "Capturing baseline statistics..."
    show_statistics > "$test_dir/stats_before.txt" 2>/dev/null
    
    # Extract baseline counters for comparison
    local baseline_rx=$(get_statistics "total")
    local baseline_vxlan=$(get_statistics "vxlan")
    local baseline_nat=$(get_statistics "nat")
    
    echo "Baseline - RX: $baseline_rx, VXLAN: $baseline_vxlan, NAT: $baseline_nat"
    
    # Enable debug logging temporarily if .env exists
    local original_debug=""
    if [ -f "${SCRIPT_DIR}/../.env" ]; then
        original_debug=$(grep "DEBUG_LEVEL=" "${SCRIPT_DIR}/../.env" | cut -d'=' -f2 | tr -d '"' || echo "0")
        print_color "yellow" "Enabling debug logging (level 3)..."
        sed -i 's/DEBUG_LEVEL=".*"/DEBUG_LEVEL="3"/' "${SCRIPT_DIR}/../.env" 2>/dev/null || true
    fi
    
    # Start packet captures
    echo ""
    print_color "yellow" "Starting packet captures..."
    
    # Ingress capture (VXLAN traffic)
    echo "Capturing ingress VXLAN traffic..."
    timeout 30 sudo tcpdump -i "$INTERFACE" "port 4789" -w "$test_dir/ingress_vxlan.pcap" -c 50 >/dev/null 2>&1 &
    local ingress_pid=$!
    
    # Egress capture (processed traffic)
    echo "Capturing egress traffic..."
    timeout 30 sudo tcpdump -i "$TARGET_INTERFACE" -w "$test_dir/egress.pcap" -c 50 >/dev/null 2>&1 &
    local egress_pid=$!
    
    # BPF trace capture
    echo "Starting BPF trace logging..."
    timeout 30 bash -c "sudo cat /sys/kernel/debug/tracing/trace_pipe 2>/dev/null | grep -E '(vxlan|nat|trace)' > '$test_dir/bpf_trace.log'" &
    local trace_pid=$!
    
    print_color "green" "✓ Monitoring started"
    echo "┌─────────────────────────────────────────────────┐"
    echo "│                 LIVE MONITORING                 │"
    echo "├─────────────────────────────────────────────────┤"
    echo "│ Ingress ($INTERFACE):    Capturing VXLAN (port 4789) │"
    echo "│ Egress ($TARGET_INTERFACE):     Capturing processed traffic │"
    echo "│ BPF Traces:        Kernel debug logs           │"
    echo "│ Statistics:        Real-time counters          │"
    echo "└─────────────────────────────────────────────────┘"
    
    # Monitor for specified duration
    local test_duration=30
    echo ""
    print_color "yellow" "Monitoring for $test_duration seconds..."
    echo "Waiting for real VXLAN packets (you can send traffic now)..."
    
    for i in $(seq 1 $test_duration); do
        # Show current statistics every 5 seconds
        if [ $((i % 5)) -eq 0 ]; then
            local current_rx=$(get_statistics "total")
            local current_vxlan=$(get_statistics "vxlan")
            local current_nat=$(get_statistics "nat")
            
            local new_rx=$((current_rx - baseline_rx))
            local new_vxlan=$((current_vxlan - baseline_vxlan))
            local new_nat=$((current_nat - baseline_nat))
            
            printf "\r[%02d/%02d] New packets - RX: %d, VXLAN: %d, NAT: %d" $i $test_duration $new_rx $new_vxlan $new_nat
        else
            printf "\r[%02d/%02d] Monitoring..." $i $test_duration
        fi
        sleep 1
    done
    
    echo ""
    echo ""
    print_color "yellow" "Stopping captures..."
    
    # Stop all captures gracefully
    kill $ingress_pid 2>/dev/null || true
    kill $egress_pid 2>/dev/null || true
    kill $trace_pid 2>/dev/null || true
    
    # Wait for captures to finish
    wait $ingress_pid 2>/dev/null || true
    wait $egress_pid 2>/dev/null || true
    wait $trace_pid 2>/dev/null || true
    
    # Get final statistics
    echo "Capturing final statistics..."
    show_statistics > "$test_dir/stats_after.txt" 2>/dev/null
    
    # Restore original debug level
    if [ -n "$original_debug" ] && [ -f "${SCRIPT_DIR}/../.env" ]; then
        sed -i "s/DEBUG_LEVEL=\".*\"/DEBUG_LEVEL=\"$original_debug\"/" "${SCRIPT_DIR}/../.env" 2>/dev/null || true
    fi
    
    # Analysis and results
    echo ""
    print_color "green" "Test Results Analysis"
    echo "===================="
    
    # Calculate packet deltas
    local final_rx=$(get_statistics "total")
    local final_vxlan=$(get_statistics "vxlan")
    local final_nat=$(get_statistics "nat")
    
    local total_new_rx=$((final_rx - baseline_rx))
    local total_new_vxlan=$((final_vxlan - baseline_vxlan))
    local total_new_nat=$((final_nat - baseline_nat))
    
    echo "Packets processed during test:"
    echo "  Total RX:        $total_new_rx packets"
    echo "  VXLAN processed: $total_new_vxlan packets"
    echo "  NAT applied:     $total_new_nat packets"
    
    # Check capture files
    echo ""
    echo "Capture file analysis:"
    if [ -f "$test_dir/ingress_vxlan.pcap" ]; then
        local ingress_count=$(tcpdump -r "$test_dir/ingress_vxlan.pcap" 2>/dev/null | wc -l || echo "0")
        echo "  Ingress VXLAN:   $ingress_count packets captured"
    fi
    
    if [ -f "$test_dir/egress.pcap" ]; then
        local egress_count=$(tcpdump -r "$test_dir/egress.pcap" 2>/dev/null | wc -l || echo "0")
        echo "  Egress packets:  $egress_count packets captured"
    fi
    
    # Show trace log summary
    if [ -f "$test_dir/bpf_trace.log" ]; then
        local trace_lines=$(wc -l < "$test_dir/bpf_trace.log" 2>/dev/null || echo "0")
        echo "  BPF trace logs:  $trace_lines lines captured"
    fi
    
    print_color "green" "✓ Test completed successfully!"
    print_color "yellow" "Test outputs saved in: $test_dir"
    echo ""
    echo "Available files:"
    echo "  • ingress_vxlan.pcap - Raw VXLAN packets from $INTERFACE"
    echo "  • egress.pcap       - Processed packets to $TARGET_INTERFACE"
    echo "  • bpf_trace.log     - Kernel BPF debug traces"
    echo "  • stats_before.txt  - Statistics before test"
    echo "  • stats_after.txt   - Statistics after test"
    echo ""
    echo "Analysis commands:"
    echo "  tcpdump -r $test_dir/ingress_vxlan.pcap -vvn"
    echo "  tcpdump -r $test_dir/egress.pcap -vvn"
    echo "  diff $test_dir/stats_before.txt $test_dir/stats_after.txt"
}

# Quick health check
quick_health_check() {
    print_color "cyan" "=== Quick Health Check ==="
    
    local checks_passed=0
    local checks_total=4
    
    # Check 1: BPF programs
    if [ "$(check_bpf_program)" -gt 0 ]; then
        print_color "green" "✓ BPF programs loaded"
        checks_passed=$((checks_passed + 1))
    else
        print_color "red" "✗ No BPF programs"
    fi
    
    # Check 2: Processes running
    if pgrep -f "vxlan_loader" >/dev/null; then
        print_color "green" "✓ vxlan_loader running"
        checks_passed=$((checks_passed + 1))
    else
        print_color "red" "✗ vxlan_loader not running"
    fi
    
    # Check 3: Interface XDP attachment
    if check_xdp_attached "$INTERFACE"; then
        print_color "green" "✓ XDP attached to $INTERFACE"
        checks_passed=$((checks_passed + 1))
    else
        print_color "red" "✗ XDP not attached to $INTERFACE"
    fi
    
    # Check 4: Packet processing
    local current_rx=$(get_statistics "total")
    if [ "$current_rx" -gt 0 ]; then
        print_color "green" "✓ Packets being processed: $current_rx"
        checks_passed=$((checks_passed + 1))
    else
        print_color "yellow" "⚠ No packets processed yet"
    fi
    
    echo ""
    
    # Summary
    if [ "$checks_passed" -eq "$checks_total" ]; then
        print_color "green" "Health check: PASSED ($checks_passed/$checks_total)"
        return 0
    elif [ "$checks_passed" -ge 2 ]; then
        print_color "yellow" "Health check: PARTIAL ($checks_passed/$checks_total)"
        return 1
    else
        print_color "red" "Health check: FAILED ($checks_passed/$checks_total)"
        return 1
    fi
}

# Performance benchmark test
performance_benchmark() {
    print_color "cyan" "=== Performance Benchmark ==="
    
    if ! pgrep -f "vxlan_loader" >/dev/null; then
        print_color "red" "Pipeline not running. Start with: ./xdp.sh start"
        return 1
    fi
    
    local duration="${1:-60}"
    print_color "blue" "Running $duration second benchmark..."
    
    # Collect baseline
    local baseline_rx=$(get_statistics "total")
    local baseline_time=$(date +%s)
    
    # Wait for measurement period
    sleep "$duration"
    
    # Collect final measurements
    local final_rx=$(get_statistics "total")
    local final_time=$(date +%s)
    
    # Calculate results
    local packets_processed=$((final_rx - baseline_rx))
    local time_elapsed=$((final_time - baseline_time))
    local avg_pps=$((packets_processed / time_elapsed))
    
    echo "Benchmark Results:"
    echo "  Duration:         ${time_elapsed}s"
    echo "  Packets:          $(format_number $packets_processed)"
    echo "  Average PPS:      $(format_number $avg_pps)"
    echo "  Target PPS:       $(format_number $TARGET_PPS)"
    
    # Performance assessment
    if [ "$avg_pps" -ge "$TARGET_PPS" ]; then
        print_color "green" "Performance: EXCELLENT (Target met)"
    elif [ "$avg_pps" -ge $((TARGET_PPS * 80 / 100)) ]; then
        print_color "yellow" "Performance: GOOD (80% of target)"
    elif [ "$avg_pps" -ge $((TARGET_PPS * 50 / 100)) ]; then
        print_color "yellow" "Performance: MODERATE (50% of target)"
    else
        print_color "red" "Performance: POOR (Below 50% of target)"
    fi
}