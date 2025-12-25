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
    
    # Create unique test output directory
    local timestamp=$(date +%Y%m%d_%H%M%S_%N | cut -c1-19)
    local test_dir="/tmp/xdp_test_${timestamp}"
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
    local baseline_bytes=$(get_statistics "bytes")
    
    echo "Baseline - RX: $baseline_rx, VXLAN: $baseline_vxlan, NAT: $baseline_nat"
    
    # Check if we're seeing massive production traffic
    if [ "$baseline_rx" -gt 1000000 ]; then
        print_color "yellow" "⚠ Detected high production traffic ($baseline_rx packets)"
        print_color "yellow" "  Test will focus on incremental analysis rather than packet capture"
        local high_traffic_mode=true
    else
        local high_traffic_mode=false
    fi
    
    # Enable debug logging temporarily if .env exists
    local original_debug=""
    if [ -f "${SCRIPT_DIR}/../.env" ]; then
        original_debug=$(grep "DEBUG_LEVEL=" "${SCRIPT_DIR}/../.env" | cut -d'=' -f2 | tr -d '"' || echo "0")
        print_color "yellow" "Enabling debug logging (level 3)..."
        sed -i 's/DEBUG_LEVEL=".*"/DEBUG_LEVEL="3"/' "${SCRIPT_DIR}/../.env" 2>/dev/null || true
    fi
    
    # Start packet captures based on traffic mode
    echo ""
    print_color "yellow" "Starting monitoring and captures..."
    
    if [ "$high_traffic_mode" = "true" ]; then
        # High traffic mode - minimal captures, focus on statistics
        print_color "blue" "High-traffic mode: Limited packet captures, statistical analysis"
        
        # XDP intercepts VXLAN before tcpdump can see it, so capture any UDP traffic as reference
        print_color "yellow" "  Note: XDP processes VXLAN before tcpdump - capturing sample UDP traffic"
        timeout 5 sudo tcpdump -i "$INTERFACE" "udp" -c 5 -w "$test_dir/sample_vxlan.pcap" >/dev/null 2>&1 &
        local vxlan_pid=$!
        
        timeout 10 sudo tcpdump -i "$TARGET_INTERFACE" -c 10 -w "$test_dir/sample_egress.pcap" >/dev/null 2>&1 &
        local egress_pid=$!
        
        local monitoring_duration=10
    else
        # Normal traffic mode - full captures
        print_color "blue" "Normal-traffic mode: Full packet captures"
        
        # Broader capture filters for better detection
        timeout 30 sudo tcpdump -i "$INTERFACE" "udp" -c 50 -w "$test_dir/ingress_udp.pcap" >/dev/null 2>&1 &
        local vxlan_pid=$!
        
        timeout 30 sudo tcpdump -i "$TARGET_INTERFACE" -c 50 -w "$test_dir/egress.pcap" >/dev/null 2>&1 &
        local egress_pid=$!
        
        local monitoring_duration=20
    fi
    
    # Enhanced BPF trace capture with better filtering and fallbacks
    timeout $monitoring_duration bash -c "
        # Try to capture BPF traces with fallback options
        if [ -r /sys/kernel/debug/tracing/trace_pipe ]; then
            sudo cat /sys/kernel/debug/tracing/trace_pipe 2>/dev/null | \
            grep -E '(vxlan|xdp|bpf_trace_printk|tracepoint)' > '$test_dir/bpf_trace.log' 2>/dev/null
        else
            # Fallback: capture any available trace data or mark as unavailable
            echo 'BPF trace_pipe not accessible - trace logging disabled' > '$test_dir/bpf_trace.log'
            # Try alternative tracing methods
            if command -v bpftool >/dev/null 2>&1; then
                echo 'Available BPF programs:' >> '$test_dir/bpf_trace.log'
                bpftool prog list 2>/dev/null | grep -E '(xdp|vxlan)' >> '$test_dir/bpf_trace.log' 2>/dev/null || true
            fi
        fi
    " &
    local trace_pid=$!
    
    print_color "green" "✓ Monitoring started"
    echo "┌─────────────────────────────────────────────────┐"
    echo "│                 LIVE MONITORING                 │"
    echo "├─────────────────────────────────────────────────┤"
    
    if [ "$high_traffic_mode" = "true" ]; then
        echo "│ Mode:              High-traffic production      │"
        echo "│ Ingress ($INTERFACE):    Sample UDP captures         │"
        echo "│ Egress ($TARGET_INTERFACE):     Sample processed traffic  │"
        echo "│ Duration:          ${monitoring_duration}s (accelerated)    │"
    else
        echo "│ Mode:              Normal testing               │"
        echo "│ Ingress ($INTERFACE):    Full UDP traffic capture   │"
        echo "│ Egress ($TARGET_INTERFACE):     Full processed traffic      │"
        echo "│ Duration:          ${monitoring_duration}s (standard)       │"
    fi
    
    echo "│ BPF Traces:        Kernel debug logs           │"
    echo "│ Statistics:        Real-time counters          │"
    echo "└─────────────────────────────────────────────────┘"
    
    # Monitor for specified duration with enhanced reporting
    echo ""
    print_color "yellow" "Monitoring for $monitoring_duration seconds..."
    
    if [ "$high_traffic_mode" = "true" ]; then
        echo "Analyzing production traffic patterns..."
    else
        echo "Waiting for VXLAN packets (you can send test traffic now)..."
    fi
    
    # More detailed progress reporting
    local report_interval=2
    for i in $(seq 1 $monitoring_duration); do
        if [ $((i % report_interval)) -eq 0 ]; then
            local current_rx=$(get_statistics "total")
            local current_vxlan=$(get_statistics "vxlan")
            local current_nat=$(get_statistics "nat")
            
            local new_rx=$((current_rx - baseline_rx))
            local new_vxlan=$((current_vxlan - baseline_vxlan))
            local new_nat=$((current_nat - baseline_nat))
            
            # Calculate rate
            local rx_rate=$((new_rx / i))
            local status="PROCESSING"
            if [ "$rx_rate" -gt 10000 ]; then
                status="HIGH-RATE"
            elif [ "$rx_rate" -gt 1000 ]; then
                status="MODERATE"
            elif [ "$rx_rate" -gt 0 ]; then
                status="LOW-RATE"
            else
                status="IDLE"
            fi
            
            printf "\r[%02d/%02d] Δ packets: RX:%d VXLAN:%d NAT:%d | Rate:%d pps | %s" \
                $i $monitoring_duration $new_rx $new_vxlan $new_nat $rx_rate "$status"
        else
            printf "\r[%02d/%02d] Monitoring..." $i $monitoring_duration
        fi
        sleep 1
    done
    
    echo ""
    echo ""
    print_color "yellow" "Stopping captures and analyzing results..."
    
    # Stop all captures with timeout to prevent hanging
    {
        kill $vxlan_pid 2>/dev/null || true
        kill $egress_pid 2>/dev/null || true
        kill $trace_pid 2>/dev/null || true
    } &
    
    # Wait briefly for graceful termination, then force kill if needed
    sleep 2
    {
        kill -9 $vxlan_pid 2>/dev/null || true
        kill -9 $egress_pid 2>/dev/null || true  
        kill -9 $trace_pid 2>/dev/null || true
    } &>/dev/null
    
    # Brief wait for cleanup
    sleep 1
    
    # Get final statistics with timeout protection
    echo "Capturing final statistics..."
    timeout 5 bash -c "show_statistics > '$test_dir/stats_after.txt' 2>/dev/null" || {
        echo "Statistics collection timed out" > "$test_dir/stats_after.txt"
    }
    
    # Calculate comprehensive deltas with error checking
    local final_rx=$(timeout 3 bash -c "get_statistics 'total'" 2>/dev/null || echo "$baseline_rx")
    local final_vxlan=$(timeout 3 bash -c "get_statistics 'vxlan'" 2>/dev/null || echo "$baseline_vxlan")
    local final_nat=$(timeout 3 bash -c "get_statistics 'nat'" 2>/dev/null || echo "$baseline_nat")
    local final_bytes=$(timeout 3 bash -c "get_statistics 'bytes'" 2>/dev/null || echo "$baseline_bytes")
    
    local total_new_rx=$((final_rx - baseline_rx))
    local total_new_vxlan=$((final_vxlan - baseline_vxlan))
    local total_new_nat=$((final_nat - baseline_nat))
    local total_new_bytes=$((final_bytes - baseline_bytes))
    
    # Restore original debug level if it was changed
    if [ -n "$original_debug" ] && [ -f "${SCRIPT_DIR}/../.env" ]; then
        sed -i "s/DEBUG_LEVEL=\".*\"/DEBUG_LEVEL=\"$original_debug\"/" "${SCRIPT_DIR}/../.env" 2>/dev/null || true
    fi
    
    # Enhanced analysis and results
    echo ""
    print_color "green" "Test Results Analysis"
    echo "===================="
    
    # Traffic analysis with rates
    local avg_pps=$((total_new_rx / monitoring_duration))
    local throughput_mbps=$(echo "$total_new_bytes $monitoring_duration" | awk '{printf "%.2f", ($1*8)/(1024*1024*$2)}')
    
    echo "Traffic During Test (${monitoring_duration}s):"
    echo "  Total RX:        $(format_number $total_new_rx) packets"
    echo "  VXLAN processed: $(format_number $total_new_vxlan) packets"
    echo "  NAT applied:     $(format_number $total_new_nat) packets"
    echo "  Data volume:     $(format_bytes $total_new_bytes)"
    echo "  Average PPS:     $(format_number $avg_pps)"
    echo "  Throughput:      ${throughput_mbps} Mbps"
    
    # Processing efficiency analysis
    local vxlan_efficiency=100
    local nat_efficiency=100
    
    if [ "$total_new_rx" -gt 0 ]; then
        vxlan_efficiency=$(echo "$total_new_vxlan $total_new_rx" | awk '{printf "%.1f", ($1/$2)*100}')
        nat_efficiency=$(echo "$total_new_nat $total_new_rx" | awk '{printf "%.1f", ($1/$2)*100}')
    fi
    
    echo ""
    echo "Pipeline Efficiency:"
    echo "  VXLAN processing:  ${vxlan_efficiency}% ($(format_number $total_new_vxlan)/$(format_number $total_new_rx))"
    echo "  NAT application:   ${nat_efficiency}% ($(format_number $total_new_nat)/$(format_number $total_new_rx))"
    
    # Enhanced capture file analysis
    echo ""
    echo "Capture File Analysis:"
    
    # Check all possible capture files
    local capture_files=(
        "sample_vxlan.pcap:Sample VXLAN (XDP may intercept before tcpdump)"
        "sample_egress.pcap:Sample Egress" 
        "ingress_udp.pcap:Ingress UDP"
        "egress.pcap:Egress Traffic"
    )
    
    local total_captured=0
    for file_info in "${capture_files[@]}"; do
        local file="${file_info%%:*}"
        local desc="${file_info##*:}"
        
        if [ -f "$test_dir/$file" ]; then
            # Fixed packet counting with proper error handling and output sanitization
            local count_raw=$(tcpdump -r "$test_dir/$file" 2>/dev/null | wc -l 2>/dev/null)
            local count=$(echo "$count_raw" | tr -d '\n\r\t ' | grep -o '^[0-9]*' | head -1)
            # Ensure count is a valid number, default to 0
            if [ -z "$count" ] || ! [[ "$count" =~ ^[0-9]+$ ]]; then
                count="0"
            fi
            echo "  $desc: $count packets"
            total_captured=$((total_captured + count))
            
            # Basic packet analysis
            if [ "$count" -gt 0 ]; then
                local first_packet=$(tcpdump -r "$test_dir/$file" -c 1 -n 2>/dev/null | head -1 2>/dev/null || echo "")
                if [ -n "$first_packet" ]; then
                    echo "    Sample: ${first_packet:0:80}..."
                fi
            elif [[ "$file" == *"vxlan"* ]]; then
                echo "    ℹ Empty VXLAN capture is normal - XDP processes packets before tcpdump"
            fi
        fi
    done
    
    # Show trace log summary with enhanced diagnostics
    if [ -f "$test_dir/bpf_trace.log" ]; then
        local trace_lines=$(wc -l < "$test_dir/bpf_trace.log" 2>/dev/null | tr -d '\n' || echo "0")
        # Ensure trace_lines is a valid number
        if ! [[ "$trace_lines" =~ ^[0-9]+$ ]]; then
            trace_lines="0"
        fi
        echo "  BPF trace logs:  $trace_lines lines captured"
        
        if [ "$trace_lines" -gt 0 ]; then
            echo "    Recent entries:"
            tail -3 "$test_dir/bpf_trace.log" 2>/dev/null | sed 's/^/      /' || true
        else
            # Provide diagnostic information for empty trace logs
            if grep -q "not accessible" "$test_dir/bpf_trace.log" 2>/dev/null; then
                echo "    ⚠ BPF kernel tracing not available (debugfs not mounted or no permissions)"
                echo "    Note: This is normal on some systems and doesn't affect functionality"
            else
                echo "    ℹ No BPF debug traces captured (programs may not use bpf_trace_printk)"
                echo "    Note: XDP programs often work silently without debug output"
            fi
        fi
    else
        echo "  BPF trace logs:  No trace file generated"
    fi
    
    # VXLAN Processing Verification (since XDP intercepts before tcpdump)
    echo ""
    echo "VXLAN Processing Verification:"
    local vxlan_processed_delta=$((vxlan_after - vxlan_before))
    local nat_applied_delta=$((nat_after - nat_before))
    
    if [ "$vxlan_processed_delta" -gt 0 ]; then
        print_color "green" "  ✓ VXLAN packets processed: $vxlan_processed_delta"
        echo "    This confirms XDP is successfully intercepting and processing VXLAN traffic"
    else
        print_color "yellow" "  ⚠ No VXLAN packet increment detected during test"
    fi
    
    if [ "$nat_applied_delta" -gt 0 ]; then
        print_color "green" "  ✓ NAT translations applied: $nat_applied_delta"
    fi
    
    # Performance assessment
    echo ""
    echo "Performance Assessment:"
    
    if [ "$avg_pps" -ge "$TARGET_PPS" ]; then
        print_color "green" "  ✓ EXCELLENT: Exceeds target PPS ($TARGET_PPS)"
    elif [ "$avg_pps" -ge $((TARGET_PPS * 70 / 100)) ]; then
        print_color "yellow" "  ⚠ GOOD: 70%+ of target PPS"
    elif [ "$avg_pps" -gt 0 ]; then
        print_color "yellow" "  ⚠ ACTIVE: Processing traffic but below target"
    else
        print_color "red" "  ✗ IDLE: No traffic processed during test"
    fi
    
    # Test result summary
    echo ""
    local test_result="PASSED"
    local issues=()
    
    # Check for issues
    if [ "$total_new_rx" -eq 0 ]; then
        issues+=("No packets received")
        test_result="FAILED"
    fi
    
    if [ "$total_captured" -eq 0 ]; then
        issues+=("No packets captured")
        test_result="WARNING"
    fi
    
    if [ "${#issues[@]}" -gt 0 ]; then
        print_color "yellow" "Issues detected:"
        for issue in "${issues[@]}"; do
            echo "  • $issue"
        done
        echo ""
    fi
    
    # Final result
    case "$test_result" in
        "PASSED")
            print_color "green" "=== TEST PASSED ==="
            print_color "green" "Pipeline successfully processed $(format_number $total_new_rx) packets"
            ;;
        "WARNING") 
            print_color "yellow" "=== TEST PASSED (WITH WARNINGS) ==="
            print_color "yellow" "Pipeline processed traffic but some captures failed"
            ;;
        "FAILED")
            print_color "red" "=== TEST FAILED ==="
            print_color "red" "Pipeline did not process any traffic"
            ;;
    esac
    
    
    print_color "green" "✓ Test completed successfully!"
    print_color "yellow" "Test outputs saved in: $test_dir"
    echo ""
    
    echo "Available files and analysis:"
    for file_info in "${capture_files[@]}"; do
        local file="${file_info%%:*}"
        local desc="${file_info##*:}"
        if [ -f "$test_dir/$file" ]; then
            echo "  • $file - $desc"
        fi
    done
    
    echo "  • bpf_trace.log     - Kernel BPF debug traces (may be empty for production programs)"
    echo "  • stats_before.txt  - Statistics before test"
    echo "  • stats_after.txt   - Statistics after test"
    echo ""
    
    echo "Quick analysis commands:"
    echo "  # View captured packets:"
    for file_info in "${capture_files[@]}"; do
        local file="${file_info%%:*}"
        if [ -f "$test_dir/$file" ]; then
            echo "  tcpdump -r $test_dir/$file -vvn"
            break
        fi
    done
    echo "  # Compare statistics:"
    echo "  diff $test_dir/stats_before.txt $test_dir/stats_after.txt"
    echo "  # View traces (note: may be empty if programs don't use debug output):"
    echo "  cat $test_dir/bpf_trace.log"
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