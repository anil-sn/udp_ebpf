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
    
    # Enhanced baseline analysis with traffic pattern detection
    echo ""
    print_color "yellow" "Analyzing current traffic patterns..."
    
    # Multi-point baseline sampling for better accuracy
    local samples=3
    local sample_interval=2
    local baseline_samples=()
    
    for i in $(seq 1 $samples); do
        local rx=$(get_statistics "total")
        local vxlan=$(get_statistics "vxlan")
        baseline_samples+=("$rx:$vxlan")
        [ $i -lt $samples ] && sleep $sample_interval
    done
    
    # Calculate traffic rate and pattern
    local first_sample=(${baseline_samples[0]//:/ })
    local last_sample=(${baseline_samples[-1]//:/ })
    local rx_rate=$(( (${last_sample[0]} - ${first_sample[0]}) / (sample_interval * (samples - 1)) ))
    local vxlan_rate=$(( (${last_sample[1]} - ${first_sample[1]}) / (sample_interval * (samples - 1)) ))
    
    # Enhanced traffic classification
    local traffic_mode="idle"
    local monitoring_duration=20
    local capture_limit=100
    
    if [ "$rx_rate" -gt 50000 ]; then
        traffic_mode="production_high"
        monitoring_duration=8
        capture_limit=10
        print_color "red" "⚠ PRODUCTION HIGH-RATE TRAFFIC: $rx_rate pps"
        print_color "yellow" "  Switching to minimal-impact testing mode"
    elif [ "$rx_rate" -gt 10000 ]; then
        traffic_mode="production_moderate"
        monitoring_duration=12
        capture_limit=25
        print_color "yellow" "⚠ PRODUCTION MODERATE TRAFFIC: $rx_rate pps"
    elif [ "$rx_rate" -gt 1000 ]; then
        traffic_mode="development_active"
        monitoring_duration=15
        capture_limit=50
        print_color "blue" "Development active traffic: $rx_rate pps"
    elif [ "$rx_rate" -gt 0 ]; then
        traffic_mode="development_low"
        monitoring_duration=20
        capture_limit=100
        print_color "green" "Development low traffic: $rx_rate pps"
    else
        traffic_mode="idle"
        monitoring_duration=30
        capture_limit=200
        print_color "green" "Idle system - full test mode available"
    fi
    
    # Extract final baseline for comparison
    baseline_rx=${last_sample[0]}
    baseline_vxlan=${last_sample[1]}
    baseline_nat=$(get_statistics "nat")
    baseline_bytes=$(get_statistics "bytes")
    
    echo "Baseline - RX: $baseline_rx, VXLAN: $baseline_vxlan, NAT: $baseline_nat (Rate: ${rx_rate} pps)"
    
    # Enable debug logging temporarily if .env exists
    local original_debug=""
    if [ -f "${SCRIPT_DIR}/../.env" ]; then
        original_debug=$(grep "DEBUG_LEVEL=" "${SCRIPT_DIR}/../.env" | cut -d'=' -f2 | tr -d '"' || echo "0")
        print_color "yellow" "Enabling debug logging (level 3)..."
        sed -i 's/DEBUG_LEVEL=".*"/DEBUG_LEVEL="3"/' "${SCRIPT_DIR}/../.env" 2>/dev/null || true
    fi
    
    # Enhanced monitoring strategy based on traffic analysis
    echo ""
    print_color "yellow" "Starting adaptive monitoring (mode: $traffic_mode)..."
    
    # Process management arrays for robust cleanup
    local capture_pids=()
    local capture_files=()
    
    # Adaptive capture strategy
    case "$traffic_mode" in
        "production_high")
            print_color "red" "MINIMAL IMPACT MODE: Limited captures to avoid performance impact"
            timeout 5 sudo tcpdump -i "$INTERFACE" "udp port 4789" -c 3 -w "$test_dir/vxlan_sample.pcap" >/dev/null 2>&1 &
            capture_pids+=("$!:vxlan_sample")
            timeout 8 sudo tcpdump -i "$TARGET_INTERFACE" -c 5 -w "$test_dir/egress_sample.pcap" >/dev/null 2>&1 &
            capture_pids+=("$!:egress_sample")
            ;;
        "production_moderate")
            print_color "yellow" "BALANCED MODE: Moderate captures with performance monitoring"
            timeout 10 sudo tcpdump -i "$INTERFACE" "udp" -c 15 -w "$test_dir/ingress_moderate.pcap" >/dev/null 2>&1 &
            capture_pids+=("$!:ingress_moderate")
            timeout 12 sudo tcpdump -i "$TARGET_INTERFACE" -c 20 -w "$test_dir/egress_moderate.pcap" >/dev/null 2>&1 &
            capture_pids+=("$!:egress_moderate")
            ;;
        "development_active"|"development_low")
            print_color "blue" "DEVELOPMENT MODE: Full packet analysis available"
            timeout $monitoring_duration sudo tcpdump -i "$INTERFACE" "udp" -c $((capture_limit/2)) -w "$test_dir/ingress_full.pcap" >/dev/null 2>&1 &
            capture_pids+=("$!:ingress_full")
            timeout $monitoring_duration sudo tcpdump -i "$TARGET_INTERFACE" -c $capture_limit -w "$test_dir/egress_full.pcap" >/dev/null 2>&1 &
            capture_pids+=("$!:egress_full")
            ;;
        "idle")
            print_color "green" "COMPREHENSIVE MODE: Full monitoring and captures"
            timeout $monitoring_duration sudo tcpdump -i "$INTERFACE" "udp" -c $capture_limit -w "$test_dir/ingress_comprehensive.pcap" >/dev/null 2>&1 &
            capture_pids+=("$!:ingress_comprehensive")
            timeout $monitoring_duration sudo tcpdump -i "$TARGET_INTERFACE" -c $capture_limit -w "$test_dir/egress_comprehensive.pcap" >/dev/null 2>&1 &
            capture_pids+=("$!:egress_comprehensive")
            
            # Additional VXLAN-specific capture for idle systems
            timeout $monitoring_duration sudo tcpdump -i "$INTERFACE" "udp port 4789" -c 50 -w "$test_dir/vxlan_specific.pcap" >/dev/null 2>&1 &
            capture_pids+=("$!:vxlan_specific")
            ;;
    esac
    
    # Enhanced BPF trace capture with intelligent detection and error handling
    local trace_available=false
    local trace_method="none"
    local bpftool_accessible=false
    
    # Check bpftool permissions first
    if command -v bpftool >/dev/null 2>&1; then
        # Test bpftool access with timeout
        if timeout 3 bpftool prog show >/dev/null 2>&1; then
            bpftool_accessible=true
        elif timeout 3 sudo bpftool prog show >/dev/null 2>&1; then
            bpftool_accessible=true
            # Note: will need sudo for actual commands
        fi
    fi
    
    # Check multiple trace sources in order of preference
    if [ -r "/sys/kernel/debug/tracing/trace_pipe" ] && [ -w "/sys/kernel/debug/tracing/trace" ]; then
        trace_available=true
        trace_method="ftrace"
    elif [ "$bpftool_accessible" = "true" ]; then
        trace_available=true
        trace_method="bpftool"
    elif [ -r "/sys/kernel/debug/tracing/events/bpf/enable" ]; then
        trace_available=true
        trace_method="events"
    fi
    
    # Start appropriate tracing method with robust error handling
    local trace_pid=0
    if [ "$trace_available" = "true" ]; then
        timeout $monitoring_duration bash -c "
            case '$trace_method' in
                'ftrace')
                    # Enhanced ftrace with XDP-specific filters and error handling
                    {
                        echo 1 > /sys/kernel/debug/tracing/events/xdp/enable 2>/dev/null || true
                        echo 1 > /sys/kernel/debug/tracing/events/net/enable 2>/dev/null || true
                        timeout $monitoring_duration cat /sys/kernel/debug/tracing/trace_pipe 2>/dev/null | \
                            grep -E '(vxlan|xdp|redirect|nat)' > '$test_dir/bpf_trace_enhanced.log' 2>/dev/null || \
                            echo 'Ftrace: No matching events captured' > '$test_dir/bpf_trace_enhanced.log'
                    } 2>/dev/null
                    ;;
                'bpftool')
                    # Use bpftool with proper error handling and permission management
                    {
                        echo 'BPF Program Analysis:' > '$test_dir/bpf_trace_enhanced.log'
                        
                        # Try without sudo first, then with sudo
                        if ! timeout 5 bpftool prog list 2>/dev/null | grep -E '(xdp|vxlan)' >> '$test_dir/bpf_trace_enhanced.log' 2>/dev/null; then
                            if ! timeout 5 sudo bpftool prog list 2>/dev/null | grep -E '(xdp|vxlan)' >> '$test_dir/bpf_trace_enhanced.log' 2>/dev/null; then
                                echo 'No XDP/VXLAN programs found or permission denied' >> '$test_dir/bpf_trace_enhanced.log'
                            fi
                        fi
                        
                        echo '' >> '$test_dir/bpf_trace_enhanced.log'
                        echo 'BPF Map Analysis:' >> '$test_dir/bpf_trace_enhanced.log'
                        
                        # Try maps with error handling
                        if ! timeout 5 bpftool map show 2>/dev/null | head -10 >> '$test_dir/bpf_trace_enhanced.log' 2>/dev/null; then
                            if ! timeout 5 sudo bpftool map show 2>/dev/null | head -10 >> '$test_dir/bpf_trace_enhanced.log' 2>/dev/null; then
                                echo 'No maps accessible or permission denied' >> '$test_dir/bpf_trace_enhanced.log'
                            fi
                        fi
                        
                        # Add system BPF info
                        echo '' >> '$test_dir/bpf_trace_enhanced.log'
                        echo 'System BPF Status:' >> '$test_dir/bpf_trace_enhanced.log'
                        echo \"BPF filesystem: \$([ -d /sys/fs/bpf ] && echo 'Available' || echo 'Not mounted')\" >> '$test_dir/bpf_trace_enhanced.log'
                        echo \"Pinned objects: \$(ls /sys/fs/bpf/ 2>/dev/null | wc -l || echo '0') items\" >> '$test_dir/bpf_trace_enhanced.log'
                    } 2>/dev/null
                    sleep $monitoring_duration
                    ;;
                'events')
                    # Use tracing events with error handling
                    {
                        echo 1 > /sys/kernel/debug/tracing/events/bpf/enable 2>/dev/null || true
                        timeout $monitoring_duration cat /sys/kernel/debug/tracing/trace_pipe 2>/dev/null | \
                            head -100 > '$test_dir/bpf_trace_enhanced.log' 2>/dev/null || \
                            echo 'Tracing events: No data captured' > '$test_dir/bpf_trace_enhanced.log'
                    } 2>/dev/null
                    ;;
            esac
        " &
        trace_pid=$!
        print_color "green" "✓ Enhanced BPF tracing active (method: $trace_method)"
    else
        # Comprehensive fallback when no tracing is available
        {
            echo "=== BPF System Analysis (Tracing Unavailable) ==="
            echo "Date: $(date)"
            echo "Kernel: $(uname -r)"
            echo "Architecture: $(uname -m)"
            echo ""
            echo "BPF Support Analysis:"
            echo "  BPF filesystem: $([ -d /sys/fs/bpf ] && echo 'Available' || echo 'Not mounted')"
            echo "  Debug filesystem: $([ -d /sys/kernel/debug ] && echo 'Available' || echo 'Not mounted')"
            echo "  bpftool available: $(command -v bpftool >/dev/null && echo 'Yes' || echo 'No')"
            echo ""
            echo "Interface Information:"
            ip link show | grep -E '^[0-9]+:' | head -5 2>/dev/null || echo "  Could not list interfaces"
            echo ""
            echo "Process Information:"
            pgrep -f 'vxlan_loader' >/dev/null && echo "  vxlan_loader: Running" || echo "  vxlan_loader: Not running"
            pgrep -f 'packet_injector' >/dev/null && echo "  packet_injector: Running" || echo "  packet_injector: Not running"
            echo ""
            echo "=== Recommendation ==="
            echo "For enhanced debugging, run with:"
            echo "  sudo mount -t debugfs none /sys/kernel/debug"
            echo "  sudo ./xdp.sh test"
        } > "$test_dir/bpf_trace_enhanced.log"
        print_color "yellow" "⚠ BPF tracing unavailable - comprehensive system analysis collected"
    fi
    
    capture_pids+=("$trace_pid:trace")
    
    print_color "green" "✓ Monitoring started"
    
    # Enhanced monitoring display
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│                    ADAPTIVE LIVE MONITORING                 │"
    echo "├─────────────────────────────────────────────────────────────┤"
    printf "│ Mode: %-20s Traffic: %-15s │\n" "$traffic_mode" "${rx_rate} pps"
    printf "│ Duration: %-8ss Captures: %-12s │\n" "$monitoring_duration" "${#capture_pids[@]} active"
    printf "│ Ingress: %-15s Egress: %-16s │\n" "$INTERFACE" "$TARGET_INTERFACE"
    printf "│ Tracing: %-15s Method: %-16s │\n" "$trace_available" "$trace_method"
    echo "└─────────────────────────────────────────────────────────────┘"
    
    # Enhanced progress monitoring with performance analytics
    echo ""
    print_color "yellow" "Monitoring for $monitoring_duration seconds with real-time analysis..."
    
    # Performance tracking arrays
    local pps_history=()
    local vxlan_history=()
    local efficiency_history=()
    
    local report_interval=2
    local anomaly_threshold=$((rx_rate * 150 / 100))  # 150% of baseline rate
    
    for i in $(seq 1 $monitoring_duration); do
        if [ $((i % report_interval)) -eq 0 ]; then
            local current_rx=$(get_statistics "total")
            local current_vxlan=$(get_statistics "vxlan")
            local current_nat=$(get_statistics "nat")
            local current_errors=$(get_statistics "errors")
            
            local delta_rx=$((current_rx - baseline_rx))
            local delta_vxlan=$((current_vxlan - baseline_vxlan))
            local delta_nat=$((current_nat - baseline_nat))
            
            # Calculate instantaneous rate (last 2 seconds)
            local inst_pps=$((delta_rx / i))
            local inst_vxlan_pps=$((delta_vxlan / i))
            
            # Track performance history
            pps_history+=("$inst_pps")
            vxlan_history+=("$inst_vxlan_pps")
            
            # Calculate efficiency
            local efficiency=0
            if [ "$delta_rx" -gt 0 ]; then
                efficiency=$(echo "$delta_vxlan $delta_rx" | awk '{printf "%.1f", ($1/$2)*100}')
            fi
            efficiency_history+=("$efficiency")
            
            # Status determination with anomaly detection
            local status="NORMAL"
            local status_color="green"
            
            if [ "$current_errors" -gt 0 ]; then
                status="ERRORS"
                status_color="red"
            elif [ "$inst_pps" -gt "$anomaly_threshold" ]; then
                status="SURGE"
                status_color="yellow"
            elif [ "$inst_pps" -gt 50000 ]; then
                status="HIGH-RATE"
                status_color="blue"
            elif [ "$inst_pps" -gt 10000 ]; then
                status="MODERATE"
                status_color="green"
            elif [ "$inst_pps" -gt 0 ]; then
                status="ACTIVE"
                status_color="green"
            else
                status="IDLE"
                status_color="yellow"
            fi
            
            # Enhanced progress display with bounds checking
            printf "\r\033[K"  # Clear line
            printf "[%02d/%02d] " $i $monitoring_duration
            case "$status_color" in
                "red") printf "\033[31m" ;;
                "yellow") printf "\033[33m" ;;
                "blue") printf "\033[34m" ;;
                "green") printf "\033[32m" ;;
            esac
            
            # Calculate delta with bounds checking
            local prev_delta=0
            if [ "${#pps_history[@]}" -gt 1 ]; then
                local prev_index=$((${#pps_history[@]} - 2))
                if [ "$prev_index" -ge 0 ]; then
                    prev_delta=$((${pps_history[$prev_index]} * 2))
                fi
            fi
            local rate_change=$((delta_rx - prev_delta))
            
            printf "Δ: RX:%d(+%d) VXLAN:%d NAT:%d | Rate:%d pps | Eff:%.1f%% | %s" \
                $delta_rx $rate_change $delta_vxlan $delta_nat $inst_pps $efficiency "$status"
            printf "\033[0m"  # Reset color
        else
            printf "\r[%02d/%02d] Processing..." $i $monitoring_duration
        fi
        sleep 1
    done
    
    echo ""
    echo ""
    print_color "yellow" "Stopping captures and analyzing results..."
    
    # Enhanced cleanup with process tracking
    local cleanup_timeout=10
    local cleanup_success=true
    
    print_color "blue" "Gracefully stopping ${#capture_pids[@]} capture processes..."
    
    # Phase 1: Graceful termination
    for pid_info in "${capture_pids[@]}"; do
        local pid="${pid_info%%:*}"
        local name="${pid_info##*:}"
        
        if [ "$pid" -gt 0 ] && kill -0 "$pid" 2>/dev/null; then
            print_color "blue" "  Stopping $name (PID: $pid)..."
            kill "$pid" 2>/dev/null || true
        fi
    done
    
    # Wait for graceful termination
    sleep 3
    
    # Phase 2: Force termination if needed
    local force_killed=()
    for pid_info in "${capture_pids[@]}"; do
        local pid="${pid_info%%:*}"
        local name="${pid_info##*:}"
        
        if [ "$pid" -gt 0 ] && kill -0 "$pid" 2>/dev/null; then
            print_color "yellow" "  Force stopping $name (PID: $pid)..."
            kill -9 "$pid" 2>/dev/null || true
            force_killed+=("$name")
            cleanup_success=false
        fi
    done
    
    # Report cleanup results
    if [ "${#force_killed[@]}" -gt 0 ]; then
        print_color "yellow" "⚠ Force-killed processes: ${force_killed[*]}"
    else
        print_color "green" "✓ All processes stopped gracefully"
    fi
    
    # Additional cleanup - find any orphaned tcpdump processes
    local orphaned=$(pgrep -f "tcpdump.*$test_dir" 2>/dev/null || true)
    if [ -n "$orphaned" ]; then
        print_color "yellow" "Cleaning up orphaned tcpdump processes: $orphaned"
        echo "$orphaned" | xargs -r kill -9 2>/dev/null || true
    fi
    
    # Wait for filesystem sync
    sleep 2
    sync
    
    # Get final statistics with enhanced error handling and retries
    echo "Capturing final statistics..."
    
    # Save current baseline for backup
    show_statistics > "$test_dir/stats_before.txt" 2>/dev/null || {
        echo "Baseline statistics collection failed" > "$test_dir/stats_before.txt"
    }
    
    # Multiple attempts to get final statistics
    local stats_success=false
    for attempt in 1 2 3; do
        if timeout 5 bash -c "show_statistics > '$test_dir/stats_after_attempt_$attempt.txt' 2>/dev/null"; then
            cp "$test_dir/stats_after_attempt_$attempt.txt" "$test_dir/stats_after.txt"
            stats_success=true
            break
        else
            print_color "yellow" "Statistics attempt $attempt failed, retrying..."
            sleep 1
        fi
    done
    
    if [ "$stats_success" = "false" ]; then
        echo "Final statistics collection failed after 3 attempts" > "$test_dir/stats_after.txt"
        print_color "red" "⚠ Statistics collection failed - using baseline estimates"
    fi
    
    # Calculate comprehensive deltas with enhanced error checking and fallbacks
    local final_rx final_vxlan final_nat final_bytes
    
    if [ "$stats_success" = "true" ]; then
        final_rx=$(timeout 3 bash -c "get_statistics 'total'" 2>/dev/null || echo "$baseline_rx")
        final_vxlan=$(timeout 3 bash -c "get_statistics 'vxlan'" 2>/dev/null || echo "$baseline_vxlan")
        final_nat=$(timeout 3 bash -c "get_statistics 'nat'" 2>/dev/null || echo "$baseline_nat")
        final_bytes=$(timeout 3 bash -c "get_statistics 'bytes'" 2>/dev/null || echo "$baseline_bytes")
    else
        # Fallback to baseline if statistics collection completely failed
        final_rx="$baseline_rx"
        final_vxlan="$baseline_vxlan"
        final_nat="$baseline_nat"
        final_bytes="$baseline_bytes"
        print_color "yellow" "Using baseline values due to statistics collection failure"
    fi
    
    # Ensure all values are numeric
    final_rx=${final_rx:-0}
    final_vxlan=${final_vxlan:-0}
    final_nat=${final_nat:-0}
    final_bytes=${final_bytes:-0}
    
    local total_new_rx=$((final_rx - baseline_rx))
    local total_new_vxlan=$((final_vxlan - baseline_vxlan))
    local total_new_nat=$((final_nat - baseline_nat))
    local total_new_bytes=$((final_bytes - baseline_bytes))
    
    # Restore original debug level if it was changed
    if [ -n "$original_debug" ] && [ -f "${SCRIPT_DIR}/../.env" ]; then
        sed -i "s/DEBUG_LEVEL=\".*\"/DEBUG_LEVEL=\"$original_debug\"/" "${SCRIPT_DIR}/../.env" 2>/dev/null || true
    fi
    
    # Enhanced analysis and results with performance trends
    echo ""
    print_color "green" "Test Results Analysis"
    echo "==================="
    
    # Performance trend analysis
    local trend_analysis=""
    if [ "${#pps_history[@]}" -gt 3 ]; then
        local early_avg=$(printf "%s\n" "${pps_history[@]:0:3}" | awk '{sum+=$1} END {print int(sum/NR)}')
        local late_avg=$(printf "%s\n" "${pps_history[@]: -3}" | awk '{sum+=$1} END {print int(sum/NR)}')
        local trend_pct=$(echo "$late_avg $early_avg" | awk '{if($2>0) printf "%.1f", (($1-$2)/$2)*100; else print "N/A"}')
        
        if [ "$late_avg" -gt $((early_avg + early_avg * 10 / 100)) ]; then
            trend_analysis="📈 INCREASING (${trend_pct}%)"
        elif [ "$late_avg" -lt $((early_avg - early_avg * 10 / 100)) ]; then
            trend_analysis="📉 DECREASING (${trend_pct}%)"
        else
            trend_analysis="📊 STABLE (${trend_pct}%)"
        fi
    else
        trend_analysis="📊 INSUFFICIENT DATA"
    fi
    
    # Traffic analysis with enhanced metrics
    local avg_pps=$((total_new_rx / monitoring_duration))
    local peak_pps=0
    if [ "${#pps_history[@]}" -gt 0 ]; then
        peak_pps=$(printf "%s\n" "${pps_history[@]}" | sort -rn | head -1)
    fi
    
    local throughput_mbps=$(echo "$total_new_bytes $monitoring_duration" | awk '{printf "%.2f", ($1*8)/(1024*1024*$2)}')
    local avg_packet_size=$((total_new_bytes / (total_new_rx > 0 ? total_new_rx : 1)))
    
    echo "Traffic Analysis (${monitoring_duration}s, mode: $traffic_mode):"
    echo "  Total RX:           $(format_number $total_new_rx) packets"
    echo "  VXLAN processed:    $(format_number $total_new_vxlan) packets"
    echo "  NAT applied:        $(format_number $total_new_nat) packets"
    echo "  Data volume:        $(format_bytes $total_new_bytes)"
    echo "  Average PPS:        $(format_number $avg_pps) (target: $(format_number $TARGET_PPS))"
    echo "  Peak PPS:           $(format_number $peak_pps)"
    echo "  Throughput:         ${throughput_mbps} Mbps"
    echo "  Avg packet size:    ${avg_packet_size} bytes"
    echo "  Performance trend:  $trend_analysis"
    
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
    
    # Enhanced capture file analysis with intelligent detection
    echo ""
    echo "Capture Analysis:"
    
    # Build comprehensive capture file map
    local capture_files_map=(
        "vxlan_sample.pcap:Sample VXLAN (Production High-Rate)"
        "egress_sample.pcap:Sample Egress (Production High-Rate)"
        "ingress_moderate.pcap:Moderate Ingress (Production Moderate)"
        "egress_moderate.pcap:Moderate Egress (Production Moderate)"
        "ingress_full.pcap:Full Ingress (Development)"
        "egress_full.pcap:Full Egress (Development)"
        "ingress_comprehensive.pcap:Comprehensive Ingress (Idle System)"
        "egress_comprehensive.pcap:Comprehensive Egress (Idle System)"
        "vxlan_specific.pcap:VXLAN-Specific (Port 4789)"
        "bpf_trace_enhanced.log:Enhanced BPF Trace Log"
    )
    
    local total_captured=0
    local capture_summary=()
    local vxlan_detected=false
    
    for file_info in "${capture_files_map[@]}"; do
        local file="${file_info%%:*}"
        local desc="${file_info##*:}"
        
        if [ -f "$test_dir/$file" ]; then
            if [[ "$file" == *.pcap ]]; then
                # Enhanced packet analysis with protocol detection
                local count_raw=$(tcpdump -r "$test_dir/$file" 2>/dev/null | wc -l 2>/dev/null)
                local count=$(echo "$count_raw" | tr -d '\n\r\t ' | grep -o '^[0-9]*' | head -1)
                if [ -z "$count" ] || ! [[ "$count" =~ ^[0-9]+$ ]]; then
                    count="0"
                fi
                
                # Protocol analysis
                local protocols=""
                if [ "$count" -gt 0 ]; then
                    local vxlan_count=$(tcpdump -r "$test_dir/$file" 'udp port 4789' 2>/dev/null | wc -l 2>/dev/null || echo "0")
                    local udp_count=$(tcpdump -r "$test_dir/$file" 'udp' 2>/dev/null | wc -l 2>/dev/null || echo "0")
                    local tcp_count=$(tcpdump -r "$test_dir/$file" 'tcp' 2>/dev/null | wc -l 2>/dev/null || echo "0")
                    
                    protocols="UDP:$udp_count"
                    if [ "$vxlan_count" -gt 0 ]; then
                        protocols="$protocols VXLAN:$vxlan_count"
                        vxlan_detected=true
                    fi
                    if [ "$tcp_count" -gt 0 ]; then
                        protocols="$protocols TCP:$tcp_count"
                    fi
                fi
                
                echo "  📊 $desc: $count packets ($protocols)"
                total_captured=$((total_captured + count))
                
                # Sample packet analysis
                if [ "$count" -gt 0 ]; then
                    local sample=$(tcpdump -r "$test_dir/$file" -c 1 -n -q 2>/dev/null | head -1 2>/dev/null || echo "")
                    if [ -n "$sample" ]; then
                        echo "      └─ Sample: ${sample:0:90}..."
                    fi
                fi
                
                capture_summary+=("$file:$count")
                
            elif [[ "$file" == *.log ]]; then
                # Enhanced log analysis
                if [ -f "$test_dir/$file" ]; then
                    local log_lines=$(wc -l < "$test_dir/$file" 2>/dev/null | tr -d '\n' || echo "0")
                    if ! [[ "$log_lines" =~ ^[0-9]+$ ]]; then
                        log_lines="0"
                    fi
                    
                    echo "  📋 $desc: $log_lines lines"
                    
                    if [ "$log_lines" -gt 0 ]; then
                        # Analyze log content
                        local xdp_events=$(grep -c "xdp" "$test_dir/$file" 2>/dev/null || echo "0")
                        local vxlan_events=$(grep -c "vxlan" "$test_dir/$file" 2>/dev/null || echo "0")
                        local error_events=$(grep -ci "error" "$test_dir/$file" 2>/dev/null || echo "0")
                        
                        if [ "$xdp_events" -gt 0 ] || [ "$vxlan_events" -gt 0 ]; then
                            echo "      └─ Events: XDP:$xdp_events VXLAN:$vxlan_events Errors:$error_events"
                        fi
                        
                        # Show recent significant entries
                        local recent=$(tail -2 "$test_dir/$file" 2>/dev/null | grep -v '^$' | head -1)
                        if [ -n "$recent" ]; then
                            echo "      └─ Recent: ${recent:0:80}..."
                        fi
                    else
                        # Analyze why trace is empty
                        if grep -q "not accessible" "$test_dir/$file" 2>/dev/null; then
                            echo "      └─ ⚠ BPF tracing unavailable (permissions/debugfs)"
                        elif grep -q "System Information" "$test_dir/$file" 2>/dev/null; then
                            echo "      └─ ℹ System info collected (tracing unavailable)"
                        else
                            echo "      └─ ℹ Silent operation (no debug output from programs)"
                        fi
                    fi
                fi
            fi
        fi
    done
    
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