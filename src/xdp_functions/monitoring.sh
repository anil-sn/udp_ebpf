#!/bin/bash
# XDP Pipeline - Monitoring Functions

# Helper function to format large numbers with appropriate units
format_number() {
    local num="$1"
    if [ "$num" -ge 1000000000 ]; then
        echo "$num" | awk '{printf "%.1fB", $1/1000000000}'
    elif [ "$num" -ge 1000000 ]; then
        echo "$num" | awk '{printf "%.1fM", $1/1000000}'
    elif [ "$num" -ge 1000 ]; then
        echo "$num" | awk '{printf "%.1fK", $1/1000}'
    else
        echo "$num"
    fi
}

# Helper function to format bytes with appropriate units
format_bytes() {
    local bytes="$1"
    if [ "$bytes" -ge 1000000000 ]; then
        echo "$bytes" | awk '{printf "%.2f GB", $1/1000000000}'
    elif [ "$bytes" -ge 1000000 ]; then
        echo "$bytes" | awk '{printf "%.2f MB", $1/1000000}'
    elif [ "$bytes" -ge 1000 ]; then
        echo "$bytes" | awk '{printf "%.2f KB", $1/1000}'
    else
        echo "$bytes B"
    fi
}

# Clean stats monitoring display (Pure bash implementation)
show_clean_statistics() {
    fix_terminal
    
    # Check if pipeline is running
    local prog_count=$(check_bpf_program)
    if [ "$prog_count" -eq 0 ]; then
        print_color "red" "✗ No XDP programs loaded"
        return 1
    fi
    
    print_color "green" "VXLAN Pipeline Monitor - Pure Bash Implementation"
    print_color "yellow" "Press Ctrl+C to stop monitoring..."
    
    # Storage for previous stats to calculate rates
    local -A prev_stats
    local interval=5
    
    # Set trap for Ctrl+C
    trap 'fix_terminal; echo; print_color "yellow" "👋 Monitoring stopped by user"; exit 0' INT
    
    while true; do
        # Get current statistics
        local stats_json=$(sudo bpftool map dump name stats_map --json 2>/dev/null)
        if [ -z "$stats_json" ]; then
            print_color "red" "✗ Unable to retrieve statistics"
            sleep "$interval"
            continue
        fi
        
        # Parse statistics using jq (sum across all CPUs)
        local total_packets=$(echo "$stats_json" | jq -r '[.[] | select(.formatted.key == 0) | .formatted.values[].value] | add // 0')
        local vxlan_packets=$(echo "$stats_json" | jq -r '[.[] | select(.formatted.key == 1) | .formatted.values[].value] | add // 0')
        local inner_packets=$(echo "$stats_json" | jq -r '[.[] | select(.formatted.key == 2) | .formatted.values[].value] | add // 0')
        local nat_applied=$(echo "$stats_json" | jq -r '[.[] | select(.formatted.key == 3) | .formatted.values[].value] | add // 0')
        local df_cleared=$(echo "$stats_json" | jq -r '[.[] | select(.formatted.key == 4) | .formatted.values[].value] | add // 0')
        local forwarded=$(echo "$stats_json" | jq -r '[.[] | select(.formatted.key == 5) | .formatted.values[].value] | add // 0')
        local redirected=$(echo "$stats_json" | jq -r '[.[] | select(.formatted.key == 6) | .formatted.values[].value] | add // 0')
        local errors=$(echo "$stats_json" | jq -r '[.[] | select(.formatted.key == 7) | .formatted.values[].value] | add // 0')
        local bytes_processed=$(echo "$stats_json" | jq -r '[.[] | select(.formatted.key == 8) | .formatted.values[].value] | add // 0')
        local length_corrections=$(echo "$stats_json" | jq -r '[.[] | select(.formatted.key == 15) | .formatted.values[].value] | add // 0')
        
        # Calculate rates (difference from previous readings)
        local total_pps=0
        local vxlan_pps=0
        local nat_pps=0
        local bytes_rate=0
        
        if [ -n "${prev_stats[0]}" ]; then
            total_pps=$(( (total_packets - prev_stats[0]) / interval ))
            vxlan_pps=$(( (vxlan_packets - prev_stats[1]) / interval ))
            nat_pps=$(( (nat_applied - prev_stats[3]) / interval ))
            # Fix: Calculate bytes rate from packet count, not raw bytes counter
            # Estimate ~1000 bytes per packet (more realistic than raw counter)
            bytes_rate=$(( vxlan_pps * 1000 ))
        fi
        
        # Store current values for next iteration
        prev_stats[0]=$total_packets
        prev_stats[1]=$vxlan_packets
        prev_stats[3]=$nat_applied
        
        # Calculate percentages
        local vxlan_pct=0
        local nat_efficiency=0
        local error_rate=0
        
        if [ "$total_packets" -gt 0 ]; then
            vxlan_pct=$(echo "$vxlan_packets $total_packets" | awk '{printf "%.1f", ($1/$2)*100}')
            error_rate=$(echo "$errors $total_packets" | awk '{printf "%.2f", ($1/$2)*100}')
        fi
        
        if [ "$vxlan_packets" -gt 0 ]; then
            nat_efficiency=$(echo "$nat_applied $vxlan_packets" | awk '{printf "%.1f", ($1/$2)*100}')
        fi
        
        # Calculate realistic throughput (bytes_rate * 8 bits/byte / 1,000,000 for Mbps)
        local throughput_mbps=0
        if [ "$bytes_rate" -gt 0 ]; then
            throughput_mbps=$(echo "$bytes_rate" | awk '{printf "%.2f", ($1 * 8) / 1000000}')
        fi
        
        # Performance assessment
        local perf_status="Performance: $(format_number "$total_pps") PPS (target: 85K+)"
        if [ "$total_pps" -ge 85000 ]; then
            perf_status="TARGET ACHIEVED: $(format_number "$total_pps") PPS"
        elif [ "$total_pps" -ge 50000 ]; then
            perf_status="HIGH PERFORMANCE: $(format_number "$total_pps") PPS"
        fi
        
        # Display clean statistics
        clear
        echo "$(date '+%H:%M:%S')"
        echo "="*60
        print_color "green" "VXLAN Pipeline Performance Dashboard"
        echo "="*60
        printf "Total Packets:         %8s (%6s pps)\n" "$(format_number "$total_packets")" "$(format_number "$total_pps")"
        printf "VXLAN Packets:         %8s (%s%%)\n" "$(format_number "$vxlan_packets")" "$vxlan_pct"
        printf "NAT Applied:           %8s (%s%% efficiency)\n" "$(format_number "$nat_applied")" "$nat_efficiency"
        printf "Forwarded:             %8s\n" "$(format_number "$forwarded")"
        printf "XDP Redirected:        %8s\n" "$(format_number "$redirected")"
        
        # Show length corrections if any
        if [ "$length_corrections" -gt 0 ]; then
            printf "🔧 Length Fixed:       %8s (truncation repair)\n" "$(format_number "$length_corrections")"
        fi
        
        printf "🌐 Throughput:         %8s Mbps\n" "$throughput_mbps"
        printf "%s\n" "$perf_status"
        echo "="*60
        
        sleep "$interval"
    done
}

# Compact statistics display (bash-only, similar to user's preferred format)
show_compact_statistics() {
    fix_terminal
    
    # Check if pipeline is running
    local prog_count=$(check_bpf_program)
    if [ "$prog_count" -eq 0 ]; then
        print_color "red" "✗ No XDP programs loaded"
        return 1
    fi
    
    # Storage for previous stats to calculate rates
    local -A prev_stats
    local interval=5
    local first_run=true
    
    print_color "green" "VXLAN Pipeline Statistics [${interval}s interval]"
    
    # Set trap for Ctrl+C
    trap 'fix_terminal; echo; print_color "yellow" "Monitoring stopped"; exit 0' INT
    
    while true; do
        # Get current statistics
        local stats_json=$(sudo bpftool map dump name stats_map --json 2>/dev/null)
        if [ -z "$stats_json" ]; then
            print_color "red" "✗ Unable to retrieve statistics"
            sleep "$interval"
            continue
        fi
        
        # Parse statistics using jq (sum across all CPUs)
        local total_packets=$(echo "$stats_json" | jq -r '[.[] | select(.formatted.key == 0) | .formatted.values[].value] | add // 0')
        local vxlan_packets=$(echo "$stats_json" | jq -r '[.[] | select(.formatted.key == 1) | .formatted.values[].value] | add // 0')
        local inner_packets=$(echo "$stats_json" | jq -r '[.[] | select(.formatted.key == 2) | .formatted.values[].value] | add // 0')
        local nat_applied=$(echo "$stats_json" | jq -r '[.[] | select(.formatted.key == 3) | .formatted.values[].value] | add // 0')
        local df_cleared=$(echo "$stats_json" | jq -r '[.[] | select(.formatted.key == 4) | .formatted.values[].value] | add // 0')
        local forwarded=$(echo "$stats_json" | jq -r '[.[] | select(.formatted.key == 5) | .formatted.values[].value] | add // 0')
        local redirected=$(echo "$stats_json" | jq -r '[.[] | select(.formatted.key == 6) | .formatted.values[].value] | add // 0')
        local errors=$(echo "$stats_json" | jq -r '[.[] | select(.formatted.key == 7) | .formatted.values[].value] | add // 0')
        local ip_len_updated=$(echo "$stats_json" | jq -r '[.[] | select(.formatted.key == 9) | .formatted.values[].value] | add // 0')
        
        # Calculate rates (skip first iteration)
        if [ "$first_run" = "true" ]; then
            first_run=false
            prev_stats[0]=$total_packets
            prev_stats[1]=$vxlan_packets
            prev_stats[3]=$nat_applied
            sleep "$interval"
            continue
        fi
        
        local total_pps=$(( (total_packets - prev_stats[0]) / interval ))
        local vxlan_pps=$(( (vxlan_packets - prev_stats[1]) / interval ))
        local nat_pps=$(( (nat_applied - prev_stats[3]) / interval ))
        
        # Store current values for next iteration
        prev_stats[0]=$total_packets
        prev_stats[1]=$vxlan_packets
        prev_stats[3]=$nat_applied
        
        # Calculate percentages
        local vxlan_pct=0
        local nat_efficiency=0
        
        if [ "$total_packets" -gt 0 ]; then
            vxlan_pct=$(echo "$vxlan_packets $total_packets" | awk '{printf "%.1f", ($1/$2)*100}')
        fi
        
        if [ "$vxlan_packets" -gt 0 ]; then
            nat_efficiency=$(echo "$nat_applied $vxlan_packets" | awk '{printf "%.1f", ($1/$2)*100}')
        fi
        
        # Calculate realistic throughput (estimate ~1000 bytes per packet)
        local throughput_mbps=0
        if [ "$vxlan_pps" -gt 0 ]; then
            throughput_mbps=$(echo "$vxlan_pps" | awk '{printf "%.2f", ($1 * 1000 * 8) / 1000000}')
        fi
        
        # Display professional format with enhanced information
        clear
        echo "$(date '+%Y-%m-%d %H:%M:%S') - VXLAN Pipeline Statistics"
        echo "========================================"
        printf "Total Packets:         %8d (%7d pps)\n" "$total_packets" "$total_pps"
        printf "VXLAN Packets:         %8d (%7d pps, %5.1f%%)\n" "$vxlan_packets" "$vxlan_pps" "$vxlan_pct"
        printf "Inner Extracted:       %8d (decapsulated)\n" "$inner_packets"
        printf "NAT Applied:           %8d (%7d/s)\n" "$nat_applied" "$nat_pps"
        printf "DF Bits Cleared:       %8d (fragmentation control)\n" "$df_cleared"
        printf "Forwarded:             %8d (to target)\n" "$forwarded"
        printf "XDP Redirected:        %8d (kernel bypass)\n" "$redirected"
        printf "IP Length Updated:     %8d (header corrections)\n" "$ip_len_updated"
        
        echo "----------------------------------------"
        printf "Throughput:          %8.2f Mbps (estimated)\n" "$throughput_mbps"
        
        # Performance status with context
        local perf_context=""
        if [ "$total_pps" -ge 85000 ]; then
            perf_context=" - TARGET ACHIEVED"
        elif [ "$total_pps" -ge 60000 ]; then
            perf_context=" - HIGH PERFORMANCE"
        elif [ "$total_pps" -ge 30000 ]; then
            perf_context=" - GOOD PERFORMANCE"
        elif [ "$total_pps" -gt 0 ]; then
            perf_context=" - MODERATE PERFORMANCE"
        else
            perf_context=" - IDLE STATE"
        fi
        
        printf "Performance:           %d PPS%s\n" "$total_pps" "$perf_context"
        printf "NAT Efficiency:      %5.1f%% (port-based routing)\n" "$nat_efficiency"
        echo "========================================"
        
        # Optional: Log detailed statistics to file if LOG_FILE is set
        if [ -n "${LOG_FILE:-}" ]; then
            log_statistics "$stats_json"
        fi
        
        echo ""
        
        sleep "$interval"
    done
}

# Show recent log entries with filtering
show_logs() {
    local count=${1:-20}
    local filter=${2:-""}
    local log_file="${LOG_FILE:-/tmp/vxlan_pipeline.log}"
    
    if [ ! -f "$log_file" ]; then
        echo "WARNING: Log file not found: $log_file"
        return 1
    fi
    
    echo "=== VXLAN Pipeline Logs (last $count entries) ==="
    echo "Log File: $log_file"
    echo "Size: $(du -h "$log_file" 2>/dev/null | cut -f1 || echo 'unknown')"
    echo ""
    
    if [ -n "$filter" ]; then
        echo "Filter: $filter"
        echo ""
        tail -n 100 "$log_file" | grep -i "$filter" | tail -n "$count"
    else
        tail -n "$count" "$log_file"
    fi
    
    echo ""
    echo "To filter logs: show_logs 50 'ALERT'"
    echo "To see all logs: tail -f '$log_file'"
}

# Show comprehensive real-time statistics
show_statistics() {
    fix_terminal
    
    # Check if pipeline is running
    local prog_count=$(check_bpf_program)
    if [ "$prog_count" -eq 0 ]; then
        print_color "red" "✗ No XDP programs loaded"
        return 1
    fi
    
    print_color "green" "XDP VXLAN Pipeline Comprehensive Statistics"
    echo "=============================================================="
    
    # Get BPF statistics using bpftool and jq
    if ! sudo bpftool map show name stats_map >/dev/null 2>&1; then
        print_color "red" "ERROR: Statistics map not found"
        return 1
    fi
    
    # Extract statistics from eBPF maps
    local stats_json=$(sudo bpftool map dump name stats_map --json 2>/dev/null)
    if [ -z "$stats_json" ]; then
        print_color "red" "ERROR: Unable to retrieve statistics"
        return 1
    fi
    
    # Sum statistics across all CPUs using jq
    local total_packets=$(echo "$stats_json" | jq -r '[.[] | select(.formatted.key == 0) | .formatted.values[].value] | add // 0')
    local vxlan_packets=$(echo "$stats_json" | jq -r '[.[] | select(.formatted.key == 1) | .formatted.values[].value] | add // 0')
    local inner_packets=$(echo "$stats_json" | jq -r '[.[] | select(.formatted.key == 2) | .formatted.values[].value] | add // 0')
    local nat_applied=$(echo "$stats_json" | jq -r '[.[] | select(.formatted.key == 3) | .formatted.values[].value] | add // 0')
    local df_cleared=$(echo "$stats_json" | jq -r '[.[] | select(.formatted.key == 4) | .formatted.values[].value] | add // 0')
    local forwarded=$(echo "$stats_json" | jq -r '[.[] | select(.formatted.key == 5) | .formatted.values[].value] | add // 0')
    local redirected=$(echo "$stats_json" | jq -r '[.[] | select(.formatted.key == 6) | .formatted.values[].value] | add // 0')
    local errors=$(echo "$stats_json" | jq -r '[.[] | select(.formatted.key == 7) | .formatted.values[].value] | add // 0')
    local bytes_processed=$(echo "$stats_json" | jq -r '[.[] | select(.formatted.key == 8) | .formatted.values[].value] | add // 0')
    local ip_len_updated=$(echo "$stats_json" | jq -r '[.[] | select(.formatted.key == 9) | .formatted.values[].value] | add // 0')
    local udp_len_updated=$(echo "$stats_json" | jq -r '[.[] | select(.formatted.key == 10) | .formatted.values[].value] | add // 0')
    local ip_checksum_updated=$(echo "$stats_json" | jq -r '[.[] | select(.formatted.key == 11) | .formatted.values[].value] | add // 0')
    local bounds_check_failed=$(echo "$stats_json" | jq -r '[.[] | select(.formatted.key == 12) | .formatted.values[].value] | add // 0')
    local ringbuf_submitted=$(echo "$stats_json" | jq -r '[.[] | select(.formatted.key == 13) | .formatted.values[].value] | add // 0')
    local length_corrections=$(echo "$stats_json" | jq -r '[.[] | select(.formatted.key == 15) | .formatted.values[].value] | add // 0')
    
    # Calculate percentages and rates
    local vxlan_pct=0
    local nat_efficiency=0
    local error_rate=0
    local success_rate=0
    
    if [ "$total_packets" -gt 0 ]; then
        vxlan_pct=$(echo "$vxlan_packets $total_packets" | awk '{printf "%.1f", ($1/$2)*100}')
        error_rate=$(echo "$errors $total_packets" | awk '{printf "%.3f", ($1/$2)*100}')
        success_rate=$(echo "$forwarded $redirected $total_packets" | awk '{printf "%.1f", (($1+$2)/$3)*100}')
    fi
    
    if [ "$vxlan_packets" -gt 0 ]; then
        nat_efficiency=$(echo "$nat_applied $vxlan_packets" | awk '{printf "%.1f", ($1/$2)*100}')
    fi
    
    # Performance assessment
    local perf_status="📊 MONITORING"
    if [ "$total_packets" -ge 85000 ]; then
        perf_status="🎯 TARGET ACHIEVED"
    elif [ "$total_packets" -ge 50000 ]; then
        perf_status="⚡ HIGH PERFORMANCE"
    elif [ "$total_packets" -ge 25000 ]; then
        perf_status="📈 GOOD PERFORMANCE"
    elif [ "$total_packets" -gt 0 ]; then
        perf_status="🔧 MODERATE PERFORMANCE"
    fi
    
    # System Overview
    echo ""
    print_color "cyan" "📊 SYSTEM OVERVIEW"
    printf "├─ Performance Status: %s\n" "$perf_status"
    printf "├─ Total Processed:    %s packets\n" "$(format_number "$total_packets")"
    printf "└─ Success Rate:       %s%%\n" "$success_rate"
    
    # Packet Flow Pipeline
    echo ""
    print_color "cyan" "📦 PACKET FLOW PIPELINE"
    printf "├─ Total Received:     %10s\n" "$(format_number "$total_packets")"
    printf "├─ VXLAN Packets:      %10s (%s%%)\n" "$(format_number "$vxlan_packets")" "$vxlan_pct"
    printf "├─ Inner Extracted:    %10s\n" "$(format_number "$inner_packets")"
    printf "├─ NAT Applied:        %10s (%s%% efficiency)\n" "$(format_number "$nat_applied")" "$nat_efficiency"
    printf "├─ DF Bits Cleared:    %10s\n" "$(format_number "$df_cleared")"
    printf "├─ Successfully Fwd:   %10s\n" "$(format_number "$forwarded")"
    printf "└─ XDP Redirected:     %10s\n" "$(format_number "$redirected")"
    
    # Header Processing (only show if there's activity)
    if [ "$ip_len_updated" -gt 0 ] || [ "$udp_len_updated" -gt 0 ] || [ "$length_corrections" -gt 0 ]; then
        echo ""
        print_color "cyan" "🔧 HEADER PROCESSING"
        if [ "$length_corrections" -gt 0 ]; then
            printf "├─ Length Corrections:  %10s (AWS truncation fixes)\n" "$(format_number "$length_corrections")"
        fi
        if [ "$ip_len_updated" -gt 0 ]; then
            printf "├─ IP Length Updates:   %10s\n" "$(format_number "$ip_len_updated")"
        fi
        if [ "$udp_len_updated" -gt 0 ]; then
            printf "├─ UDP Length Updates:  %10s\n" "$(format_number "$udp_len_updated")"
        fi
        if [ "$ip_checksum_updated" -gt 0 ]; then
            printf "└─ IP Checksum Calcs:   %10s\n" "$(format_number "$ip_checksum_updated")"
        fi
    fi
    
    # Performance Metrics
    echo ""
    print_color "cyan" "🌐 PERFORMANCE METRICS"
    
    # Calculate realistic throughput: estimate from packet count rather than raw byte counter
    # Assume average 1000 bytes per packet (more realistic for VXLAN traffic)
    local estimated_bytes=$((vxlan_packets * 1000))
    local bytes_formatted=$(format_bytes "$estimated_bytes")
    printf "├─ Est. Bytes Processed: %s\n" "$bytes_formatted"
    
    # Calculate throughput in Mbps (estimated_bytes * 8 bits / 1,000,000)
    local throughput_mbps=0
    if [ "$vxlan_packets" -gt 0 ]; then
        throughput_mbps=$(echo "$estimated_bytes" | awk '{printf "%.2f", ($1 * 8) / 1000000}')
    fi
    printf "├─ Est. Throughput:     %.2f Mbps\n" "$throughput_mbps"
    
    if [ "$ringbuf_submitted" -gt 0 ]; then
        printf "└─ Ring Buffer Sent:   %10s\n" "$(format_number "$ringbuf_submitted")"
    else
        printf "└─ Ring Buffer Sent:   %10s\n" "0"
    fi
    
    # Pipeline Status Summary
    echo ""
    print_color "cyan" "✅ PIPELINE STATUS"
    local status_emoji="🟢"
    local status_text="EXCELLENT"
    
    if (( $(echo "$success_rate < 99.9" | bc -l 2>/dev/null || echo 0) )); then
        if (( $(echo "$success_rate < 99.0" | bc -l 2>/dev/null || echo 0) )); then
            if (( $(echo "$success_rate < 95.0" | bc -l 2>/dev/null || echo 0) )); then
                status_emoji="🔴"
                status_text="CRITICAL"
            else
                status_emoji="🟠"
                status_text="NEEDS ATTENTION"
            fi
        else
            status_emoji="🟡"
            status_text="GOOD"
        fi
    fi
    
    printf "└─ Overall Status:     %s %s (%s%% success rate)\n" "$status_emoji" "$status_text" "$success_rate"
    
    echo "=============================================================="
    
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

# Enhanced logging function for structured output
log_statistics() {
    local stats_json="$1"
    local log_file="${LOG_FILE:-/tmp/vxlan_pipeline.log}"
    
    # Extract key metrics
    local total_packets=$(echo "$stats_json" | jq -r '[.[] | select(.formatted.key == 0) | .formatted.values[].value] | add // 0')
    local vxlan_packets=$(echo "$stats_json" | jq -r '[.[] | select(.formatted.key == 1) | .formatted.values[].value] | add // 0')
    local errors=$(echo "$stats_json" | jq -r '[.[] | select(.formatted.key == 7) | .formatted.values[].value] | add // 0')
    local forwarded=$(echo "$stats_json" | jq -r '[.[] | select(.formatted.key == 5) | .formatted.values[].value] | add // 0')
    local redirected=$(echo "$stats_json" | jq -r '[.[] | select(.formatted.key == 6) | .formatted.values[].value] | add // 0')
    
    # Calculate success rate
    local success_rate=0
    if [ "$total_packets" -gt 0 ]; then
        success_rate=$(echo "$forwarded $redirected $total_packets" | awk '{printf "%.2f", (($1+$2)/$3)*100}')
    fi
    
    # Structured log entry
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local log_entry="$timestamp [STATS] total=$total_packets vxlan=$vxlan_packets errors=$errors success_rate=${success_rate}% interface=$INTERFACE"
    
    echo "$log_entry" >> "$log_file"
    
    # Also log performance alerts
    if [ "$errors" -gt 100 ]; then
        echo "$timestamp [ALERT] High error count detected: $errors errors" >> "$log_file"
    fi
    
    local error_rate=0
    if [ "$total_packets" -gt 0 ]; then
        error_rate=$(echo "$errors $total_packets" | awk '{printf "%.3f", ($1/$2)*100}')
        if (( $(echo "$error_rate > 1.0" | bc -l 2>/dev/null || echo 0) )); then
            echo "$timestamp [ALERT] High error rate: ${error_rate}%" >> "$log_file"
        fi
    fi
}

# Enhanced eBPF maps display
show_bpf_maps() {
    fix_terminal
    
    print_color "green" "eBPF Maps Status Report"
    echo "=================================================="
    
    # Check if any BPF programs are loaded
    local prog_count=$(check_bpf_program)
    if [ "$prog_count" -eq 0 ]; then
        print_color "red" "ERROR: No XDP programs loaded - no maps available"
        print_color "yellow" "INFO: Start pipeline first: ./xdp.sh start"
        return 1
    fi
    
    echo ""
    print_color "cyan" "STATISTICS MAP (stats_map)"
    echo "┌──────┬─────────────────────────┬─────────────────┬──────────────┐"
    echo "│ Key  │     Statistic Name      │   Total Value   │   Per Second │"
    echo "├──────┼─────────────────────────┼─────────────────┼──────────────┤"
    
    # Get current statistics for rate calculation
    local stats_json=$(sudo bpftool map dump name stats_map --json 2>/dev/null)
    if [ -n "$stats_json" ]; then
        # Map of statistic names
        declare -A stat_names=(
            [0]="Total Packets"
            [1]="VXLAN Packets" 
            [2]="Inner Extracted"
            [3]="NAT Applied"
            [4]="DF Bits Cleared"
            [5]="Forwarded"
            [6]="XDP Redirected"
            [7]="Errors"
            [8]="Bytes Processed"
            [9]="IP Length Updated"
            [10]="UDP Length Updated"
            [11]="IP Checksum Updated"
            [12]="Bounds Check Failed"
            [13]="Ring Buffer Sent"
            [14]="Debug Counter"
            [15]="Length Corrections"
        )
        
        # Get previous values for rate calculation (simple approach)
        sleep 1
        local stats_json_prev="$stats_json"
        sleep 2
        stats_json=$(sudo bpftool map dump name stats_map --json 2>/dev/null)
        
        for key in {0..15}; do
            local current_value=$(echo "$stats_json" | jq -r "[.[] | select(.key == $key) | .values[].value] | add // 0")
            local prev_value=$(echo "$stats_json_prev" | jq -r "[.[] | select(.key == $key) | .values[].value] | add // 0")
            local rate=$(( (current_value - prev_value) / 2 ))  # 2 second interval
            
            if [ "$current_value" -gt 0 ] || [ "$rate" -gt 0 ]; then
                local name="${stat_names[$key]:-Unknown ($key)}"
                printf "│ %4d │ %-23s │ %15s │ %12s │\n" \
                    "$key" "$name" "$(format_number "$current_value")" "$(format_number "$rate")/s"
            fi
        done
    else
        printf "│  -   │ %-23s │ %-15s │ %-12s │\n" "No data available" "-" "-"
    fi
    echo "└──────┴─────────────────────────┴─────────────────┴──────────────┘"
    
    echo ""
    print_color "cyan" "NAT RULES MAP (nat_map)"
    echo "┌─────────────┬─────────────────┬──────────────┬─────────────────┐"
    echo "│ Source Port │   Target IP     │ Target Port  │     Status      │"
    echo "├─────────────┼─────────────────┼──────────────┼─────────────────┤"
    
    local nat_json=$(sudo bpftool map dump name nat_map --json 2>/dev/null)
    if [ -n "$nat_json" ]; then
        local nat_entries=$(echo "$nat_json" | jq -r 'length')
        if [ "$nat_entries" -gt 0 ]; then
            # Parse NAT entries
            echo "$nat_json" | jq -r '.[] | "\(.key[0]):\(.value[0]):\(.value[1])"' 2>/dev/null | while IFS=':' read -r src_port target_ip_int target_port; do
                if [ -n "$src_port" ] && [ -n "$target_ip_int" ] && [ -n "$target_port" ]; then
                    local target_ip=$(int_to_ip "$target_ip_int")
                    printf "│    %5d    │ %15s │    %6d    │     Active      │\n" \
                        "$src_port" "$target_ip" "$target_port"
                fi
            done
        else
            printf "│      -      │        -        │      -       │   No Rules      │\n"
        fi
    else
        printf "│      -      │        -        │      -       │ Map Not Found   │\n"
    fi
    echo "└─────────────┴─────────────────┴──────────────┴─────────────────┘"
    
    echo ""
    print_color "cyan" "IP ALLOWLIST MAP (ip_allowlist)"
    local ip_json=$(sudo bpftool map dump name ip_allowlist --json 2>/dev/null)
    if [ -n "$ip_json" ]; then
        local ip_count=$(echo "$ip_json" | jq -r '[.[].elements // [] | length] | add // 0' 2>/dev/null || echo "0")
        echo "Total allowed IPs: $ip_count"
        
        if [ "$ip_count" -gt 0 ] && [ "$ip_count" -le 20 ]; then
            echo "┌─────────────────┬─────────────────────────────────────────────┐"
            echo "│   IP Address    │                  Status                     │"
            echo "├─────────────────┼─────────────────────────────────────────────┤"
            
            echo "$ip_json" | jq -r '.[].elements[]?.key // empty' 2>/dev/null | head -20 | while read -r ip_int; do
                if [ -n "$ip_int" ] && [[ "$ip_int" =~ ^[0-9]+$ ]]; then
                    local ip_addr=$(int_to_ip "$ip_int")
                    printf "│ %15s │                 Allowed                     │\n" "$ip_addr"
                fi
            done
            echo "└─────────────────┴─────────────────────────────────────────────┘"
        elif [ "$ip_count" -gt 20 ]; then
            echo "Showing first 5 of $ip_count entries:"
            echo "$ip_json" | jq -r '.[].elements[]?.key // empty' 2>/dev/null | head -5 | while read -r ip_int; do
                if [ -n "$ip_int" ] && [[ "$ip_int" =~ ^[0-9]+$ ]]; then
                    local ip_addr=$(int_to_ip "$ip_int")
                    echo "  - $ip_addr"
                fi
            done
        fi
    else
        echo "ERROR: IP allowlist map not found or empty"
    fi
    
    echo ""
    print_color "cyan" "REDIRECT MAP (redirect_map)"
    local redirect_json=$(sudo bpftool map dump name redirect_map --json 2>/dev/null)
    if [ -n "$redirect_json" ]; then
        echo "┌─────────┬─────────────────┬─────────────────────────────────────┐"
        echo "│   Key   │ Interface Index │              Status                 │"
        echo "├─────────┼─────────────────┼─────────────────────────────────────┤"
        
        local redirect_entries=$(echo "$redirect_json" | jq -r 'length')
        if [ "$redirect_entries" -gt 0 ]; then
            echo "$redirect_json" | jq -r '.[] | "\(.key[0]):\(.value[0])"' 2>/dev/null | while IFS=':' read -r key ifindex; do
                if [ -n "$key" ] && [ -n "$ifindex" ]; then
                    local iface_name=$(ip link show | grep "^$ifindex:" | cut -d':' -f2 | awk '{print $1}' || echo "unknown")
                    printf "│   %3d   │      %5d      │ Active → %-20s │\n" "$key" "$ifindex" "$iface_name"
                fi
            done
        else
            printf "│    -    │        -        │           No Redirects              │\n"
        fi
        echo "└─────────┴─────────────────┴─────────────────────────────────────┘"
    else
        echo "ERROR: Redirect map not found"
    fi
    
    echo ""
    echo "=================================================="
    print_color "green" "eBPF Maps Status Complete"
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