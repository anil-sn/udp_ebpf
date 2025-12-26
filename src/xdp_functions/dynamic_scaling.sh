#!/bin/bash
# Dynamic Performance Scaling for XDP VXLAN Pipeline
# Simplified version focused on reliable performance optimization

# Load configuration and utilities
source "$(dirname "${BASH_SOURCE[0]}")/config.sh" 2>/dev/null || true
source "$(dirname "${BASH_SOURCE[0]}")/utils.sh" 2>/dev/null || true

# Auto-detect interface if not set
if [ -z "$INTERFACE" ]; then
    INTERFACE=$(ip route get 8.8.8.8 2>/dev/null | awk 'NR==1 {print $5}')
    [ -n "$INTERFACE" ] || INTERFACE="ens5"
fi

# Performance thresholds
HIGH_PPS_THRESHOLD=${HIGH_PPS_THRESHOLD:-50000}
LOW_PPS_THRESHOLD=${LOW_PPS_THRESHOLD:-10000}

# Get statistics from BPF map
get_bpf_statistics() {
    local stat_type="$1"
    local stats_map="${STATS_MAP:-stats_map}"
    
    local stats_json=$(bpftool map dump name "$stats_map" 2>/dev/null)
    if [ $? -ne 0 ]; then
        echo "0"
        return 1
    fi
    
    case "$stat_type" in
        "total")
            echo "$stats_json" | jq -r '[.[] | select(.formatted.key == 0) | .formatted.values[].value] | add // 0' 2>/dev/null || echo "0"
            ;;
        "vxlan")
            echo "$stats_json" | jq -r '[.[] | select(.formatted.key == 1) | .formatted.values[].value] | add // 0' 2>/dev/null || echo "0"
            ;;
        "dropped"|"errors")
            echo "$stats_json" | jq -r '[.[] | select(.formatted.key == 7) | .formatted.values[].value] | add // 0' 2>/dev/null || echo "0"
            ;;
        *)
            echo "0"
            ;;
    esac
}

# Calculate performance metrics
calculate_performance() {
    local current_time=$(date +%s)
    local current_packets=$(get_bpf_statistics "total")
    local current_errors=$(get_bpf_statistics "errors")
    
    local pps=0
    local error_rate="0.000"
    
    if [ -f "/tmp/xdp_perf_state" ]; then
        local prev_time prev_packets prev_errors
        read prev_time prev_packets prev_errors < "/tmp/xdp_perf_state" 2>/dev/null || {
            echo "$current_time $current_packets $current_errors" > "/tmp/xdp_perf_state"
            echo "$pps $error_rate"
            return
        }
        
        local time_diff=$((current_time - prev_time))
        if [ "$time_diff" -gt 0 ]; then
            local packet_diff=$((current_packets - prev_packets))
            pps=$((packet_diff / time_diff))
            
            if [ "$current_packets" -gt 0 ]; then
                error_rate=$(echo "$current_errors $current_packets" | awk '{printf "%.3f", ($1/$2)*100}' 2>/dev/null || echo "0.000")
            fi
        fi
    fi
    
    echo "$current_time $current_packets $current_errors" > "/tmp/xdp_perf_state"
    echo "$pps $error_rate"
}

# Get system information
show_system_info() {
    local total_cpus=$(nproc)
    local interface_info=""
    
    if command -v ethtool >/dev/null 2>&1; then
        local queue_info=$(ethtool -l "$INTERFACE" 2>/dev/null)
        if [ $? -eq 0 ]; then
            local current_queues=$(echo "$queue_info" | grep "Combined:" | tail -1 | awk '{print $2}')
            local max_queues=$(echo "$queue_info" | grep "Combined:" | head -1 | awk '{print $2}')
            interface_info="$current_queues/$max_queues queues"
        fi
    fi
    
    echo "=== System Information ==="
    echo "Interface: $INTERFACE"
    echo "CPUs: $total_cpus cores"
    echo "Queues: ${interface_info:-unavailable}"
    echo "PPS Thresholds: Low=$LOW_PPS_THRESHOLD, High=$HIGH_PPS_THRESHOLD"
}

# Apply performance tuning
tune_performance() {
    local mode="$1"
    
    echo "=== Performance Tuning ==="
    echo "Mode: $mode"
    
    case "$mode" in
        "max-performance"|"high")
            echo "Applying maximum performance settings..."
            
            # Network interface optimizations
            if command -v ethtool >/dev/null 2>&1; then
                sudo ethtool -G "$INTERFACE" rx 4096 tx 4096 2>/dev/null || true
                sudo ethtool -K "$INTERFACE" gro on gso on tso on 2>/dev/null || true
            fi
            
            # System-level optimizations
            echo "Optimizing system settings..."
            
            # Network buffer sizes
            sudo sysctl -w net.core.rmem_max=134217728 2>/dev/null || true
            sudo sysctl -w net.core.wmem_max=134217728 2>/dev/null || true
            sudo sysctl -w net.core.netdev_max_backlog=5000 2>/dev/null || true
            
            echo "SUCCESS: Applied maximum performance settings"
            ;;
            
        "balanced"|"default")
            echo "Applying balanced performance settings..."
            
            # Moderate optimizations
            if command -v ethtool >/dev/null 2>&1; then
                sudo ethtool -G "$INTERFACE" rx 2048 tx 2048 2>/dev/null || true
            fi
            
            sudo sysctl -w net.core.netdev_max_backlog=1000 2>/dev/null || true
            
            echo "SUCCESS: Applied balanced settings"
            ;;
            
        "monitor")
            # Continuous monitoring mode
            echo "Starting performance monitoring..."
            echo "Press Ctrl+C to stop"
            
            while true; do
                local perf_data=$(calculate_performance)
                local pps=$(echo "$perf_data" | awk '{print $1}')
                local error_rate=$(echo "$perf_data" | awk '{print $2}')
                local timestamp=$(date '+%H:%M:%S')
                
                # Performance status
                local status="NORMAL"
                if [ "$pps" -gt "$HIGH_PPS_THRESHOLD" ]; then
                    status="HIGH LOAD"
                elif [ "$pps" -lt "$LOW_PPS_THRESHOLD" ]; then
                    status="LOW LOAD"
                fi
                
                printf "%s | PPS: %6d | Error Rate: %s%% | Status: %s\n" \
                    "$timestamp" "$pps" "$error_rate" "$status"
                
                sleep 2
            done
            ;;
            
        *)
            echo "ERROR: Invalid mode. Use: max-performance, balanced, or monitor"
            return 1
            ;;
    esac
}

# Main scaling function
scale_performance() {
    local mode="${1:-balanced}"
    
    echo "XDP VXLAN Pipeline - Performance Scaling"
    echo "======================================="
    
    show_system_info
    echo ""
    
    tune_performance "$mode"
}

# Cleanup function
cleanup_scaling() {
    echo "Cleaning up performance scaling artifacts..."
    rm -f "/tmp/xdp_perf_state"
    echo "SUCCESS: Cleanup completed"
}

# Export functions
export -f scale_performance
export -f cleanup_scaling
export -f show_system_info
export -f calculate_performance