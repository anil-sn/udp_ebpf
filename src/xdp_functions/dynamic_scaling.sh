#!/bin/bash
# Dynamic CPU Affinity and Queue Scaling for XDP VXLAN Pipeline
# Automatically adapts network queues and CPU affinity based on traffic load

# Load configuration and utilities
source "$(dirname "${BASH_SOURCE[0]}")/config.sh" 2>/dev/null || true
source "$(dirname "${BASH_SOURCE[0]}")/utils.sh" 2>/dev/null || true
source "$(dirname "${BASH_SOURCE[0]}")/bpf_ops.sh" 2>/dev/null || true

# Auto-detect interface if not set
if [ -z "$INTERFACE" ]; then
    INTERFACE=$(ip route get 8.8.8.8 | awk 'NR==1 {print $5}')
    [ -n "$INTERFACE" ] || INTERFACE="ens5"
fi

# Performance thresholds
HIGH_PPS_THRESHOLD=${HIGH_PPS_THRESHOLD:-50000}    # Scale up above 50K PPS
LOW_PPS_THRESHOLD=${LOW_PPS_THRESHOLD:-10000}      # Scale down below 10K PPS
CPU_USAGE_THRESHOLD=${CPU_USAGE_THRESHOLD:-80}     # Scale up if CPU > 80%

# Current system state
CURRENT_QUEUES=""
CURRENT_CPU_COUNT=""
MAX_QUEUES=""

# Get system information
get_system_info() {
    # Available CPU cores
    local total_cpus=$(nproc)
    
    # Current queue configuration
    local queue_info=$(ethtool -l "$INTERFACE" 2>/dev/null)
    CURRENT_QUEUES=$(echo "$queue_info" | grep "Combined:" | tail -1 | awk '{print $2}')
    MAX_QUEUES=$(echo "$queue_info" | grep "Combined:" | head -1 | awk '{print $2}')
    
    print_color "blue" "System Info: $total_cpus CPUs, $CURRENT_QUEUES/$MAX_QUEUES queues active"
}

# Calculate current performance metrics
get_performance_metrics() {
    local current_time=$(date +%s)
    local current_packets=$(get_statistics "total" 2>/dev/null || echo "0")
    local current_dropped=$(get_statistics "dropped" 2>/dev/null || echo "0")
    
    # Calculate PPS if we have previous measurement
    if [ -f "/tmp/xdp_perf_state" ]; then
        local prev_time prev_packets
        read prev_time prev_packets < "/tmp/xdp_perf_state"
        
        local time_diff=$((current_time - prev_time))
        local packet_diff=$((current_packets - prev_packets))
        
        if [ "$time_diff" -gt 0 ]; then
            local pps=$((packet_diff / time_diff))
            local drop_rate=0
            if [ "$current_packets" -gt 0 ]; then
                drop_rate=$(echo "$current_dropped $current_packets" | awk '{printf "%.3f", ($1/$2)*100}')
            fi
            
            echo "$pps $drop_rate $current_packets $current_dropped"
            echo "$current_time $current_packets" > "/tmp/xdp_perf_state"
            return 0
        fi
    fi
    
    # First run - store baseline
    echo "$current_time $current_packets" > "/tmp/xdp_perf_state"
    echo "0 0.000 $current_packets $current_dropped"
}

# Get CPU usage for network interrupts
get_network_cpu_usage() {
    # Get network interrupt CPU usage
    local net_irq_usage=$(cat /proc/interrupts | grep -E "(eth|ens)" | awk '
    {
        total = 0
        for(i=2; i<=NF-1; i++) {
            if($i ~ /^[0-9]+$/) total += $i
        }
        print total
    }' | awk '{sum += $1} END {print sum+0}')
    
    # Get overall CPU idle percentage
    local cpu_idle=$(top -bn1 | grep "Cpu(s)" | awk '{print $8}' | sed 's/%id,//')
    local cpu_usage=$(echo "100 - $cpu_idle" | bc -l 2>/dev/null || echo "50")
    
    echo "$cpu_usage"
}

# Optimize network queue count based on load
optimize_queue_count() {
    local pps="$1"
    local drop_rate="$2"
    local cpu_usage="$3"
    
    local target_queues="$CURRENT_QUEUES"
    local reason=""
    
    # Scale up conditions
    if [ "$pps" -gt "$HIGH_PPS_THRESHOLD" ] || [ "$(echo "$cpu_usage > $CPU_USAGE_THRESHOLD" | bc -l 2>/dev/null || echo "0")" = "1" ] || [ "$(echo "$drop_rate > 0.1" | bc -l 2>/dev/null || echo "0")" = "1" ]; then
        if [ "$CURRENT_QUEUES" -lt "$MAX_QUEUES" ]; then
            target_queues=$((CURRENT_QUEUES + 1))
            reason="High load: ${pps}PPS, ${cpu_usage}% CPU, ${drop_rate}% drops"
        fi
    # Scale down conditions  
    elif [ "$pps" -lt "$LOW_PPS_THRESHOLD" ] && [ "$(echo "$cpu_usage < 30" | bc -l 2>/dev/null || echo "0")" = "1" ] && [ "$(echo "$drop_rate < 0.001" | bc -l 2>/dev/null || echo "0")" = "1" ]; then
        if [ "$CURRENT_QUEUES" -gt 2 ]; then
            target_queues=$((CURRENT_QUEUES - 1))
            reason="Low load: ${pps}PPS, ${cpu_usage}% CPU"
        fi
    fi
    
    # Apply queue change
    if [ "$target_queues" != "$CURRENT_QUEUES" ]; then
        print_color "yellow" "Scaling queues: $CURRENT_QUEUES → $target_queues ($reason)"
        
        if sudo ethtool -L "$INTERFACE" combined "$target_queues" 2>/dev/null; then
            print_color "green" "✓ Scaled to $target_queues queues"
            CURRENT_QUEUES="$target_queues"
            return 0
        else
            print_color "red" "✗ Failed to scale queues"
            return 1
        fi
    fi
    
    return 0
}

# Set optimal CPU affinity for network interrupts
optimize_interrupt_affinity() {
    local queue_count="$1"
    
    # Get network interface IRQ numbers
    local irq_numbers=$(grep "$INTERFACE" /proc/interrupts | awk -F: '{print $1}' | tr -d ' ')
    
    if [ -z "$irq_numbers" ]; then
        print_color "yellow" "Warning: No IRQs found for $INTERFACE"
        return 1
    fi
    
    print_color "blue" "Optimizing IRQ affinity for $queue_count queues..."
    
    local cpu=0
    for irq in $irq_numbers; do
        # Distribute IRQs across available CPUs
        local cpu_mask=$((1 << cpu))
        printf "%x" "$cpu_mask" | sudo tee "/proc/irq/$irq/smp_affinity" >/dev/null 2>&1
        
        print_color "green" "✓ IRQ $irq → CPU $cpu (mask: $(printf "%x" "$cpu_mask"))"
        
        cpu=$(((cpu + 1) % queue_count))
    done
}

# Start multiple packet injector instances for multi-core utilization
start_multicore_injectors() {
    local cpu_count="$1"
    local injector_binary="../packet_injector"
    
    # Check if packet_injector exists
    if [ ! -f "$injector_binary" ]; then
        print_color "yellow" "Warning: packet_injector binary not found at $injector_binary"
        return 1
    fi
    
    print_color "blue" "Starting $cpu_count packet_injector instances..."
    
    # Start one injector per CPU core
    for ((cpu=0; cpu<cpu_count; cpu++)); do
        # Start injector with CPU affinity
        taskset -c "$cpu" "$injector_binary" &
        local pid=$!
        print_color "green" "✓ Started packet_injector PID $pid on CPU $cpu"
        sleep 0.1  # Small delay between starts
    done
}

# Set process affinity for XDP components
optimize_process_affinity() {
    local queue_count="$1"
    
    # Get vxlan_loader PIDs
    local vxlan_pids=$(pgrep -f "vxlan_loader.*-i.*$INTERFACE" 2>/dev/null)
    
    # Get packet_injector PIDs  
    local injector_pids=$(pgrep -f "packet_injector" 2>/dev/null)
    
    if [ -n "$vxlan_pids" ]; then
        # Distribute vxlan_loader processes across CPUs
        local cpu=0
        for pid in $vxlan_pids; do
            if sudo taskset -cp "$cpu" "$pid" >/dev/null 2>&1; then
                print_color "green" "✓ vxlan_loader PID $pid → CPU $cpu"
            fi
            cpu=$(((cpu + 1) % queue_count))
        done
    fi
    
    if [ -n "$injector_pids" ]; then
        # Distribute packet_injector processes across remaining CPUs
        local start_cpu=$((queue_count / 2))
        local cpu="$start_cpu"
        for pid in $injector_pids; do
            if sudo taskset -cp "$cpu" "$pid" >/dev/null 2>&1; then
                print_color "green" "✓ packet_injector PID $pid → CPU $cpu"
            fi
            cpu=$(((cpu + 1) % queue_count))
            if [ "$cpu" -ge "$queue_count" ]; then
                cpu="$start_cpu"
            fi
        done
    fi
}

# Main dynamic scaling function
run_dynamic_scaling() {
    print_color "blue" "Starting dynamic XDP scaling monitor..."
    
    get_system_info
    
    while true; do
        # Get current performance metrics
        local metrics=($(get_performance_metrics))
        local pps="${metrics[0]:-0}"
        local drop_rate="${metrics[1]:-0.000}"
        local total_packets="${metrics[2]:-0}"
        local total_drops="${metrics[3]:-0}"
        
        # Get CPU usage
        local cpu_usage=$(get_network_cpu_usage)
        
        # Print current status
        print_color "cyan" "[$(date '+%H:%M:%S')] PPS: $pps, Drops: ${drop_rate}%, CPU: ${cpu_usage}%, Queues: $CURRENT_QUEUES"
        
        # Optimize queue count based on load
        if optimize_queue_count "$pps" "$drop_rate" "$cpu_usage"; then
            # Optimize affinity after queue changes
            optimize_interrupt_affinity "$CURRENT_QUEUES"
            optimize_process_affinity "$CURRENT_QUEUES"
        fi
        
        # Wait before next check
        sleep "${MONITOR_INTERVAL:-10}"
    done
}

# Show current scaling status
show_scaling_status() {
    get_system_info
    
    echo "┌─────────────────────────────────────────────────────────────────┐"
    echo "│                    Dynamic Scaling Status                       │"
    echo "├─────────────────────────────────────────────────────────────────┤"
    printf "│ Interface: %-20s Queues: %2s/%-2s                    │\n" "$INTERFACE" "$CURRENT_QUEUES" "$MAX_QUEUES"
    
    local metrics=($(get_performance_metrics))
    local pps="${metrics[0]:-0}"
    local drop_rate="${metrics[1]:-0.000}"
    
    printf "│ Current PPS: %-15s Drop Rate: %-10s         │\n" "$pps" "${drop_rate}%"
    printf "│ Scale Up Threshold: %-10s Scale Down: %-10s     │\n" "$HIGH_PPS_THRESHOLD" "$LOW_PPS_THRESHOLD"
    echo "└─────────────────────────────────────────────────────────────────┘"
    
    # Show current IRQ affinity
    echo ""
    echo "Current IRQ Affinity:"
    local irq_numbers=$(grep "$INTERFACE" /proc/interrupts | awk -F: '{print $1}' | tr -d ' ')
    for irq in $irq_numbers; do
        local affinity=$(cat "/proc/irq/$irq/smp_affinity" 2>/dev/null || echo "unknown")
        printf "  IRQ %-3s: CPU mask %s\n" "$irq" "$affinity"
    done
}

# Command line interface
case "${1:-status}" in
    "start"|"monitor")
        run_dynamic_scaling
        ;;
    "status"|"show")
        show_scaling_status
        ;;
    "scale-up")
        get_system_info
        if [ "$CURRENT_QUEUES" -lt "$MAX_QUEUES" ]; then
            target=$((CURRENT_QUEUES + 1))
            print_color "blue" "Manual scale up: $CURRENT_QUEUES → $target queues"
            sudo ethtool -L "$INTERFACE" combined "$target"
            optimize_interrupt_affinity "$target"
            optimize_process_affinity "$target"
        else
            print_color "yellow" "Already at maximum queues ($MAX_QUEUES)"
        fi
        ;;
    "scale-down") 
        get_system_info
        if [ "$CURRENT_QUEUES" -gt 2 ]; then
            target=$((CURRENT_QUEUES - 1))
            print_color "blue" "Manual scale down: $CURRENT_QUEUES → $target queues"
            sudo ethtool -L "$INTERFACE" combined "$target"
            optimize_interrupt_affinity "$target"
            optimize_process_affinity "$target"
        else
            print_color "yellow" "Already at minimum queues (2)"
        fi
        ;;
    "optimize")
        get_system_info
        print_color "blue" "Optimizing CPU affinity for current $CURRENT_QUEUES queues..."
        optimize_interrupt_affinity "$CURRENT_QUEUES"
        optimize_process_affinity "$CURRENT_QUEUES"
        ;;
    "start-injectors")
        get_system_info
        cpu_count=${2:-$CURRENT_QUEUES}
        start_multicore_injectors "$cpu_count"
        ;;
    "max-performance")
        get_system_info
        print_color "blue" "Configuring for maximum performance..."
        # Scale to maximum queues
        if [ "$CURRENT_QUEUES" -lt "$MAX_QUEUES" ]; then
            sudo ethtool -L "$INTERFACE" combined "$MAX_QUEUES"
            CURRENT_QUEUES="$MAX_QUEUES"
        fi
        # Optimize affinity
        optimize_interrupt_affinity "$CURRENT_QUEUES"
        # Start multi-core injectors
        pkill -f "packet_injector" 2>/dev/null || true
        sleep 1
        start_multicore_injectors "$CURRENT_QUEUES"
        ;;
    "help")
        echo "Dynamic XDP Scaling Usage:"
        echo "  $0 start           - Start dynamic scaling monitor"  
        echo "  $0 status          - Show current scaling status"
        echo "  $0 scale-up        - Manually add one queue"
        echo "  $0 scale-down      - Manually remove one queue"
        echo "  $0 optimize        - Optimize CPU affinity"
        echo "  $0 start-injectors [N] - Start N packet_injector instances"
        echo "  $0 max-performance - Scale to max queues + multi-core injectors"
        ;;
    *)
        print_color "red" "Unknown command: $1"
        $0 help
        exit 1
        ;;
esac