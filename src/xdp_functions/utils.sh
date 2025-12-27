#!/bin/bash
# XDP Pipeline - Utility Functions

# Initialize logging
init_logging() {
    local log_file="${1:-/tmp/xdp_pipeline.log}"
    exec 3>&1 4>&2
    exec 1> >(tee -a "$log_file" >&3)
    exec 2> >(tee -a "$log_file" >&4)
    echo "[$(date)] XDP Pipeline logging initialized" >> "$log_file"
}

# Fix terminal settings
fix_terminal() {
    stty sane 2>/dev/null
    stty opost onlcr 2>/dev/null
    printf "\r\033[0m"
    tput cnorm 2>/dev/null
    tput sgr0 2>/dev/null
}

# Convert integer IP to dotted decimal
int_to_ip() {
    local ip_int="$1"
    printf "%d.%d.%d.%d" \
        $((ip_int & 0xFF)) \
        $(((ip_int >> 8) & 0xFF)) \
        $(((ip_int >> 16) & 0xFF)) \
        $(((ip_int >> 24) & 0xFF))
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then 
        print_color "red" "Please run as root (use sudo)"
        exit 1
    fi
}

# Check command availability
check_command() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        print_color "red" "ERROR: Required command not found: $cmd"
        return 1
    fi
    return 0
}

# Retry mechanism for operations
retry_operation() {
    local max_attempts="${1:-3}"
    local delay="${2:-2}"
    local description="${3:-operation}"
    shift 3
    
    local attempt=1
    while [ "$attempt" -le "$max_attempts" ]; do
        if "$@"; then
            return 0
        fi
        
        if [ "$attempt" -lt "$max_attempts" ]; then
            print_color "yellow" "WARNING: $description failed (attempt $attempt/$max_attempts), retrying in ${delay}s..."
            sleep "$delay"
        else
            print_color "red" "ERROR: $description failed after $max_attempts attempts"
            return 1
        fi
        
        ((attempt++))
    done
}

# Pre-populate ARP table to help MAC resolution
populate_arp_table() {
    local target_ip="$1"
    local interface="${2:-$TARGET_INTERFACE}"
    
    if [ -z "$target_ip" ]; then
        return 1
    fi
    
    print_color "blue" "Pre-populating ARP table for $target_ip..."
    
    # Check if already in ARP table
    if ip neighbor show "$target_ip" | grep -q "lladdr"; then
        local mac=$(ip neighbor show "$target_ip" | awk '{print $5}' | head -1)
        print_color "green" "✓ MAC address already known: $target_ip -> $mac"
        return 0
    fi
    
    # Method 1: arping (primary method since ICMP/ping often blocked)
    if command -v arping >/dev/null 2>&1 && [ -n "$interface" ]; then
        print_color "blue" "  Using arping method (primary)..."
        timeout 10 arping -c 5 -w 5 -I "$interface" "$target_ip" >/dev/null 2>&1
        
        # Check if arping succeeded
        if ip neighbor show "$target_ip" | grep -q "lladdr"; then
            local mac=$(ip neighbor show "$target_ip" | awk '{print $5}' | head -1)
            print_color "green" "✓ arping successful: $target_ip -> $mac"
            return 0
        fi
    else
        print_color "yellow" "  arping not available or no interface specified"
    fi
    
    # Method 2: Connection attempts to common ports (TCP SYN packets)
    print_color "blue" "  Trying TCP connection method..."
    for port in 80 443 22 8080 8081 8443 3389; do
        timeout 2 nc -w 1 "$target_ip" "$port" </dev/null >/dev/null 2>&1 || true
    done
    
    # Method 3: UDP connection attempt to target port if specified
    if [ -n "$NAT_PORT" ] && [ "$NAT_PORT" != "0" ]; then
        print_color "blue" "  Trying UDP connection to port $NAT_PORT..."
        timeout 2 nc -u -w 1 "$target_ip" "$NAT_PORT" </dev/null >/dev/null 2>&1 || true
    fi
    
    # Method 4: ip neigh probe
    print_color "blue" "  Using ip neigh probe method..."
    sudo ip neigh add "$target_ip" dev "$interface" nud probe >/dev/null 2>&1 || \
    sudo ip neigh replace "$target_ip" dev "$interface" nud probe >/dev/null 2>&1 || true
    
    # Wait for ARP resolution
    sleep 3
    
    # Check if we succeeded
    if ip neighbor show "$target_ip" | grep -q "lladdr"; then
        local mac=$(ip neighbor show "$target_ip" | awk '{print $5}' | head -1)
        print_color "green" "✓ Successfully resolved MAC: $target_ip -> $mac"
        return 0
    else
        print_color "yellow" "⚠ Could not pre-resolve MAC for $target_ip"
        print_color "blue" "  This may cause startup delays, but vxlan_loader will retry with more methods"
        return 1
    fi
}

# Validate numeric input
validate_numeric() {
    local value="$1"
    local name="${2:-value}"
    
    if ! [[ "$value" =~ ^[0-9]+$ ]]; then
        print_color "red" "ERROR: Invalid $name: '$value' (must be numeric)"
        return 1
    fi
    return 0
}

# Apply system tuning for high-performance packet processing
apply_system_tuning() {
    print_color "blue" "Applying system tuning for high-performance packet processing..."
    
    local tuning_applied=false
    local current_rmem_max
    local current_wmem_max
    local current_rt_runtime
    local current_netdev_budget
    
    current_rmem_max=$(sysctl -n net.core.rmem_max 2>/dev/null || echo "0")
    current_wmem_max=$(sysctl -n net.core.wmem_max 2>/dev/null || echo "0")
    current_rt_runtime=$(sysctl -n kernel.sched_rt_runtime_us 2>/dev/null || echo "950000")
    current_netdev_budget=$(sysctl -n net.core.netdev_budget 2>/dev/null || echo "300")
    
    # Network buffer tuning for high throughput
    if [ "$current_rmem_max" -lt 134217728 ]; then
        print_color "yellow" "  • Increasing receive buffer size: $(( current_rmem_max / 1024 / 1024 ))MB → 128MB"
        sudo sysctl -w net.core.rmem_max=134217728 >/dev/null 2>&1 && tuning_applied=true
    else
        print_color "green" "  ✓ Receive buffer size optimal: $(( current_rmem_max / 1024 / 1024 ))MB"
    fi
    
    if [ "$current_wmem_max" -lt 134217728 ]; then
        print_color "yellow" "  • Increasing send buffer size: $(( current_wmem_max / 1024 / 1024 ))MB → 128MB"
        sudo sysctl -w net.core.wmem_max=134217728 >/dev/null 2>&1 && tuning_applied=true
    else
        print_color "green" "  ✓ Send buffer size optimal: $(( current_wmem_max / 1024 / 1024 ))MB"
    fi
    
    # Network device budget for packet processing
    if [ "$current_netdev_budget" -lt 600 ]; then
        print_color "yellow" "  • Increasing network device budget: $current_netdev_budget → 600"
        sudo sysctl -w net.core.netdev_budget=600 >/dev/null 2>&1 && tuning_applied=true
    else
        print_color "green" "  ✓ Network device budget optimal: $current_netdev_budget"
    fi
    
    # Real-time scheduling optimization for packet processing
    if [ "$current_rt_runtime" -ne 950000 ]; then
        print_color "yellow" "  • Optimizing real-time scheduler: $current_rt_runtime → 950000µs"
        sudo sysctl -w kernel.sched_rt_runtime_us=950000 >/dev/null 2>&1 && tuning_applied=true
    else
        print_color "green" "  ✓ Real-time scheduler optimal: ${current_rt_runtime}µs"
    fi
    
    # Ring buffer parameters for XDP
    local current_rx_ring
    local max_rx_ring
    
    current_rx_ring=$(ethtool -g "$INTERFACE" 2>/dev/null | grep "RX:" | tail -1 | awk '{print $2}' || echo "0")
    max_rx_ring=$(ethtool -g "$INTERFACE" 2>/dev/null | grep "RX:" | head -1 | awk '{print $2}' || echo "0")
    
    if [ "$current_rx_ring" != "0" ] && [ "$max_rx_ring" != "0" ] && [ "$current_rx_ring" -lt "$max_rx_ring" ]; then
        print_color "yellow" "  • Optimizing RX ring buffer: $current_rx_ring → $max_rx_ring"
        if sudo ethtool -G "$INTERFACE" rx "$max_rx_ring" 2>/dev/null; then
            print_color "green" "    ✓ RX ring buffer optimized"
            tuning_applied=true
        else
            print_color "yellow" "    ⚠ RX ring buffer optimization failed (may not be supported)"
        fi
    elif [ "$current_rx_ring" = "$max_rx_ring" ] && [ "$current_rx_ring" != "0" ]; then
        print_color "green" "  ✓ RX ring buffer optimal: $current_rx_ring"
    fi
    
    # CPU scaling governor for performance
    local cpu_gov
    cpu_gov=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo "unknown")
    if [ "$cpu_gov" != "performance" ] && [ "$cpu_gov" != "unknown" ]; then
        print_color "yellow" "  • Setting CPU governor: $cpu_gov → performance"
        if sudo bash -c 'echo performance > /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor' 2>/dev/null; then
            print_color "green" "    ✓ CPU governor set to performance"
            tuning_applied=true
        else
            print_color "yellow" "    ⚠ CPU governor change failed (may not be supported)"
        fi
    elif [ "$cpu_gov" = "performance" ]; then
        print_color "green" "  ✓ CPU governor optimal: $cpu_gov"
    fi
    
    # IRQ affinity optimization
    if command -v irqbalance >/dev/null 2>&1 && pgrep irqbalance >/dev/null; then
        print_color "yellow" "  • Stopping irqbalance for manual IRQ optimization"
        sudo systemctl stop irqbalance 2>/dev/null || sudo service irqbalance stop 2>/dev/null || true
        tuning_applied=true
    fi
    
    # Set IRQ affinity for network interface (distribute across first 4 CPUs)
    local irq_nums
    irq_nums=$(grep "$INTERFACE" /proc/interrupts 2>/dev/null | cut -d: -f1 | tr -d ' ' || true)
    if [ -n "$irq_nums" ]; then
        print_color "yellow" "  • Optimizing IRQ affinity for $INTERFACE"
        local cpu_mask=1
        for irq in $irq_nums; do
            if [ -w "/proc/irq/$irq/smp_affinity" ]; then
                printf "%x" $cpu_mask | sudo tee "/proc/irq/$irq/smp_affinity" >/dev/null 2>&1
                cpu_mask=$(( (cpu_mask << 1) % 16 )) # Rotate through CPUs 0-3
                [ $cpu_mask -eq 0 ] && cpu_mask=1
            fi
        done
        print_color "green" "    ✓ IRQ affinity optimized"
        tuning_applied=true
    fi
    
    if [ "$tuning_applied" = true ]; then
        print_color "green" "✓ System tuning applied successfully"
    else
        print_color "green" "✓ System already optimally tuned"
    fi
    
    return 0
}

# Create persistent system tuning configuration
create_persistent_tuning() {
    local sysctl_conf="/etc/sysctl.d/99-xdp-vxlan-performance.conf"
    
    print_color "blue" "Creating persistent system tuning configuration..."
    
    if [ ! -f "$sysctl_conf" ]; then
        cat << 'EOF' | sudo tee "$sysctl_conf" >/dev/null
# XDP VXLAN Pipeline Performance Tuning
# Applied automatically during pipeline startup

# Network buffer sizes for high-throughput packet processing
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728

# Network device processing budget
net.core.netdev_budget = 600

# Real-time scheduler optimization for packet processing
kernel.sched_rt_runtime_us = 950000

# Additional network performance tuning
net.core.netdev_max_backlog = 5000
net.core.rmem_default = 262144
net.core.wmem_default = 262144

# TCP memory tuning
net.ipv4.tcp_rmem = 4096 262144 134217728
net.ipv4.tcp_wmem = 4096 262144 134217728

# Reduce network latency
net.core.busy_read = 50
net.core.busy_poll = 50
EOF
        
        print_color "green" "✓ Created persistent tuning configuration: $sysctl_conf"
        print_color "yellow" "  Settings will be applied automatically on system boot"
    else
        print_color "green" "✓ Persistent tuning configuration already exists: $sysctl_conf"
    fi
    
    return 0
}

# Print colored output
print_color() {
    local color="$1"
    local message="$2"
    
    # Handle case where colors are not yet loaded
    if [ -z "${NC:-}" ]; then
        case "$color" in
            "red") echo -e "\033[0;31m${message}\033[0m" ;;
            "green") echo -e "\033[0;32m${message}\033[0m" ;;
            "yellow") echo -e "\033[1;33m${message}\033[0m" ;;
            "blue") echo -e "\033[0;34m${message}\033[0m" ;;
            "cyan") echo -e "\033[0;36m${message}\033[0m" ;;
            *) echo -e "${message}" ;;
        esac
    else
        case "$color" in
            "red") echo -e "${RED}${message}${NC}" ;;
            "green") echo -e "${GREEN}${message}${NC}" ;;
            "yellow") echo -e "${YELLOW}${message}${NC}" ;;
            "blue") echo -e "${BLUE}${message}${NC}" ;;
            "cyan") echo -e "${CYAN}${message}${NC}" ;;
            *) echo -e "${message}" ;;
        esac
    fi
}

# Spinner animation for long operations
show_spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\\'
    
    while kill -0 "$pid" 2>/dev/null; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

# Wait for process to start
wait_for_process() {
    local process_pattern="$1"
    local timeout="${2:-10}"
    local count=0
    
    while [ "$count" -lt "$timeout" ]; do
        if pgrep -f "$process_pattern" >/dev/null; then
            return 0
        fi
        sleep 1
        count=$((count + 1))
    done
    return 1
}

# Format bytes in human readable format
format_bytes() {
    local bytes="$1"
    
    if [ "$bytes" -ge 1073741824 ]; then
        echo "$bytes" | awk '{printf "%.2f GB", $1/1073741824}'
    elif [ "$bytes" -ge 1048576 ]; then
        echo "$bytes" | awk '{printf "%.2f MB", $1/1048576}'
    elif [ "$bytes" -ge 1024 ]; then
        echo "$bytes" | awk '{printf "%.2f KB", $1/1024}'
    else
        echo "${bytes} bytes"
    fi
}

# Format numbers with thousand separators
format_number() {
    local num="$1"
    printf "%'d" "$num" 2>/dev/null || echo "$num"
}

# Show usage information
show_usage() {
    cat << EOF
XDP VXLAN Pipeline Control

Usage: ./xdp.sh [COMMAND] [OPTIONS]

Commands:
  start           Start the XDP pipeline
  stop            Stop the XDP pipeline
  restart         Restart the XDP pipeline
  status          Show pipeline status
  stats           Show comprehensive statistics dashboard
  info            Show comprehensive information
  monitor         Real-time monitoring
  pps             Interface PPS monitoring:
                    both - Monitor both incoming and target interfaces (default)
                    incoming - Monitor only incoming interface (ens5)
                    target - Monitor only target interface (ens6)
                    Usage: ./xdp.sh pps [both|incoming|target] [interval] [duration]
  test            Run end-to-end tests
  scale           Dynamic scaling operations:
                    status - Show scaling status
                    max-performance - Configure for maximum performance
                    scale-up - Add one queue manually
                    scale-down - Remove one queue manually
                    optimize - Optimize CPU affinity
                    start-injectors [N] - Start N injector instances
  clean           Clean up everything
  help            Show this help

Configuration:
  Edit .env file or set environment variables:
    INTERFACE, TARGET_INTERFACE, NAT_IP, NAT_PORT,
    SOURCE_PORT, STATS_INTERVAL, TARGET_PPS, etc.

Examples:
  ./xdp.sh start          # Start pipeline
  ./xdp.sh monitor        # Real-time monitoring
  ./xdp.sh pps both       # Monitor PPS on both interfaces  
  ./xdp.sh pps incoming 2 # Monitor incoming interface every 2s
  ./xdp.sh pps target 1 30 # Monitor target interface for 30s
  ./xdp.sh test           # Run tests
  ./xdp.sh clean          # Clean up everything
EOF
}