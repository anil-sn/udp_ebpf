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
        echo "Required command not found: $cmd"
        return 1
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
    local spinstr='|/-\'
    
    while kill -0 $pid 2>/dev/null; do
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
    
    while [ $count -lt $timeout ]; do
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
  ./xdp.sh test           # Run tests
  ./xdp.sh clean          # Clean up everything
EOF
}