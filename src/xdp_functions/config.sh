#!/bin/bash
# XDP Pipeline - Configuration Management

# Load configuration from .env file
load_configuration() {
    local config_file="${SCRIPT_DIR}/../.env"
    
    if [ -f "$config_file" ]; then
        # Export all variables from .env
        set -a
        source "$config_file"
        set +a
        print_color "green" "✓ Configuration loaded from $config_file"
    else
        print_color "yellow" "⚠ Warning: .env file not found, using defaults"
        load_default_config
    fi
    
    # Set color variables
    if [ "${ENABLE_COLORS:-true}" = "true" ]; then
        RED='\033[0;31m'
        GREEN='\033[0;32m'
        YELLOW='\033[1;33m'
        BLUE='\033[0;34m'
        CYAN='\033[0;36m'
        NC='\033[0m'
    else
        RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; NC=''
    fi
    
    # Validate required configuration
    validate_configuration
}

# Load default configuration
load_default_config() {
    INTERFACE="${INTERFACE:-ens4}"
    TARGET_INTERFACE="${TARGET_INTERFACE:-ens5}"
    NAT_IP="${NAT_IP:-10.2.41.17}"
    NAT_PORT="${NAT_PORT:-8081}"
    SOURCE_PORT="${SOURCE_PORT:-42844}"
    STATS_INTERVAL="${STATS_INTERVAL:-5}"
    LOG_FILE="${LOG_FILE:-/tmp/vxlan_loader.log}"
    TARGET_PPS="${TARGET_PPS:-85000}"
    PERFORMANCE_THRESHOLD="${PERFORMANCE_THRESHOLD:-60000}"
    DEBUG_LEVEL="${DEBUG_LEVEL:-0}"
    XDP_MODE="${XDP_MODE:-auto}"
    ENABLE_COLORS="${ENABLE_COLORS:-true}"
}

# Validate configuration
validate_configuration() {
    local errors=()
    
    # Check required variables
    [ -z "$INTERFACE" ] && errors+=("INTERFACE not set")
    [ -z "$TARGET_INTERFACE" ] && errors+=("TARGET_INTERFACE not set")
    
    # Validate IP address
    if ! [[ "$NAT_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        errors+=("Invalid NAT_IP: $NAT_IP")
    fi
    
    # Validate ports
    if [ "$NAT_PORT" -lt 1 ] || [ "$NAT_PORT" -gt 65535 ]; then
        errors+=("Invalid NAT_PORT: $NAT_PORT")
    fi
    
    if [ "$SOURCE_PORT" -lt 1 ] || [ "$SOURCE_PORT" -gt 65535 ]; then
        errors+=("Invalid SOURCE_PORT: $SOURCE_PORT")
    fi
    
    if [ ${#errors[@]} -gt 0 ]; then
        print_color "red" "Configuration errors:"
        for error in "${errors[@]}"; do
            print_color "red" "  • $error"
        done
        exit 1
    fi
}

# Show current configuration
show_configuration() {
    echo "┌─────────────────────────────────────────────────────────┐"
    echo "│                 Pipeline Configuration                  │"
    echo "├─────────────────────────────────────────────────────────┤"
    printf "│ %-20s : %-30s │\n" "Interface" "$INTERFACE"
    printf "│ %-20s : %-30s │\n" "Target Interface" "$TARGET_INTERFACE"
    printf "│ %-20s : %-30s │\n" "NAT IP" "$NAT_IP"
    printf "│ %-20s : %-30s │\n" "NAT Port" "$NAT_PORT"
    printf "│ %-20s : %-30s │\n" "Source Port" "$SOURCE_PORT"
    printf "│ %-20s : %-30s │\n" "Stats Interval" "${STATS_INTERVAL}s"
    printf "│ %-20s : %-30s │\n" "Target PPS" "$TARGET_PPS"
    printf "│ %-20s : %-30s │\n" "XDP Mode" "$XDP_MODE"
    printf "│ %-20s : %-30s │\n" "Debug Level" "$DEBUG_LEVEL"
    echo "└─────────────────────────────────────────────────────────┘"
}