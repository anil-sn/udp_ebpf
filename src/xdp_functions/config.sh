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
    INTERFACE="${INTERFACE:-ens5}"
    TARGET_INTERFACE="${TARGET_INTERFACE:-ens6}"
    NAT_IP="${NAT_IP:-172.30.82.95}"
    NAT_PORT="${NAT_PORT:-8081}"
    SOURCE_PORT="${SOURCE_PORT:-31765}"
    STATS_INTERVAL="${STATS_INTERVAL:-5}"
    LOG_FILE="${LOG_FILE:-}"  # Disable logging by default to prevent memory bloat
    TARGET_PPS="${TARGET_PPS:-85000}"
    PERFORMANCE_THRESHOLD="${PERFORMANCE_THRESHOLD:-60000}"
    DEBUG_LEVEL="${DEBUG_LEVEL:-0}"
    XDP_MODE="${XDP_MODE:-auto}"
    ENABLE_COLORS="${ENABLE_COLORS:-true}"
    MAX_RETRIES="${MAX_RETRIES:-3}"
    RETRY_DELAY="${RETRY_DELAY:-2}"
    
    print_color "yellow" "Using default configuration values"
}

# Validate configuration with comprehensive checks
validate_configuration() {
    local errors=()
    
    # Check required variables
    [ -z "$INTERFACE" ] && errors+=("INTERFACE not set")
    [ -z "$TARGET_INTERFACE" ] && errors+=("TARGET_INTERFACE not set")
    
    # Validate IP address format
    if ! [[ "$NAT_IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        errors+=("Invalid NAT_IP format: $NAT_IP")
    else
        # Check IP address ranges (0-255)
        IFS='.' read -ra ADDR <<< "$NAT_IP"
        for octet in "${ADDR[@]}"; do
            if [ "$octet" -lt 0 ] || [ "$octet" -gt 255 ]; then
                errors+=("Invalid NAT_IP octet: $octet in $NAT_IP")
                break
            fi
        done
    fi
    
    # Validate port ranges
    if ! validate_numeric "$NAT_PORT" "NAT_PORT" || [ "$NAT_PORT" -lt 1 ] || [ "$NAT_PORT" -gt 65535 ]; then
        errors+=("Invalid NAT_PORT: $NAT_PORT (must be 1-65535)")
    fi
    
    if ! validate_numeric "$SOURCE_PORT" "SOURCE_PORT" || [ "$SOURCE_PORT" -lt 1 ] || [ "$SOURCE_PORT" -gt 65535 ]; then
        errors+=("Invalid SOURCE_PORT: $SOURCE_PORT (must be 1-65535)")
    fi
    
    # Validate numeric settings
    if ! validate_numeric "$TARGET_PPS" "TARGET_PPS" || [ "$TARGET_PPS" -lt 1000 ]; then
        errors+=("Invalid TARGET_PPS: $TARGET_PPS (must be >= 1000)")
    fi
    
    if ! validate_numeric "$STATS_INTERVAL" "STATS_INTERVAL" || [ "$STATS_INTERVAL" -lt 1 ] || [ "$STATS_INTERVAL" -gt 60 ]; then
        errors+=("Invalid STATS_INTERVAL: $STATS_INTERVAL (must be 1-60 seconds)")
    fi
    
    # Check interfaces exist
    if ! check_interface_exists "$INTERFACE" 2>/dev/null; then
        errors+=("Input interface '$INTERFACE' not found")
    fi
    
    if ! check_interface_exists "$TARGET_INTERFACE" 2>/dev/null; then
        errors+=("Target interface '$TARGET_INTERFACE' not found")
    fi
    
    # Report errors
    if [ ${#errors[@]} -gt 0 ]; then
        print_color "red" "Configuration validation failed:"
        for error in "${errors[@]}"; do
            print_color "red" "  - $error"
        done
        return 1
    fi
    
    print_color "green" "Configuration validation passed"
    return 0
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