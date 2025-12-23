#!/bin/bash
# XDP UDP DF Modifier - Safe Production Deployment Script
#
# This script provides safer deployment with proper validation,
# rollback capabilities, and non-destructive defaults.

set -e

# Configuration
PROGRAM_NAME="udp_df_modifier_xdp"
SERVICE_NAME="xdp-udp-df-modifier"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/xdp-udp-modifier"
LOG_DIR="/var/log/xdp-udp-modifier"
BPF_PROGRAM="udp_df_modifier.bpf.o"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions - minimal output for production
log() {
    echo "[INFO] $1"
}

error() {
    echo "[ERROR] $1" >&2
}

success() {
    echo "[SUCCESS] $1"
}

warning() {
    echo "[WARNING] $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        echo "Usage: sudo $0 <command> [interface]"
        exit 1
    fi
}

# Validate network interface
validate_interface() {
    local interface=$1
    
    if [[ -z "$interface" ]]; then
        error "Interface name required"
        echo "Available: $(ls /sys/class/net/ | tr '\n' ' ')"
        exit 1
    fi
    
    if ! ip link show "$interface" &>/dev/null; then
        error "Interface '$interface' not found"
        echo "Available: $(ls /sys/class/net/ | tr '\n' ' ')"
        exit 1
    fi
    
    local state=$(cat /sys/class/net/$interface/operstate 2>/dev/null || echo "unknown")
    if [[ "$state" == "down" ]]; then
        warning "Interface $interface is DOWN"
        read -p "Continue? (y/N): " -n 1 -r
        echo
        [[ ! $REPLY =~ ^[Yy]$ ]] && exit 1
    fi
}

# Check for existing XDP programs
check_existing_xdp() {
    local interface=$1
    local existing=$(ip link show "$interface" | grep -o "xdpgeneric\|xdpdrv\|xdpoffload" || true)
    
    if [[ -n "$existing" ]]; then
        warning "XDP program already attached to $interface ($existing)"
        read -p "Replace existing XDP program? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
        
        log "Removing existing XDP program..."
        ip link set "$interface" xdp off || true
    fi
}

# Install programs with validation
install_programs() {
    log "Installing XDP UDP DF modifier programs..."
    
    # Validate build artifacts exist
    if [[ ! -f "$PROGRAM_NAME" ]]; then
        error "Program $PROGRAM_NAME not found. Build it first with: make -f Makefile_xdp"
        exit 1
    fi
    
    if [[ ! -f "$BPF_PROGRAM" ]]; then
        error "eBPF program $BPF_PROGRAM not found. Build it first with: make -f Makefile_xdp"
        exit 1
    fi
    
    # Create directories with proper permissions
    mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR"
    chmod 755 "$INSTALL_DIR" "$CONFIG_DIR"
    chmod 750 "$LOG_DIR"
    
    # Install programs
    install -m 755 "$PROGRAM_NAME" "$INSTALL_DIR/"
    install -m 644 "$BPF_PROGRAM" "$INSTALL_DIR/"
    
    # Create basic configuration file (user must customize)
    if [[ ! -f "$CONFIG_DIR/config" ]]; then
        cat > "$CONFIG_DIR/config" << EOF
# XDP UDP DF Modifier Configuration
# IMPORTANT: Review and customize these settings for your environment

# Interface to attach XDP program (MUST be set by administrator)
INTERFACE=CHANGEME

# Statistics update interval in seconds
STATS_INTERVAL=5

# Log level (debug, info, warning, error)
LOG_LEVEL=info

# Enable monitoring
ENABLE_MONITORING=true
EOF
        warning "Configuration file created at $CONFIG_DIR/config"
        warning "You MUST edit this file and set the correct INTERFACE before starting"
    fi
    
    success "Programs installed successfully"
}

# Create systemd service for XDP program
create_service() {
    local interface=$1
    log "Creating systemd service for interface $interface..."
    
    cat << EOF > /etc/systemd/system/${SERVICE_NAME}.service
[Unit]
Description=eBPF XDP UDP DF Modifier
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/$PROGRAM_NAME $interface
Restart=always
RestartSec=5
KillSignal=SIGTERM
TimeoutStopSec=30
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable ${SERVICE_NAME}
}

# Attach XDP program to interface
attach_xdp() {
    local interface=$1
    
    validate_interface "$interface"
    check_existing_xdp "$interface"
    
    log "Attaching XDP program to interface $interface..."
    create_service "$interface"
    
    log "Starting XDP service..."
    systemctl start ${SERVICE_NAME}
    
    # Verify attachment
    if systemctl is-active --quiet ${SERVICE_NAME} && ip link show "$interface" | grep -q xdp; then
        success "XDP service started and program attached to $interface"
        log "Use 'systemctl status ${SERVICE_NAME}' to monitor"
        log "Use 'journalctl -u ${SERVICE_NAME} -f' to view logs"
    else
        error "Service failed to start. Check: journalctl -u ${SERVICE_NAME}"
        exit 1
    fi
}

# Detach XDP program
detach_xdp() {
    local interface=$1
    
    # Stop systemd service first
    if systemctl is-active --quiet ${SERVICE_NAME}; then
        log "Stopping XDP service..."
        systemctl stop ${SERVICE_NAME}
        systemctl disable ${SERVICE_NAME}
    fi
    
    if [[ -z "$interface" ]]; then
        # Try to detach from all interfaces with XDP
        log "Searching for interfaces with XDP programs..."
        local interfaces=$(ip link show | grep -B1 xdp | grep -E '^[0-9]+:' | cut -d: -f2 | tr -d ' ')
        
        if [[ -z "$interfaces" ]]; then
            log "No XDP programs found"
            return 0
        fi
        
        for iface in $interfaces; do
            log "Detaching XDP from $iface..."
            ip link set "$iface" xdp off || warning "Failed to detach from $iface"
        done
    else
        if ! ip link show "$interface" &>/dev/null; then
            error "Interface '$interface' does not exist"
            exit 1
        fi
        
        log "Detaching XDP program from $interface..."
        ip link set "$interface" xdp off || {
            error "Failed to detach XDP program from $interface"
            exit 1
        }
        success "XDP program detached from $interface"
    fi
}

# Start monitoring (non-service mode)
start_monitoring() {
    local interface=$1
    
    validate_interface "$interface"
    
    if ! ip link show "$interface" | grep -q xdp; then
        error "No XDP program attached to $interface"
        echo "Attach first with: $0 attach $interface"
        exit 1
    fi
    
    log "Starting monitoring for $interface (Ctrl+C to stop)"
    exec "$INSTALL_DIR/$PROGRAM_NAME" "$interface"
}

# Show status
show_status() {
    echo "XDP Status:"
    
    local found=false
    for iface in $(ls /sys/class/net/); do
        if ip link show "$iface" 2>/dev/null | grep -q xdp; then
            echo "  $iface: Active"
            found=true
        fi
    done
    
    if ! $found; then
        echo "  No active XDP programs"
    fi
    
    echo "Installation:"
    if [[ -f "$INSTALL_DIR/$PROGRAM_NAME" ]]; then
        echo "  Programs: Installed"
    else
        echo "  Programs: Not installed"
    fi
    
    if [[ -f "$CONFIG_DIR/config" ]]; then
        local iface=$(grep "^INTERFACE=" "$CONFIG_DIR/config" 2>/dev/null | cut -d= -f2)
        if [[ "$iface" == "CHANGEME" ]]; then
            echo "  Config: Needs customization"
        else
            echo "  Config: Ready ($iface)"
        fi
    else
        echo "  Config: Not created"
    fi
}

# Main script logic
case "${1:-}" in
    install)
        check_root
        install_programs
        ;;
    attach)
        check_root
        interface=${2:-}
        attach_xdp "$interface"
        ;;
    detach)
        check_root
        interface=${2:-}
        detach_xdp "$interface"
        ;;
    monitor)
        check_root
        interface=${2:-}
        start_monitoring "$interface"
        ;;
    status)
        show_status
        ;;
    *)
        echo "XDP UDP DF Modifier - Safe Production Deployment"
        echo
        echo "Usage: $0 <command> [interface]"
        echo
        echo "Commands:"
        echo "  install           - Install programs to system"
        echo "  attach <interface> - Attach XDP program to interface"
        echo "  detach [interface] - Detach XDP program (all interfaces if none specified)"
        echo "  monitor <interface> - Start monitoring (requires attached program)"
        echo "  status            - Show current status"
        echo
        echo "Examples:"
        echo "  $0 install"
        echo "  $0 attach eth0"
        echo "  $0 monitor eth0"
        echo "  $0 detach eth0"
        echo "  $0 status"
        exit 1
        ;;
esac