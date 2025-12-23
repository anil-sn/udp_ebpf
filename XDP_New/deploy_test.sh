#!/bin/bash
# Quick deployment script for testing the VXLAN Pipeline XDP program
# Designed for rapid testing and validation

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Configuration - modify these for your environment
INPUT_INTERFACE="ens5"
TARGET_INTERFACE="ens6" 
NAT_TARGET_IP="10.0.0.100"  # Your AWS_IPSEC_VM_IP
NAT_TARGET_PORT="8080"      # Your AWS_IPSEC_VM_PORT
NAT_SOURCE_PORT="31765"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date +'%H:%M:%S')]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[$(date +'%H:%M:%S')] WARNING:${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%H:%M:%S')] ERROR:${NC} $1"
    exit 1
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root (use sudo)"
    fi
}

check_interfaces() {
    log "Checking network interfaces..."
    
    if ! ip link show "$INPUT_INTERFACE" > /dev/null 2>&1; then
        error "Input interface '$INPUT_INTERFACE' not found"
    fi
    
    if ! ip link show "$TARGET_INTERFACE" > /dev/null 2>&1; then
        warn "Target interface '$TARGET_INTERFACE' not found - will run without forwarding"
        TARGET_INTERFACE=""
    fi
    
    log "✓ Network interfaces validated"
}

build_program() {
    log "Building XDP program..."
    
    if ! make clean; then
        error "Failed to clean previous build"
    fi
    
    if ! make all; then
        error "Failed to build XDP program"
    fi
    
    log "✓ XDP program built successfully"
}

setup_environment() {
    log "Setting up environment for high-performance processing..."
    
    # Enable IP forwarding
    echo 1 > /proc/sys/net/ipv4/ip_forward
    
    # Optimize network buffers for 85K pps
    sysctl -w net.core.rmem_max=16777216 > /dev/null
    sysctl -w net.core.wmem_max=16777216 > /dev/null
    sysctl -w net.core.netdev_max_backlog=5000 > /dev/null
    
    # Set CPU governor to performance (if available)
    for gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
        if [[ -f "$gov" ]]; then
            echo performance > "$gov" 2>/dev/null || true
        fi
    done
    
    log "✓ Environment optimized"
}

check_existing_xdp() {
    log "Checking for existing XDP programs..."
    
    # Check if XDP is already attached to interface
    if ip link show "$INPUT_INTERFACE" | grep -q "xdp"; then
        warn "XDP program already attached to $INPUT_INTERFACE"
        read -p "Remove existing XDP program? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            ip link set "$INPUT_INTERFACE" xdp off
            log "✓ Existing XDP program removed"
        else
            error "Cannot proceed with existing XDP program attached"
        fi
    fi
}

run_program() {
    log "Starting VXLAN Pipeline XDP program..."
    
    # Build command line arguments
    ARGS="-i $INPUT_INTERFACE"
    
    if [[ -n "$TARGET_INTERFACE" ]]; then
        ARGS="$ARGS -t $TARGET_INTERFACE"
    fi
    
    ARGS="$ARGS -a $NAT_TARGET_IP -p $NAT_TARGET_PORT -s $NAT_SOURCE_PORT -v"
    
    log "Command: ./vxlan_loader $ARGS"
    log "Press Ctrl+C to stop the program"
    log "Statistics will be displayed every 5 seconds"
    echo
    
    # Run the program
    ./vxlan_loader $ARGS
}

cleanup() {
    log "Cleaning up..."
    
    # Remove XDP program if attached
    if ip link show "$INPUT_INTERFACE" 2>/dev/null | grep -q "xdp"; then
        ip link set "$INPUT_INTERFACE" xdp off
        log "✓ XDP program detached"
    fi
    
    log "Cleanup complete"
}

show_config() {
    echo
    echo "=== VXLAN Pipeline Test Configuration ==="
    echo "Input Interface:    $INPUT_INTERFACE"
    echo "Target Interface:   ${TARGET_INTERFACE:-"None (kernel forwarding)"}"
    echo "NAT Rule:           port $NAT_SOURCE_PORT -> $NAT_TARGET_IP:$NAT_TARGET_PORT"
    echo "Expected Traffic:   VXLAN packets on port 4789 (VNI 1)"
    echo "Performance Target: 85,000+ packets per second"
    echo "========================================"
    echo
}

main() {
    echo "VXLAN Pipeline XDP - Quick Test Deployment"
    echo "=========================================="
    
    # Setup trap for cleanup on exit
    trap cleanup EXIT
    
    check_root
    show_config
    
    # Validate environment
    check_interfaces
    check_existing_xdp
    
    # Build and setup
    build_program
    setup_environment
    
    # Run the program
    run_program
}

# Handle command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -i|--input)
            INPUT_INTERFACE="$2"
            shift 2
            ;;
        -t|--target)
            TARGET_INTERFACE="$2"
            shift 2
            ;;
        -a|--nat-ip)
            NAT_TARGET_IP="$2"
            shift 2
            ;;
        -p|--nat-port)
            NAT_TARGET_PORT="$2"
            shift 2
            ;;
        -s|--source-port)
            NAT_SOURCE_PORT="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo
            echo "Options:"
            echo "  -i, --input IFACE     Input interface (default: ens5)"
            echo "  -t, --target IFACE    Target interface (default: ens6)"
            echo "  -a, --nat-ip IP       NAT target IP (default: 10.0.0.100)"
            echo "  -p, --nat-port PORT   NAT target port (default: 8080)"
            echo "  -s, --source-port PORT Source port to match (default: 31765)"
            echo "  -h, --help           Show this help"
            echo
            echo "Example:"
            echo "  sudo $0 -i ens5 -t ens6 -a 192.168.1.100 -p 9000"
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            ;;
    esac
done

main