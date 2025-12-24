#!/bin/bash
# VXLAN Pipeline XDP - Unified Deployment, Testing & Monitoring Script
# Combines system validation, deployment, testing, and real-time monitoring

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ============================================================================
# CONFIGURATION - Modify these for your environment
# ============================================================================

# Network Configuration (matching your analysis)
INPUT_INTERFACE="ens4"           # Ingress interface (100.68.16.39)
TARGET_INTERFACE="ens5"          # Egress interface (100.68.32.10)
NAT_TARGET_IP="10.2.41.17"       # Target IP from your hex dump analysis
NAT_TARGET_PORT="8081"           # Target port from your analysis
NAT_SOURCE_PORT="42844"          # Source port from your analysis (10.2.41.20:42844)

# Performance Configuration
TARGET_PPS=85000                 # Target packet processing rate
STATS_INTERVAL=5                 # Statistics reporting interval
MONITOR_DURATION=0               # Monitor duration (0 = indefinite)

# Colors and logging
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Global state
XDP_ATTACHED=0
PROGRAM_PID=0

# ============================================================================
# LOGGING AND UTILITIES
# ============================================================================

timestamp() { date '+%Y-%m-%d %H:%M:%S'; }

log() { echo -e "${GREEN}[$(timestamp)] ✓${NC} $1"; }
warn() { echo -e "${YELLOW}[$(timestamp)] ⚠${NC} $1"; }
error() { echo -e "${RED}[$(timestamp)] ✗${NC} $1"; }
info() { echo -e "${BLUE}[$(timestamp)] ℹ${NC} $1"; }
section() { echo -e "${CYAN}[$(timestamp)] ===${NC} $1 ${CYAN}===${NC}"; }

# ============================================================================
# SYSTEM VALIDATION FUNCTIONS
# ============================================================================

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root (use sudo)"
        exit 1
    fi
}

check_kernel_version() {
    local kernel_version=$(uname -r | cut -d. -f1-2)
    local major=$(echo $kernel_version | cut -d. -f1)
    local minor=$(echo $kernel_version | cut -d. -f2)
    
    if [[ $major -lt 4 ]] || [[ $major -eq 4 && $minor -lt 18 ]]; then
        error "Kernel version $kernel_version is too old. Minimum required: 4.18+"
        return 1
    fi
    
    log "Kernel version: $(uname -r) (✓ compatible)"
}

check_xdp_support() {
    if [[ ! -d /sys/fs/bpf ]]; then
        error "BPF filesystem not mounted. Run: mount -t bpf bpf /sys/fs/bpf"
        return 1
    fi
    
    if ! grep -q "xdp" /proc/kallsyms 2>/dev/null; then
        warn "XDP support may not be available in kernel"
        return 1
    fi
    
    log "XDP support available"
}

check_interfaces() {
    info "Validating network interfaces..."
    
    if ! ip link show "$INPUT_INTERFACE" &>/dev/null; then
        error "Input interface '$INPUT_INTERFACE' not found"
        return 1
    fi
    
    local input_ip=$(ip addr show "$INPUT_INTERFACE" | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
    log "Input interface: $INPUT_INTERFACE ($input_ip)"
    
    if ! ip link show "$TARGET_INTERFACE" &>/dev/null; then
        warn "Target interface '$TARGET_INTERFACE' not found - will use kernel forwarding"
        TARGET_INTERFACE=""
    else
        local target_ip=$(ip addr show "$TARGET_INTERFACE" | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
        log "Target interface: $TARGET_INTERFACE ($target_ip)"
    fi
    
    # Check XDP driver compatibility
    local driver=$(ethtool -i "$INPUT_INTERFACE" 2>/dev/null | grep "driver:" | awk '{print $2}')
    case $driver in
        "ixgbe"|"i40e"|"mlx5_core"|"mlx4_en"|"bnxt_en"|"virtio_net")
            log "XDP-compatible driver: $driver"
            ;;
        *)
            warn "Driver ($driver) may not support native XDP (will use generic mode)"
            ;;
    esac
}

check_build_dependencies() {
    info "Checking build dependencies..."
    
    local missing=0
    
    for cmd in clang gcc make; do
        if ! command -v $cmd &>/dev/null; then
            error "$cmd not found"
            missing=1
        fi
    done
    
    if [[ ! -f /usr/lib/x86_64-linux-gnu/libbpf.a ]] && [[ ! -f /usr/lib/libbpf.a ]]; then
        error "libbpf development library not found"
        error "Install with: apt-get install libbpf-dev"
        missing=1
    fi
    
    if [[ ! -d /lib/modules/$(uname -r)/build ]]; then
        error "Kernel headers not found"
        error "Install with: apt-get install linux-headers-$(uname -r)"
        missing=1
    fi
    
    if [[ $missing -eq 0 ]]; then
        log "All build dependencies satisfied"
    fi
    
    return $missing
}

check_system_performance() {
    info "Analyzing system performance capabilities..."
    
    # CPU Analysis
    local cpu_count=$(nproc)
    local cpu_freq=$(grep "cpu MHz" /proc/cpuinfo | head -1 | awk '{print $4}' | cut -d. -f1)
    
    log "CPU cores: $cpu_count, Frequency: ${cpu_freq}MHz"
    
    if [[ $cpu_freq -lt 2000 ]]; then
        warn "CPU frequency ($cpu_freq MHz) is low for $TARGET_PPS PPS processing"
    fi
    
    # Memory Analysis
    local total_mem=$(free -m | awk '/^Mem:/{print $2}')
    log "Available memory: ${total_mem}MB"
    
    if [[ $total_mem -lt 4096 ]]; then
        warn "System has ${total_mem}MB RAM - may be insufficient for high-rate processing"
    fi
    
    # Network buffer analysis
    local rmem_max=$(sysctl -n net.core.rmem_max)
    local netdev_backlog=$(sysctl -n net.core.netdev_max_backlog)
    
    if [[ $rmem_max -lt 16777216 ]]; then
        warn "net.core.rmem_max ($rmem_max) is low for high-rate traffic"
    fi
    
    if [[ $netdev_backlog -lt 5000 ]]; then
        warn "net.core.netdev_max_backlog ($netdev_backlog) is low"
    fi
}

# ============================================================================
# SYSTEM OPTIMIZATION FUNCTIONS
# ============================================================================

optimize_system() {
    section "Optimizing system for 85K+ PPS processing"
    
    # Network optimizations
    info "Configuring network parameters..."
    sysctl -w net.core.rmem_max=134217728 > /dev/null
    sysctl -w net.core.rmem_default=67108864 > /dev/null
    sysctl -w net.core.netdev_max_backlog=30000 > /dev/null
    sysctl -w net.core.netdev_budget=600 > /dev/null
    echo 1 > /proc/sys/net/ipv4/ip_forward
    log "Network parameters optimized"
    
    # CPU performance
    info "Setting CPU performance mode..."
    for gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
        if [[ -f "$gov" ]]; then
            echo performance > "$gov" 2>/dev/null || true
        fi
    done
    log "CPU governor set to performance mode"
    
    # Interface optimizations
    info "Optimizing network interfaces..."
    
    # Disable GRO (critical for jumbo frame processing as per user analysis)
    ethtool -K "$INPUT_INTERFACE" gro off 2>/dev/null || warn "Could not disable GRO on $INPUT_INTERFACE"
    ethtool -K "$INPUT_INTERFACE" lro off 2>/dev/null || true
    ethtool -K "$INPUT_INTERFACE" tso off 2>/dev/null || true
    
    if [[ -n "$TARGET_INTERFACE" ]]; then
        ethtool -K "$TARGET_INTERFACE" gro off 2>/dev/null || true
        ethtool -K "$TARGET_INTERFACE" lro off 2>/dev/null || true
    fi
    
    # Set ring buffer sizes
    ethtool -G "$INPUT_INTERFACE" rx 4096 tx 4096 2>/dev/null || warn "Could not set ring buffer sizes"
    
    # Set interrupt coalescing for low latency
    ethtool -C "$INPUT_INTERFACE" rx-usecs 1 rx-frames 1 2>/dev/null || true
    
    log "Interface optimizations applied"
}

# ============================================================================
# BUILD AND DEPLOYMENT FUNCTIONS
# ============================================================================

build_program() {
    section "Building XDP VXLAN Pipeline"
    
    if ! make clean &>/dev/null; then
        warn "Clean failed (may be normal if no previous build)"
    fi
    
    if ! make all; then
        error "Build failed - check dependencies and source code"
        return 1
    fi
    
    log "XDP program compiled successfully"
    
    # Verify binary exists
    if [[ ! -f "./src/vxlan_loader" ]]; then
        error "vxlan_loader binary not found after build"
        return 1
    fi
    
    log "Binary validation passed"
}

check_existing_xdp() {
    info "Checking for existing XDP programs on $INPUT_INTERFACE..."
    
    if ip link show "$INPUT_INTERFACE" | grep -q "xdp"; then
        warn "XDP program already attached to $INPUT_INTERFACE"
        info "Removing existing XDP program..."
        ip link set "$INPUT_INTERFACE" xdp off || warn "Failed to remove existing XDP program"
        sleep 1
    fi
}

# ============================================================================
# MONITORING FUNCTIONS
# ============================================================================

display_configuration() {
    section "VXLAN Pipeline Configuration"
    cat << EOF
📡 Network Configuration:
   Input Interface:     $INPUT_INTERFACE
   Target Interface:    ${TARGET_INTERFACE:-"None (kernel forwarding)"}
   
🔄 NAT Configuration (from your packet analysis):
   Source Port Match:   $NAT_SOURCE_PORT (e.g., 10.2.41.20:42844)
   Target Destination:  $NAT_TARGET_IP:$NAT_TARGET_PORT
   
🎯 Performance Targets:
   Packet Rate:         $TARGET_PPS PPS
   Processing Mode:     ${TARGET_INTERFACE:+XDP_REDIRECT}${TARGET_INTERFACE:-kernel forwarding}
   Jumbo Frame Support: 2852B → 1500B (DF bit clearing)
   
📊 Monitoring:
   Statistics Interval: ${STATS_INTERVAL}s
   Monitor Duration:    ${MONITOR_DURATION:-∞}s
EOF
}

monitor_performance() {
    local start_time=$(date +%s)
    local iteration=0
    
    section "Real-time Performance Monitoring"
    info "Monitoring XDP pipeline performance (Ctrl+C to stop)..."
    echo
    
    # Header
    printf "%-8s %-10s %-10s %-8s %-12s %-10s %-8s\n" \
           "TIME" "PPS" "VXLAN_PPS" "NAT_HIT%" "REDIRECTED" "ERRORS" "STATUS"
    printf "%-8s %-10s %-10s %-8s %-12s %-10s %-8s\n" \
           "--------" "----------" "----------" "--------" "------------" "----------" "--------"
    
    while true; do
        local current_time=$(date +%H:%M:%S)
        
        # Get statistics from the running program (would need to implement stats reading)
        # For now, simulate with system network statistics
        local rx_packets_before=$(cat /sys/class/net/$INPUT_INTERFACE/statistics/rx_packets)
        sleep $STATS_INTERVAL
        local rx_packets_after=$(cat /sys/class/net/$INPUT_INTERFACE/statistics/rx_packets)
        
        local pps=$(((rx_packets_after - rx_packets_before) / STATS_INTERVAL))
        
        # Performance status
        local status="🔴"
        if [[ $pps -ge $TARGET_PPS ]]; then
            status="🟢"
        elif [[ $pps -ge $((TARGET_PPS * 70 / 100)) ]]; then
            status="🟡"
        fi
        
        printf "%-8s %-10d %-10s %-8s %-12s %-10s %-8s\n" \
               "$current_time" "$pps" "N/A" "N/A" "N/A" "N/A" "$status"
        
        ((iteration++))
        
        # Check if monitoring duration exceeded
        if [[ $MONITOR_DURATION -gt 0 ]]; then
            local elapsed=$(($(date +%s) - start_time))
            if [[ $elapsed -ge $MONITOR_DURATION ]]; then
                break
            fi
        fi
    done
}

run_program_with_monitoring() {
    section "Launching XDP VXLAN Pipeline"
    
    # Build command line arguments
    local args="-i $INPUT_INTERFACE"
    
    if [[ -n "$TARGET_INTERFACE" ]]; then
        args="$args -t $TARGET_INTERFACE"
    fi
    
    args="$args -a $NAT_TARGET_IP -p $NAT_TARGET_PORT -s $NAT_SOURCE_PORT"
    args="$args -I $STATS_INTERVAL -v"
    
    info "Command: ./vxlan_loader $args"
    log "Starting VXLAN pipeline..."
    
    # Start the program in background for monitoring
    ./vxlan_loader $args &
    PROGRAM_PID=$!
    XDP_ATTACHED=1
    
    sleep 2  # Give program time to start
    
    if ! kill -0 $PROGRAM_PID 2>/dev/null; then
        error "XDP program failed to start"
        return 1
    fi
    
    log "XDP program started (PID: $PROGRAM_PID)"
    
    # Start monitoring
    monitor_performance
}

# ============================================================================
# CLEANUP FUNCTIONS
# ============================================================================

cleanup() {
    section "Cleaning up VXLAN Pipeline"
    
    # Stop program if running
    if [[ $PROGRAM_PID -gt 0 ]]; then
        info "Stopping XDP program (PID: $PROGRAM_PID)..."
        kill -TERM $PROGRAM_PID 2>/dev/null || true
        sleep 2
        kill -KILL $PROGRAM_PID 2>/dev/null || true
    fi
    
    # Remove XDP program if attached
    if [[ $XDP_ATTACHED -eq 1 ]] && ip link show "$INPUT_INTERFACE" 2>/dev/null | grep -q "xdp"; then
        info "Detaching XDP program from $INPUT_INTERFACE..."
        ip link set "$INPUT_INTERFACE" xdp off || warn "Failed to detach XDP program"
    fi
    
    log "Cleanup complete"
}

# ============================================================================
# MAIN EXECUTION FUNCTIONS
# ============================================================================

run_system_check() {
    section "System Readiness Validation"
    
    local failed=0
    
    check_kernel_version || failed=1
    check_xdp_support || failed=1
    check_interfaces || failed=1
    check_build_dependencies || failed=1
    check_system_performance
    
    if [[ $failed -eq 0 ]]; then
        log "✅ System validation passed - ready for deployment"
        return 0
    else
        error "❌ System validation failed - fix issues before proceeding"
        return 1
    fi
}

run_deployment() {
    section "XDP Pipeline Deployment"
    
    check_existing_xdp
    optimize_system
    build_program || return 1
    
    log "✅ Deployment preparation complete"
}

run_full_pipeline() {
    display_configuration
    echo
    
    run_system_check || exit 1
    echo
    
    run_deployment || exit 1
    echo
    
    run_program_with_monitoring
}

# ============================================================================
# COMMAND LINE INTERFACE
# ============================================================================

show_help() {
    cat << EOF
VXLAN Pipeline XDP - Unified Deployment & Monitoring Tool
=========================================================

USAGE:
    $0 [COMMAND] [OPTIONS]

COMMANDS:
    deploy          Full deployment pipeline (default)
    check           System readiness validation only
    build           Build program only
    monitor         Monitor existing deployment
    clean           Clean up and remove XDP program
    help            Show this help

OPTIONS:
    -i, --input IFACE       Input interface (default: $INPUT_INTERFACE)
    -t, --target IFACE      Target interface (default: $TARGET_INTERFACE)
    -a, --nat-ip IP         NAT target IP (default: $NAT_TARGET_IP)
    -p, --nat-port PORT     NAT target port (default: $NAT_TARGET_PORT)
    -s, --source-port PORT  Source port to match (default: $NAT_SOURCE_PORT)
    -r, --rate PPS          Target packet rate (default: $TARGET_PPS)
    -d, --duration SECS     Monitor duration, 0=infinite (default: $MONITOR_DURATION)
    --stats-interval SECS   Statistics interval (default: $STATS_INTERVAL)
    -v, --verbose           Verbose output
    -h, --help             Show help

EXAMPLES:
    # Full deployment with monitoring
    sudo $0 deploy
    
    # Custom configuration matching your packet analysis
    sudo $0 -i ens4 -t ens5 -a 10.2.41.17 -p 8081 -s 42844
    
    # System check only
    sudo $0 check
    
    # Monitor for 60 seconds
    sudo $0 monitor -d 60

NOTES:
    - Based on your packet analysis: 10.2.41.20:42844 → 10.2.41.17:8081
    - Processes 2852-byte jumbo frames → 1500-byte packets (DF bit clearing)
    - Optimized for 85,000+ packets per second sustained performance
    - Requires root privileges for XDP program attachment
EOF
}

# Parse command line arguments
COMMAND="deploy"
VERBOSE=0

while [[ $# -gt 0 ]]; do
    case $1 in
        deploy|check|build|monitor|clean|help)
            COMMAND="$1"
            shift
            ;;
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
        -r|--rate)
            TARGET_PPS="$2"
            shift 2
            ;;
        -d|--duration)
            MONITOR_DURATION="$2"
            shift 2
            ;;
        --stats-interval)
            STATS_INTERVAL="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# ============================================================================
# MAIN EXECUTION
# ============================================================================

# Set up signal handlers
trap cleanup EXIT
trap cleanup SIGINT
trap cleanup SIGTERM

echo "🚀 VXLAN Pipeline XDP - High-Performance Packet Processing"
echo "============================================================"
echo

# Execute command
case $COMMAND in
    "deploy")
        check_root
        run_full_pipeline
        ;;
    "check")
        run_system_check
        ;;
    "build")
        check_root
        build_program
        ;;
    "monitor")
        check_root
        monitor_performance
        ;;
    "clean")
        check_root
        cleanup
        ;;
    "help")
        show_help
        ;;
    *)
        error "Unknown command: $COMMAND"
        show_help
        exit 1
        ;;
esac