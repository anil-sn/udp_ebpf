#!/bin/bash
# Pre-deployment validation script for VXLAN Pipeline XDP
# Ensures system is ready for 85K+ PPS processing

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}✓${NC} $1"; }
warn() { echo -e "${YELLOW}⚠${NC} $1"; }
error() { echo -e "${RED}✗${NC} $1"; }

# System requirements
check_kernel_version() {
    local kernel_version=$(uname -r | cut -d. -f1-2)
    local major=$(echo $kernel_version | cut -d. -f1)
    local minor=$(echo $kernel_version | cut -d. -f2)
    
    if [[ $major -lt 4 ]] || [[ $major -eq 4 && $minor -lt 18 ]]; then
        error "Kernel version $kernel_version is too old. Minimum required: 4.18+"
        return 1
    fi
    
    log "Kernel version: $(uname -r) (compatible)"
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

check_interface_capabilities() {
    local iface=${1:-"ens5"}
    
    if ! ip link show "$iface" &>/dev/null; then
        error "Interface $iface not found"
        return 1
    fi
    
    # Check for XDP driver support
    local driver=$(ethtool -i "$iface" 2>/dev/null | grep "driver:" | cut -d' ' -f2)
    case $driver in
        "ixgbe"|"i40e"|"mlx5_core"|"mlx4_en"|"bnxt_en")
            log "Interface $iface uses XDP-compatible driver: $driver"
            ;;
        *)
            warn "Interface $iface driver ($driver) may not support native XDP mode"
            warn "Will fall back to generic XDP mode (lower performance)"
            ;;
    esac
}

check_cpu_performance() {
    local cpu_count=$(nproc)
    local cpu_freq=$(grep "cpu MHz" /proc/cpuinfo | head -1 | awk '{print $4}' | cut -d. -f1)
    
    log "CPU cores: $cpu_count"
    
    if [[ $cpu_freq -lt 2000 ]]; then
        warn "CPU frequency ($cpu_freq MHz) is low for 85K+ PPS processing"
        warn "Consider enabling performance governor"
    else
        log "CPU frequency: $cpu_freq MHz (good)"
    fi
    
    # Check CPU governor
    local governor=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo "unknown")
    if [[ "$governor" != "performance" ]]; then
        warn "CPU governor is '$governor' - recommend 'performance' for consistent latency"
    else
        log "CPU governor: performance (optimal)"
    fi
}

check_memory() {
    local total_mem=$(free -m | awk '/^Mem:/{print $2}')
    
    if [[ $total_mem -lt 4096 ]]; then
        warn "System has ${total_mem}MB RAM - may be insufficient for high-rate processing"
    else
        log "Available memory: ${total_mem}MB (sufficient)"
    fi
}

check_network_buffers() {
    local rmem_max=$(sysctl -n net.core.rmem_max)
    local wmem_max=$(sysctl -n net.core.wmem_max)
    local netdev_max_backlog=$(sysctl -n net.core.netdev_max_backlog)
    
    if [[ $rmem_max -lt 16777216 ]]; then
        warn "net.core.rmem_max ($rmem_max) is low for high-rate traffic"
    else
        log "Receive buffer size: $rmem_max bytes (good)"
    fi
    
    if [[ $netdev_max_backlog -lt 5000 ]]; then
        warn "net.core.netdev_max_backlog ($netdev_max_backlog) is low"
    else
        log "Network device backlog: $netdev_max_backlog (good)"
    fi
}

check_build_dependencies() {
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
        log "All build dependencies available"
    fi
    
    return $missing
}

test_compilation() {
    log "Testing program compilation..."
    
    cd "$SCRIPT_DIR"
    
    if ! make clean &>/dev/null; then
        warn "Clean failed (may be normal if no previous build)"
    fi
    
    if ! make all &>/dev/null; then
        error "Compilation failed - check build dependencies"
        return 1
    fi
    
    log "Compilation successful"
    return 0
}

print_recommendations() {
    echo
    echo "=== PERFORMANCE RECOMMENDATIONS ==="
    echo
    echo "For optimal 85K+ PPS performance:"
    echo
    echo "1. System tuning (run as root):"
    echo "   echo performance > /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor"
    echo "   sysctl -w net.core.rmem_max=16777216"
    echo "   sysctl -w net.core.wmem_max=16777216"  
    echo "   sysctl -w net.core.netdev_max_backlog=5000"
    echo "   echo 1 > /proc/sys/net/ipv4/ip_forward"
    echo
    echo "2. Interface optimization:"
    echo "   ethtool -A ens5 rx off tx off"
    echo "   ethtool -K ens5 gro off lro off"
    echo
    echo "3. IRQ affinity (optional):"
    echo "   echo 2 > /proc/irq/\$(cat /proc/interrupts | grep ens5 | cut -d: -f1)/smp_affinity"
    echo
    echo "4. Monitor performance:"
    echo "   ./vxlan_loader -i ens5 -t ens6 -v"
    echo "   watch -n1 'cat /proc/net/dev'"
    echo
}

main() {
    echo "VXLAN Pipeline XDP - System Readiness Check"
    echo "==========================================="
    echo
    
    local failed=0
    
    # Core requirements
    check_kernel_version || failed=1
    check_xdp_support || failed=1
    check_build_dependencies || failed=1
    
    echo
    # System performance checks
    check_cpu_performance
    check_memory  
    check_network_buffers
    check_interface_capabilities "ens5"
    check_interface_capabilities "ens6" 2>/dev/null || true
    
    echo
    # Build test
    test_compilation || failed=1
    
    echo
    if [[ $failed -eq 0 ]]; then
        log "System is ready for VXLAN Pipeline XDP deployment"
        echo
        print_recommendations
    else
        error "System has issues that need to be resolved before deployment"
        echo
        echo "Fix the errors above and run this script again."
        exit 1
    fi
}

# Handle command line
case "${1:-check}" in
    "check"|"")
        main
        ;;
    "deps")
        check_build_dependencies
        ;;
    "perf")
        check_cpu_performance
        check_memory
        check_network_buffers
        ;;
    "help"|"-h"|"--help")
        echo "Usage: $0 [command]"
        echo
        echo "Commands:"
        echo "  check    Full system readiness check (default)"
        echo "  deps     Check build dependencies only"
        echo "  perf     Check performance settings only"
        echo "  help     Show this help"
        ;;
    *)
        error "Unknown command: $1"
        exit 1
        ;;
esac