#!/bin/bash
# Safe eBPF/XDP Development Environment Setup
# 
# This script installs development dependencies without making
# destructive system changes. All optimizations are optional
# and can be applied separately.

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Simple logging functions
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
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root for package installation"
   echo "Usage: sudo $0 [--minimal|--with-optimizations]"
   exit 1
fi

# Parse command line arguments
MINIMAL_INSTALL=false
APPLY_OPTIMIZATIONS=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --minimal)
            MINIMAL_INSTALL=true
            shift
            ;;
        --with-optimizations)
            APPLY_OPTIMIZATIONS=true
            shift
            ;;
        --help)
            cat << EOF
Safe eBPF/XDP Development Environment Setup

Usage: sudo $0 [options]

Options:
  --minimal              Install only essential development packages
  --with-optimizations   Apply optional system optimizations for performance
  --help                 Show this help message

Default behavior: Install development packages without system modifications

Examples:
  sudo $0                      # Install dev packages only
  sudo $0 --minimal            # Install minimal required packages
  sudo $0 --with-optimizations # Install packages + apply optimizations
EOF
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

echo "=== Safe eBPF/XDP Development Environment Setup ==="
echo "This script will install development dependencies for eBPF/XDP"
if $APPLY_OPTIMIZATIONS; then
    warning "System optimizations will be applied (can be reversed)"
fi
echo

# Function to backup current settings (only if optimizations requested)
backup_settings() {
    if ! $APPLY_OPTIMIZATIONS; then
        return 0
    fi
    
    log "Creating backup of current settings..."
    mkdir -p /etc/xdp-udp-modifier-backup
    
    # Backup current sysctl settings
    sysctl -a 2>/dev/null | grep -E "net\.core\.|vm\." > /etc/xdp-udp-modifier-backup/sysctl_original.conf || true
    
    success "Settings backed up to /etc/xdp-udp-modifier-backup/"
}

# Install development dependencies
install_dependencies() {
    log "Installing eBPF development dependencies..."
    apt-get update -q
    
    # Essential packages
    local packages=("clang" "llvm" "libbpf-dev" "libelf-dev" "build-essential")
    
    if ! $MINIMAL_INSTALL; then
        packages+=("bpftool" "linux-tools-generic" "iproute2" "pkg-config" "zlib1g-dev")
        
        # Try kernel headers
        local kernel=$(uname -r)
        packages+=("linux-headers-$kernel")
    fi
    
    log "Installing packages: ${packages[*]}"
    apt-get install -y "${packages[@]}" || {
        warning "Some packages failed to install, continuing..."
    }
    
    success "Dependencies installed"
}

# Apply optional performance optimizations
apply_optimizations() {
    if ! $APPLY_OPTIMIZATIONS; then
        log "Skipping system optimizations (use --with-optimizations to enable)"
        return 0
    fi
    
    warning "Applying system optimizations..."
    
    # Create sysctl configuration for eBPF/XDP
    cat > /etc/sysctl.d/99-xdp-ebpf.conf << 'EOF'
# eBPF/XDP Performance Optimizations
# Applied by XDP UDP DF Modifier setup script
# To remove: sudo rm /etc/sysctl.d/99-xdp-ebpf.conf && sudo sysctl --system

# Enable eBPF JIT compilation for better performance
net.core.bpf_jit_enable = 1

# Increase memory map areas for complex eBPF programs
vm.max_map_count = 262144

# Disable unprivileged eBPF for security (production recommended)
kernel.unprivileged_bpf_disabled = 1

# Network optimizations (minimal impact on other services)
net.core.netdev_max_backlog = 5000
net.core.netdev_budget = 600
EOF
    
    # Apply settings
    sysctl -p /etc/sysctl.d/99-xdp-ebpf.conf
    
    success "System optimizations applied"
    log "To remove optimizations: sudo rm /etc/sysctl.d/99-xdp-ebpf.conf && sudo sysctl --system"
}

# Verify installation
verify_installation() {
    log "Verifying eBPF development environment..."
    
    local errors=0
    
    # Check for clang with eBPF support
    if clang --version | grep -q "clang version"; then
        success "Clang compiler available"
    else
        error "Clang compiler not found"
        errors=$((errors + 1))
    fi
    
    # Check for libbpf
    if pkg-config --exists libbpf 2>/dev/null; then
        local libbpf_version=$(pkg-config --modversion libbpf)
        success "libbpf available (version: $libbpf_version)"
    else
        error "libbpf development library not found"
        errors=$((errors + 1))
    fi
    
    # Check for bpf() syscall support
    if [ -f /proc/sys/kernel/unprivileged_bpf_disabled ]; then
        success "eBPF syscall support detected"
    else
        warning "eBPF syscall support unclear (older kernel?)"
    fi
    
    if [[ $errors -eq 0 ]]; then
        success "Environment verification completed successfully"
        
        echo
        log "Next steps:"
        echo "1. Build the project: make -f Makefile_xdp"
        echo "2. Install programs: sudo ./deploy_xdp_safe.sh install"
        echo "3. Attach to interface: sudo ./deploy_xdp_safe.sh attach <interface>"
        echo "4. Monitor: sudo ./deploy_xdp_safe.sh monitor <interface>"
        
    else
        error "Environment verification failed with $errors error(s)"
        echo "Please install missing dependencies and run again"
        exit 1
    fi
}

# Main execution
main() {
    backup_settings
    install_dependencies
    apply_optimizations
    verify_installation
    
    echo
    success "eBPF/XDP development environment setup completed!"
    
    if $APPLY_OPTIMIZATIONS; then
        echo
        warning "System optimizations were applied and are now active"
        log "Backup available in: /etc/xdp-udp-modifier-backup/"
        log "To restore: sudo sysctl -p /etc/xdp-udp-modifier-backup/sysctl_original.conf"
    fi
}