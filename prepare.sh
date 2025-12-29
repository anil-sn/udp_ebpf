#!/bin/bash
# XDP VXLAN Pipeline - Complete Environment Preparation
# Unified setup: dependencies, venv, build, and verification

set -e

# Make script fully non-interactive
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a  # Restart services automatically
export UCF_FORCE_CONFFNEW=1  # Use new config files without prompting

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Logging utilities (from xdp_pipeline.sh pattern)
timestamp() { date '+%H:%M:%S'; }
log() { echo -e "${GREEN}[$(timestamp)] ✓${NC} $1"; }
warn() { echo -e "${YELLOW}[$(timestamp)] ⚠${NC} $1"; }
error() { echo -e "${RED}[$(timestamp)] ✗${NC} $1"; }
info() { echo -e "${BLUE}[$(timestamp)] ℹ${NC} $1"; }
section() { echo -e "${CYAN}=== $1 ===${NC}"; }

# Progress indicator for long operations
show_progress() {
    local pid=$1
    local message=$2
    local spin='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local i=0
    
    echo -n "  $message "
    while kill -0 "$pid" 2>/dev/null; do
        printf "\b%s" "${spin:i++%${#spin}:1}"
        sleep 0.1
    done
    printf "\b✓\n"
}

# Wait for apt locks to be released
wait_for_apt_lock() {
    local max_wait=${1:-300}  # Maximum wait time in seconds (5 minutes)
    local wait_time=0
    local check_interval=5
    
    info "Checking for existing package manager operations..."
    
    while [ $wait_time -lt $max_wait ]; do
        # Check for dpkg lock files
        if sudo fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || \
           sudo fuser /var/lib/dpkg/lock >/dev/null 2>&1 || \
           sudo fuser /var/cache/apt/archives/lock >/dev/null 2>&1; then
            
            if [ $wait_time -eq 0 ]; then
                warn "Package manager is busy (dpkg/apt locks detected)"
                info "Waiting for existing operations to complete..."
            fi
            
            # Show which processes are holding locks
            local apt_processes
            apt_processes=$(ps aux | grep -E '(apt|dpkg|unattended-upgrade)' | grep -v grep | wc -l)
            if [ "$apt_processes" -gt 0 ]; then
                info "Found $apt_processes active package management processes"
            fi
            
            sleep $check_interval
            wait_time=$((wait_time + check_interval))
        else
            if [ $wait_time -gt 0 ]; then
                log "Package manager is now available (waited ${wait_time}s)"
            else
                log "Package manager is available"
            fi
            return 0
        fi
    done
    
    error "Timed out waiting for package manager (${max_wait}s)"
    return 1
}

# Kill hanging apt processes if needed
cleanup_apt_processes() {
    info "Checking for stuck package management processes..."
    
    # Find potentially stuck apt/dpkg processes
    local stuck_processes
    stuck_processes=$(ps aux | grep -E '(apt-get|dpkg|unattended-upgrade)' | grep -v grep | awk '{print $2}' || true)
    
    if [ -n "$stuck_processes" ]; then
        warn "Found potentially stuck processes: $stuck_processes"
        
        # Try graceful termination first
        echo "$stuck_processes" | while read -r pid; do
            if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
                info "Attempting graceful termination of process $pid"
                sudo kill -TERM "$pid" 2>/dev/null || true
            fi
        done
        
        sleep 5
        
        # Force kill if still running
        echo "$stuck_processes" | while read -r pid; do
            if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
                warn "Force killing stuck process $pid"
                sudo kill -KILL "$pid" 2>/dev/null || true
            fi
        done
        
        # Clean up lock files if processes are gone
        sleep 2
        if ! sudo fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; then
            sudo rm -f /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock 2>/dev/null || true
            info "Cleaned up stale lock files"
            
            # Attempt to recover package database state
            info "Running dpkg recovery to fix any incomplete package configurations..."
            if sudo dpkg --configure -a 2>/dev/null; then
                log "Package database recovered successfully"
            else
                warn "dpkg recovery completed with warnings (this may be normal)"
            fi
            
            # Fix any broken dependencies
            info "Checking for broken dependencies..."
            if sudo apt-get -f install -y >/dev/null 2>&1; then
                log "Dependencies verified and fixed"
            else
                warn "Dependency fix completed with warnings"
            fi
        fi
    else
        log "No stuck processes found"
    fi
}

# Safe apt operation wrapper
safe_apt() {
    local max_retries=3
    local retry_count=0
    
    while [ $retry_count -lt $max_retries ]; do
        # Wait for locks to be available
        if ! wait_for_apt_lock; then
            if [ $retry_count -eq 0 ]; then
                cleanup_apt_processes
                wait_for_apt_lock 60 || {
                    error "Could not acquire package manager locks after cleanup"
                    return 1
                }
            else
                return 1
            fi
        fi
        
        # Execute the apt command
        if "$@"; then
            return 0
        else
            retry_count=$((retry_count + 1))
            if [ $retry_count -lt $max_retries ]; then
                warn "Apt operation failed, retrying ($retry_count/$max_retries)..."
                sleep 3
            fi
        fi
    done
    
    return 1
}

# Check sudo access and handle authentication issues
check_sudo() {
    section "Checking Sudo Access"
    
    # Test sudo without password prompt first
    if sudo -n true 2>/dev/null; then
        log "Sudo access confirmed (passwordless)"
        return 0
    fi
    
    # Check if we can get sudo with a timeout
    info "Testing sudo access..."
    if timeout 10 sudo -v 2>/dev/null; then
        log "Sudo access confirmed"
        return 0
    else
        error "Sudo access required but not available"
        error "Please ensure you can run 'sudo -v' successfully"
        echo ""
        info "Common solutions:"
        echo "  1. Run: sudo -v    (to authenticate)"
        echo "  2. Add your user to sudoers: sudo usermod -aG sudo \$USER"
        echo "  3. Configure passwordless sudo for your user"
        echo ""
        return 1
    fi
}

# Pre-flight checks
preflight_checks() {
    section "Pre-flight System Checks"
    
    local issues=0
    
    # Check internet connectivity
    info "Checking internet connectivity..."
    if ping -c 1 8.8.8.8 >/dev/null 2>&1 || ping -c 1 1.1.1.1 >/dev/null 2>&1; then
        log "Internet connectivity confirmed"
    else
        error "No internet connectivity detected"
        issues=1
    fi
    
    # Check disk space (need at least 2GB)
    info "Checking available disk space..."
    local available
    available=$(df / | awk 'NR==2 {print $4}')
    if [ "$available" -gt 2097152 ] 2>/dev/null; then  # 2GB in KB
        log "Sufficient disk space available"
    else
        warn "Low disk space detected (less than 2GB free)"
        issues=1
    fi
    
    # Check if running in a container
    if [ -f /.dockerenv ] || grep -q docker /proc/1/cgroup 2>/dev/null; then
        warn "Running in Docker container - XDP functionality will be limited"
    fi
    
    # Check kernel version for XDP support
    local kernel_version
    kernel_version=$(uname -r | cut -d. -f1,2)
    if awk "BEGIN {exit !($kernel_version >= 4.18)}"; then
        log "Kernel version supports XDP ($(uname -r))"
    else
        warn "Kernel version may have limited XDP support ($(uname -r))"
    fi
    
    return $issues
}

# Project paths
PROJECT_ROOT="$SCRIPT_DIR"
VENV_PATH="$PROJECT_ROOT/.venv"
SRC_DIR="$PROJECT_ROOT/src"

echo -e "${BLUE}XDP VXLAN Pipeline - Environment Preparation${NC}"
echo "============================================"
echo ""

# Check for common hostname issues
if ! hostname -f >/dev/null 2>&1; then
    warn "Hostname resolution issues detected"
    info "Attempting to fix hostname resolution..."
    
    # Get the current hostname
    current_hostname=$(hostname)
    current_ip=$(hostname -I | awk '{print $1}' 2>/dev/null || echo "127.0.1.1")
    
    # Add to /etc/hosts if not present
    if ! grep -q "$current_hostname" /etc/hosts 2>/dev/null; then
        info "Adding hostname to /etc/hosts..."
        echo "$current_ip $current_hostname" | sudo tee -a /etc/hosts >/dev/null
        log "Hostname resolution configured"
    fi
fi

echo -e "${CYAN}This script will automatically:${NC}"
echo "  • Install system dependencies (apt/yum packages)"
echo "  • Build and install XDP tools from source"
echo "  • Set up Python virtual environment"
echo "  • Build the XDP pipeline"
echo "  • Configure network routing"
echo ""
echo -e "${GREEN}Running in non-interactive mode - no user input required${NC}"
echo ""

# Brief pause to let user read
sleep 1

# ============================================================================
# STEP 1: SYSTEM DEPENDENCIES
# ============================================================================

install_dependencies() {
    section "Installing System Dependencies"
    
    # Clean up any existing stuck processes first
    cleanup_apt_processes
    
    # Check if running as root
    if [[ $EUID -eq 0 ]]; then
        warn "Running as root. Consider using sudo instead."
    fi
    
    # Detect OS
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
    else
        error "Cannot detect OS. Please install dependencies manually."
        exit 1
    fi
    
    info "Detected OS: $OS"
    
    case $OS in
        "ubuntu"|"debian")
            info "Installing for Ubuntu/Debian..."
            
            # Update package lists safely
            info "Updating package lists (non-interactive mode)..."
            if safe_apt sudo DEBIAN_FRONTEND=noninteractive apt-get update -y; then
                log "Package lists updated successfully"
            else
                error "Failed to update package lists"
                error "Please check your internet connection and try again"
                return 1
            fi
            
            # Core build dependencies (non-interactive)
            info "Installing core build dependencies..."
            if safe_apt sudo DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential clang gcc make libbpf-dev; then
                log "Core build tools installed"
            else
                error "Failed to install core build dependencies"
                return 1
            fi
            
            # Kernel headers (optional for WSL2)
            info "Installing kernel headers for $(uname -r)..."
            if ! safe_apt sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "linux-headers-$(uname -r)"; then
                warn "Could not install kernel headers for $(uname -r)"
                warn "This is normal for WSL2. XDP functionality may be limited."
                info "Continuing with setup..."
            else
                log "Kernel headers installed successfully"
            fi
            
            # Network tools (including ARP discovery and JSON processing)
            info "Installing network analysis tools..."
            if safe_apt sudo DEBIAN_FRONTEND=noninteractive apt-get install -y iproute2 net-tools tcpdump iputils-arping jq; then
                log "Network tools installed (including arping for MAC discovery and jq for JSON processing)"
            else
                warn "Some network tools may not be available, trying basic set..."
                if safe_apt sudo DEBIAN_FRONTEND=noninteractive apt-get install -y iproute2 net-tools jq; then
                    log "Basic network tools installed"
                else
                    warn "Network tools installation partially failed, continuing..."
                fi
            fi
            
            # Extended XDP development packages
            info "Installing extended XDP development packages..."
            if safe_apt sudo DEBIAN_FRONTEND=noninteractive apt-get install -y git llvm libelf-dev libpcap-dev pkg-config m4 zlib1g-dev libcap-dev; then
                log "Extended XDP development packages installed"
            else
                warn "Some extended packages may not be available, continuing..."
            fi
            
            # BPF tools - Build from source for reliability (AWS kernels often need this)
            if ! command -v bpftool >/dev/null 2>&1 || bpftool version 2>&1 | grep -q "WARNING.*not found"; then
                info "Installing bpftool from source..."
                
                # Install build dependencies (non-interactive)
                info "Installing bpftool build dependencies..."
                if safe_apt sudo DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential libssl-dev binutils-dev libcap-dev git; then
                    log "Build dependencies installed"
                else
                    error "Failed to install bpftool build dependencies"
                    return 1
                fi
                
                # Build bpftool from source
                local bpftool_dir="/tmp/bpftool"
                [ -d "$bpftool_dir" ] && rm -rf "$bpftool_dir"
                
                info "Cloning bpftool repository (this may take a moment)..."
                cd /tmp
                
                # Handle existing directory gracefully
                if [ -d "bpftool" ]; then
                    info "Existing bpftool directory found, updating..."
                    cd bpftool
                    if git pull --quiet && git submodule update --quiet --init --recursive; then
                        info "Updated existing bpftool repository"
                    else
                        warn "Failed to update existing repository, removing and re-cloning..."
                        cd /tmp
                        rm -rf bpftool
                        git clone --quiet --recurse-submodules https://github.com/libbpf/bpftool.git
                    fi
                else
                    git clone --quiet --recurse-submodules https://github.com/libbpf/bpftool.git
                fi
                
                if [ -d "bpftool" ]; then
                    cd bpftool/src
                    
                    info "Building bpftool from source (this may take a few minutes)..."
                    if make -j"$(nproc)" && sudo make install; then
                        log "bpftool built and installed successfully"
                        
                        # Verify installation
                        if [ -f "/usr/local/sbin/bpftool" ]; then
                            log "bpftool installed at /usr/local/sbin/bpftool"
                            
                            # Update PATH immediately for current session
                            export PATH="/usr/local/sbin:$PATH"
                            
                            # Update shell profile for future sessions
                            if ! grep -q "/usr/local/sbin.*PATH" ~/.bashrc 2>/dev/null; then
                                echo "export PATH=\"/usr/local/sbin:\$PATH\"" >> ~/.bashrc
                                info "Updated ~/.bashrc to prioritize /usr/local/sbin"
                            fi
                            
                            # Create symlink for broader compatibility
                            sudo ln -sf /usr/local/sbin/bpftool /usr/local/bin/bpftool
                            
                            # Verify the new version works
                            local bpftool_version
                            bpftool_version=$(/usr/local/sbin/bpftool version 2>/dev/null | head -1)
                            log "bpftool version: $bpftool_version"
                            info "bpftool features: $(bpftool version 2>/dev/null | grep features | cut -d: -f2)"
                        else
                            error "bpftool installation failed - binary not found"
                        fi
                    else
                        error "Failed to build bpftool from source"
                    fi
                    
                    cd "$PROJECT_ROOT"
                    rm -rf "$bpftool_dir"
                else
                    error "Failed to clone bpftool repository"
                fi
            else
                log "bpftool already available and working"
                info "bpftool version: $(bpftool version 2>/dev/null | head -1 || echo 'installed')"
            fi
            
            # Python development tools
            info "Installing Python development environment..."
            if safe_apt sudo DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-dev python3-pip; then
                log "Python development tools installed"
            else
                error "Failed to install Python development tools"
                return 1
            fi
            ;;
            
        "centos"|"rhel"|"fedora")
            info "Installing for RedHat/CentOS/Fedora (non-interactive)..."
            info "Updating system packages..."
            sudo yum update -y -q || sudo dnf update -y -q
            info "Installing development dependencies..."
            sudo yum install -y -q clang gcc make libbpf-devel kernel-headers kernel-devel || \
            sudo dnf install -y -q clang gcc make libbpf-devel kernel-headers kernel-devel
            log "Dependencies installed via yum/dnf"
            ;;
            
        *)
            warn "Unsupported OS: $OS"
            warn "Please install manually: clang, gcc, make, libbpf-dev, kernel-headers"
            ;;
    esac
}

# ============================================================================
# STEP 2: XDP TOOLS INSTALLATION
# ============================================================================

install_xdp_tools() {
    section "Installing XDP Tools"
    
    local xdp_tools_dir="/tmp/xdp-tools"
    
    # Check if xdp-loader already exists
    if command -v xdp-loader >/dev/null 2>&1; then
        log "XDP tools already installed"
        return 0
    fi
    
    info "Cloning xdp-tools repository..."
    
    # Remove existing directory if it exists
    [ -d "$xdp_tools_dir" ] && rm -rf "$xdp_tools_dir"
    
    # Clone/update xdp-tools (non-interactive)
    info "Downloading XDP tools source code..."
    
    # Handle existing directory gracefully  
    if [ -d "$xdp_tools_dir" ]; then
        info "Existing XDP tools directory found, updating..."
        cd "$xdp_tools_dir"
        if git pull --quiet && git submodule update --quiet --init --recursive; then
            log "Updated existing XDP tools repository"
        else
            warn "Failed to update existing repository, removing and re-cloning..."
            cd /tmp
            rm -rf "$xdp_tools_dir"
            if git clone --quiet https://github.com/xdp-project/xdp-tools.git "$xdp_tools_dir"; then
                log "XDP tools repository cloned successfully"
            else
                warn "Failed to clone xdp-tools repository"
                return 1
            fi
        fi
    else
        if git clone --quiet https://github.com/xdp-project/xdp-tools.git "$xdp_tools_dir"; then
            log "XDP tools repository cloned successfully"
        else
            warn "Failed to clone xdp-tools repository"
            return 1
        fi
    fi
    
    cd "$xdp_tools_dir"
    
    info "Cleaning previous build..."
    make clean >/dev/null 2>&1 || true
    
    info "Updating submodules (this may take a moment)..."
    git submodule update --quiet --init --recursive
    
    info "Configuring with bundled libbpf..."
    export FORCE_SUBDIR_LIBBPF=1
    ./configure
    
    info "Building xdp-tools (this may take a few minutes)..."
    if make -j"$(nproc)"; then
        log "XDP tools built successfully"
    else
        error "Failed to build xdp-tools"
        cd "$PROJECT_ROOT"
        return 1
    fi
    
    info "Installing xdp-tools..."
    if sudo make install && sudo ldconfig; then
        log "XDP tools installed successfully"
    else
        error "Failed to install xdp-tools"
        cd "$PROJECT_ROOT"
        return 1
    fi
    
    cd "$PROJECT_ROOT"
    
    # Verify installation
    if command -v xdp-loader >/dev/null 2>&1; then
        log "XDP tools verification successful"
        info "xdp-loader version: $(xdp-loader --version 2>/dev/null || echo 'installed')"
    else
        warn "XDP tools installation may have issues"
    fi
    
    # Cleanup
    rm -rf "$xdp_tools_dir"
    log "Temporary files cleaned up"
}

# ============================================================================
# STEP 3: PYTHON VIRTUAL ENVIRONMENT
# ============================================================================

setup_venv() {
    section "Setting Up Python Environment"
    
    # Check/install uv
    if ! command -v uv >/dev/null 2>&1; then
        if [ -f "$HOME/.local/bin/uv" ]; then
            export PATH="$HOME/.local/bin:$PATH"
            log "Added uv to PATH"
        else
            info "Installing uv package manager (non-interactive)..."
            if curl -LsSf https://astral.sh/uv/install.sh | sh -s -- --no-modify-path; then
                export PATH="$HOME/.local/bin:$PATH"
                log "uv installed successfully"
            else
                warn "uv installation failed, continuing with pip"
                return 1
            fi
        fi
    fi
    
    # Check uv version safely
    if command -v uv >/dev/null 2>&1; then
        info "Using uv version: $(uv --version 2>/dev/null || echo 'unknown')"
    else
        warn "uv not available, falling back to pip"
    fi
    
    # Create virtual environment
    if [ ! -d "$VENV_PATH" ]; then
        info "Creating virtual environment..."
        uv venv "$VENV_PATH"
        log "Virtual environment created"
    else
        log "Virtual environment already exists"
    fi
    
    # Install Python dependencies
    if [ -f "$VENV_PATH/bin/activate" ]; then
        source "$VENV_PATH/bin/activate"
        info "Installing Python packages..."
        
        if [ -f "requirements.txt" ]; then
            if command -v uv >/dev/null 2>&1; then
                uv pip install -r requirements.txt
            else
                pip install -r requirements.txt
            fi
            log "Requirements installed from requirements.txt"
        else
            # Essential packages only
            if command -v uv >/dev/null 2>&1; then
                uv pip install scapy psutil
            else
                pip install scapy psutil
            fi
            log "Essential packages installed"
        fi
    else
        error "Virtual environment activation script not found"
        return 1
    fi
}

# ============================================================================
# STEP 4: BUILD PROJECT
# ============================================================================

build_project() {
    section "Building Project"
    
    # Verify source directory
    if [ ! -d "$SRC_DIR" ]; then
        error "Source directory not found: $SRC_DIR"
        exit 1
    fi
    
    cd "$SRC_DIR"
    
    # Clean and build
    info "Cleaning previous build..."
    make clean >/dev/null 2>&1 || true
    
    info "Building XDP pipeline..."
    if make all; then
        log "Build successful"
    else
        error "Build failed"
        exit 1
    fi
    
    cd "$PROJECT_ROOT"
}

# ============================================================================
# STEP 5: VERIFY SETUP
# ============================================================================

verify_setup() {
    section "Verifying Setup"
    
    # Check build artifacts
    local missing_files=()
    
    [ ! -f "$SRC_DIR/vxlan_loader" ] && missing_files+=("vxlan_loader")
    [ ! -f "$SRC_DIR/vxlan_pipeline.bpf.o" ] && missing_files+=("vxlan_pipeline.bpf.o")
    [ ! -f "$SRC_DIR/packet_injector" ] && missing_files+=("packet_injector")
    
    if [ ${#missing_files[@]} -gt 0 ]; then
        error "Missing build artifacts: ${missing_files[*]}"
        exit 1
    fi
    
    log "All build artifacts present"
    
    # Check configuration
    if [ -f ".env" ]; then
        log ".env configuration file found"
    else
        if [ -f ".env.example" ]; then
            cp ".env.example" ".env"
            log "Created .env from .env.example"
            warn "Please edit .env file with your configuration"
        else
            warn ".env file not found. You may need to create one manually"
        fi
    fi
    
    # Check key commands
    local missing_commands=()
    
    command -v clang >/dev/null 2>&1 || missing_commands+=("clang")
    command -v make >/dev/null 2>&1 || missing_commands+=("make")
    
    if [ ${#missing_commands[@]} -gt 0 ]; then
        error "Missing required commands: ${missing_commands[*]}"
        exit 1
    fi
    
    log "All required commands available"
    
    # Test virtual environment
    if source "$VENV_PATH/bin/activate" 2>/dev/null; then
        if python3 -c "import scapy" 2>/dev/null; then
            log "Python environment working"
        else
            warn "Python packages may have installation issues"
        fi
    else
        warn "Virtual environment activation failed"
    fi
}

# ============================================================================
# STEP 6: SYSTEM PERFORMANCE TUNING
# ============================================================================

optimize_system_performance() {
    section "Optimizing System for High-PPS Performance"
    
    info "Applying performance optimizations for 85K+ PPS target..."
    
    # Network stack optimizations
    info "Configuring network stack for high throughput..."
    
    # Increase network buffer sizes
    sudo sysctl -w net.core.rmem_max=134217728 >/dev/null 2>&1 || warn "Could not set rmem_max"
    sudo sysctl -w net.core.wmem_max=134217728 >/dev/null 2>&1 || warn "Could not set wmem_max"
    sudo sysctl -w net.core.netdev_max_backlog=5000 >/dev/null 2>&1 || warn "Could not set netdev_max_backlog"
    sudo sysctl -w net.core.netdev_budget=600 >/dev/null 2>&1 || warn "Could not set netdev_budget"
    
    # Optimize network device queue lengths
    for iface in ens5 ens6; do
        if ip link show "$iface" >/dev/null 2>&1; then
            sudo ip link set "$iface" txqueuelen 10000 >/dev/null 2>&1 || warn "Could not set $iface txqueuelen"
        fi
    done
    
    # CPU performance optimizations
    info "Configuring CPU performance settings..."
    
    # Disable CPU frequency scaling for consistent performance
    if [ -d "/sys/devices/system/cpu/cpu0/cpufreq" ]; then
        for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
            [ -w "$cpu" ] && echo "performance" | sudo tee "$cpu" >/dev/null 2>&1 || true
        done
        log "CPU governor set to performance mode"
    else
        info "CPU frequency scaling not available or already optimized"
    fi
    
    # Memory optimization
    info "Optimizing memory settings..."
    
    # Disable swap usage for consistent latency
    sudo sysctl -w vm.swappiness=1 >/dev/null 2>&1 || warn "Could not set swappiness"
    
    # Optimize memory allocation
    sudo sysctl -w vm.dirty_ratio=15 >/dev/null 2>&1 || warn "Could not set dirty_ratio"
    sudo sysctl -w vm.dirty_background_ratio=5 >/dev/null 2>&1 || warn "Could not set dirty_background_ratio"
    
    log "✓ System performance optimizations applied"
    info "System configured for high-throughput packet processing"
}

# ============================================================================
# STEP 7: NETWORK CONFIGURATION
# ============================================================================

configure_network() {
    section "Configuring Network Routing for XDP Pipeline"
    
    # Configure hairpin routing - processed packets return via ens5
    info "Configuring hairpin routing for VXLAN pipeline..."
    if sudo ip route del default via 172.30.82.1 dev ens6 >/dev/null 2>&1; then
        log "✓ Removed ens6 default route - packets will now egress via ens5"
    else
        info "ens6 default route already removed or not found"
    fi
    
    # Target configuration from .env or defaults
    local TARGET_IP="172.30.82.95"
    local TARGET_PORT="8081"
    local BRIDGE_INTERFACE="br0"
    local EGRESS_INTERFACE="ens6"
    
    # Source .env if it exists for custom configuration
    if [ -f ".env" ]; then
        source .env
        TARGET_IP="${TARGET_IP:-172.30.82.95}"
        info "Using configuration from .env file"
    fi
    
    info "Target: $TARGET_IP:$TARGET_PORT"
    info "Bridge interface: $BRIDGE_INTERFACE"
    info "Egress interface: $EGRESS_INTERFACE"
    
    # Check if interfaces exist
    if ! ip link show "$BRIDGE_INTERFACE" >/dev/null 2>&1; then
        warn "Bridge interface $BRIDGE_INTERFACE not found"
        warn "Skipping network configuration (will configure manually later)"
        return 0
    fi
    
    if ! ip link show "$EGRESS_INTERFACE" >/dev/null 2>&1; then
        warn "Egress interface $EGRESS_INTERFACE not found"
        warn "Skipping network configuration (will configure manually later)"
        return 0
    fi
    
    # Step 1: Discover MAC address using multiple methods
    echo ""
    info "=== Discovering MAC address for $TARGET_IP ==="
    
    # Method 1: arping (most reliable)
    if command -v arping >/dev/null 2>&1; then
        info "Trying arping discovery..."
        if sudo arping -c 2 -I "$BRIDGE_INTERFACE" "$TARGET_IP" >/dev/null 2>&1; then
            log "ARP ping successful"
        else
            warn "arping failed, trying alternatives"
        fi
    fi
    
    # Method 2: netcat connection attempt
    info "Trying connection-based discovery..."
    timeout 3 nc -w 1 "$TARGET_IP" "$TARGET_PORT" 2>/dev/null || true
    timeout 3 nc -w 1 -u "$TARGET_IP" "$TARGET_PORT" 2>/dev/null || true
    sleep 1
    
    # Method 3: Manual ARP probe if needed
    if ! ip neighbor show "$TARGET_IP" | grep -q "lladdr"; then
        info "Trying manual ARP probe..."
        sudo ip neighbor add "$TARGET_IP" dev "$BRIDGE_INTERFACE" nud incomplete >/dev/null 2>&1 || true
        sleep 2
    fi
    
    # Check what we discovered
    TARGET_MAC=$(ip neighbor show "$TARGET_IP" | awk '{print $5}' | head -1)
    
    if [ -n "$TARGET_MAC" ] && [ "$TARGET_MAC" != "" ]; then
        log "Discovered MAC: $TARGET_MAC"
        echo ""
        
        # Step 2: Configure routing for egress via specific interface
        info "=== Configuring routing for $EGRESS_INTERFACE egress ==="
        
        # Remove any existing route for this IP
        sudo ip route del "$TARGET_IP/32" >/dev/null 2>&1 || true
        sudo ip neighbor del "$TARGET_IP" dev "$EGRESS_INTERFACE" >/dev/null 2>&1 || true
        
        # Add specific route with high priority (low metric)
        if sudo ip route add "$TARGET_IP/32" dev "$EGRESS_INTERFACE" metric 50; then
            log "Route added: $TARGET_IP/32 dev $EGRESS_INTERFACE"
        else
            warn "Failed to add route"
            return 1
        fi
        
        # Add neighbor entry for L2 forwarding
        if sudo ip neighbor add "$TARGET_IP" lladdr "$TARGET_MAC" dev "$EGRESS_INTERFACE"; then
            log "Neighbor entry added: $TARGET_IP -> $TARGET_MAC on $EGRESS_INTERFACE"
        else
            warn "Failed to add neighbor entry"
        fi
        
        # Verify the configuration
        echo ""
        info "Verifying network configuration:"
        local route_info
        route_info=$(ip route get "$TARGET_IP" 2>/dev/null)
        echo "  Route: $route_info"
        
        if echo "$route_info" | grep -q "$EGRESS_INTERFACE"; then
            log "✓ Traffic to $TARGET_IP will egress via $EGRESS_INTERFACE"
        else
            warn "⚠ Route verification failed - check manual configuration"
        fi
        
        # Test connectivity
        if nc -zv "$TARGET_IP" "$TARGET_PORT" -u 2>/dev/null; then
            log "✓ UDP connectivity to $TARGET_IP:$TARGET_PORT confirmed"
        else
            warn "⚠ Could not verify UDP connectivity"
        fi
        
    else
        warn "Could not discover MAC address for $TARGET_IP"
        warn "You may need to configure network routing manually:"
        echo ""
        echo "  # Discover MAC address:"
        echo "  sudo arping -c 2 -I $BRIDGE_INTERFACE $TARGET_IP"
        echo "  TARGET_MAC=\$(ip neighbor show $TARGET_IP | awk '{print \$5}' | head -1)"
        echo ""
        echo "  # Configure routing:"
        echo "  sudo ip route add $TARGET_IP/32 dev $EGRESS_INTERFACE metric 50"
        echo "  sudo ip neighbor add $TARGET_IP lladdr \$TARGET_MAC dev $EGRESS_INTERFACE"
        echo ""
    fi
}

# ============================================================================
# STEP 7: FINAL STATUS
# ============================================================================

show_status() {
    section "Setup Complete"
    
    echo ""
    log "Environment is ready!"
    info "Next steps:"
    echo "  1. Edit .env file with your network configuration"
    echo "  2. Run: ./xdp.sh start"
    echo "  3. Monitor with: ./xdp.sh monitor"
    echo ""
    info "Key files:"
    echo "  - Configuration: .env"
    echo "  - Main control: ./xdp.sh"
    echo "  - Source code: src/"
    echo ""
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

main() {
    local start_time
    start_time=$(date +%s)
    
    echo -e "${CYAN}=========================================${NC}"
    echo -e "${BLUE} XDP VXLAN Pipeline - Auto Setup${NC}"
    echo -e "${CYAN}=========================================${NC}"
    echo ""
    
    # Verify we're in the right directory
    if [ ! -f "xdp.sh" ] || [ ! -d "src" ]; then
        error "Please run this script from the project root directory"
        error "(directory containing xdp.sh and src/)"
        exit 1
    fi
    
    info "Starting automated setup (non-interactive mode)..."
    echo ""
    
    # Run pre-flight checks
    if ! preflight_checks; then
        warn "Pre-flight checks detected issues, but continuing..."
        echo ""
    fi
    
    # Check sudo access
    if ! check_sudo; then
        exit 1
    fi
    echo ""
    
    # Run all setup steps with progress
    log "Step 1/7: Installing system dependencies..."
    install_dependencies
    echo ""
    
    log "Step 2/7: Installing XDP tools..."
    install_xdp_tools
    echo ""
    
    log "Step 3/7: Setting up Python environment..."
    setup_venv
    echo ""
    
    log "Step 4/7: Building project..."
    build_project
    echo ""
    
    log "Step 5/7: Verifying setup..."
    verify_setup
    echo ""
    
    log "Step 6/7: Optimizing system performance..."
    optimize_system_performance
    echo ""
    
    log "Step 7/7: Configuring network..."
    configure_network
    echo ""
    
    log "Step 8/8: Finalizing..."
    show_status
    
    local end_time
    end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    echo ""
    echo -e "${GREEN}=========================================${NC}"
    log "Setup completed successfully in ${duration}s!"
    echo -e "${GREEN}=========================================${NC}"
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi