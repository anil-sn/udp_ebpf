#!/bin/bash
# XDP VXLAN Pipeline - Complete Environment Preparation
# Unified setup: dependencies, venv, build, and verification

set -e

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

# Project paths
PROJECT_ROOT="$SCRIPT_DIR"
VENV_PATH="$PROJECT_ROOT/.venv"
SRC_DIR="$PROJECT_ROOT/src"

echo -e "${BLUE}XDP VXLAN Pipeline - Environment Preparation${NC}"
echo "============================================"

# ============================================================================
# STEP 1: SYSTEM DEPENDENCIES
# ============================================================================

install_dependencies() {
    section "Installing System Dependencies"
    
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
            sudo apt-get update -qq
            
            # Core build dependencies
            sudo apt-get install -y build-essential clang gcc make libbpf-dev
            log "Core build tools installed"
            
            # Kernel headers (optional for WSL2)
            sudo apt-get install -y linux-headers-$(uname -r) || {
                warn "Could not install kernel headers for $(uname -r)"
                warn "This is normal for WSL2. XDP functionality may be limited."
            }
            
            # Network tools
            sudo apt-get install -y iproute2 net-tools tcpdump
            log "Network tools installed"
            
            # BPF tools (try multiple approaches)
            if ! command -v bpftool >/dev/null 2>&1; then
                sudo apt-get install -y linux-tools-common linux-tools-generic || {
                    sudo apt-get install -y bpftool || {
                        warn "Could not install bpftool via package manager"
                    }
                }
            fi
            
            # Python development
            sudo apt-get install -y python3 python3-dev python3-pip
            log "Python development tools installed"
            ;;
            
        "centos"|"rhel"|"fedora")
            info "Installing for RedHat/CentOS/Fedora..."
            sudo yum update -y || sudo dnf update -y
            sudo yum install -y clang gcc make libbpf-devel kernel-headers kernel-devel || \
            sudo dnf install -y clang gcc make libbpf-devel kernel-headers kernel-devel
            log "Dependencies installed via yum/dnf"
            ;;
            
        *)
            warn "Unsupported OS: $OS"
            warn "Please install manually: clang, gcc, make, libbpf-dev, kernel-headers"
            ;;
    esac
}

# ============================================================================
# STEP 2: PYTHON VIRTUAL ENVIRONMENT
# ============================================================================

setup_venv() {
    section "Setting Up Python Environment"
    
    # Check/install uv
    if ! command -v uv >/dev/null 2>&1; then
        if [ -f "$HOME/.local/bin/uv" ]; then
            export PATH="$HOME/.local/bin:$PATH"
            log "Added uv to PATH"
        else
            info "Installing uv package manager..."
            curl -LsSf https://astral.sh/uv/install.sh | sh
            export PATH="$HOME/.local/bin:$PATH"
            log "uv installed"
        fi
    fi
    
    info "Using uv version: $(uv --version)"
    
    # Create virtual environment
    if [ ! -d "$VENV_PATH" ]; then
        info "Creating virtual environment..."
        uv venv "$VENV_PATH"
        log "Virtual environment created"
    else
        log "Virtual environment already exists"
    fi
    
    # Install Python dependencies
    source "$VENV_PATH/bin/activate"
    info "Installing Python packages..."
    
    if [ -f "requirements.txt" ]; then
        uv pip install -r requirements.txt
        log "Requirements installed from requirements.txt"
    else
        # Essential packages only
        uv pip install scapy psutil
        log "Essential packages installed"
    fi
}

# ============================================================================
# STEP 3: BUILD PROJECT
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
# STEP 4: VERIFY SETUP
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
# STEP 5: FINAL STATUS
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
    # Verify we're in the right directory
    if [ ! -f "xdp.sh" ] || [ ! -d "src" ]; then
        error "Please run this script from the project root directory"
        error "(directory containing xdp.sh and src/)"
        exit 1
    fi
    
    # Run all setup steps
    install_dependencies
    setup_venv
    build_project
    verify_setup
    show_status
    
    log "Preparation completed successfully!"
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi