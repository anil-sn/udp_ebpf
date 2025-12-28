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
    
    # Load configuration first
    local config_loaded=false
    if [ -f "config.yaml" ]; then
        if load_config_values "config.yaml"; then
            config_loaded=true
        fi
    fi
    
    # Use configured values or defaults
    local min_disk_gb="${MIN_DISK_SPACE_GB:-2}"
    local min_kernel="${MIN_KERNEL_VERSION:-4.18}"
    local connectivity_hosts="${CONNECTIVITY_TEST_HOSTS:-8.8.8.8 1.1.1.1}"
    
    local issues=0
    
    # Check internet connectivity
    info "Checking internet connectivity..."
    local connectivity_ok=false
    for host in $connectivity_hosts; do
        if ping -c 1 "$host" >/dev/null 2>&1; then
            log "Internet connectivity confirmed (tested $host)"
            connectivity_ok=true
            break
        fi
    done
    
    if [ "$connectivity_ok" = false ]; then
        error "No internet connectivity detected"
        issues=1
    fi
    
    # Check disk space (convert GB to KB)
    info "Checking available disk space..."
    local available
    available=$(df / | awk 'NR==2 {print $4}')
    local required_kb=$((min_disk_gb * 1024 * 1024))
    if [ "$available" -gt "$required_kb" ] 2>/dev/null; then
        log "Sufficient disk space available (${min_disk_gb}GB+ required)"
    else
        warn "Low disk space detected (less than ${min_disk_gb}GB free)"
        issues=1
    fi
    
    # Check if running in a container
    if [ -f /.dockerenv ] || grep -q docker /proc/1/cgroup 2>/dev/null; then
        warn "Running in Docker container - XDP functionality will be limited"
    fi
    
    # Check kernel version for XDP support
    local kernel_version
    kernel_version=$(uname -r | cut -d. -f1,2)
    if awk "BEGIN {exit !($kernel_version >= $min_kernel)}"; then
        log "Kernel version supports XDP ($(uname -r), minimum $min_kernel required)"
    else
        warn "Kernel version may have limited XDP support ($(uname -r), minimum $min_kernel recommended)"
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
echo "  • Set up Python virtual environment with all packages"
echo "  • Install xdp-manager CLI globally for easy access"
echo "  • Build the XDP pipeline components"
echo "  • Configure network routing"
echo ""
echo -e "${GREEN}✨ After completion, you'll have:${NC}"
echo "  • Global 'xdp-manager' command available anywhere"
echo "  • Professional CLI with help, monitoring, and diagnostics"
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
            info "Updating package lists (non-interactive mode)..."
            if ! sudo apt-get update -y -qq 2>/dev/null; then
                warn "Package update failed, trying with different approach..."
                # Try without quiet mode to see errors
                sudo apt-get update -y || {
                    error "Failed to update package lists"
                    error "Please check your internet connection and try again"
                    return 1
                }
            fi
            
            # Core build dependencies (non-interactive)
            info "Installing core build dependencies..."
            if sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq build-essential clang gcc make libbpf-dev 2>/dev/null; then
                log "Core build tools installed"
            else
                warn "Retrying core dependencies installation..."
                if sudo DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential clang gcc make libbpf-dev; then
                    log "Core build tools installed (retry successful)"
                else
                    error "Failed to install core build dependencies"
                    return 1
                fi
            fi
            
            # Kernel headers (optional for WSL2)
            info "Installing kernel headers for $(uname -r)..."
            sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "linux-headers-$(uname -r)" || {
                warn "Could not install kernel headers for $(uname -r)"
                warn "This is normal for WSL2. XDP functionality may be limited."
                info "Continuing with setup..."
            }
            
            # Network tools (including ARP discovery and JSON processing)
            info "Installing network analysis tools..."
            if sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iproute2 net-tools tcpdump iputils-arping jq 2>/dev/null; then
                log "Network tools installed (including arping for MAC discovery and jq for JSON processing)"
            else
                warn "Some network tools may not be available, continuing..."
                sudo DEBIAN_FRONTEND=noninteractive apt-get install -y iproute2 net-tools jq || true
                log "Basic network tools installed"
            fi
            
            # Extended XDP development packages
            info "Installing extended XDP development packages..."
            if sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq git llvm libelf-dev libpcap-dev pkg-config m4 zlib1g-dev libcap-dev 2>/dev/null; then
                log "Extended XDP development packages installed"
            else
                warn "Retrying extended packages installation..."
                if sudo DEBIAN_FRONTEND=noninteractive apt-get install -y git llvm libelf-dev libpcap-dev pkg-config m4 zlib1g-dev libcap-dev; then
                    log "Extended XDP development packages installed (retry successful)"
                else
                    warn "Some extended packages may not be available, continuing..."
                fi
            fi
            
            # BPF tools - Build from source for reliability (AWS kernels often need this)
            if ! command -v bpftool >/dev/null 2>&1 || bpftool version 2>&1 | grep -q "WARNING.*not found"; then
                info "Installing bpftool from source..."
                
                # Install build dependencies (non-interactive)
                info "Installing bpftool build dependencies..."
                if sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq build-essential libssl-dev binutils-dev libcap-dev git 2>/dev/null; then
                    log "Build dependencies installed"
                else
                    warn "Retrying build dependencies installation..."
                    if sudo DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential libssl-dev binutils-dev libcap-dev git; then
                        log "Build dependencies installed (retry successful)"
                    else
                        error "Failed to install bpftool build dependencies"
                        return 1
                    fi
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
            if sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 python3-dev python3-pip 2>/dev/null; then
                log "Python development tools installed"
            else
                warn "Retrying Python installation..."
                if sudo DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-dev python3-pip; then
                    log "Python development tools installed (retry successful)"
                else
                    error "Failed to install Python development tools"
                    return 1
                fi
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
    
    # Install Python dependencies and xdp-manager package
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
        
        # Install xdp-manager package in editable mode
        info "Installing xdp-manager CLI package..."
        if command -v uv >/dev/null 2>&1; then
            if uv pip install -e .; then
                log "xdp-manager package installed successfully"
            else
                error "Failed to install xdp-manager package"
                return 1
            fi
        else
            if pip install -e .; then
                log "xdp-manager package installed successfully"
            else
                error "Failed to install xdp-manager package"
                return 1
            fi
        fi
        
        # Verify CLI installation
        if "$VENV_PATH/bin/xdp-manager" --version >/dev/null 2>&1; then
            log "xdp-manager CLI verified and ready"
        else
            warn "xdp-manager CLI installation may have issues"
        fi
        
    else
        error "Virtual environment activation script not found"
        return 1
    fi
}

# ============================================================================
# STEP 3.5: SETUP GLOBAL CLI ACCESS
# ============================================================================

setup_global_cli() {
    section "Setting Up Global CLI Access"
    
    local project_dir="$(pwd)"
    local venv_bin="$project_dir/.venv/bin"
    local global_bin="/usr/local/bin"
    local user_bin="$HOME/.local/bin"
    
    # Create user bin directory if it doesn't exist
    mkdir -p "$user_bin"
    
    # Option 1: Create wrapper script in user's local bin
    info "Creating global xdp-manager wrapper script..."
    cat > "$user_bin/xdp-manager" << EOF
#!/bin/bash
# XDP Manager CLI Wrapper - Auto-generated by prepare.sh
# Project location: $project_dir

set -e

# Navigate to project directory
cd "$project_dir"

# Check if virtual environment exists
if [ ! -f ".venv/bin/xdp-manager" ]; then
    echo "Error: XDP Manager not found. Please run prepare.sh from $project_dir" >&2
    exit 1
fi

# Use uv run if available, otherwise use direct venv execution
if command -v uv >/dev/null 2>&1 && [ -f "pyproject.toml" ]; then
    exec uv run xdp-manager "\$@"
else
    exec .venv/bin/xdp-manager "\$@"
fi
EOF
    
    chmod +x "$user_bin/xdp-manager"
    log "Global xdp-manager wrapper created at $user_bin/xdp-manager"
    
    # Also create shortcut for xdp-pipeline (alias)
    cat > "$user_bin/xdp-pipeline" << 'EOF'
#!/bin/bash
# XDP Pipeline alias - calls xdp-manager
exec xdp-manager "$@"
EOF
    
    chmod +x "$user_bin/xdp-pipeline"
    log "xdp-pipeline alias created"
    
    # Add to PATH if not already there
    if [[ ":$PATH:" != *":$user_bin:"* ]]; then
        info "Adding $user_bin to PATH for current session"
        export PATH="$user_bin:$PATH"
        
        # Add to shell profile for persistence - check multiple locations
        local shell_profiles=()
        local primary_profile=""
        
        # Detect current shell and preferred profiles
        if [ -n "$ZSH_VERSION" ]; then
            [ -f "$HOME/.zshrc" ] && shell_profiles+=("$HOME/.zshrc")
            primary_profile="$HOME/.zshrc"
        elif [ -n "$BASH_VERSION" ]; then
            [ -f "$HOME/.bashrc" ] && shell_profiles+=("$HOME/.bashrc")
            [ -f "$HOME/.bash_profile" ] && shell_profiles+=("$HOME/.bash_profile")
            primary_profile="$HOME/.bashrc"
        fi
        
        # Always check .profile as fallback
        [ -f "$HOME/.profile" ] && shell_profiles+=("$HOME/.profile")
        [ -z "$primary_profile" ] && primary_profile="$HOME/.profile"
        
        # Update existing profiles
        local updated_any=false
        for profile in "${shell_profiles[@]}"; do
            if [ -f "$profile" ] && ! grep -q "$user_bin" "$profile" 2>/dev/null; then
                echo "" >> "$profile"
                echo "# XDP Manager CLI - Added by prepare.sh $(date)" >> "$profile"
                echo "export PATH=\"$user_bin:\$PATH\"" >> "$profile"
                log "Added PATH export to $profile"
                updated_any=true
            fi
        done
        
        # Create primary profile if no profiles exist
        if [ "$updated_any" = false ] && [ ! -f "$primary_profile" ]; then
            echo "# XDP Manager CLI - Added by prepare.sh $(date)" > "$primary_profile"
            echo "export PATH=\"$user_bin:\$PATH\"" >> "$primary_profile"
            log "Created $primary_profile with PATH export"
            updated_any=true
        fi
        
        if [ "$updated_any" = true ]; then
            info "PATH will be available in new shell sessions"
            info "For current session, run: export PATH=\"$user_bin:\$PATH\""
        fi
    else
        log "PATH already includes $user_bin"
    fi
    
    # Create project activation script
    info "Creating project activation script..."
    cat > "activate-xdp.sh" << EOF
#!/bin/bash
# XDP Manager Environment Activation Script
# Source this file to activate the environment: source activate-xdp.sh

# Navigate to project directory
cd "$project_dir"

# Activate virtual environment
if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
    echo "✓ XDP Manager virtual environment activated"
    echo "✓ You can now use 'xdp-manager' directly"
    
    # Show quick help
    echo ""
    echo "Quick commands:"
    echo "  xdp-manager --help              # Show help"
    echo "  xdp-manager status              # Check pipeline status" 
    echo "  xdp-manager config show         # Show configuration"
    echo "  xdp-manager allowlist list      # List IP allowlist"
    echo ""
else
    echo "Error: Virtual environment not found" >&2
    return 1
fi
EOF
    
    chmod +x "activate-xdp.sh"
    log "Project activation script created: activate-xdp.sh"
    
    # Test global CLI access
    if command -v xdp-manager >/dev/null 2>&1; then
        log "Global xdp-manager command verified and ready"
    else
        warn "xdp-manager not immediately available in current session"
        info "To activate now: export PATH=\"$user_bin:\$PATH\""
        info "Or restart your shell to pick up profile changes"
        
        # Create a source-able script for immediate activation
        cat > "setup-path.sh" << EOF
#!/bin/bash
# Temporary PATH setup for XDP Manager CLI
# Run: source setup-path.sh

export PATH="$user_bin:\$PATH"
echo "✓ XDP Manager CLI added to PATH for this session"
echo "✓ You can now use 'xdp-manager' directly"
echo ""
echo "To make permanent, restart your shell or add to your profile:"
echo "  echo 'export PATH=\"$user_bin:\$PATH\"' >> ~/.bashrc"
echo ""
EOF
        chmod +x "setup-path.sh"
        info "Created setup-path.sh - run 'source setup-path.sh' for immediate access"
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
    if [ -f "config.yaml" ]; then
        log "config.yaml configuration file found"
    else
        warn "No configuration file found. CLI will use defaults"
        info "You can create config.yaml manually or run: xdp-manager config init"
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
    
    # Test virtual environment and CLI
    if source "$VENV_PATH/bin/activate" 2>/dev/null; then
        if python3 -c "import scapy" 2>/dev/null; then
            log "Python environment working"
        else
            warn "Python packages may have installation issues"
        fi
        
        # Test CLI installation
        if "$VENV_PATH/bin/xdp-manager" --help >/dev/null 2>&1; then
            log "XDP Manager CLI working correctly"
            
            # Test global CLI access
            if command -v xdp-manager >/dev/null 2>&1; then
                if xdp-manager --help >/dev/null 2>&1; then
                    log "Global xdp-manager command working"
                else
                    warn "Global xdp-manager command has issues"
                fi
            else
                info "Global xdp-manager will be available after shell restart"
            fi
        else
            warn "XDP Manager CLI installation has issues"
        fi
    else
        warn "Virtual environment activation failed"
    fi
}

# ============================================================================
# CONFIGURATION LOADING FUNCTION
# ============================================================================

load_config_values() {
    local config_file="$1"
    
    if [ ! -f "$config_file" ]; then
        warn "Configuration file not found: $config_file"
        return 1
    fi
    
    if ! command -v python3 >/dev/null 2>&1; then
        warn "Python3 not available for configuration parsing"
        return 1
    fi
    
    # Test if PyYAML is available
    if ! python3 -c "import yaml" 2>/dev/null; then
        warn "PyYAML not available, using default values"
        return 1
    fi
    
    info "Loading configuration from $config_file"
    
    # Load configuration using Python
    local config_script="
import yaml
import sys
import os

try:
    with open('$config_file', 'r') as f:
        config = yaml.safe_load(f)
    
    # Network configuration
    network = config.get('network', {})
    TARGET_IP = network.get('nat_ip', '172.30.82.95')
    TARGET_PORT = network.get('nat_port', '8081')
    SOURCE_PORT = network.get('source_port', '31765')
    EGRESS_INTERFACE = network.get('egress_interface', 'ens6')
    
    # Pipeline configuration
    pipeline = config.get('pipeline', {})
    BRIDGE_INTERFACE = pipeline.get('bridge_interface', 'br0')
    INTERFACE = pipeline.get('interface', 'eth0')
    TARGET_INTERFACE = pipeline.get('target_interface', 'eth1')
    
    # System configuration
    system = config.get('system', {})
    MIN_DISK_SPACE_GB = system.get('min_disk_space_gb', 2)
    MIN_KERNEL_VERSION = system.get('min_kernel_version', '4.18')
    
    # Build configuration  
    build = config.get('build', {})
    SOURCE_DIR = build.get('source_dir', 'src')
    TEMP_DIR = build.get('temp_dir', '/tmp')
    COMPILER_JOBS = build.get('compiler_jobs', 'auto')
    
    # Installation configuration
    install = config.get('installation', {})
    USER_BIN_DIR = install.get('user_bin_dir', '\$HOME/.local/bin')
    
    # Export as shell variables
    print(f'export TARGET_IP=\"{TARGET_IP}\"')
    print(f'export TARGET_PORT=\"{TARGET_PORT}\"')
    print(f'export SOURCE_PORT=\"{SOURCE_PORT}\"')
    print(f'export EGRESS_INTERFACE=\"{EGRESS_INTERFACE}\"')
    print(f'export BRIDGE_INTERFACE=\"{BRIDGE_INTERFACE}\"')
    print(f'export INTERFACE=\"{INTERFACE}\"')
    print(f'export TARGET_INTERFACE=\"{TARGET_INTERFACE}\"')
    print(f'export MIN_DISK_SPACE_GB=\"{MIN_DISK_SPACE_GB}\"')
    print(f'export MIN_KERNEL_VERSION=\"{MIN_KERNEL_VERSION}\"')
    print(f'export SOURCE_DIR=\"{SOURCE_DIR}\"')
    print(f'export TEMP_DIR=\"{TEMP_DIR}\"')
    print(f'export COMPILER_JOBS=\"{COMPILER_JOBS}\"')
    print(f'export USER_BIN_DIR=\"{USER_BIN_DIR}\"')
    
except Exception as e:
    print(f'echo \"Error loading config: {e}\"', file=sys.stderr)
    sys.exit(1)
"
    
    # Execute Python script and source the output
    local config_output
    config_output=$(python3 -c "$config_script" 2>/dev/null)
    
    if [ $? -eq 0 ] && [ -n "$config_output" ]; then
        eval "$config_output"
        log "Configuration loaded successfully"
        return 0
    else
        warn "Failed to load configuration from $config_file"
        return 1
    fi
}

# ============================================================================
# STEP 6: NETWORK CONFIGURATION  
# ============================================================================

configure_network() {
    section "Configuring Network Routing for XDP Pipeline"
    
    # Load configuration from YAML files
    local config_loaded=false
    
    if [ -f "config.yaml" ]; then
        if load_config_values "config.yaml"; then
            config_loaded=true
        fi
    fi
    
    # Set defaults if configuration loading failed
    if [ "$config_loaded" = false ]; then
        info "Using hardcoded default values"
        export TARGET_IP="172.30.82.95"
        export TARGET_PORT="8081"
        export BRIDGE_INTERFACE="br0"
        export EGRESS_INTERFACE="ens6"
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
    
    # Check if global CLI is available
    local global_cli_status="Run: source setup-path.sh (or restart shell)"
    if command -v xdp-manager >/dev/null 2>&1; then
        global_cli_status="Available now"
    fi
    
    echo ""
    info "🚀 XDP Manager CLI Usage:"
    echo "  Global command:      xdp-manager --help     ($global_cli_status)"
    echo "  Direct execution:    .venv/bin/xdp-manager --help"
    echo "  With uv:             uv run xdp-manager --help"
    echo "  Activate environment: source activate-xdp.sh"
    echo ""
    
    # Show immediate activation instructions if needed
    if ! command -v xdp-manager >/dev/null 2>&1; then
        info "⚡ To activate global CLI immediately:"
        echo "  source setup-path.sh        # Add to current session"
        echo "  # OR"
        echo "  export PATH=\"\$HOME/.local/bin:\$PATH\"  # Manual export"
        echo ""
    fi
    info "📋 Quick Commands:"
    echo "  xdp-manager status              # Check pipeline status"
    echo "  xdp-manager config show         # View configuration"
    echo "  xdp-manager allowlist list      # Show IP allowlist"
    echo "  xdp-manager start --interface eth0  # Start pipeline"
    echo "  xdp-manager monitor             # Real-time monitoring"
    echo ""
    info "🎯 Next steps:"
    echo "  1. Edit configuration: xdp-manager config edit"
    echo "  2. Check status: xdp-manager status"
    echo "  3. Start pipeline: xdp-manager start --interface <interface>"
    echo ""
    info "📁 Key files:"
    echo "  - CLI Package:      pyproject.toml, xdp_manager/"
    echo "  - Configuration:    config.yaml"
    echo "  - Activation:       activate-xdp.sh, setup-path.sh"
    echo "  - Source code:      src/"
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
    if [ ! -d "src" ] || [ ! -f "pyproject.toml" ]; then
        error "Please run this script from the project root directory"
        error "(directory containing pyproject.toml and src/)"
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
    
    log "Step 3/8: Setting up Python environment..."
    setup_venv
    echo ""
    
    log "Step 4/8: Setting up global CLI access..."
    setup_global_cli
    echo ""
    
    log "Step 5/8: Building project..."
    build_project
    echo ""
    
    log "Step 6/8: Verifying setup..."
    verify_setup
    echo ""
    
    log "Step 7/8: Configuring network..."
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