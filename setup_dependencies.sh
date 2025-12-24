#!/bin/bash
# XDP VXLAN Pipeline - Dependency Installation Script
# Automatically installs all required and optional dependencies

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}XDP VXLAN Pipeline - Dependency Setup${NC}"
echo "======================================"

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    echo -e "${YELLOW}Warning: Running as root. Consider using sudo instead.${NC}"
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo -e "${RED}Cannot detect OS. Please install dependencies manually.${NC}"
    exit 1
fi

echo "Detected OS: $OS"
echo ""

# Install based on OS
case $OS in
    "ubuntu"|"debian")
        echo -e "${GREEN}Installing for Ubuntu/Debian...${NC}"
        sudo apt-get update
        
        echo "Installing core build dependencies..."
        sudo apt-get install -y build-essential clang gcc make libbpf-dev
        
        echo "Installing kernel headers..."
        sudo apt-get install -y linux-headers-$(uname -r) || {
            echo -e "${YELLOW}Warning: Could not install kernel headers for $(uname -r)${NC}"
            echo "This is normal for WSL2. XDP may not work without proper headers."
        }
        
        echo "Installing network tools..."
        sudo apt-get install -y iproute2 net-tools tcpdump
        
        echo "Installing optional testing tools..."
        sudo apt-get install -y hping3
        
        echo "Installing Python scapy..."
        pip3 install scapy || {
            echo -e "${YELLOW}Warning: pip3 install scapy failed, trying system package...${NC}"
            sudo apt-get install -y python3-scapy || {
                echo -e "${YELLOW}Warning: Could not install scapy. Install manually if needed.${NC}"
            }
        }
        ;;
        
    "rhel"|"centos"|"fedora")
        echo -e "${GREEN}Installing for RHEL/CentOS/Fedora...${NC}"
        
        if command -v dnf >/dev/null 2>&1; then
            PKG_MGR="dnf"
        else
            PKG_MGR="yum"
        fi
        
        echo "Installing core build dependencies..."
        sudo $PKG_MGR install -y clang gcc make libbpf-devel kernel-devel
        
        echo "Installing network tools..."
        sudo $PKG_MGR install -y iproute tcpdump
        
        echo "Installing optional testing tools..."
        sudo $PKG_MGR install -y hping3 python3-scapy || {
            echo "Installing scapy via pip as fallback..."
            pip3 install scapy
        }
        ;;
        
    *)
        echo -e "${YELLOW}Unsupported OS: $OS${NC}"
        echo "Please install the following packages manually:"
        echo "- build-essential (or equivalent)"
        echo "- clang, gcc, make"
        echo "- libbpf development headers"
        echo "- kernel headers"
        echo "- iproute2, tcpdump"
        echo "- hping3, python3-scapy (optional)"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}✓ Dependency installation complete!${NC}"
echo ""
echo "Next steps:"
echo "1. Copy configuration: cp .env.example .env"
echo "2. Edit configuration: nano .env"
echo "3. Validate setup: cd tests && ./validate_config.sh"
echo "4. Build project: cd src && make"
echo "5. Run tests: cd tests && sudo ./test_framework.sh"