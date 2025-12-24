#!/bin/bash
# Virtual Environment Setup Script for XDP VXLAN Pipeline
# Uses uv for fast and reliable Python environment management

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PATH="$PROJECT_ROOT/.venv"

echo -e "${BLUE}XDP VXLAN Pipeline - Virtual Environment Setup${NC}"
echo "================================================"

# Check if uv is installed
if ! command -v uv >/dev/null 2>&1; then
    echo -e "${YELLOW}uv not found in PATH. Installing...${NC}"
    
    # Add uv to PATH if it exists in local bin
    if [ -f "$HOME/.local/bin/uv" ]; then
        export PATH="$HOME/.local/bin:$PATH"
        echo -e "${GREEN}✓ Added uv to PATH${NC}"
    else
        echo -e "${RED}ERROR: uv not found. Install with:${NC}"
        echo "curl -LsSf https://astral.sh/uv/install.sh | sh"
        exit 1
    fi
fi

echo "Using uv version: $(uv --version)"

# Create virtual environment if it doesn't exist
if [ ! -d "$VENV_PATH" ]; then
    echo -e "${BLUE}Creating virtual environment...${NC}"
    uv venv "$VENV_PATH"
    echo -e "${GREEN}✓ Virtual environment created at $VENV_PATH${NC}"
else
    echo -e "${GREEN}✓ Virtual environment already exists${NC}"
fi

# Activate the virtual environment and install dependencies
source "$VENV_PATH/bin/activate"

# Install dependencies
echo -e "${BLUE}Installing Python dependencies...${NC}"
uv pip install scapy

# Install optional test dependencies
echo -e "${BLUE}Installing test dependencies...${NC}"
uv pip install pytest pytest-cov

echo ""
echo -e "${GREEN}✓ Virtual environment setup complete!${NC}"
echo ""
echo -e "${YELLOW}To activate the environment:${NC}"
echo "  source .venv/bin/activate"
echo ""
echo -e "${YELLOW}To run tests with the virtual environment:${NC}"
echo "  ./run_tests_venv.sh"
echo ""
echo -e "${YELLOW}Or use uv to run commands directly:${NC}"
echo "  uv run python tests/generate_packets.py --help"