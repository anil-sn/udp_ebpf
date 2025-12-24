#!/bin/bash
# Run tests using the virtual environment
# This script activates the venv and runs the test framework

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PATH="$PROJECT_ROOT/.venv"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}Running XDP VXLAN Pipeline Tests with Virtual Environment${NC}"
echo "======================================================="

# Check if virtual environment exists
if [ ! -d "$VENV_PATH" ]; then
    echo -e "${RED}ERROR: Virtual environment not found at $VENV_PATH${NC}"
    echo "Run ./setup_venv.sh first to create the virtual environment"
    exit 1
fi

# Check if we're already in the virtual environment
if [[ "$VIRTUAL_ENV" != "$VENV_PATH" ]]; then
    echo "Activating virtual environment..."
    source "$VENV_PATH/bin/activate"
fi

# Test that scapy is available
echo "Testing Python dependencies..."
python3 -c "import scapy; print('✓ Scapy available:', scapy.__version__)" || {
    echo -e "${RED}ERROR: Scapy not available in virtual environment${NC}"
    exit 1
}

# Test the packet generator
echo ""
echo -e "${BLUE}Testing packet generator...${NC}"
python3 tests/generate_packets.py --help

# Run the full test framework with sudo (preserving environment)
echo ""
echo -e "${BLUE}Running full test suite...${NC}"
echo -e "${YELLOW}Note: Test framework requires sudo for XDP operations${NC}"

# Preserve the PATH and virtual environment when running with sudo
sudo --preserve-env=PATH,VIRTUAL_ENV,PYTHONPATH bash -c "
    source '$VENV_PATH/bin/activate'
    cd tests
    ./test_framework.sh
"