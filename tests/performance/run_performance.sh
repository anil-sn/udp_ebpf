#!/bin/bash
# Simple Performance Test Runner
# Streamlined performance testing following KISS principles

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$TEST_DIR")"
VENV_PATH="$PROJECT_ROOT/.venv"
INTERFACE="${1:-lo}"
SCENARIO="${2:-baseline}"

echo -e "${BLUE}XDP Performance Test${NC}"
echo "==================="
echo "Interface: $INTERFACE"
echo "Scenario: $SCENARIO"

# Check requirements
if [ $EUID -ne 0 ]; then
    echo "❌ Must run as root for XDP operations"
    echo "Usage: sudo $0 [interface] [scenario]"
    exit 1
fi

# Activate virtual environment
source "$VENV_PATH/bin/activate" || {
    echo "❌ Virtual environment not found. Run: ./setup_venv.sh"
    exit 1
}

# Create results directory
RESULTS_DIR="$TEST_DIR/reports/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_DIR"

echo -e "${BLUE}Starting XDP pipeline...${NC}"
cd "$PROJECT_ROOT"
./xdp_pipeline.sh > "$RESULTS_DIR/xdp.log" 2>&1 &
XDP_PID=$!
sleep 3

# Run performance test
echo -e "${BLUE}Running performance test...${NC}"
python3 "$TEST_DIR/performance/scale_performance_test.py" \
    "$SCENARIO" \
    --interface "$INTERFACE" \
    --workers $(nproc) \
    --output "$RESULTS_DIR" || {
    echo "❌ Performance test failed"
    kill $XDP_PID 2>/dev/null || true
    exit 1
}

# Stop XDP pipeline
kill $XDP_PID 2>/dev/null || true
sleep 2

# Generate simple report
echo -e "${BLUE}Generating report...${NC}"
python3 "$TEST_DIR/performance/performance_report.py" \
    --results-dir "$RESULTS_DIR" \
    --output-dir "$RESULTS_DIR" || {
    echo "⚠️  Report generation failed (results still available)"
}

echo -e "${GREEN}✅ Performance test complete!${NC}"
echo "Results: $RESULTS_DIR"