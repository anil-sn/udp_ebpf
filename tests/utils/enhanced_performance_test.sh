#!/bin/bash
# Enhanced Performance Test with Real Traffic Generation
# Uses multi-threaded traffic injection to show real XDP statistics

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Configuration
TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$TEST_DIR")")"
VENV_PATH="$PROJECT_ROOT/.venv"

# Load configuration from .env file
if [ -f "$PROJECT_ROOT/.env" ]; then
    source "$PROJECT_ROOT/.env"
    INTERFACE="${INTERFACE:-ens4}"  # Use real interface from config
else
    INTERFACE="${1:-ens4}"  # Default to ens4, not lo
fi

DURATION="${2:-20}"
PPS="${3:-5000}"
THREADS="${4:-4}"

echo -e "${BLUE}🚀 Enhanced XDP Performance Test${NC}"
echo "=================================="
echo "Interface: $INTERFACE"
echo "Duration: ${DURATION}s"
echo "Target PPS: $PPS"
echo "Threads: $THREADS"
echo

# Check requirements
if [ $EUID -ne 0 ]; then
    echo "❌ Must run as root for XDP operations"
    echo "Usage: sudo $0 [interface] [duration] [pps] [threads]"
    exit 1
fi

# Activate virtual environment
source "$VENV_PATH/bin/activate" || {
    echo "❌ Virtual environment not found. Run: ../setup_venv.sh"
    exit 1
}

# Create results directory
RESULTS_DIR="$PROJECT_ROOT/tests/reports/performance_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_DIR"

echo -e "${BLUE}📋 Step 1: Starting XDP Pipeline${NC}"
cd "$PROJECT_ROOT/src"

# Start XDP pipeline with verbose stats
./vxlan_loader -i "$INTERFACE" -I 2 -v > "$RESULTS_DIR/xdp_stats.log" 2>&1 &
XDP_PID=$!

# Wait for XDP to initialize
sleep 3

# Check if XDP is running
if ! kill -0 $XDP_PID 2>/dev/null; then
    echo "❌ XDP pipeline failed to start"
    cat "$RESULTS_DIR/xdp_stats.log"
    exit 1
fi

echo "✅ XDP pipeline started (PID: $XDP_PID)"

# Function to cleanup on exit
cleanup() {
    echo -e "\n${YELLOW}🧹 Cleaning up...${NC}"
    
    # Stop traffic injector
    if [ ! -z "$TRAFFIC_PID" ]; then
        kill $TRAFFIC_PID 2>/dev/null || true
        wait $TRAFFIC_PID 2>/dev/null || true
    fi
    
    # Stop XDP pipeline
    if kill -0 $XDP_PID 2>/dev/null; then
        kill -TERM $XDP_PID
        sleep 2
        kill -KILL $XDP_PID 2>/dev/null || true
    fi
    
    echo "✅ Cleanup complete"
}

# Set trap for cleanup
trap cleanup EXIT INT TERM

echo -e "\n${BLUE}📋 Step 2: Starting Multi-threaded Traffic Generation${NC}"

# Start traffic injector in background
python3 "$TEST_DIR/traffic_injector.py" \
    --interface "$INTERFACE" \
    --threads "$THREADS" \
    --pps "$TARGET_PPS" \
    --duration "$DURATION" > "$RESULTS_DIR/traffic_stats.log" 2>&1 &

TRAFFIC_PID=$!

echo "✅ Traffic injector started (PID: $TRAFFIC_PID)"
echo -e "${YELLOW}⏳ Generating $TARGET_PPS PPS traffic for ${DURATION}s...${NC}"

# Monitor both processes
echo -e "\n${BLUE}📊 Real-time Monitoring${NC}"
echo "=================================="

# Wait a bit for traffic to start
sleep 2

# Show live statistics by tailing XDP log
echo -e "${GREEN}📈 XDP Pipeline Statistics (live):${NC}"
timeout $((DURATION + 5)) tail -f "$RESULTS_DIR/xdp_stats.log" &
TAIL_PID=$!

# Wait for traffic injector to complete
wait $TRAFFIC_PID 2>/dev/null || true

# Stop tailing
kill $TAIL_PID 2>/dev/null || true

echo -e "\n${BLUE}📋 Step 3: Generating Performance Report${NC}"

# Extract final statistics from logs
FINAL_STATS=$(tail -20 "$RESULTS_DIR/xdp_stats.log" | grep "Total Packets" | tail -1 || echo "No stats found")
TRAFFIC_STATS=$(tail -10 "$RESULTS_DIR/traffic_stats.log" || echo "No traffic stats")

# Create summary report
cat > "$RESULTS_DIR/summary.txt" << EOF
XDP VXLAN Performance Test Results
=================================
Test Configuration:
  Interface: $INTERFACE
  Duration: ${DURATION}s
  Target PPS: $PPS
  Threads: $THREADS
  
XDP Statistics (Final):
$FINAL_STATS

Traffic Generator Stats:
$TRAFFIC_STATS

Files Generated:
- xdp_stats.log: Complete XDP pipeline statistics
- traffic_stats.log: Traffic generator performance
- summary.txt: This summary report

Test completed at: $(date)
EOF

echo -e "\n${GREEN}✅ Performance Test Complete!${NC}"
echo "=================================="
echo "📁 Results saved to: $RESULTS_DIR"
echo
echo -e "${BLUE}📊 Quick Summary:${NC}"
cat "$RESULTS_DIR/summary.txt"

# Show if we achieved target performance
if echo "$FINAL_STATS" | grep -q "PERFORMANCE TARGET ACHIEVED"; then
    echo -e "\n🎉 ${GREEN}TARGET PERFORMANCE ACHIEVED!${NC}"
else
    echo -e "\n⚠️  ${YELLOW}Performance target not reached${NC}"
    echo "   This may be normal for loopback testing"
fi

echo
echo "📖 View detailed stats: cat $RESULTS_DIR/xdp_stats.log"
echo "🔍 View traffic stats: cat $RESULTS_DIR/traffic_stats.log"