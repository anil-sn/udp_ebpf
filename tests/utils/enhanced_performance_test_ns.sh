#!/bin/bash
# Enhanced XDP Performance Test with Network Namespace
# Solves the localhost loopback issue by using isolated network environment

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

# Network namespace configuration
NAMESPACE="xdp-test"
VETH_HOST="veth-host"
VETH_NS="veth-ns"
HOST_IP="192.168.100.1"
NS_IP="192.168.100.2"

DURATION="${1:-20}"
PPS="${2:-5000}"
THREADS="${3:-8}"

echo -e "${BLUE}🚀 Enhanced XDP Performance Test (Network Namespace)${NC}"
echo "=================================================================="
echo "Host Interface: $VETH_HOST (IP: $HOST_IP)"
echo "Traffic Source: $NAMESPACE (IP: $NS_IP)"  
echo "Duration: ${DURATION}s"
echo "Target PPS: $PPS"
echo "Threads: $THREADS"
echo

# Check requirements
if [ $EUID -ne 0 ]; then
    echo "❌ Must run as root for XDP operations"
    echo "Usage: sudo $0 [duration] [pps] [threads]"
    exit 1
fi

# Activate virtual environment
source "$VENV_PATH/bin/activate" || {
    echo "❌ Virtual environment not found. Run: ../setup_venv.sh"
    exit 1
}

# Create results directory
RESULTS_DIR="$PROJECT_ROOT/tests/reports/performance_ns_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_DIR"

echo -e "${BLUE}📋 Step 1: Setting up test environment${NC}"
$TEST_DIR/setup_test_namespace.sh setup

echo -e "\n${BLUE}📋 Step 2: Starting XDP Pipeline on Host Interface${NC}"
cd "$PROJECT_ROOT/src"

# Start XDP pipeline on the veth host interface
./vxlan_loader -i "$VETH_HOST" -I 2 -v > "$RESULTS_DIR/xdp_stats.log" 2>&1 &
XDP_PID=$!

# Wait for XDP to initialize
sleep 3

# Check if XDP is running
if ! kill -0 $XDP_PID 2>/dev/null; then
    echo "❌ XDP pipeline failed to start"
    cat "$RESULTS_DIR/xdp_stats.log"
    $TEST_DIR/setup_test_namespace.sh cleanup
    exit 1
fi

echo "✅ XDP pipeline started on $VETH_HOST (PID: $XDP_PID)"

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
    
    # Cleanup network namespace
    $TEST_DIR/setup_test_namespace.sh cleanup
    
    echo "✅ Cleanup complete"
}

# Set trap for cleanup
trap cleanup EXIT INT TERM

echo -e "\n${BLUE}📋 Step 3: Starting Traffic Generation from Namespace${NC}"

# Start traffic injector in namespace background
ip netns exec $NAMESPACE python3 "$TEST_DIR/traffic_injector.py" \
    --target-ip "$HOST_IP" \
    --interface "$VETH_NS" \
    --threads "$THREADS" \
    --pps "$PPS" \
    --duration "$DURATION" > "$RESULTS_DIR/traffic_stats.log" 2>&1 &

TRAFFIC_PID=$!

echo "✅ Traffic injector started in namespace (PID: $TRAFFIC_PID)"
echo -e "${YELLOW}⏳ Generating $PPS PPS traffic from $NS_IP to $HOST_IP for ${DURATION}s...${NC}"

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

echo -e "\n${BLUE}📋 Step 4: Generating Performance Report${NC}"

# Extract final statistics from logs
FINAL_STATS=$(tail -20 "$RESULTS_DIR/xdp_stats.log" | grep "Total Packets" | tail -1 || echo "No stats found")
TRAFFIC_STATS=$(tail -10 "$RESULTS_DIR/traffic_stats.log" || echo "No traffic stats")

# Create summary report
cat > "$RESULTS_DIR/summary.txt" << EOF
XDP VXLAN Performance Test Results (Network Namespace)
====================================================
Test Configuration:
  Host Interface: $VETH_HOST (IP: $HOST_IP)
  Traffic Source: $NAMESPACE (IP: $NS_IP)
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
    echo -e "\n💡 ${YELLOW}Network namespace test completed${NC}"
    echo "   This should show proper XDP packet processing"
fi

echo
echo "📖 View detailed stats: cat $RESULTS_DIR/xdp_stats.log"
echo "🔍 View traffic stats: cat $RESULTS_DIR/traffic_stats.log"