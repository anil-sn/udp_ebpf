#!/bin/bash
# XDP VXLAN Pipeline - Comprehensive Performance Benchmark Suite
# Automated testing with system monitoring and detailed reporting

set -e

# Colors and formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="$SCRIPT_DIR/performance_results"
VENV_PATH="$PROJECT_ROOT/.venv"

# Performance test configuration
DEFAULT_INTERFACE="lo"
DEFAULT_DURATION=60
MONITOR_INTERVAL=1
CPU_CORES=$(nproc)
MEMORY_GB=$(($(free -g | awk 'NR==2{print $2}')))

# System requirements check
check_requirements() {
    echo -e "${BLUE}🔍 Checking System Requirements${NC}"
    echo "════════════════════════════════════════════════════════"
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}❌ Must run as root for XDP operations${NC}"
        echo "Use: sudo ./performance_benchmark.sh"
        exit 1
    fi
    
    # Check virtual environment
    if [ ! -d "$VENV_PATH" ]; then
        echo -e "${YELLOW}⚠️  Virtual environment not found${NC}"
        echo "Setting up virtual environment..."
        cd "$PROJECT_ROOT" && ./setup_venv.sh
    fi
    
    # Check system resources
    echo -e "${GREEN}✓${NC} CPU Cores: $CPU_CORES"
    echo -e "${GREEN}✓${NC} Memory: ${MEMORY_GB}GB"
    
    # Check network interface
    if [ "$INTERFACE" != "lo" ] && ! ip link show "$INTERFACE" >/dev/null 2>&1; then
        echo -e "${RED}❌ Interface $INTERFACE not found${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓${NC} Interface: $INTERFACE"
    
    # Check dependencies
    local missing=()
    for cmd in tcpdump sar iostat; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing+=("$cmd")
        fi
    done
    
    if [ ${#missing[@]} -ne 0 ]; then
        echo -e "${YELLOW}⚠️  Installing missing tools: ${missing[*]}${NC}"
        if command -v apt-get >/dev/null 2>&1; then
            apt-get update && apt-get install -y tcpdump sysstat
        elif command -v yum >/dev/null 2>&1; then
            yum install -y tcpdump sysstat
        fi
    fi
    
    echo -e "${GREEN}✓${NC} All requirements met"
}

# System monitoring functions
start_system_monitoring() {
    local test_id=$1
    local monitor_dir="$RESULTS_DIR/monitoring/$test_id"
    
    mkdir -p "$monitor_dir"
    
    echo -e "${BLUE}📊 Starting System Monitoring${NC}"
    
    # CPU monitoring
    sar -u "$MONITOR_INTERVAL" > "$monitor_dir/cpu_usage.log" &
    echo $! > "$monitor_dir/sar_cpu.pid"
    
    # Memory monitoring  
    sar -r "$MONITOR_INTERVAL" > "$monitor_dir/memory_usage.log" &
    echo $! > "$monitor_dir/sar_mem.pid"
    
    # Network monitoring
    sar -n DEV "$MONITOR_INTERVAL" > "$monitor_dir/network_stats.log" &
    echo $! > "$monitor_dir/sar_net.pid"
    
    # I/O monitoring
    iostat -x "$MONITOR_INTERVAL" > "$monitor_dir/io_stats.log" &
    echo $! > "$monitor_dir/iostat.pid"
    
    # Custom resource monitor
    (
        echo "timestamp,cpu_percent,memory_percent,network_rx_bytes,network_tx_bytes"
        while true; do
            timestamp=$(date '+%Y-%m-%d %H:%M:%S')
            cpu_percent=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | sed 's/%us,//')
            mem_info=$(free | grep Mem)
            mem_used=$(echo $mem_info | awk '{print $3}')
            mem_total=$(echo $mem_info | awk '{print $2}')
            mem_percent=$(echo "scale=2; $mem_used * 100 / $mem_total" | bc -l 2>/dev/null || echo "0")
            
            if [ "$INTERFACE" != "lo" ]; then
                net_stats=$(cat "/sys/class/net/$INTERFACE/statistics/rx_bytes" "/sys/class/net/$INTERFACE/statistics/tx_bytes" 2>/dev/null || echo "0 0")
                rx_bytes=$(echo $net_stats | awk '{print $1}')
                tx_bytes=$(echo $net_stats | awk '{print $2}')
            else
                rx_bytes=0
                tx_bytes=0
            fi
            
            echo "$timestamp,$cpu_percent,$mem_percent,$rx_bytes,$tx_bytes"
            sleep "$MONITOR_INTERVAL"
        done
    ) > "$monitor_dir/system_metrics.csv" &
    echo $! > "$monitor_dir/system_monitor.pid"
    
    echo -e "${GREEN}✓${NC} Monitoring started for test: $test_id"
}

stop_system_monitoring() {
    local test_id=$1
    local monitor_dir="$RESULTS_DIR/monitoring/$test_id"
    
    echo -e "${BLUE}🛑 Stopping System Monitoring${NC}"
    
    # Stop all monitoring processes
    for pid_file in "$monitor_dir"/*.pid; do
        if [ -f "$pid_file" ]; then
            local pid=$(cat "$pid_file")
            if kill -0 "$pid" 2>/dev/null; then
                kill "$pid" 2>/dev/null || true
            fi
            rm -f "$pid_file"
        fi
    done
    
    echo -e "${GREEN}✓${NC} Monitoring stopped"
}

# XDP pipeline control
start_xdp_pipeline() {
    echo -e "${BLUE}🚀 Starting XDP VXLAN Pipeline${NC}"
    
    cd "$PROJECT_ROOT"
    
    # Build if needed
    if [ ! -f "src/vxlan_loader" ]; then
        echo "Building XDP program..."
        cd src && make clean && make && cd ..
    fi
    
    # Start pipeline in background
    ./xdp_pipeline.sh > "$RESULTS_DIR/xdp_pipeline.log" 2>&1 &
    XDP_PID=$!
    echo $XDP_PID > "$RESULTS_DIR/xdp_pipeline.pid"
    
    # Wait for startup
    sleep 5
    
    # Verify pipeline is running
    if ! kill -0 "$XDP_PID" 2>/dev/null; then
        echo -e "${RED}❌ Failed to start XDP pipeline${NC}"
        cat "$RESULTS_DIR/xdp_pipeline.log"
        exit 1
    fi
    
    echo -e "${GREEN}✓${NC} XDP pipeline started (PID: $XDP_PID)"
}

stop_xdp_pipeline() {
    echo -e "${BLUE}🛑 Stopping XDP Pipeline${NC}"
    
    if [ -f "$RESULTS_DIR/xdp_pipeline.pid" ]; then
        local pid=$(cat "$RESULTS_DIR/xdp_pipeline.pid")
        if kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid"
            sleep 3
            if kill -0 "$pid" 2>/dev/null; then
                kill -KILL "$pid"
            fi
        fi
        rm -f "$RESULTS_DIR/xdp_pipeline.pid"
    fi
    
    # Clean up any remaining XDP programs
    if [ "$INTERFACE" != "lo" ]; then
        ip link set dev "$INTERFACE" xdp off 2>/dev/null || true
    fi
    
    echo -e "${GREEN}✓${NC} XDP pipeline stopped"
}

# Run individual performance test
run_performance_test() {
    local scenario=$1
    local test_id="${scenario}_$(date +%Y%m%d_%H%M%S)"
    
    echo -e "\n${CYAN}${BOLD}🎯 Running Performance Test: $scenario${NC}"
    echo "════════════════════════════════════════════════════════"
    
    # Start monitoring
    start_system_monitoring "$test_id"
    
    # Activate virtual environment and run test
    source "$VENV_PATH/bin/activate"
    
    # Run the performance test
    local test_output="$RESULTS_DIR/${test_id}_output.log"
    
    if python3 "$SCRIPT_DIR/scale_performance_test.py" \
        "$scenario" \
        --interface "$INTERFACE" \
        --workers "$CPU_CORES" \
        --output "$RESULTS_DIR" > "$test_output" 2>&1; then
        
        echo -e "${GREEN}✓${NC} Test completed successfully"
    else
        echo -e "${RED}❌${NC} Test failed - check $test_output"
        cat "$test_output"
    fi
    
    # Stop monitoring
    sleep 2
    stop_system_monitoring "$test_id"
    
    deactivate 2>/dev/null || true
}

# Generate comprehensive benchmark report
generate_benchmark_report() {
    local report_file="$RESULTS_DIR/benchmark_summary_$(date +%Y%m%d_%H%M%S).html"
    
    echo -e "${BLUE}📋 Generating Benchmark Report${NC}"
    
    cat > "$report_file" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>XDP VXLAN Pipeline - Performance Benchmark Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }
        .metric { background: #f8f9fa; padding: 15px; border-radius: 5px; text-align: center; }
        .metric h3 { margin: 0 0 10px 0; color: #2c3e50; }
        .metric .value { font-size: 24px; font-weight: bold; color: #27ae60; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
        .pass { color: #27ae60; font-weight: bold; }
        .fail { color: #e74c3c; font-weight: bold; }
        .warn { color: #f39c12; font-weight: bold; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🚀 XDP VXLAN Pipeline Performance Benchmark</h1>
        <p>Comprehensive Performance Analysis Report</p>
        <p>Generated: $(date)</p>
        <p>System: $(uname -sr) | CPU Cores: $CPU_CORES | Memory: ${MEMORY_GB}GB</p>
    </div>
EOF

    # Add system information
    echo "    <div class=\"section\">" >> "$report_file"
    echo "        <h2>🖥️ System Information</h2>" >> "$report_file"
    echo "        <table>" >> "$report_file"
    echo "            <tr><th>Property</th><th>Value</th></tr>" >> "$report_file"
    echo "            <tr><td>Hostname</td><td>$(hostname)</td></tr>" >> "$report_file"
    echo "            <tr><td>Kernel</td><td>$(uname -r)</td></tr>" >> "$report_file"
    echo "            <tr><td>CPU</td><td>$(lscpu | grep 'Model name' | cut -d: -f2 | xargs)</td></tr>" >> "$report_file"
    echo "            <tr><td>CPU Cores</td><td>$CPU_CORES</td></tr>" >> "$report_file"
    echo "            <tr><td>Memory</td><td>${MEMORY_GB}GB</td></tr>" >> "$report_file"
    echo "            <tr><td>Interface</td><td>$INTERFACE</td></tr>" >> "$report_file"
    echo "        </table>" >> "$report_file"
    echo "    </div>" >> "$report_file"

    # Add test results summary
    echo "    <div class=\"section\">" >> "$report_file"
    echo "        <h2>📊 Performance Test Results</h2>" >> "$report_file"
    
    # Parse JSON results and add to report
    local json_files=($(find "$RESULTS_DIR" -name "performance_results_*.json" | sort))
    
    if [ ${#json_files[@]} -gt 0 ]; then
        echo "        <table>" >> "$report_file"
        echo "            <tr><th>Test Scenario</th><th>Total Packets</th><th>Avg PPS</th><th>Peak PPS</th><th>Throughput (Mbps)</th><th>Efficiency</th></tr>" >> "$report_file"
        
        for json_file in "${json_files[@]}"; do
            if command -v python3 >/dev/null 2>&1; then
                local scenario=$(python3 -c "import json; print(json.load(open('$json_file'))['scenario'])" 2>/dev/null || echo "Unknown")
                echo "            <tr><td>$scenario</td><td colspan=\"5\">See detailed results in $(basename $json_file)</td></tr>" >> "$report_file"
            fi
        done
        
        echo "        </table>" >> "$report_file"
    else
        echo "        <p>No performance test results found.</p>" >> "$report_file"
    fi
    
    echo "    </div>" >> "$report_file"

    # Close HTML
    cat >> "$report_file" << 'EOF'
    <div class="section">
        <h2>📁 Generated Files</h2>
        <ul>
            <li>Performance test results: JSON files in results directory</li>
            <li>System monitoring data: CSV files in monitoring subdirectory</li>
            <li>XDP pipeline logs: xdp_pipeline.log</li>
        </ul>
    </div>
</body>
</html>
EOF

    echo -e "${GREEN}✓${NC} Benchmark report saved: $report_file"
    echo -e "${CYAN}View report: file://$report_file${NC}"
}

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}🧹 Cleaning up...${NC}"
    
    stop_system_monitoring "cleanup" 2>/dev/null || true
    stop_xdp_pipeline
    
    # Kill any remaining background processes
    jobs -p | xargs -r kill 2>/dev/null || true
    
    echo -e "${GREEN}✓${NC} Cleanup complete"
}

# Main execution
main() {
    echo -e "${CYAN}${BOLD}"
    echo "══════════════════════════════════════════════════════════════════"
    echo "    XDP VXLAN PIPELINE - PERFORMANCE BENCHMARK SUITE"
    echo "══════════════════════════════════════════════════════════════════"
    echo -e "${NC}"
    
    # Parse command line arguments
    INTERFACE="${1:-$DEFAULT_INTERFACE}"
    SCENARIOS="${2:-baseline,high_throughput,small_packets}"
    
    # Setup
    mkdir -p "$RESULTS_DIR/monitoring"
    
    # Check requirements
    check_requirements
    
    # Setup signal handlers
    trap cleanup EXIT INT TERM
    
    # Start XDP pipeline
    start_xdp_pipeline
    
    # Run performance tests
    IFS=',' read -ra SCENARIO_ARRAY <<< "$SCENARIOS"
    
    for scenario in "${SCENARIO_ARRAY[@]}"; do
        scenario=$(echo "$scenario" | xargs)  # trim whitespace
        
        if [[ "$scenario" == "all" ]]; then
            # Run all available scenarios
            source "$VENV_PATH/bin/activate"
            local all_scenarios=$(python3 "$SCRIPT_DIR/scale_performance_test.py" --list | tail -n +3 | awk '{print $1}')
            deactivate
            
            for s in $all_scenarios; do
                run_performance_test "$s"
                sleep 5  # Brief pause between tests
            done
        else
            run_performance_test "$scenario"
            sleep 5  # Brief pause between tests
        fi
    done
    
    # Generate final report
    generate_benchmark_report
    
    echo -e "\n${GREEN}${BOLD}🏁 Performance Benchmark Complete!${NC}"
    echo -e "${CYAN}Results saved in: $RESULTS_DIR${NC}"
}

# Help function
show_help() {
    cat << EOF
XDP VXLAN Pipeline Performance Benchmark Suite

Usage: $0 [INTERFACE] [SCENARIOS]

Arguments:
    INTERFACE    Network interface to test (default: lo)
    SCENARIOS    Comma-separated list of scenarios to run (default: baseline,high_throughput,small_packets)
                 Use 'all' to run all available scenarios

Available scenarios:
    baseline        - Basic performance test (1K PPS, 64B packets)
    high_throughput - High throughput test (100K PPS, 1400B packets)
    small_packets   - Small packet flood (500K PPS, 64B packets)
    large_packets   - Large packet test (10K PPS, 9000B packets)
    mixed_traffic   - Mixed size traffic (50K PPS, varied sizes)
    burst_test      - Burst traffic patterns (variable PPS)
    cpu_stress      - CPU stress test (1M PPS, 64B packets)
    all            - Run all scenarios

Examples:
    $0                           # Run default tests on loopback
    $0 eth0                      # Test on eth0 interface
    $0 lo baseline,cpu_stress    # Run specific scenarios
    $0 eth0 all                  # Run all scenarios on eth0

Note: Must be run as root for XDP operations.
EOF
}

# Handle help request
if [[ "${1:-}" == "-h" ]] || [[ "${1:-}" == "--help" ]]; then
    show_help
    exit 0
fi

# Run main function
main "$@"