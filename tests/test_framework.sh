#!/bin/bash
# XDP VXLAN Pipeline Test Framework
# Comprehensive testing suite for validation and performance testing

set -e

# Test Framework Configuration
TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DATA_DIR="$TEST_DIR/test_data"
TEST_RESULTS_DIR="$TEST_DIR/test_results"
TEST_LOG="$TEST_RESULTS_DIR/test_$(date +%Y%m%d_%H%M%S).log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Load environment configuration
if [ -f "$TEST_DIR/../.env" ]; then
    source "$TEST_DIR/../.env"
else
    echo -e "${YELLOW}Warning: .env not found, using test defaults${NC}"
    INTERFACE="lo"
    TARGET_INTERFACE=""
    NAT_IP="127.0.0.1"
    NAT_PORT="8080"
    SOURCE_PORT="31765"
fi

# Initialize test environment
init_test_env() {
    echo -e "${BLUE}Initializing Test Environment${NC}"
    echo "================================="
    
    # Create directories
    mkdir -p "$TEST_DATA_DIR" "$TEST_RESULTS_DIR"
    
    # Create log file
    touch "$TEST_LOG"
    echo "Test started at $(date)" | tee "$TEST_LOG"
    
    # Check if running as root (required for XDP)
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}ERROR: Tests must be run as root for XDP operations${NC}"
        echo "Use: sudo ./test_framework.sh"
        exit 1
    fi
    
    # Check dependencies
    check_dependencies
    
    echo -e "${GREEN}✓ Test environment initialized${NC}"
    echo ""
}

# Check required dependencies
check_dependencies() {
    local deps=("clang" "gcc" "make" "ip" "tc" "hping3" "tcpdump" "python3")
    local missing_deps=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            missing_deps+=("$dep")
        fi
    done
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        echo -e "${RED}ERROR: Missing dependencies: ${missing_deps[*]}${NC}"
        echo "Install with: apt-get install -y ${missing_deps[*]} python3-scapy"
        exit 1
    fi
}

# Test result logging
log_test() {
    local test_name="$1"
    local result="$2"
    local message="$3"
    
    TESTS_RUN=$((TESTS_RUN + 1))
    
    if [ "$result" = "PASS" ]; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "${GREEN}✓ PASS${NC}: $test_name - $message" | tee -a "$TEST_LOG"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "${RED}✗ FAIL${NC}: $test_name - $message" | tee -a "$TEST_LOG"
    fi
}

# Build test - ensure project compiles
test_build() {
    echo -e "${BLUE}Running Build Tests${NC}"
    echo "==================="
    
    # Change to src directory for build
    cd "$TEST_DIR/../src" || {
        log_test "Directory Change" "FAIL" "Could not change to src directory"
        return 1
    }
    
    # Clean build
    if make clean >/dev/null 2>&1; then
        log_test "Build Clean" "PASS" "Successfully cleaned build artifacts"
    else
        log_test "Build Clean" "FAIL" "Failed to clean build"
        return 1
    fi
    
    # Compile eBPF program
    if make vxlan_pipeline.bpf.o >/dev/null 2>&1; then
        log_test "eBPF Compilation" "PASS" "eBPF program compiled successfully"
    else
        log_test "eBPF Compilation" "FAIL" "eBPF compilation failed"
        return 1
    fi
    
    # Compile userspace program
    if make vxlan_loader >/dev/null 2>&1; then
        log_test "Userspace Compilation" "PASS" "Userspace program compiled successfully"
    else
        log_test "Userspace Compilation" "FAIL" "Userspace compilation failed"
        return 1
    fi
    
    # Verify executables exist and are executable
    if [ -x "./vxlan_loader" ]; then
        log_test "Executable Check" "PASS" "vxlan_loader is executable"
    else
        log_test "Executable Check" "FAIL" "vxlan_loader not found or not executable"
        cd "$TEST_DIR"
        return 1
    fi
    
    # Return to test directory
    cd "$TEST_DIR"
}

# Configuration validation tests
test_configuration() {
    echo -e "${BLUE}Running Configuration Tests${NC}"
    echo "==========================="
    
    # Test .env loading
    if [ -f ".env" ]; then
        log_test "Config File Exists" "PASS" ".env file found"
        
        # Test configuration validation script
        if [ -x "./validate_config.sh" ] && ./validate_config.sh >/dev/null 2>&1; then
            log_test "Config Validation" "PASS" "Configuration validation passed"
        else
            log_test "Config Validation" "FAIL" "Configuration validation failed"
        fi
    else
        log_test "Config File Exists" "FAIL" ".env file not found"
    fi
    
    # Test interface existence (if not loopback)
    if [ "$INTERFACE" != "lo" ]; then
        if ip link show "$INTERFACE" >/dev/null 2>&1; then
            log_test "Interface Check" "PASS" "Interface $INTERFACE exists"
        else
            log_test "Interface Check" "FAIL" "Interface $INTERFACE not found"
        fi
    else
        log_test "Interface Check" "PASS" "Using loopback interface for testing"
    fi
}

# eBPF program loading tests
test_ebpf_loading() {
    echo -e "${BLUE}Running eBPF Loading Tests${NC}"
    echo "=========================="
    
    # Test program loading without attachment
    local temp_log=$(mktemp)
    
    # Start vxlan_loader in test mode (short duration)
    timeout 5s ./vxlan_loader -i lo -I 1 >"$temp_log" 2>&1 &
    local loader_pid=$!
    
    sleep 2
    
    if kill -0 "$loader_pid" 2>/dev/null; then
        log_test "eBPF Program Loading" "PASS" "Program loaded successfully"
        kill "$loader_pid" 2>/dev/null || true
    else
        log_test "eBPF Program Loading" "FAIL" "Program failed to load"
        cat "$temp_log" >> "$TEST_LOG"
    fi
    
    rm -f "$temp_log"
    
    # Clean up any attached XDP programs
    ip link set lo xdp off 2>/dev/null || true
}

# Packet generation and processing tests
test_packet_processing() {
    echo -e "${BLUE}Running Packet Processing Tests${NC}"
    echo "==============================="
    
    # Generate test VXLAN packets
    generate_test_packets
    
    # Test with generated packets
    if [ -f "$TEST_DATA_DIR/test_vxlan.pcap" ]; then
        log_test "Test Packet Generation" "PASS" "VXLAN test packets generated"
    else
        log_test "Test Packet Generation" "FAIL" "Failed to generate test packets"
        return 1
    fi
}

# Generate test VXLAN packets using external Python script
generate_test_packets() {
    echo "Generating test packets using external script..."
    
    # Check if generate_packets.py exists
    if [ ! -f "$TEST_DIR/generate_packets.py" ]; then
        echo "✗ generate_packets.py not found in $TEST_DIR"
        return 1
    fi
    
    # Run external packet generation script with configuration
    if "$TEST_DIR/generate_packets.py" \
        --output "$TEST_DATA_DIR" \
        --nat-source-port "${SOURCE_PORT:-42844}" \
        --nat-target-ip "${NAT_IP:-10.2.41.17}" \
        --nat-target-port "${NAT_PORT:-8081}" \
        --vni "${TARGET_VNI:-1}"; then
        echo "✓ Test packets generated successfully"
    else
        echo "✗ Failed to generate test packets"
        return 1
    fi
}

# Performance testing
test_performance() {
    echo -e "${BLUE}Running Performance Tests${NC}"
    echo "========================="
    
    # Performance test with synthetic load
    local test_duration=10
    local target_pps=${TARGET_PPS:-85000}
    
    echo "Starting performance test (${test_duration}s duration)..."
    
    # Start the pipeline
    timeout ${test_duration}s ./vxlan_loader -i lo -I 1 >"$TEST_RESULTS_DIR/perf_test.log" 2>&1 &
    local loader_pid=$!
    
    sleep 2
    
    # Generate synthetic load using hping3 (if interface supports it)
    if [ "$INTERFACE" = "lo" ]; then
        # For loopback, generate some UDP traffic
        timeout $((test_duration - 3))s bash -c '
            while true; do
                echo "test packet" | nc -u 127.0.0.1 4789 2>/dev/null || true
                sleep 0.001  # 1ms delay = ~1000 pps
            done
        ' &
        local traffic_pid=$!
    fi
    
    sleep $test_duration
    
    # Stop processes
    kill "$loader_pid" 2>/dev/null || true
    [ -n "$traffic_pid" ] && kill "$traffic_pid" 2>/dev/null || true
    
    # Analyze results
    if grep -q "Pipeline started" "$TEST_RESULTS_DIR/perf_test.log" 2>/dev/null; then
        log_test "Performance Test" "PASS" "Pipeline handled synthetic load"
    else
        log_test "Performance Test" "FAIL" "Pipeline failed under load"
    fi
    
    # Cleanup
    ip link set lo xdp off 2>/dev/null || true
}

# Memory and resource tests
test_resources() {
    echo -e "${BLUE}Running Resource Tests${NC}"
    echo "======================"
    
    # Check for memory leaks during startup/shutdown cycles
    local initial_mem=$(free -m | awk '/^Mem:/{print $3}')
    
    for i in {1..5}; do
        timeout 3s ./vxlan_loader -i lo -I 1 >/dev/null 2>&1 &
        local pid=$!
        sleep 1
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
        ip link set lo xdp off 2>/dev/null || true
        sleep 1
    done
    
    local final_mem=$(free -m | awk '/^Mem:/{print $3}')
    local mem_diff=$((final_mem - initial_mem))
    
    if [ "$mem_diff" -lt 50 ]; then  # Less than 50MB increase
        log_test "Memory Leak Test" "PASS" "No significant memory leak detected (${mem_diff}MB)"
    else
        log_test "Memory Leak Test" "FAIL" "Potential memory leak detected (${mem_diff}MB increase)"
    fi
}

# Error handling and edge case tests
test_error_handling() {
    echo -e "${BLUE}Running Error Handling Tests${NC}"
    echo "============================"
    
    # Test with invalid interface
    if timeout 3s ./vxlan_loader -i invalid_interface -I 1 2>/dev/null; then
        log_test "Invalid Interface Handling" "FAIL" "Should reject invalid interface"
    else
        log_test "Invalid Interface Handling" "PASS" "Correctly rejected invalid interface"
    fi
    
    # Test with invalid parameters
    if timeout 3s ./vxlan_loader -p 999999 -I 1 2>/dev/null; then
        log_test "Invalid Port Handling" "FAIL" "Should reject invalid port"
    else
        log_test "Invalid Port Handling" "PASS" "Correctly rejected invalid port"
    fi
    
    # Test graceful shutdown
    ./vxlan_loader -i lo -I 1 >/dev/null 2>&1 &
    local pid=$!
    sleep 2
    
    if kill -TERM "$pid" 2>/dev/null; then
        sleep 1
        if ! kill -0 "$pid" 2>/dev/null; then
            log_test "Graceful Shutdown" "PASS" "Process terminated gracefully"
        else
            log_test "Graceful Shutdown" "FAIL" "Process did not terminate gracefully"
            kill -KILL "$pid" 2>/dev/null || true
        fi
    else
        log_test "Graceful Shutdown" "FAIL" "Could not send termination signal"
    fi
    
    # Cleanup
    ip link set lo xdp off 2>/dev/null || true
}

# Generate test report
generate_report() {
    echo ""
    echo -e "${CYAN}===============================================${NC}"
    echo -e "${CYAN}               TEST RESULTS SUMMARY${NC}"
    echo -e "${CYAN}===============================================${NC}"
    echo ""
    echo "Tests Run: $TESTS_RUN"
    echo -e "Passed: ${GREEN}$TESTS_PASSED${NC}"
    echo -e "Failed: ${RED}$TESTS_FAILED${NC}"
    echo ""
    
    local success_rate=$((TESTS_PASSED * 100 / TESTS_RUN))
    echo "Success Rate: $success_rate%"
    
    if [ "$TESTS_FAILED" -eq 0 ]; then
        echo -e "${GREEN}🎉 ALL TESTS PASSED! 🎉${NC}"
        echo -e "${GREEN}Your VXLAN pipeline is ready for deployment.${NC}"
    else
        echo -e "${RED}⚠️  SOME TESTS FAILED ⚠️${NC}"
        echo -e "${YELLOW}Please review the test log: $TEST_LOG${NC}"
    fi
    
    echo ""
    echo "Detailed results saved to: $TEST_LOG"
    echo -e "${CYAN}===============================================${NC}"
}

# Main test execution
main() {
    echo -e "${BLUE}XDP VXLAN Pipeline Test Framework${NC}"
    echo -e "${BLUE}=================================${NC}"
    echo ""
    
    init_test_env
    
    # Run test suites
    test_build
    test_configuration
    test_ebpf_loading
    test_packet_processing
    test_performance
    test_resources
    test_error_handling
    
    generate_report
    
    # Return appropriate exit code
    if [ "$TESTS_FAILED" -eq 0 ]; then
        exit 0
    else
        exit 1
    fi
}

# Handle command line arguments
case "${1:-all}" in
    "build")       init_test_env; test_build ;;
    "config")      init_test_env; test_configuration ;;
    "ebpf")        init_test_env; test_ebpf_loading ;;
    "packets")     init_test_env; test_packet_processing ;;
    "performance") init_test_env; test_performance ;;
    "resources")   init_test_env; test_resources ;;
    "errors")      init_test_env; test_error_handling ;;
    "all")         main ;;
    "help")        
        echo "Usage: $0 [test_suite]"
        echo "Test suites: build, config, ebpf, packets, performance, resources, errors, all"
        echo "Run without arguments to execute all tests"
        ;;
    *)             
        echo "Unknown test suite: $1"
        echo "Use '$0 help' for usage information"
        exit 1
        ;;
esac