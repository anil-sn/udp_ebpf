#!/bin/bash
#
# Simple Test Runner for XDP VXLAN Pipeline
# Runs core functionality and performance tests
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test configuration
TEST_DIR="tests"
PYTHON_CMD="python3"

print_header() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  XDP VXLAN Pipeline - Simple Tests    ${NC}"
    echo -e "${BLUE}========================================${NC}"
}

print_section() {
    echo -e "\n${YELLOW}>>> $1${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

check_dependencies() {
    print_section "Checking Dependencies"
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        print_error "Python3 not found"
        exit 1
    fi
    print_success "Python3 found: $(python3 --version)"
    
    # Check required Python packages
    if ! python3 -c "import scapy" 2>/dev/null; then
        print_error "Scapy not installed. Install with: pip install scapy"
        exit 1
    fi
    print_success "Scapy available"
    
    if ! python3 -c "import pytest" 2>/dev/null; then
        print_error "Pytest not installed. Install with: pip install pytest"
        exit 1
    fi
    print_success "Pytest available"
}

run_basic_tests() {
    print_section "Running Basic Functionality Tests"
    
    if [ -f "$TEST_DIR/test_xdp_functions.py" ]; then
        echo "Running core XDP function tests..."
        if python3 -m pytest "$TEST_DIR/test_xdp_functions.py" -v; then
            print_success "Basic functionality tests passed"
        else
            print_error "Basic functionality tests failed"
            return 1
        fi
    else
        print_error "Basic test file not found: $TEST_DIR/test_xdp_functions.py"
        return 1
    fi
}

run_performance_tests() {
    print_section "Running Load & Performance Tests"
    
    if [ -f "$TEST_DIR/test_stress_load.py" ]; then
        echo "Running performance and load tests..."
        if python3 -m pytest "$TEST_DIR/test_stress_load.py" -v; then
            print_success "Performance tests passed"
        else
            print_error "Performance tests failed"
            return 1
        fi
    else
        print_error "Performance test file not found: $TEST_DIR/test_stress_load.py"
        return 1
    fi
}

run_packet_tests() {
    print_section "Running Packet Generator Tests"
    
    if [ -f "$TEST_DIR/utils/generate_packets.py" ]; then
        echo "Testing packet generator..."
        if python3 "$TEST_DIR/utils/generate_packets.py" --test-mode; then
            print_success "Packet generator working"
        else
            print_error "Packet generator failed"
            return 1
        fi
    else
        print_error "Packet generator not found: $TEST_DIR/utils/generate_packets.py"
        return 1
    fi
}

print_stats() {
    print_section "Test Statistics & Stats Verification"
    
    if [ -f "$TEST_DIR/performance/system_monitor.py" ]; then
        echo "Checking system monitoring capabilities..."
        python3 "$TEST_DIR/performance/system_monitor.py" --check || true
        print_success "Stats monitoring available"
    fi
    
    if [ -f "$TEST_DIR/utils/analyze_packets.py" ]; then
        echo "Checking packet analysis tools..."
        python3 "$TEST_DIR/utils/analyze_packets.py" --help > /dev/null || true
        print_success "Packet verification tools available"
    fi
}

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo "Options:"
    echo "  basic       - Run basic functionality tests only"
    echo "  performance - Run performance/load tests only" 
    echo "  packets     - Test packet generator and verification"
    echo "  stats       - Check statistics and monitoring tools"
    echo "  all         - Run all tests (default)"
    echo "  help        - Show this help"
}

main() {
    print_header
    
    case "${1:-all}" in
        "basic")
            check_dependencies
            run_basic_tests
            ;;
        "performance")
            check_dependencies
            run_performance_tests
            ;;
        "packets")
            check_dependencies
            run_packet_tests
            ;;
        "stats")
            check_dependencies
            print_stats
            ;;
        "all")
            check_dependencies
            run_basic_tests
            run_performance_tests
            run_packet_tests
            print_stats
            ;;
        "help"|"-h"|"--help")
            usage
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
    
    echo -e "\n${GREEN}========================================${NC}"
    echo -e "${GREEN}         Tests Completed Successfully   ${NC}"
    echo -e "${GREEN}========================================${NC}"
}

# Run main function with all arguments
main "$@"