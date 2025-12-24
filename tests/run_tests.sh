#!/bin/bash
# XDP VXLAN Pipeline - Simple Test Runner
# Clean and simple test execution following KISS principles

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Paths
TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$TEST_DIR")"
VENV_PATH="$PROJECT_ROOT/.venv"

# Load configuration from .env file
if [ -f "$PROJECT_ROOT/.env" ]; then
    source "$PROJECT_ROOT/.env"
    echo -e "${GREEN}✓${NC} Configuration loaded from .env"
else
    echo -e "${YELLOW}⚠${NC} No .env file found - using defaults"
    INTERFACE="eth0"
    TARGET_INTERFACE="eth1"
fi

# Simple banner
echo -e "${BLUE}XDP VXLAN Pipeline Test Suite${NC}"
echo "=============================="

# Check virtual environment
check_venv() {
    if [ ! -d "$VENV_PATH" ]; then
        echo -e "${YELLOW}Setting up virtual environment...${NC}"
        cd "$PROJECT_ROOT" && ./setup_venv.sh
    fi
    source "$VENV_PATH/bin/activate"
    echo -e "${GREEN}✓${NC} Virtual environment ready"
}

# Run configuration tests
test_config() {
    echo -e "\n${BLUE}Configuration Tests${NC}"
    echo "-------------------"
    
    if "$TEST_DIR/config/validate_config.sh"; then
        echo -e "${GREEN}✓${NC} Configuration validation passed"
        return 0
    else
        echo -e "${RED}✗${NC} Configuration validation failed"
        return 1
    fi
}

# Run unit tests (basic packet generation)
test_unit() {
    echo -e "\n${BLUE}Unit Tests${NC}"
    echo "----------"
    
    echo "Testing packet generation..."
    if python3 "$TEST_DIR/utils/generate_packets.py" --help >/dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} Packet generator working"
        return 0
    else
        echo -e "${RED}✗${NC} Packet generator failed"
        return 1
    fi
}

# Run integration tests
test_integration() {
    echo -e "\n${BLUE}Integration Tests${NC}"
    echo "-----------------"
    
    if [ $EUID -ne 0 ]; then
        echo -e "${YELLOW}⚠${NC}  Integration tests require sudo (skipping)"
        return 0
    fi
    
    if "$TEST_DIR/integration/test_framework.sh"; then
        echo -e "${GREEN}✓${NC} Integration tests passed"
        return 0
    else
        echo -e "${RED}✗${NC} Integration tests failed"
        return 1
    fi
}

# Run performance tests
test_performance() {
    echo -e "\n${BLUE}Performance Tests${NC}"
    echo "-----------------"
    
    local scenario="${1:-baseline}"
    
    if [ $EUID -ne 0 ]; then
        echo -e "${YELLOW}⚠${NC}  Performance tests require sudo (skipping)"
        return 0
    fi
    
    echo "Running $scenario performance test..."
    if python3 "$TEST_DIR/performance/scale_performance_test.py" "$scenario" \
        --interface lo --workers 2 --output "$TEST_DIR/reports" >/dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} Performance test completed"
        return 0
    else
        echo -e "${RED}✗${NC} Performance test failed"
        return 1
    fi
}

# Show help
show_help() {
    cat << EOF
Usage: $0 [COMMAND]

Commands:
    config      - Run configuration tests
    unit        - Run unit tests
    integration - Run integration tests (requires sudo)
    performance - Run basic performance test (requires sudo)
    all         - Run all tests (requires sudo for some)
    help        - Show this help

Examples:
    $0 config           # Test configuration only
    $0 unit            # Test basic functionality
    sudo $0 all        # Run complete test suite
EOF
}

# Main execution
main() {
    local command="${1:-help}"
    local failed=0
    
    case "$command" in
        config)
            check_venv
            test_config || failed=1
            ;;
        unit)
            check_venv
            test_unit || failed=1
            ;;
        integration)
            check_venv
            test_integration || failed=1
            ;;
        performance)
            check_venv
            test_performance "${2:-baseline}" || failed=1
            ;;
        all)
            check_venv
            test_config || failed=1
            test_unit || failed=1
            test_integration || failed=1
            test_performance baseline || failed=1
            ;;
        help|--help|-h)
            show_help
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown command: $command${NC}"
            show_help
            exit 1
            ;;
    esac
    
    echo ""
    if [ $failed -eq 0 ]; then
        echo -e "${GREEN}🎉 All tests passed!${NC}"
    else
        echo -e "${RED}❌ Some tests failed${NC}"
        exit 1
    fi
}

main "$@"