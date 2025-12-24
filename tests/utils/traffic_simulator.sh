#!/bin/bash
# Traffic Simulator for XDP VXLAN Pipeline Testing
# Generates realistic network traffic for performance and stress testing

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PCAP_DIR="$SCRIPT_DIR/test_data"

# Load environment
if [ -f "$SCRIPT_DIR/../.env" ]; then
    source "$SCRIPT_DIR/../.env"
else
    INTERFACE="lo"
    NAT_IP="127.0.0.1"
    NAT_PORT="8080"
    SOURCE_PORT="42844"
fi

# PPS monitoring variables
PPS_LOG_FILE=""
PPS_MONITORING=false
MONITOR_PID=""
STATS_INTERVAL=1

# PPS monitoring variables
PPS_LOG_FILE=""
PPS_MONITORING=false
MONITOR_PID=""
STATS_INTERVAL=1

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Traffic Simulator for XDP VXLAN Pipeline Testing"
    echo ""
    echo "OPTIONS:"
    echo "  -i, --interface IFACE    Target interface (default: $INTERFACE)"
    echo "  -r, --rate PPS          Packet rate in packets per second (default: 1000)"
    echo "  -d, --duration SECONDS  Test duration in seconds (default: 10)"
    echo "  -t, --type TYPE         Traffic type: vxlan, mixed, flood (default: vxlan)"
    echo "  -s, --size SIZE         Packet size range: small, medium, large, mixed (default: mixed)"
    echo "  -p, --performance       Run performance test (high rate traffic)"
    echo "  -c, --capture FILE      Capture traffic to pcap file"
    echo "  -v, --verbose           Verbose output"
    echo "  -h, --help             Show this help"
    echo ""
    echo "EXAMPLES:"
    echo "  $0 --rate 10000 --duration 30      # 10K PPS for 30 seconds"
    echo "  $0 --performance                    # High-rate performance test"
    echo "  $0 --type mixed --capture test.pcap # Mixed traffic with capture"
}

# Default values
RATE=1000
DURATION=10
TRAFFIC_TYPE="vxlan"
SIZE_TYPE="mixed"
PERFORMANCE_MODE=false
CAPTURE_FILE=""
VERBOSE=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -i|--interface)
            INTERFACE="$2"
            shift 2
            ;;
        -r|--rate)
            RATE="$2"
            shift 2
            ;;
        -d|--duration)
            DURATION="$2"
            shift 2
            ;;
        -t|--type)
            TRAFFIC_TYPE="$2"
            shift 2
            ;;
        -s|--size)
            SIZE_TYPE="$2"
            shift 2
            ;;
        -p|--performance)
            PERFORMANCE_MODE=true
            RATE=50000  # High rate for performance testing
            DURATION=60
            shift
            ;;
        -c|--capture)
            CAPTURE_FILE="$2"
            shift 2
            ;;
        --pps-monitor)
            PPS_MONITORING=true
            shift
            ;;
        --pps-log)
            PPS_LOG_FILE="$2"
            PPS_MONITORING=true
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

log() {
    if [ "$VERBOSE" = true ]; then
        echo -e "${BLUE}[$(date '+%H:%M:%S')]${NC} $1"
    fi
}

error() {
    echo -e "${RED}ERROR:${NC} $1" >&2
}

success() {
    echo -e "${GREEN}✓${NC} $1"
}

warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# PPS monitoring functions
start_pps_monitoring() {
    if [ "$PPS_MONITORING" = true ]; then
        log "Starting PPS monitoring..."
        
        local pps_args="-i $INTERFACE -d $DURATION"
        if [ -n "$PPS_LOG_FILE" ]; then
            pps_args="$pps_args -o $PPS_LOG_FILE"
        fi
        
        if [ -x "$SCRIPT_DIR/pps_monitor.py" ]; then
            "$SCRIPT_DIR/pps_monitor.py" $pps_args &
            MONITOR_PID=$!
            log "PPS monitor started (PID: $MONITOR_PID)"
        else
            warning "pps_monitor.py not found, using basic monitoring"
            start_basic_pps_monitoring
        fi
    fi
}

stop_pps_monitoring() {
    if [ -n "$MONITOR_PID" ]; then
        log "Stopping PPS monitoring..."
        kill "$MONITOR_PID" 2>/dev/null || true
        wait "$MONITOR_PID" 2>/dev/null || true
        MONITOR_PID=""
    fi
}

start_basic_pps_monitoring() {
    {
        local start_rx=$(cat "/sys/class/net/$INTERFACE/statistics/rx_packets" 2>/dev/null || echo 0)
        local start_tx=$(cat "/sys/class/net/$INTERFACE/statistics/tx_packets" 2>/dev/null || echo 0)
        local start_time=$(date +%s)
        
        sleep "$DURATION"
        
        local end_rx=$(cat "/sys/class/net/$INTERFACE/statistics/rx_packets" 2>/dev/null || echo 0)
        local end_tx=$(cat "/sys/class/net/$INTERFACE/statistics/tx_packets" 2>/dev/null || echo 0)
        local end_time=$(date +%s)
        
        local rx_packets=$((end_rx - start_rx))
        local tx_packets=$((end_tx - start_tx))
        local total_packets=$((rx_packets + tx_packets))
        local time_elapsed=$((end_time - start_time))
        
        if [ "$time_elapsed" -gt 0 ]; then
            local rx_pps=$((rx_packets / time_elapsed))
            local tx_pps=$((tx_packets / time_elapsed))
            local total_pps=$((total_packets / time_elapsed))
            
            echo ""
            echo -e "${BLUE}Basic PPS Statistics:${NC}"
            echo "  RX: $rx_pps PPS ($rx_packets packets)"
            echo "  TX: $tx_pps PPS ($tx_packets packets)"
            echo "  Total: $total_pps PPS ($total_packets packets)"
            echo "  Duration: ${time_elapsed}s"
        fi
    } &
    MONITOR_PID=$!
}

# Check dependencies
check_dependencies() {
    local missing_deps=()
    
    for dep in hping3 tcpreplay python3; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            missing_deps+=("$dep")
        fi
    done
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        error "Missing dependencies: ${missing_deps[*]}"
        echo "Install with: apt-get install -y ${missing_deps[*]}"
        exit 1
    fi
}

# Generate test packets if not exists
ensure_test_packets() {
    mkdir -p "$PCAP_DIR"
    
    if [ ! -f "$PCAP_DIR/test_vxlan.pcap" ]; then
        log "Generating test packets..."
        if [ -x "$SCRIPT_DIR/generate_packets.py" ]; then
            "$SCRIPT_DIR/generate_packets.py" --output "$PCAP_DIR" >/dev/null
            success "Test packets generated"
        else
            error "generate_packets.py not found or not executable"
            exit 1
        fi
    fi
}

# Generate VXLAN traffic using hping3
generate_vxlan_traffic() {
    log "Generating VXLAN traffic to $INTERFACE (rate: $RATE PPS, duration: ${DURATION}s)"
    
    local interval=$(echo "scale=6; 1/$RATE" | bc -l)
    local total_packets=$((RATE * DURATION))
    
    # Use hping3 to generate UDP traffic on VXLAN port
    timeout "$DURATION" hping3 \
        -2 \
        -p 4789 \
        -i "u$(echo "$interval * 1000000" | bc -l | cut -d. -f1)" \
        -c "$total_packets" \
        -q \
        127.0.0.1 >/dev/null 2>&1 &
    
    local hping_pid=$!
    
    # Monitor progress
    for ((i=1; i<=DURATION; i++)); do
        sleep 1
        if [ "$VERBOSE" = true ]; then
            printf "\rProgress: %d/%d seconds" "$i" "$DURATION"
        fi
    done
    
    if [ "$VERBOSE" = true ]; then
        echo ""
    fi
    
    # Ensure hping3 is stopped
    kill "$hping_pid" 2>/dev/null || true
    wait "$hping_pid" 2>/dev/null || true
}

# Generate mixed traffic (VXLAN + regular UDP)
generate_mixed_traffic() {
    log "Generating mixed traffic (VXLAN + regular UDP)"
    
    local vxlan_rate=$((RATE * 7 / 10))  # 70% VXLAN
    local regular_rate=$((RATE * 3 / 10))  # 30% regular UDP
    
    # VXLAN traffic
    timeout "$DURATION" hping3 \
        -2 -p 4789 \
        -i "u$(echo "scale=0; 1000000/$vxlan_rate" | bc)" \
        -q 127.0.0.1 >/dev/null 2>&1 &
    local vxlan_pid=$!
    
    # Regular UDP traffic
    timeout "$DURATION" hping3 \
        -2 -p 8080 \
        -i "u$(echo "scale=0; 1000000/$regular_rate" | bc)" \
        -q 127.0.0.1 >/dev/null 2>&1 &
    local regular_pid=$!
    
    # Wait for completion
    sleep "$DURATION"
    
    kill "$vxlan_pid" "$regular_pid" 2>/dev/null || true
    wait "$vxlan_pid" "$regular_pid" 2>/dev/null || true
}

# Flood test - maximum rate traffic
generate_flood_traffic() {
    warning "Starting flood test - high CPU usage expected"
    
    # Multiple parallel hping3 processes for maximum load
    local processes=4
    local rate_per_process=$((RATE / processes))
    
    for ((i=1; i<=processes; i++)); do
        timeout "$DURATION" hping3 \
            -2 -p 4789 \
            -i "u$(echo "scale=0; 1000000/$rate_per_process" | bc)" \
            --flood \
            -q 127.0.0.1 >/dev/null 2>&1 &
    done
    
    # Wait for all processes
    wait
}

# Replay captured packets
replay_pcap_traffic() {
    if [ ! -f "$PCAP_DIR/test_vxlan.pcap" ]; then
        error "Test packet file not found: $PCAP_DIR/test_vxlan.pcap"
        return 1
    fi
    
    log "Replaying captured packets (rate: $RATE PPS)"
    
    # Use tcpreplay for accurate timing
    if command -v tcpreplay >/dev/null 2>&1; then
        timeout "$DURATION" tcpreplay \
            --intf1="$INTERFACE" \
            --pps="$RATE" \
            --loop=1000 \
            "$PCAP_DIR/test_vxlan.pcap" >/dev/null 2>&1
    else
        warning "tcpreplay not available, using alternative method"
        generate_vxlan_traffic
    fi
}

# Start packet capture if requested
start_capture() {
    if [ -n "$CAPTURE_FILE" ]; then
        log "Starting packet capture: $CAPTURE_FILE"
        timeout $((DURATION + 5)) tcpdump \
            -i "$INTERFACE" \
            -w "$CAPTURE_FILE" \
            -q \
            "udp port 4789 or udp port $NAT_PORT" >/dev/null 2>&1 &
        echo $! > "/tmp/traffic_sim_tcpdump.pid"
        sleep 1  # Give tcpdump time to start
    fi
}

# Stop packet capture
stop_capture() {
    if [ -f "/tmp/traffic_sim_tcpdump.pid" ]; then
        local tcpdump_pid=$(cat "/tmp/traffic_sim_tcpdump.pid")
        kill "$tcpdump_pid" 2>/dev/null || true
        rm -f "/tmp/traffic_sim_tcpdump.pid"
        
        if [ -n "$CAPTURE_FILE" ] && [ -f "$CAPTURE_FILE" ]; then
            local packets=$(tcpdump -r "$CAPTURE_FILE" 2>/dev/null | wc -l)
            success "Captured $packets packets to $CAPTURE_FILE"
        fi
    fi
}

# Performance monitoring during test
monitor_performance() {
    if [ "$PERFORMANCE_MODE" = true ]; then
        log "Starting performance monitoring..."
        
        # Monitor interface statistics
        local start_rx=$(cat "/sys/class/net/$INTERFACE/statistics/rx_packets" 2>/dev/null || echo 0)
        local start_time=$(date +%s)
        
        sleep "$DURATION"
        
        local end_rx=$(cat "/sys/class/net/$INTERFACE/statistics/rx_packets" 2>/dev/null || echo 0)
        local end_time=$(date +%s)
        
        local packets_received=$((end_rx - start_rx))
        local time_elapsed=$((end_time - start_time))
        local actual_pps=$((packets_received / time_elapsed))
        
        echo ""
        echo -e "${BLUE}Performance Results:${NC}"
        echo "  Target Rate: $RATE PPS"
        echo "  Actual Rate: $actual_pps PPS"
        echo "  Duration: ${time_elapsed}s"
        echo "  Total Packets: $packets_received"
        
        if [ "$actual_pps" -gt $((RATE * 8 / 10)) ]; then
            success "Performance target achieved (>80%)"
        else
            warning "Performance target not met (<80%)"
        fi
    fi
}

# Main execution
main() {
    echo -e "${BLUE}XDP VXLAN Traffic Simulator${NC}"
    echo "==========================="
    
    check_dependencies
    ensure_test_packets
    
    echo "Configuration:"
    echo "  Interface: $INTERFACE"
    echo "  Rate: $RATE PPS"
    echo "  Duration: ${DURATION}s"
    echo "  Traffic Type: $TRAFFIC_TYPE"
    
    if [ -n "$CAPTURE_FILE" ]; then
        echo "  Capture File: $CAPTURE_FILE"
    fi
    
    echo ""
    
    # Start capture if requested
    start_capture
    
    # Start PPS monitoring if requested
    start_pps_monitoring
    
    # Generate traffic based on type
    case "$TRAFFIC_TYPE" in
        "vxlan")
            generate_vxlan_traffic
            ;;
        "mixed")
            generate_mixed_traffic
            ;;
        "flood")
            generate_flood_traffic
            ;;
        "replay")
            replay_pcap_traffic
            ;;
        *)
            error "Unknown traffic type: $TRAFFIC_TYPE"
            exit 1
            ;;
    esac
    
    # Monitor performance if requested
    if [ "$PERFORMANCE_MODE" = true ]; then
        monitor_performance &
    fi
    
    # Wait for traffic generation to complete
    sleep 1
    
    # Stop PPS monitoring
    stop_pps_monitoring
    
    # Stop capture
    stop_capture
    
    success "Traffic simulation completed"
}

# Cleanup on exit
trap 'stop_pps_monitoring; stop_capture; exit' INT TERM

main "$@"