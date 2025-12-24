# XDP VXLAN Pipeline Test Framework

A comprehensive testing suite for validating and verifying the XDP VXLAN pipeline performance, correctness, and reliability.

## 🧪 Test Suite Overview

The test framework consists of several integrated components:

### Core Testing Scripts

1. **`test_framework.sh`** - Main test orchestrator
2. **`generate_packets.py`** - VXLAN packet generator  
3. **`traffic_simulator.sh`** - Network traffic simulation
4. **`analyze_packets.py`** - Packet capture analysis
5. **`validate_config.sh`** - Configuration validation

## 🚀 Quick Start

### Prerequisites
```bash
# Install dependencies
sudo apt-get update
sudo apt-get install -y python3-scapy hping3 tcpdump tcpreplay bc netcat-openbsd

# Ensure you have build tools
sudo apt-get install -y build-essential clang libbpf-dev linux-headers-$(uname -r)
```

### Running Tests
```bash
# Run all tests (requires root for XDP operations)
sudo ./test_framework.sh

# Run specific test suites
sudo ./test_framework.sh build         # Build verification
sudo ./test_framework.sh config        # Configuration tests  
sudo ./test_framework.sh ebpf          # eBPF loading tests
sudo ./test_framework.sh packets       # Packet processing tests
sudo ./test_framework.sh performance   # Performance tests
sudo ./test_framework.sh resources     # Memory/resource tests
sudo ./test_framework.sh errors        # Error handling tests
```

## 📋 Test Categories

### 1. Build Tests
Validates that the entire project compiles correctly:
- eBPF program compilation (clang → BPF bytecode)
- Userspace loader compilation
- Executable permissions and dependencies
- Clean build process verification

### 2. Configuration Tests  
Ensures configuration management works properly:
- `.env` file loading and parsing
- Network interface validation
- Parameter validation (IPs, ports, ranges)
- Configuration validation script execution

### 3. eBPF Loading Tests
Verifies XDP program lifecycle management:
- eBPF program loading into kernel
- XDP attachment to network interfaces  
- Map creation and initialization
- Graceful program detachment and cleanup

### 4. Packet Processing Tests
Tests core packet processing functionality:
- VXLAN packet generation with various scenarios
- NAT rule application verification
- DF bit clearing for large packets
- Packet forwarding and redirection
- Error handling for malformed packets

### 5. Performance Tests
Validates high-throughput processing capabilities:
- Synthetic traffic generation at target rates (85K+ PPS)
- CPU utilization monitoring
- Memory usage tracking
- Latency measurement
- Throughput verification

### 6. Resource Tests  
Checks for resource leaks and stability:
- Memory leak detection over multiple start/stop cycles
- File descriptor management
- eBPF map resource cleanup
- Process cleanup verification

### 7. Error Handling Tests
Validates robustness and error recovery:
- Invalid interface handling
- Invalid parameter rejection
- Signal handling (SIGTERM, SIGINT)
- Graceful shutdown procedures
- Edge case packet handling

## 📊 Test Data Generation

### Packet Generator (`generate_packets.py`)
Creates comprehensive test packets covering various scenarios:

```bash
# Generate standard test packets
./generate_packets.py --output test_data/

# Generate performance test packets  
./generate_packets.py --performance --count 10000

# Custom configuration
./generate_packets.py \
    --nat-source-port 42844 \
    --nat-target-ip 10.2.41.17 \
    --nat-target-port 8081 \
    --vni 1
```

#### Generated Packet Types:
- **Normal VXLAN**: Standard packets matching NAT rules
- **Large Packets**: >1400 bytes requiring DF bit clearing
- **Non-matching**: Different source ports (no NAT applied)
- **Invalid VNI**: Wrong VNI values (should be dropped)
- **Non-VXLAN**: Regular UDP traffic (pass-through)
- **Edge Cases**: Minimal size, malformed headers

### Traffic Simulator (`traffic_simulator.sh`)
Generates realistic network load for testing:

```bash
# Basic traffic simulation
./traffic_simulator.sh --rate 10000 --duration 30

# Performance testing mode
./traffic_simulator.sh --performance

# Mixed traffic types
./traffic_simulator.sh --type mixed --rate 5000

# Traffic capture for analysis
./traffic_simulator.sh --capture output.pcap --rate 1000
```

#### Traffic Types:
- **VXLAN**: Pure VXLAN traffic on port 4789
- **Mixed**: Combination of VXLAN and regular UDP
- **Flood**: High-rate stress testing  
- **Replay**: Replay captured packet files

## 📈 Analysis and Monitoring

### Packet Analysis (`analyze_packets.py`)
Comprehensive packet capture analysis:

```bash
# Analyze captured traffic
./analyze_packets.py capture.pcap

# Compare before/after processing
./analyze_packets.py before.pcap --compare after.pcap

# Verbose analysis with progress
./analyze_packets.py large_capture.pcap --verbose
```

#### Analysis Features:
- Packet size distribution
- Protocol breakdown (VXLAN vs non-VXLAN)
- VNI distribution analysis
- Port usage statistics
- Error detection and reporting
- Before/after comparison for pipeline validation

### Real-time Monitoring
The test framework provides real-time statistics:
- Packet processing rates (PPS)
- Memory usage tracking
- CPU utilization monitoring
- Error rate calculation
- Pipeline health status

## ⚙️ Configuration

### Environment Configuration (`.env`)
```bash
# Test Configuration
INTERFACE="lo"                    # Test interface
TARGET_INTERFACE=""              # Target interface (optional)
NAT_IP="127.0.0.1"               # NAT target IP
NAT_PORT="8080"                  # NAT target port  
SOURCE_PORT="42844"              # Source port to match
TARGET_PPS="85000"               # Performance target
PERFORMANCE_THRESHOLD="60000"    # Warning threshold
```

### Test Data Directory Structure
```
test_data/
├── test_vxlan.pcap              # Main test packet file
├── test_packet_1_normal.pcap    # Individual test cases
├── test_packet_2_large.pcap
├── ...
├── performance_test.pcap        # High-volume test packets
└── packet_summary.txt           # Packet descriptions
```

### Test Results Directory
```
test_results/
├── test_20231224_143022.log     # Timestamped test logs
├── perf_test.log               # Performance test output
└── capture_*.pcap              # Captured traffic files
```

## 🎯 Performance Validation

### Target Metrics
- **Throughput**: 85,000+ packets per second sustained
- **Latency**: Sub-microsecond per-packet processing
- **CPU Usage**: <50% on single modern CPU core  
- **Memory**: <100MB including userspace control plane
- **Packet Loss**: Zero drops under sustained load

### Performance Test Scenarios
1. **Baseline**: Standard VXLAN processing without NAT
2. **NAT Processing**: Full pipeline with NAT translation  
3. **Large Packets**: DF bit clearing on jumbo frames
4. **Mixed Load**: Combination of VXLAN and pass-through traffic
5. **Stress Test**: Maximum rate flood testing

## 🔧 Troubleshooting

### Common Issues

**Test fails with "Permission denied"**
```bash
# Tests require root privileges for XDP operations
sudo ./test_framework.sh
```

**Missing dependencies**
```bash
# Install required packages
sudo apt-get install -y python3-scapy hping3 tcpdump tcpreplay bc
```

**Interface not found**
```bash
# Check available interfaces
ip link show

# Update .env with correct interface
echo "INTERFACE=eth0" >> .env
```

**eBPF compilation fails**
```bash  
# Install eBPF development tools
sudo apt-get install -y clang libbpf-dev linux-headers-$(uname -r)
```

### Debug Mode
Enable verbose output for detailed troubleshooting:
```bash
# Run with detailed logging
sudo ./test_framework.sh 2>&1 | tee debug.log

# Check specific component
./validate_config.sh
./generate_packets.py --output /tmp/test
```

## 📝 Test Reports

The framework generates comprehensive test reports:

### Summary Report Format
```
===============================================
               TEST RESULTS SUMMARY
===============================================

Tests Run: 15
Passed: ✓ 14
Failed: ✗ 1

Success Rate: 93%

⚠️  SOME TESTS FAILED ⚠️
Please review the test log: test_results/test_20231224_143022.log
===============================================
```

### Detailed Logs
- Individual test results with pass/fail status
- Error messages and stack traces for failures
- Performance metrics and statistics
- Resource usage information
- Recommendations for issue resolution

## 🚀 Integration with CI/CD

### GitHub Actions Example
```yaml
name: XDP VXLAN Pipeline Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y python3-scapy hping3 tcpdump build-essential clang libbpf-dev linux-headers-$(uname -r)
      - name: Run tests
        run: sudo ./test_framework.sh
```

### Test Automation
- Automated nightly performance regression testing
- Pre-deployment validation pipeline
- Continuous integration with build systems
- Performance trending and alerting

This comprehensive test framework ensures your XDP VXLAN pipeline is robust, performant, and ready for production deployment.