# XDP VXLAN Pipeline Testing Guide

Clean and simple testing framework following KISS principles.

## 🚀 Quick Start

### Prerequisites
```bash
# Setup virtual environment (one time)
cd ../
./setup_venv.sh
```

### Running Tests
```bash
# All tests (simple)
cd tests/
sudo ./run_tests.sh all

# Specific test types
./run_tests.sh config       # Configuration validation
./run_tests.sh unit         # Basic unit tests
sudo ./run_tests.sh integration   # Full pipeline test
sudo ./run_tests.sh performance   # Performance & scale tests
```

## 📁 Test Structure

Following KISS principles - simple, organized, professional:

```
tests/
├── run_tests.sh           # Single entry point
├── config/                # Configuration tests
├── utils/                 # Shared utilities
├── integration/           # System integration
├── performance/           # Performance & scale
└── reports/               # Test results
```

## 🧪 Test Categories

### Configuration Tests (`config/`)
- Environment validation (`.env` file)
- Interface availability checks
- System dependency verification

### Unit Tests (`unit/`)
- Basic functionality validation
- Component isolation tests

### Integration Tests (`integration/`)
- Full pipeline validation
- End-to-end packet processing
- XDP program attachment/detachment

### Performance Tests (`performance/`)
- Scale testing (7 scenarios)
- Resource monitoring

## 📊 Performance Testing Details

### Scale Test Scenarios
1. **Baseline**: 1000 PPS for stability validation
2. **High Throughput**: 85,000+ PPS target performance
3. **Small Packets**: 64-byte packet processing
4. **Large Packets**: 1500-byte jumbo frame handling
5. **Mixed Traffic**: Variable packet size processing
6. **Burst Test**: Traffic spike handling
7. **CPU Stress**: Maximum load validation

### Performance Monitoring
- Real-time resource monitoring (`system_monitor.py`)
- HTML report generation with charts
- Benchmark comparison against baselines
- Performance regression detection

## 🛠️ Development Workflow

### Testing New Features
```bash
# 1. Validate configuration
./run_tests.sh config

# 2. Test basic functionality  
./run_tests.sh unit

# 3. Integration testing
sudo ./run_tests.sh integration

# 4. Performance validation
sudo ./run_tests.sh performance
```

### Continuous Integration
The test framework is designed for CI/CD integration with clear exit codes and standardized reporting.

## 📈 Results and Reports

- Test results stored in `reports/` directory
- Performance charts generated automatically
- HTML reports with detailed metrics
- CSV data for analysis and trending

---

**Keep it simple. Keep it clean. Keep it professional.**

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