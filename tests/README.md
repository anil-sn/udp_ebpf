# XDP VXLAN Pipeline - Test Suite

Simple and comprehensive testing framework for the XDP VXLAN pipeline.

## Quick Start

```bash
# Setup (one time)
cd ../
./setup_venv.sh

# Run all tests
cd tests/
sudo ./run_tests.sh all

# Run specific tests
./run_tests.sh config      # Configuration only
./run_tests.sh unit        # Basic functionality
sudo ./run_tests.sh integration  # Full pipeline test
sudo ./run_tests.sh performance  # Performance test


# Run all tests
./run_simple_tests.sh all

# Test specific components
./run_simple_tests.sh basic       # Core functionality
./run_simple_tests.sh performance # Load testing
./run_simple_tests.sh packets     # Packet tools
./run_simple_tests.sh stats       # Statistics
```

## Test Structure

```
tests/
├── run_tests.sh           # Main test runner
├── config/                # Configuration validation
│   └── validate_config.sh
├── utils/                 # Test utilities
│   ├── generate_packets.py
│   ├── analyze_packets.py
│   └── run_tests_venv.sh
├── integration/           # Full system tests
│   └── test_framework.sh
├── performance/           # Performance & scale tests
│   ├── run_performance.sh
│   ├── scale_performance_test.py
│   ├── performance_benchmark.sh
│   ├── system_monitor.py
│   └── performance_report.py
└── reports/               # Test results and reports
```

## Test Types

### Configuration Tests
- Validates `.env` configuration
- Checks interface availability
- Verifies system dependencies

### Unit Tests  
- Packet generation functionality
- Basic scapy operations
- Virtual environment setup

### Integration Tests
- eBPF compilation and loading
- End-to-end packet processing
- XDP program functionality
- Error handling

### Performance Tests
- Throughput benchmarking
- Scalability testing
- Resource monitoring
- Performance reporting

## Performance Testing

```bash
# Quick performance test
cd performance/
sudo ./run_performance.sh lo baseline

# Advanced performance testing
sudo python3 scale_performance_test.py --list  # Show scenarios
sudo python3 scale_performance_test.py high_throughput --interface eth0

# Full benchmark suite
sudo ./performance_benchmark.sh eth0 all
```

## Available Performance Scenarios

- `baseline` - Basic test (1K PPS, 64B packets)
- `high_throughput` - High rate (100K PPS, 1400B packets) 
- `small_packets` - Small packet flood (500K PPS, 64B packets)
- `large_packets` - Large frames (10K PPS, 9000B packets)
- `mixed_traffic` - Mixed sizes (50K PPS, varied)
- `cpu_stress` - CPU stress test (1M PPS, 64B packets)

## Requirements

- Root access (for XDP operations)
- Virtual environment with dependencies
- Network interface for testing
- System monitoring tools (optional)

## Troubleshooting

1. **Permission Denied**: Use `sudo` for XDP operations
2. **Module Import Error**: Run `../setup_venv.sh` first
3. **Interface Not Found**: Check interface name with `ip link`
4. **Build Errors**: Ensure build dependencies installed

## Output

Test results are saved in:
- `reports/` - Performance reports and charts
- `test_results/` - Integration test logs  
- `test_data/` - Generated test packets

## Development

Follow KISS principles:
- Keep tests simple and focused
- Use clear naming conventions
- Minimize dependencies
- Document expected behavior
