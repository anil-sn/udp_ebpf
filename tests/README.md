# XDP VXLAN Pipeline Test Framework

This directory contains a comprehensive test framework for the XDP VXLAN pipeline with advanced packet per second (PPS) monitoring capabilities.

## Test Framework Structure

```
tests/
├── README.md              # This file
├── test_framework.sh      # Main test orchestrator
├── traffic_simulator.sh   # Traffic generation with PPS monitoring
├── pps_monitor.py         # Advanced PPS monitoring tool
├── generate_packets.py    # Scapy-based packet generator
├── analyze_packets.py     # Packet analysis and validation
├── validate_config.sh     # Configuration validation
├── monitor_performance.bt # BPFtrace real-time monitoring
└── TESTING.md            # Detailed testing documentation
```

## Quick Start

### Basic Traffic Simulation with PPS Monitoring

```bash
# Generate 1000 PPS VXLAN traffic for 30 seconds with real-time PPS monitoring
./traffic_simulator.sh --rate 1000 --duration 30 --pps-monitor

# High-performance test (50K PPS) with PPS data logging
./traffic_simulator.sh --performance --pps-log performance_results.json

# Mixed traffic with capture and PPS monitoring
./traffic_simulator.sh --type mixed --rate 5000 --capture test.pcap --pps-monitor
```

### Standalone PPS Monitoring

```bash
# Monitor interface for 60 seconds
./pps_monitor.py --interface eth0 --duration 60

# Monitor with detailed JSON output
./pps_monitor.py --interface lo --duration 30 --output detailed_stats.json

# Monitor with custom peak performance window
./pps_monitor.py --interface eth0 --duration 120 --window 10 --output results.json
```

### Complete Test Suite

```bash
# Run full test framework
./test_framework.sh

# Run specific test categories
./test_framework.sh --build-only
./test_framework.sh --performance-only
```

## PPS Monitoring Features

### Real-time Monitoring
- Live PPS display (RX, TX, Total)
- Bandwidth monitoring (Mbps)
- Timestamped measurements
- Configurable monitoring duration

### Advanced Analytics
- Peak performance window detection
- Statistical analysis (min, max, avg)
- JSON export for detailed analysis
- Historical data collection (last 1000 measurements)

### Integration with Traffic Simulator
- Automatic PPS monitoring during traffic generation
- Basic and advanced monitoring modes
- Background monitoring support
- Performance correlation analysis

## Performance Targets

The XDP VXLAN pipeline is designed to achieve:
- **Target Rate**: 85,000+ PPS
- **Latency**: Sub-microsecond processing
- **CPU Usage**: Minimal impact on system performance

## Usage Examples

### Performance Benchmarking
```bash
# Benchmark maximum PPS capacity
./traffic_simulator.sh --rate 100000 --duration 60 --pps-log benchmark.json --performance

# Sustained load testing
./traffic_simulator.sh --rate 50000 --duration 300 --pps-monitor --type mixed
```

### Development Testing
```bash
# Quick validation test
./traffic_simulator.sh --rate 1000 --duration 10 --pps-monitor

# Packet validation with analysis
./traffic_simulator.sh --rate 5000 --capture validation.pcap
./analyze_packets.py validation.pcap
```

### Advanced Monitoring with BPFtrace
```bash
# Real-time XDP pipeline monitoring
sudo ./monitor_performance.bt

# Monitor specific interface activity  
sudo bpftrace -e 'tracepoint:xdp:* { printf("%s\n", probe); }'
```

### Monitoring Integration
```bash
# Start PPS monitoring in background
./pps_monitor.py --interface eth0 --duration 300 --output monitoring.json &

# Run traffic simulation
./traffic_simulator.sh --rate 20000 --duration 60

# Analyze results
cat monitoring.json | jq '.statistics'
```

## Configuration

The test framework uses the parent directory's `.env` file for configuration:

```bash
# Interface Configuration
INTERFACE="eth0"
TARGET_INTERFACE="eth1"

# Network Configuration  
NAT_IP="10.0.0.100"
NAT_PORT="8080"
SOURCE_PORT="31765"

# VXLAN Configuration
VNI="1"
VXLAN_PORT="4789"
```

## Dependencies

Required packages:
- `python3` with `scapy` library
- `hping3` for traffic generation
- `tcpreplay` for packet replay
- `tcpdump` for packet capture
- Standard Linux networking tools

Install dependencies:
```bash
# Ubuntu/Debian
sudo apt-get install -y python3-scapy hping3 tcpreplay tcpdump

# Python dependencies
pip3 install scapy
```

## Output Files

The framework generates several output files:
- `test_results/` - Test execution logs and results
- `test_data/` - Generated test packets and captured traffic
- `*.json` - PPS monitoring data and statistics
- `*.pcap` - Packet captures for analysis

## Troubleshooting

### Common Issues

1. **Permission Denied**: Ensure running as root for XDP operations
2. **Interface Not Found**: Verify interface name in `.env` file
3. **Missing Dependencies**: Install required packages listed above
4. **High CPU Usage**: Normal during high-rate testing (>50K PPS)

### Performance Tuning

For optimal PPS measurement accuracy:
- Use dedicated test interfaces when possible
- Minimize background network activity
- Run tests on systems with sufficient resources
- Consider CPU affinity for high-rate testing

## Integration with XDP Pipeline

The test framework is designed to work with the XDP VXLAN pipeline:
- Generates VXLAN-encapsulated packets matching AWS Traffic Mirror format
- Validates DF bit clearing and NAT processing
- Measures end-to-end pipeline performance
- Provides detailed packet-level analysis

For more detailed information, see [TESTING.md](TESTING.md).