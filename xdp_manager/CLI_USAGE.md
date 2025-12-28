# XDP Manager CLI - Complete Guide

## Quick Reference

### Essential Commands

#### Pipeline Control
```bash
xdp-manager start --interface eth0     # Start pipeline
xdp-manager stop                       # Stop pipeline  
xdp-manager restart                    # Restart pipeline
xdp-manager status                     # Check status
xdp-manager reload                     # Reload BPF program
```

#### IP Allowlist
```bash
xdp-manager allowlist list             # Show allowlist
xdp-manager allowlist add 192.168.1.0/24    # Add network
xdp-manager allowlist remove 192.168.1.100  # Remove IP
xdp-manager allowlist clear --force    # Clear all
```

#### Monitoring & Stats
```bash
xdp-manager monitor                    # Real-time monitoring
xdp-manager stats                      # Show statistics
xdp-manager top                        # Interactive monitoring
xdp-manager analytics                  # Advanced analytics
```

#### Diagnostics
```bash
xdp-manager diagnostics                # System check
xdp-manager debug --info               # Debug information
xdp-manager config show                # Show configuration
```

#### Quick Start Sequence
```bash
# 1. Start pipeline
xdp-manager start --interface eth0

# 2. Check status  
xdp-manager status

# 3. Monitor activity
xdp-manager monitor --duration 60

# 4. View stats
xdp-manager stats
```

#### Access Methods
```bash
xdp-manager --help                     # Global (after prepare.sh)
.venv/bin/xdp-manager --help           # Direct path
uv run xdp-manager --help              # Using uv
source activate-xdp.sh; xdp-manager    # Environment activation
```

---

## Complete Documentation

### Overview

The XDP Manager CLI provides a professional command-line interface for managing XDP (eXpress Data Path) pipelines with advanced networking features, analytics, and monitoring capabilities.

## Installation & Setup

### Automatic Setup
```bash
# Run the preparation script for complete setup
./prepare.sh
```

### Manual Installation
```bash
# Install with uv (recommended)
uv pip install -e .

# Or with pip
pip install -e .
```

## Command Access Methods

### Global Command (after setup)
```bash
xdp-manager --help
xdp-pipeline --help  # alias
```

### Direct Execution
```bash
.venv/bin/xdp-manager --help
```

### Using uv
```bash
uv run xdp-manager --help
```

### Environment Activation
```bash
source activate-xdp.sh  # Auto-generated activation script
xdp-manager --help      # Now available directly
```

## Global Options

All commands support these global options:

- `--config, -c CONFIG`: Configuration file path
- `--verbose, -v`: Enable verbose logging
- `--quiet, -q`: Quiet mode - minimal output
- `--format {json,yaml,table,plain}`: Output format
- `--no-color`: Disable colored output

## Command Categories

### 1. Pipeline Management

#### Start Pipeline
```bash
# Basic start
xdp-manager start

# Start with specific interface
xdp-manager start --interface eth0

# Start with custom program
xdp-manager start --program vxlan_pipeline.bpf.o

# Advanced start with options
xdp-manager start --interface eth0 --program vxlan_pipeline.bpf.o --mode xdp --force --optimize
```

**Options:**
- `--interface, -i`: Network interface (defaults to config)
- `--program, -p`: BPF program path (defaults to config)
- `--mode`: XDP attachment mode (xdp, xdpgeneric, xdpdrv, xdpoffload)
- `--force`: Force attachment
- `--optimize`: Apply performance optimizations

#### Stop Pipeline
```bash
# Stop all interfaces
xdp-manager stop

# Stop specific interface
xdp-manager stop --interface eth0

# Force stop
xdp-manager stop --force
```

#### Restart Pipeline
```bash
# Basic restart
xdp-manager restart

# Quick restart without validation
xdp-manager restart --quick

# Restart with new program
xdp-manager restart --program new_program.bpf.o
```

#### Check Status
```bash
# Basic status
xdp-manager status

# Live status updates
xdp-manager status --live

# Status for specific interface
xdp-manager status --interface eth0

# Custom refresh interval for live mode
xdp-manager status --live --refresh 2.0
```

#### Reload Program
```bash
# Reload current program
xdp-manager reload

# Reload with new program
xdp-manager reload --program updated_program.bpf.o
```

### 2. IP Allowlist Management

#### List Allowlist
```bash
# Show current allowlist
xdp-manager allowlist list

# List with details
xdp-manager allowlist list --verbose

# Export to file
xdp-manager allowlist list --export allowlist_backup.json
```

#### Add IP/Network
```bash
# Add single IP
xdp-manager allowlist add 192.168.1.100

# Add network range
xdp-manager allowlist add 192.168.1.0/24

# Add multiple entries
xdp-manager allowlist add 10.0.0.0/8 172.16.0.0/12

# Add with description
xdp-manager allowlist add 192.168.1.0/24 --comment "Office network"
```

#### Remove from Allowlist
```bash
# Remove single IP
xdp-manager allowlist remove 192.168.1.100

# Remove network
xdp-manager allowlist remove 192.168.1.0/24

# Remove multiple entries
xdp-manager allowlist remove 192.168.1.100 10.0.0.1
```

#### Clear Allowlist
```bash
# Clear all entries (with confirmation)
xdp-manager allowlist clear

# Force clear without confirmation
xdp-manager allowlist clear --force
```

#### Import/Export
```bash
# Import from file
xdp-manager allowlist import --file allowlist.json

# Export current allowlist
xdp-manager allowlist export --file backup.json

# Import from production config
xdp-manager allowlist import --file config/ip_allowlist_prod.json
```

### 3. Statistics & Analytics

#### Basic Statistics
```bash
# Show current stats
xdp-manager stats

# Detailed statistics
xdp-manager stats --detailed

# Reset statistics
xdp-manager stats --reset

# Export statistics
xdp-manager stats --export stats.json
```

#### Advanced Analytics
```bash
# Run comprehensive analysis
xdp-manager analytics

# Performance analysis
xdp-manager analytics --performance

# Security analysis  
xdp-manager analytics --security

# Traffic patterns
xdp-manager analytics --traffic

# Generate report
xdp-manager analytics --report analytics_report.pdf

# Real-time analytics
xdp-manager analytics --live --duration 300
```

### 4. Monitoring

#### Real-time Monitoring
```bash
# Basic monitoring
xdp-manager monitor

# Monitor specific interface
xdp-manager monitor --interface eth0

# Monitor for specific duration
xdp-manager monitor --duration 300

# Monitor with custom refresh rate
xdp-manager monitor --refresh 0.5

# Export monitoring data
xdp-manager monitor --duration 60 --export monitor_data.json
```

#### Top-style Interface
```bash
# Interactive top-like monitoring
xdp-manager top

# Top for specific interface
xdp-manager top --interface eth0

# Top with custom refresh
xdp-manager top --refresh 2.0
```

### 5. Diagnostics & Debugging

#### Basic Diagnostics
```bash
# Quick system check
xdp-manager diagnostics

# Comprehensive diagnostics
xdp-manager diagnostics --comprehensive

# Interface-specific diagnostics
xdp-manager diagnostics --interface eth0

# Network connectivity tests
xdp-manager diagnostics --network

# Performance tests
xdp-manager diagnostics --performance
```

#### Debug Mode
```bash
# Enable debug mode
xdp-manager debug --enable

# Disable debug mode
xdp-manager debug --disable

# Show debug info
xdp-manager debug --info

# Debug specific component
xdp-manager debug --component bpf_maps

# Trace packet flow
xdp-manager debug --trace --interface eth0
```

### 6. Configuration Management

#### Show Configuration
```bash
# Display current config
xdp-manager config show

# Show specific section
xdp-manager config show --section pipeline

# Show as JSON
xdp-manager config show --format json
```

#### Edit Configuration
```bash
# Edit main config
xdp-manager config edit

# Edit specific file
xdp-manager config edit --file xdp_config.yaml

# Set specific value
xdp-manager config set pipeline.interface eth0

# Validate configuration
xdp-manager config validate
```

#### Reset Configuration
```bash
# Reset to defaults
xdp-manager config reset

# Reset specific section
xdp-manager config reset --section allowlist

# Backup before reset
xdp-manager config reset --backup
```

## Configuration Files

### Main Configuration
- `xdp_config.yaml`: Main XDP pipeline configuration
- `.env`: Environment variables and settings
- `pyproject.toml`: Project and CLI configuration

### Allowlist Files
- `config/ip_allowlist.json`: Development allowlist
- `config/ip_allowlist_prod.json`: Production allowlist

## Output Formats

All commands support multiple output formats:

```bash
# JSON output
xdp-manager status --format json

# YAML output  
xdp-manager config show --format yaml

# Plain text (no formatting)
xdp-manager stats --format plain

# Table format (default for most commands)
xdp-manager allowlist list --format table
```

## Examples & Common Use Cases

### Quick Start Sequence
```bash
# 1. Check system status
xdp-manager diagnostics

# 2. View configuration
xdp-manager config show

# 3. Start pipeline
xdp-manager start --interface eth0

# 4. Check status
xdp-manager status

# 5. Monitor in real-time
xdp-manager monitor --duration 60
```

### Production Deployment
```bash
# 1. Import production allowlist
xdp-manager allowlist import --file config/ip_allowlist_prod.json

# 2. Validate configuration
xdp-manager config validate

# 3. Start with optimizations
xdp-manager start --interface eth0 --optimize

# 4. Verify status
xdp-manager status --verbose

# 5. Start monitoring
xdp-manager monitor --duration 3600 --export production_monitoring.json
```

### Troubleshooting
```bash
# 1. Run comprehensive diagnostics
xdp-manager diagnostics --comprehensive

# 2. Check debug information
xdp-manager debug --info

# 3. Trace packet flow
xdp-manager debug --trace --interface eth0

# 4. Check BPF maps
xdp-manager debug --component bpf_maps

# 5. Generate diagnostic report
xdp-manager analytics --report diagnostic_report.pdf
```

### Performance Analysis
```bash
# 1. Reset statistics
xdp-manager stats --reset

# 2. Run performance test
xdp-manager diagnostics --performance

# 3. Monitor for analysis period
xdp-manager monitor --duration 600

# 4. Generate performance report
xdp-manager analytics --performance --report performance.pdf

# 5. Export detailed stats
xdp-manager stats --export detailed_stats.json
```

## Environment Variables

Set these in your shell or `.env` file:

```bash
# XDP Configuration
XDP_INTERFACE=eth0
XDP_PROGRAM=vxlan_pipeline.bpf.o
XDP_MODE=xdp

# Network Configuration
TARGET_IP=172.30.82.95
TARGET_PORT=8081
NAT_IP=172.30.82.95
NAT_PORT=8081

# CLI Configuration
XDP_CLI_CONFIG=xdp_config.yaml
XDP_CLI_VERBOSE=false
XDP_CLI_FORMAT=table
```

## Integration with Legacy Scripts

The CLI works alongside existing scripts:

```bash
# Legacy usage (still supported)
./xdp.sh start
./xdp.sh monitor

# Modern CLI equivalent
xdp-manager start
xdp-manager monitor

# Both can be used interchangeably
```

## Scripting & Automation

### Bash Integration
```bash
#!/bin/bash
# Automated deployment script

# Check if pipeline is ready
if xdp-manager status --format json | jq -r '.status' | grep -q "running"; then
    echo "Pipeline already running"
else
    echo "Starting pipeline..."
    xdp-manager start --interface eth0 --optimize
fi

# Monitor for issues
xdp-manager monitor --duration 300 --export monitoring.json
```

### JSON Output Processing
```bash
# Get interface statistics as JSON
xdp-manager stats --format json > stats.json

# Extract specific metrics
packets_processed=$(cat stats.json | jq -r '.packets.processed')
bytes_transferred=$(cat stats.json | jq -r '.bytes.transferred')

echo "Processed: $packets_processed packets"
echo "Transferred: $bytes_transferred bytes"
```

## Advanced Features

### Live Monitoring with Custom Scripts
```bash
# Real-time monitoring with alerts
xdp-manager monitor --live --refresh 1.0 | while read line; do
    if echo "$line" | grep -q "ERROR"; then
        echo "Alert: $line" | mail -s "XDP Alert" admin@company.com
    fi
done
```

### Automated Allowlist Management
```bash
# Dynamic allowlist updates
curl -s https://api.company.com/trusted-ips.json | \
    xdp-manager allowlist import --file -
```

### Integration with Monitoring Systems
```bash
# Prometheus metrics export
xdp-manager stats --format json > /var/lib/prometheus/xdp_metrics.json

# Grafana dashboard data
xdp-manager analytics --json | jq '.performance' > grafana_data.json
```

## Troubleshooting

### Common Issues

1. **Permission Errors**
   ```bash
   # Run with appropriate privileges
   sudo xdp-manager start --interface eth0
   ```

2. **Interface Not Found**
   ```bash
   # Check available interfaces
   xdp-manager diagnostics --network
   ip link show
   ```

3. **BPF Program Load Failures**
   ```bash
   # Verify program exists
   ls -la src/vxlan_pipeline.bpf.o
   
   # Check compilation
   cd src && make clean && make all
   ```

4. **Configuration Issues**
   ```bash
   # Validate configuration
   xdp-manager config validate
   
   # Reset to defaults
   xdp-manager config reset --backup
   ```

### Getting Help

```bash
# Command-specific help
xdp-manager <command> --help

# Global help
xdp-manager --help

# Version information
xdp-manager --version
```

## Performance Considerations

- Use `--optimize` flag for production deployments
- Monitor with appropriate refresh intervals (avoid < 0.1s for live monitoring)
- Export large datasets rather than displaying them in terminal
- Use JSON format for programmatic processing
- Consider using background monitoring for long-term data collection

## Security Notes

- Always validate allowlist imports from external sources
- Use `--force` flags carefully in production
- Regular backup of allowlist configurations
- Monitor for unauthorized access attempts via analytics
- Use debug mode only when necessary (performance impact)

---

*This document combines both the quick reference and complete CLI usage guide. For the latest updates, see `xdp-manager --help` or visit the project documentation.*