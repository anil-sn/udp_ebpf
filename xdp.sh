#!/bin/bash
# XDP VXLAN Pipeline Control - Main Entry Point

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/src"

# Source all function modules
source "$SCRIPT_DIR/xdp_functions/utils.sh"
source "$SCRIPT_DIR/xdp_functions/config.sh"
source "$SCRIPT_DIR/xdp_functions/interface.sh"
source "$SCRIPT_DIR/xdp_functions/bpf_ops.sh"
source "$SCRIPT_DIR/xdp_functions/monitoring.sh"
source "$SCRIPT_DIR/xdp_functions/pipeline.sh"

# Load configuration
load_configuration

# Ensure terminal is fixed on exit
trap fix_terminal EXIT INT TERM

# Parse command line
CMD="${1:-status}"
shift 2>/dev/null || true

case "$CMD" in
    "start") 
        start_pipeline "$@"
        ;;
    "stop") 
        stop_pipeline "$@"
        ;;
    "status") 
        show_pipeline_status "$@"
        ;;
    "stats") 
        show_compact_statistics "$@"
        ;;
    "config") 
        show_configuration "$@"
        ;;
    "maps") 
        show_bpf_maps "$@"
        ;;
    "logs") 
        show_logs "$@"
        ;;
    "info") 
        show_detailed_info "$@"
        ;;
    "monitor") 
        monitor_pipeline "$@"
        ;;
    "scale")
        source "$SCRIPT_DIR/xdp_functions/dynamic_scaling.sh"
        if [ "${1:-}" = "max-performance" ]; then
            echo "Configuring XDP pipeline for maximum performance..."
            scale_performance "max-performance"
        elif [ "${1:-}" = "monitor" ]; then
            scale_performance "monitor"
        else
            scale_performance "balanced"
        fi
        ;;
    "cleanup") 
        cleanup_pipeline "$@"
        ;;
    "restart") 
        stop_pipeline
        sleep 1
        start_pipeline "$@"
        ;;
    "help"|"--help"|"-h")
        show_usage
        ;;
    *) 
        print_color "red" "ERROR: Unknown command: $CMD"
        echo ""
        show_usage
        exit 1
        ;;
esac

# Usage information
show_usage() {
    cat << EOF
XDP VXLAN Pipeline Control

USAGE:
    ./xdp.sh <command> [options]

COMMANDS:
    start           Start the XDP VXLAN pipeline
    stop            Stop the pipeline and clean up processes
    restart         Stop and restart the pipeline
    status          Show pipeline status and basic info
    stats           Show real-time packet statistics (compact format)
    config          Show current pipeline configuration
    maps            Show detailed eBPF maps status and contents
    logs            Show recent pipeline log entries
                   Usage: logs [count] [filter]
    info            Show detailed system and configuration info
    monitor         Live traffic monitoring
    cleanup         Comprehensive cleanup of all resources
                   Use --reset-interfaces to reset network config
    scale           Dynamic performance scaling
                   Use 'max-performance' for maximum throughput
    help            Show this help message

EXAMPLES:
    ./xdp.sh start                          # Start pipeline with default config
    ./xdp.sh config                         # Show current configuration  
    ./xdp.sh maps                           # Show eBPF maps with live data
    ./xdp.sh logs 50 ALERT                  # Show last 50 log entries with alerts
    ./xdp.sh stats                          # Show live statistics
    ./xdp.sh cleanup --reset-interfaces     # Full cleanup + reset network
    ./xdp.sh scale max-performance          # Scale for maximum performance

CONFIGURATION:
    Edit .env file in project root or use environment variables
    
FILES:
    .env                           # Main configuration file
    /tmp/vxlan_loader.log         # Runtime logs
    
For detailed information: ./xdp.sh info
EOF
}

