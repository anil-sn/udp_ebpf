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

# Apply system tuning by default for optimal performance
if [ "$CMD" != "help" ] && [ "$CMD" != "--help" ] && [ "$CMD" != "-h" ]; then
    apply_system_tuning >/dev/null 2>&1 || true
    create_persistent_tuning >/dev/null 2>&1 || true
fi

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
    "pps")
        # PPS monitoring for both interfaces
        case "${1:-}" in
            "incoming")
                shift 2>/dev/null || true
                monitor_interface_pps_single "${INTERFACE:-ens5}" "$@"
                ;;
            "target")  
                shift 2>/dev/null || true
                monitor_interface_pps_single "${TARGET_INTERFACE:-ens6}" "$@"
                ;;
            "both"|"dual"|"")
                shift 2>/dev/null || true
                monitor_interface_pps "$@"
                ;;
            *)
                print_color "red" "ERROR: Invalid pps option. Use: incoming, target, both, or dual"
                echo "Usage: ./xdp.sh pps [incoming|target|both] [interval] [duration]"
                exit 1
                ;;
        esac
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
    "tune")
        print_color "blue" "Applying comprehensive system tuning for XDP VXLAN pipeline..."
        apply_system_tuning
        create_persistent_tuning
        print_color "green" "System tuning complete! Settings applied immediately and will persist after reboot."
        ;;
    "arp")
        # Manual ARP resolution for troubleshooting
        if [ -n "${1:-}" ]; then
            TARGET_IP="${1}"
            print_color "blue" "Manually populating ARP table for $TARGET_IP..."
            populate_arp_table "$TARGET_IP" "${TARGET_INTERFACE:-ens6}"
        else
            print_color "blue" "Populating ARP table for configured NAT target $NAT_IP..."
            populate_arp_table "$NAT_IP" "$TARGET_INTERFACE"
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
    tune            Apply comprehensive system tuning for optimal packet processing
                   Creates persistent configuration and applies immediately
                   NOTE: Basic tuning is applied automatically with all commands
    arp [IP]        Manually populate ARP table for MAC resolution
                   If no IP specified, uses configured NAT target IP
                   Useful for troubleshooting MAC resolution issues in fresh VMs
    help            Show this help message

EXAMPLES:
    ./xdp.sh start                          # Start pipeline with default config
    ./xdp.sh config                         # Show current configuration  
    ./xdp.sh maps                           # Show eBPF maps with live data
    ./xdp.sh logs 50 ALERT                  # Show last 50 log entries with alerts
    ./xdp.sh stats                          # Show live statistics
    ./xdp.sh cleanup --reset-interfaces     # Full cleanup + reset network
    ./xdp.sh scale max-performance          # Scale for maximum performance
    ./xdp.sh tune                           # Apply system performance tuning

CONFIGURATION:
    Edit .env file in project root or use environment variables
    
FILES:
    .env                           # Main configuration file
    /tmp/vxlan_loader.log         # Runtime logs
    
For detailed information: ./xdp.sh info
EOF
}

