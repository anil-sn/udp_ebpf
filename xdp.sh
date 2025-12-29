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

# Parse command line first
CMD="${1:-status}"
shift 2>/dev/null || true

# Load configuration
load_configuration

# Apply system tuning by default for optimal performance
if [ "$CMD" != "help" ] && [ "$CMD" != "--help" ] && [ "$CMD" != "-h" ]; then
    apply_system_tuning >/dev/null 2>&1 || true
    create_persistent_tuning >/dev/null 2>&1 || true
fi

# Ensure terminal is fixed on exit
trap fix_terminal EXIT INT TERM

# Usage information
show_usage() {
    cat << EOF
XDP VXLAN Pipeline Control

USAGE:
    ./xdp.sh <command> [options]

COMMANDS:
    start           Start the XDP VXLAN pipeline
    stop            Stop the pipeline and clean up processes (graceful shutdown)
    restart         Stop and restart the pipeline
    status          Show pipeline status and basic info
    stats           Show pipeline performance analysis
                   'stats' or 'stats --detailed' - Detailed performance analysis (default)
                   'stats --compact'              - Compact one-line statistics
    ipstats         Show per-IP traffic statistics and allowlist status
    config          Show current pipeline configuration
    maps            Show detailed eBPF maps status and contents
    ips             Display IP allowlist management options:
                   'ips' or 'ips show'     - Show all IPs from eBPF map with organization info
                   'ips status'            - Check JSON vs eBPF map status for each IP
                   'ips reload'            - Reload all IPs from JSON file (clear + load)
                   'ips sync'              - Sync eBPF map with JSON (mark and sweep)
                   'ips sync-dry-run'      - Show what would be synced without changes
                   'ips orphaned'          - Show IPs in map but not in JSON file
                   'ips add <IP>'          - Add single IP to allowlist at runtime
                   'ips remove <IP>'       - Remove single IP from allowlist at runtime
                   'ips add-bulk <IP,IP>'  - Add comma-separated list of IPs
                   'ips remove-bulk <IP,IP>' - Remove comma-separated list of IPs
                   'ips watch [interval]'  - Watch JSON file for changes and auto-sync
                   Shows all currently loaded allowed IPs from the BPF map
    logs            Show recent pipeline log entries
                   Usage: logs [count] [filter]
    info            Show detailed system and configuration info
    monitor         Live traffic monitoring (replaces pps command)
                   Usage: monitor [incoming|target|both|simple] [interval] [duration]
                   incoming - Monitor incoming interface only
                   target   - Monitor target interface only  
                   both     - Monitor both interfaces with detailed stats (default)
                   simple   - Simple pipeline monitoring with performance thresholds
    cleanup         Comprehensive cleanup of all resources (logs, temp files, maps)
                   Use --reset-interfaces to reset network config
    scale           Dynamic performance scaling (queue management and CPU affinity)
                   Use 'max-performance' for maximum CPU utilization
                   Use 'monitor' for performance monitoring mode
                   Use 'balanced' for optimal resource balance
    tune            Apply comprehensive system tuning (network buffers, IRQ, persistence)
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
    ./xdp.sh ips status                     # Check JSON vs map status for all IPs
    ./xdp.sh ips reload                     # Clear and reload IPs from JSON  
    ./xdp.sh ips orphaned                   # Show IPs in map but not in JSON
    ./xdp.sh logs 50 ALERT                  # Show last 50 log entries with alerts
    ./xdp.sh stats                          # Show detailed pipeline analysis
    ./xdp.sh stats --compact                # Show compact statistics
    ./xdp.sh ipstats                        # Show per-IP traffic analysis
    ./xdp.sh pps both 1 60                  # Monitor PPS on both interfaces for 60s
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
        # Use enhanced statistics analyzer
        if [[ "${2:-}" == "--detailed" ]] || [[ "${2:-}" == "-d" ]]; then
            python3 src/xdp_functions/analyze_stats.py --detailed
        elif [[ "${2:-}" == "--compact" ]] || [[ "${2:-}" == "-c" ]]; then
            python3 src/xdp_functions/analyze_stats.py --compact
        else
            # Default to detailed analysis
            python3 src/xdp_functions/analyze_stats.py --detailed
        fi
        ;;
    "config") 
        show_configuration "$@"
        ;;
    "maps") 
        show_bpf_maps "$@"
        ;;
    "ips")
        # Enhanced IP allowlist management with status checking
        IPS_ACTION="${1:-show}"
        case "$IPS_ACTION" in
            "show"|"")
                print_color "blue" "Displaying IP allowlist from eBPF map..."
                if [ -f "src/load_ip_allowlist.py" ]; then
                    cd src && sudo python3 load_ip_allowlist.py --display
                elif [ -f "load_ip_allowlist.py" ]; then
                    sudo python3 load_ip_allowlist.py --display  
                else
                    print_color "red" "ERROR: load_ip_allowlist.py not found"
                    print_color "yellow" "Expected locations: ./src/load_ip_allowlist.py or ./load_ip_allowlist.py"
                fi
                ;;
            "status")
                print_color "blue" "Checking IP status (JSON vs eBPF map)..."
                if [ -f "src/load_ip_allowlist.py" ]; then
                    cd src && sudo python3 load_ip_allowlist.py --check-status
                elif [ -f "load_ip_allowlist.py" ]; then
                    sudo python3 load_ip_allowlist.py --check-status
                else
                    print_color "red" "ERROR: load_ip_allowlist.py not found"
                    print_color "yellow" "Expected locations: ./src/load_ip_allowlist.py or ./load_ip_allowlist.py"
                fi
                ;;
            "reload")
                print_color "blue" "Reloading IPs from JSON file..."
                if [ -f "src/load_ip_allowlist.py" ]; then
                    cd src && sudo python3 load_ip_allowlist.py --reload
                elif [ -f "load_ip_allowlist.py" ]; then
                    sudo python3 load_ip_allowlist.py --reload
                else
                    print_color "red" "ERROR: load_ip_allowlist.py not found"
                    print_color "yellow" "Expected locations: ./src/load_ip_allowlist.py or ./load_ip_allowlist.py"
                fi
                ;;
            "orphaned")
                print_color "blue" "Showing orphaned IPs (in map but not in JSON)..."
                if [ -f "src/load_ip_allowlist.py" ]; then
                    cd src && sudo python3 load_ip_allowlist.py --show-orphaned
                elif [ -f "load_ip_allowlist.py" ]; then
                    sudo python3 load_ip_allowlist.py --show-orphaned
                else
                    print_color "red" "ERROR: load_ip_allowlist.py not found"
                    print_color "yellow" "Expected locations: ./src/load_ip_allowlist.py or ./load_ip_allowlist.py"
                fi
                ;;
            "sync")
                print_color "blue" "Synchronizing eBPF map with JSON file (mark and sweep)..."
                if [ -f "src/load_ip_allowlist.py" ]; then
                    cd src && sudo python3 load_ip_allowlist.py --sync ip_allowlist.json
                elif [ -f "load_ip_allowlist.py" ]; then
                    sudo python3 load_ip_allowlist.py --sync ip_allowlist.json
                else
                    print_color "red" "ERROR: load_ip_allowlist.py not found"
                fi
                ;;
            "sync-dry-run")
                print_color "blue" "Dry run: showing what would be synced..."
                if [ -f "src/load_ip_allowlist.py" ]; then
                    cd src && sudo python3 load_ip_allowlist.py --sync-dry-run ip_allowlist.json
                elif [ -f "load_ip_allowlist.py" ]; then
                    sudo python3 load_ip_allowlist.py --sync-dry-run ip_allowlist.json
                else
                    print_color "red" "ERROR: load_ip_allowlist.py not found"
                fi
                ;;
            "add")
                IP_TO_ADD="$2"
                if [ -z "$IP_TO_ADD" ]; then
                    print_color "red" "ERROR: No IP specified"
                    echo "Usage: ./xdp.sh ips add <IP_ADDRESS>"
                    exit 1
                fi
                print_color "blue" "Adding IP $IP_TO_ADD to allowlist..."
                if [ -f "src/load_ip_allowlist.py" ]; then
                    cd src && sudo python3 load_ip_allowlist.py --add-ip "$IP_TO_ADD"
                elif [ -f "load_ip_allowlist.py" ]; then
                    sudo python3 load_ip_allowlist.py --add-ip "$IP_TO_ADD"
                else
                    print_color "red" "ERROR: load_ip_allowlist.py not found"
                fi
                ;;
            "remove")
                IP_TO_REMOVE="$2"
                if [ -z "$IP_TO_REMOVE" ]; then
                    print_color "red" "ERROR: No IP specified"
                    echo "Usage: ./xdp.sh ips remove <IP_ADDRESS>"
                    exit 1
                fi
                print_color "blue" "Removing IP $IP_TO_REMOVE from allowlist..."
                if [ -f "src/load_ip_allowlist.py" ]; then
                    cd src && sudo python3 load_ip_allowlist.py --remove-ip "$IP_TO_REMOVE"
                elif [ -f "load_ip_allowlist.py" ]; then
                    sudo python3 load_ip_allowlist.py --remove-ip "$IP_TO_REMOVE"
                else
                    print_color "red" "ERROR: load_ip_allowlist.py not found"
                fi
                ;;
            "add-bulk")
                IP_LIST="$2"
                if [ -z "$IP_LIST" ]; then
                    print_color "red" "ERROR: No IP list specified"
                    echo "Usage: ./xdp.sh ips add-bulk <IP1,IP2,IP3>"
                    exit 1
                fi
                print_color "blue" "Adding multiple IPs to allowlist..."
                if [ -f "src/load_ip_allowlist.py" ]; then
                    cd src && sudo python3 load_ip_allowlist.py --add-ips "$IP_LIST"
                elif [ -f "load_ip_allowlist.py" ]; then
                    sudo python3 load_ip_allowlist.py --add-ips "$IP_LIST"
                else
                    print_color "red" "ERROR: load_ip_allowlist.py not found"
                fi
                ;;
            "remove-bulk")
                IP_LIST="$2"
                if [ -z "$IP_LIST" ]; then
                    print_color "red" "ERROR: No IP list specified"
                    echo "Usage: ./xdp.sh ips remove-bulk <IP1,IP2,IP3>"
                    exit 1
                fi
                print_color "blue" "Removing multiple IPs from allowlist..."
                if [ -f "src/load_ip_allowlist.py" ]; then
                    cd src && sudo python3 load_ip_allowlist.py --remove-ips "$IP_LIST"
                elif [ -f "load_ip_allowlist.py" ]; then
                    sudo python3 load_ip_allowlist.py --remove-ips "$IP_LIST"
                else
                    print_color "red" "ERROR: load_ip_allowlist.py not found"
                fi
                ;;
            "watch")
                INTERVAL="${2:-30}"
                print_color "blue" "Watching JSON file for changes (checking every ${INTERVAL}s)..."
                print_color "yellow" "Press Ctrl+C to stop watching"
                if [ -f "src/load_ip_allowlist.py" ]; then
                    cd src && sudo python3 load_ip_allowlist.py --watch ip_allowlist.json --interval "$INTERVAL"
                elif [ -f "load_ip_allowlist.py" ]; then
                    sudo python3 load_ip_allowlist.py --watch ip_allowlist.json --interval "$INTERVAL"
                else
                    print_color "red" "ERROR: load_ip_allowlist.py not found"
                fi
                ;;
            *)
                print_color "red" "ERROR: Invalid ips command option: $IPS_ACTION"
                echo "Valid options: show, status, reload, sync, sync-dry-run, orphaned, add, remove, add-bulk, remove-bulk, watch"
                echo "Usage examples:"
                echo "  ./xdp.sh ips show              # Display current IPs in eBPF map"
                echo "  ./xdp.sh ips status            # Check JSON vs eBPF map status"  
                echo "  ./xdp.sh ips sync              # Sync eBPF map with JSON (mark and sweep)"
                echo "  ./xdp.sh ips sync-dry-run      # Show what would be synced"
                echo "  ./xdp.sh ips add 1.2.3.4       # Add single IP at runtime"
                echo "  ./xdp.sh ips remove 1.2.3.4    # Remove single IP at runtime"
                echo "  ./xdp.sh ips add-bulk 1.1.1.1,2.2.2.2  # Add multiple IPs"
                echo "  ./xdp.sh ips watch 60          # Watch for JSON changes every 60s"
                exit 1
                ;;
        esac
        ;;
    "logs") 
        show_logs "$@"
        ;;
    "info") 
        show_detailed_info "$@"
        ;;
    "monitor") 
        # Unified monitoring command - defaults to dual interface monitoring
        case "${1:-both}" in
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
            "simple"|"pipeline")
                shift 2>/dev/null || true
                monitor_pipeline "$@"
                ;;
            *)
                print_color "red" "ERROR: Invalid monitor option. Use: incoming, target, both, dual, simple, or pipeline"
                echo "Usage: ./xdp.sh monitor [incoming|target|both|simple] [interval] [duration]"
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
        elif [ "${1:-}" = "balanced" ] || [ -z "${1:-}" ]; then
            scale_performance "balanced"
        else
            print_color "red" "ERROR: Invalid scale option: ${1:-}"
            echo "Valid options: max-performance, monitor, balanced"
            echo "Usage: ./xdp.sh scale [max-performance|monitor|balanced]"
            exit 1
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
    "ipstats")
        show_vxlan_analysis "$@"
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

