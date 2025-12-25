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
source "$SCRIPT_DIR/xdp_functions/testing.sh"
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
        show_statistics "$@"
        ;;
    "info") 
        show_detailed_info "$@"
        ;;
    "test") 
        run_end_to_end_test "$@"
        ;;
    "monitor") 
        monitor_pipeline "$@"
        ;;
    "clean") 
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
        print_color "red" "Unknown command: $CMD"
        echo ""
        show_usage
        exit 1
        ;;
esac

