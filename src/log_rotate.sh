#!/bin/bash
# Log rotation and cleanup script to prevent memory/disk space issues
# Run this periodically (via cron) to manage log files

LOG_DIR="/tmp"
MAX_LOG_SIZE=10485760  # 10MB
MAX_AGE_DAYS=7

echo "Starting XDP pipeline log cleanup..."

# Function to rotate large log files
rotate_large_logs() {
    find "$LOG_DIR" -name "*.log" -size +${MAX_LOG_SIZE}c -exec sh -c '
        for file do
            if [ -f "$file" ]; then
                echo "Rotating large log: $file"
                mv "$file" "${file}.$(date +%Y%m%d_%H%M%S)"
                touch "$file"
                echo "Log rotated: $file"
            fi
        done
    ' sh {} +
}

# Function to clean old log files
clean_old_logs() {
    echo "Removing logs older than $MAX_AGE_DAYS days..."
    find "$LOG_DIR" -name "vxlan_*.log*" -mtime +$MAX_AGE_DAYS -delete 2>/dev/null
    find "$LOG_DIR" -name "packet_injector*.log*" -mtime +$MAX_AGE_DAYS -delete 2>/dev/null
    find "$LOG_DIR" -name "xdp_*.log*" -mtime +$MAX_AGE_DAYS -delete 2>/dev/null
}

# Function to clean temporary state files
clean_temp_files() {
    echo "Removing old temporary files..."
    find "$LOG_DIR" -name "xdp_perf_state*" -mtime +1 -delete 2>/dev/null
    find "$LOG_DIR" -name "vxlan_test_*" -mtime +1 -delete 2>/dev/null
}

# Function to show disk usage summary
show_usage_summary() {
    echo ""
    echo "=== DISK USAGE SUMMARY ==="
    echo "XDP log files:"
    du -sh "$LOG_DIR"/*xdp* 2>/dev/null | head -5 || echo "  No XDP log files found"
    echo "VXLAN log files:"
    du -sh "$LOG_DIR"/*vxlan* 2>/dev/null | head -5 || echo "  No VXLAN log files found"
    echo "Total /tmp usage:"
    df -h "$LOG_DIR" | tail -1
    echo "=========================="
}

# Main execution
rotate_large_logs
clean_old_logs
clean_temp_files
show_usage_summary

echo "Log cleanup completed!"
echo ""
echo "To run this automatically, add to crontab:"
echo "0 */6 * * * $(realpath "$0") >/dev/null 2>&1  # Run every 6 hours"