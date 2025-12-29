#!/bin/bash
# XDP Pipeline - Monitoring Functions (Python-based wrapper)

# Colors for output
print_color() {
    local color="$1"
    local message="$2"
    case "$color" in
        red)    echo -e "\033[31m$message\033[0m" ;;
        green)  echo -e "\033[32m$message\033[0m" ;;
        yellow) echo -e "\033[33m$message\033[0m" ;;
        blue)   echo -e "\033[34m$message\033[0m" ;;
        cyan)   echo -e "\033[36m$message\033[0m" ;;
        *) echo "$message" ;;
    esac
}

# Check if BPF programs are loaded
check_bpf_program() {
    # First try bpftool if available
    if command -v bpftool >/dev/null 2>&1; then
        local count=$(sudo bpftool prog list type xdp 2>/dev/null | grep -c "xdp" || echo "0")
        echo "$count" | tr -d '\n'
    else
        # Fallback: check via ip link command for XDP programs
        local count=$(ip link show 2>/dev/null | grep -c "prog/xdp" || echo "0")
        echo "$count" | tr -d '\n'
    fi
}

# Real-time monitoring using unified Python script
show_clean_statistics() {
    python3 src/xdp_functions/xdp_monitor.py realtime
}

# Compact statistics display
show_compact_statistics() {
    python3 src/xdp_functions/xdp_monitor.py stats
}

# Show IP allowlist status 
show_ip_allowlist() {
    python3 src/xdp_functions/xdp_monitor.py allowlist
}

# Show current status (header + allowlist + stats)
show_ip_statistics() {
    python3 src/xdp_functions/xdp_monitor.py status
}

# Complete VXLAN analysis with traffic capture
show_vxlan_analysis() {
    # Use Python for header and BPF status
    python3 src/xdp_functions/xdp_monitor.py status
    if [ $? -ne 0 ]; then
        return 1
    fi
    
    echo
    print_color "cyan" "🔍 Multi-Protocol Traffic Analysis (30s capture):"
    print_color "yellow" "   Capturing incoming VXLAN, processed TAP output, and dropped packets..."
    print_color "cyan" "   (Shows allowed vs denied IPs based on allowlist status)"
    
    # Capture traffic files
    local vxlan_temp="/tmp/vxlan_traffic_$$.txt"
    local tap_temp="/tmp/tap_traffic_$$.txt"
    local ipsec_temp="/tmp/ipsec_traffic_$$.txt"
    
    echo "   Capturing incoming VXLAN traffic (pre-processing)..."
    timeout 30s sudo tcpdump -i any -nn -c 2000 'udp port 4789' > "$vxlan_temp" 2>/dev/null &
    
    echo "   Capturing IPSec traffic (UDP 4500)..."
    timeout 30s sudo tcpdump -i any -nn -c 1000 'port 4500' > "$ipsec_temp" 2>/dev/null &
    
    echo "   Capturing processed TAP output (post-processing)..."
    timeout 30s sudo tcpdump -i tap0 -nn -c 1000 > "$tap_temp" 2>/dev/null &
    
    # Simple wait approach - let timeout handle it
    echo "   Waiting for captures to complete (max 35s)..."
    sleep 35
    
    # Force cleanup of any remaining tcpdump processes
    sudo pkill -f "tcpdump.*port.*4789" 2>/dev/null || true
    sudo pkill -f "tcpdump.*port.*4500" 2>/dev/null || true  
    sudo pkill -f "tcpdump.*tap0" 2>/dev/null || true
    
    # Brief pause for cleanup
    sleep 1
    
    echo
    
    # Check capture results
    if [[ -s "$vxlan_temp" ]]; then
        local vxlan_lines=$(wc -l < "$vxlan_temp")
        echo "   ✅ VXLAN capture: $vxlan_lines lines"
    else
        echo "   ❌ VXLAN capture: No data captured"
    fi
    
    if [[ -s "$ipsec_temp" ]]; then
        local ipsec_lines=$(wc -l < "$ipsec_temp")
        echo "   ✅ IPSec capture: $ipsec_lines lines"
    else
        echo "   ❌ IPSec capture: No data captured"
    fi
    
    # Analyze traffic using Python
    if [[ -s "$vxlan_temp" ]] || [[ -s "$tap_temp" ]] || [[ -s "$ipsec_temp" ]]; then
        print_color "green" "🎯 Traffic Analysis Results:"
        python3 src/xdp_functions/traffic_analyzer.py "$vxlan_temp" "$ipsec_temp" "$tap_temp" 30
        
        echo
        print_color "blue" "📊 Pipeline Performance Analysis:"
        echo "  🔍 Incoming VXLAN packets show ALL source IPs (before filtering)"
        echo "  ✅ TAP output shows ONLY allowed IPs (after processing)"  
        echo "  ❌ Missing IPs from TAP = DROPPED by allowlist filter"
        echo "  📈 Compare VXLAN vs TAP counts to see filtering effectiveness"
    else
        print_color "yellow" "   ❌ No traffic captured during analysis"
        print_color "blue" "   💡 Check if XDP program is loaded and traffic is flowing"
    fi
    
    # Cleanup
    rm -f "$vxlan_temp" "$tap_temp" "$ipsec_temp" 2>/dev/null || true
    
    print_color "blue" "\n💡 Usage Tips:"
    echo "  • IPs with ✅ are processed by the pipeline"
    echo "  • IPs with ❌ are filtered out (not in allowlist)" 
    echo "  • Use './xdp.sh ips' to manage the allowlist"
    echo "  • Run this command periodically to monitor IP-level performance"
}

# Legacy function aliases for backward compatibility
monitor_pipeline() {
    show_clean_statistics
}

show_statistics() {
    show_clean_statistics  
}

# System status check
# Pipeline status check function
show_pipeline_status() {
    print_color "blue" "🔍 XDP VXLAN Pipeline Status"
    echo
    
    # Check for running processes
    local loader_pid=$(pgrep -f "vxlan_loader" | head -1)
    local injector_count=$(pgrep -f "packet_injector" | wc -l | tr -d ' \n')
    local prog_count=$(check_bpf_program)
    
    if [ -n "$loader_pid" ]; then
        print_color "green" "✅ vxlan_loader running (PID: $loader_pid)"
    else
        print_color "red" "❌ vxlan_loader not running"
    fi
    
    if [ "$injector_count" -gt 0 ]; then
        print_color "green" "✅ $injector_count packet_injector process(es) running"
    else
        print_color "red" "❌ No packet_injector processes running"
    fi
    
    if [ "$prog_count" -gt 0 ]; then
        print_color "green" "✅ $prog_count XDP program(s) loaded"
    else
        print_color "red" "❌ No XDP programs loaded"
    fi
    
    echo
    
    # Determine overall status
    if [ -n "$loader_pid" ] && [ "$injector_count" -gt 0 ] && [ "$prog_count" -gt 0 ]; then
        print_color "green" "🟢 Pipeline Status: RUNNING"
        echo
        print_color "blue" "📊 Quick Statistics:"
        python3 src/xdp_functions/analyze_stats.py --compact 2>/dev/null || print_color "yellow" "⚠ Statistics unavailable"
    else
        print_color "red" "🔴 Pipeline Status: STOPPED"
        echo
        print_color "yellow" "💡 Use './xdp.sh start' to start the pipeline"
    fi
}

system_status() {
    local prog_count=$(check_bpf_program)
    if [ "$prog_count" -eq 0 ]; then
        print_color "red" "❌ No XDP programs loaded"
        return 1
    else
        print_color "green" "✅ $prog_count XDP program(s) loaded"
    fi
    
    # Show full status using Python
    python3 src/xdp_functions/xdp_monitor.py status
}

# Performance test
performance_test() {
    local duration="${1:-120}"
    print_color "yellow" "🚀 Performance Test - Monitoring for ${duration} seconds"
    
    # Start real-time monitor in background and limit duration
    timeout "$duration" python3 src/xdp_functions/xdp_monitor.py realtime
    
    print_color "green" "\n✅ Performance test completed"
}

# Show BPF maps information  
show_bpf_maps() {
    print_color "blue" "🗺️  BPF Maps Status"
    echo "===================="
    echo
    
    # Check if BPF maps are pinned
    BPF_PATH="/sys/fs/bpf"
    if [ -d "$BPF_PATH" ]; then
        print_color "cyan" "📍 Pinned BPF Maps:"
        if ls "$BPF_PATH"/*vxlan* >/dev/null 2>&1; then
            for map in "$BPF_PATH"/*vxlan*; do
                if [ -e "$map" ]; then
                    basename "$map"
                    # Try to show map info if bpftool is available
                    if command -v bpftool >/dev/null 2>&1; then
                        bpftool map show pinned "$map" 2>/dev/null | grep -E "type|max_entries" | sed 's/^/    /'
                    fi
                fi
            done
        else
            echo "  No VXLAN maps found"
        fi
        echo
        
        print_color "cyan" "📊 Map Statistics (if available):"
        if command -v bpftool >/dev/null 2>&1; then
            if [ -e "$BPF_PATH/stats_map" ]; then
                echo "  Stats Map:"
                bpftool map dump pinned "$BPF_PATH/stats_map" 2>/dev/null | head -10 | sed 's/^/    /'
            fi
            if [ -e "$BPF_PATH/ip_allowlist" ]; then
                allowlist_count=$(bpftool map dump pinned "$BPF_PATH/ip_allowlist" 2>/dev/null | grep -c "key:" || echo "0")
                echo "  IP Allowlist entries: $allowlist_count"
            fi
        else
            echo "  Install bpftool for detailed map information"
        fi
    else
        print_color "red" "❌ BPF filesystem not mounted"
    fi
    echo
    
    print_color "cyan" "🔧 Active XDP Programs:"
    if command -v bpftool >/dev/null 2>&1; then
        bpftool prog show type xdp 2>/dev/null || echo "  No XDP programs found"
    else
        # Fallback: check via proc or ip command
        if ip link show | grep -q "xdp"; then
            echo "  XDP programs detected (use 'ip link show' for details)"
        else
            echo "  No XDP programs detected"
        fi
    fi
}

# Show detailed system information
show_detailed_info() {
    print_color "blue" "📋 XDP VXLAN Pipeline - Detailed Information"
    echo "============================================"
    echo
    
    print_color "cyan" "🖥️  System Information:"
    echo "  Hostname: $(hostname)"
    echo "  Kernel: $(uname -r)"
    echo "  Uptime: $(uptime -p 2>/dev/null || uptime)"
    echo "  CPU Cores: $(nproc)"
    echo "  Memory: $(free -h | awk '/^Mem:/{print $2}' | tr -d ' ')"
    echo
    
    print_color "cyan" "🔗 Network Interfaces:"
    ip link show | grep -E "^[0-9]+:" | while read -r line; do
        iface=$(echo "$line" | cut -d: -f2 | tr -d ' ')
        state=$(echo "$line" | grep -o "state [A-Z]*" | cut -d' ' -f2)
        echo "  $iface: $state"
    done
    echo
    
    print_color "cyan" "⚙️  Pipeline Configuration:"
    if [ -f "$PROJECT_ROOT/.env" ]; then
        echo "  Config File: $PROJECT_ROOT/.env"
        echo "  Target Interface: ${TARGET_INTERFACE:-"Not set"}"
        echo "  Target IP: ${TARGET_IP:-"Not set"}"
        echo "  Target Port: ${TARGET_PORT:-"Not set"}"
    else
        echo "  ⚠️  Configuration file not found"
    fi
    echo
    
    print_color "cyan" "📊 Current Status:"
    show_pipeline_status
    echo
    
    print_color "cyan" "📈 Performance Statistics:"
    python3 src/xdp_functions/analyze_stats.py --detailed 2>/dev/null || print_color "yellow" "⚠️  Statistics unavailable - run './xdp.sh start' first"
}

# Show system logs related to XDP pipeline
show_logs() {
    local log_type="${1:-all}"
    local lines="${2:-50}"
    
    print_color "blue" "📋 XDP Pipeline Logs"
    echo "====================="
    echo
    
    case "$log_type" in
        "all"|"")
            print_color "cyan" "🔍 Recent VXLAN Loader Logs:"
            if [ -f "/tmp/vxlan_loader.log" ]; then
                tail -n "$lines" /tmp/vxlan_loader.log
            else
                echo "  No vxlan_loader.log found"
            fi
            echo
            
            print_color "cyan" "📊 Recent Packet Injector Logs:"
            if [ -f "/tmp/packet_injector.log" ]; then
                tail -n "$lines" /tmp/packet_injector.log
            else
                echo "  No packet_injector.log found"
            fi
            echo
            
            print_color "cyan" "🔍 System Kernel Logs (XDP related):"
            dmesg | grep -i -E "xdp|bpf|ena" | tail -n "$lines" || echo "  No XDP-related kernel messages"
            ;;
        "kernel")
            print_color "cyan" "🔍 Kernel Logs (XDP/BPF related):"
            dmesg | grep -i -E "xdp|bpf|ena" | tail -n "$lines" || echo "  No XDP-related kernel messages"
            ;;
        "vxlan")
            print_color "cyan" "🔍 VXLAN Loader Logs:"
            if [ -f "/tmp/vxlan_loader.log" ]; then
                tail -n "$lines" /tmp/vxlan_loader.log
            else
                echo "  No vxlan_loader.log found"
            fi
            ;;
        "injector")
            print_color "cyan" "📊 Packet Injector Logs:"
            if [ -f "/tmp/packet_injector.log" ]; then
                tail -n "$lines" /tmp/packet_injector.log
            else
                echo "  No packet_injector.log found"
            fi
            ;;
        *)
            print_color "red" "❌ Unknown log type: $log_type"
            echo "Available types: all, kernel, vxlan, injector"
            ;;
    esac
}

# Help function
show_monitor_help() {
    print_color "cyan" "🛠️  XDP Pipeline Monitor - Available Commands"
    echo
    echo "Real-time Monitoring:"
    echo "  show_clean_statistics     - Interactive real-time statistics display"
    echo "  show_compact_statistics   - Show current statistics snapshot"
    echo "  performance_test [duration] - Performance monitoring test"
    echo
    echo "Traffic Analysis:"
    echo "  show_vxlan_analysis       - Complete VXLAN traffic analysis with capture"
    echo
    echo "Configuration:"
    echo "  show_ip_allowlist         - Show current allowlist from BPF map"
    echo "  show_ip_statistics        - Show complete status (header + allowlist + stats)"
    echo
    echo "System:"
    echo "  system_status             - Check system status and display full info"
    echo "  show_monitor_help         - Show this help"
    echo
    echo "Examples:"
    echo "  show_clean_statistics                    # Real-time monitoring"
    echo "  show_vxlan_analysis                     # Complete traffic analysis"
    echo "  performance_test 300                    # 5-minute performance test"
    echo
}

# Make functions available when script is sourced
if [ "${BASH_SOURCE[0]}" != "${0}" ]; then
    print_color "green" "✅ XDP monitoring functions loaded (Python-based)"
    print_color "yellow" "💡 Use 'show_monitor_help' to see available commands"
fi