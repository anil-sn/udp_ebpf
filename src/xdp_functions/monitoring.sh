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
    local count=$(sudo bpftool prog list type xdp 2>/dev/null | grep -c "xdp" || echo "0")
    echo "$count"
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
    timeout 30s sudo tcpdump -i eth0 -nn -c 2000 'udp port 4789' > "$vxlan_temp" 2>/dev/null &
    
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