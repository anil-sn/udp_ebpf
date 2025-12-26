#!/bin/bash
# XDP Pipeline - Monitoring Functions

# Helper function to format large numbers with appropriate units
format_number() {
    local num="$1"
    if [ "$num" -ge 1000000000 ]; then
        echo "$num" | awk '{printf "%.1fB", $1/1000000000}'
    elif [ "$num" -ge 1000000 ]; then
        echo "$num" | awk '{printf "%.1fM", $1/1000000}'
    elif [ "$num" -ge 1000 ]; then
        echo "$num" | awk '{printf "%.1fK", $1/1000}'
    else
        echo "$num"
    fi
}

# Helper function to format bytes with appropriate units
format_bytes() {
    local bytes="$1"
    if [ "$bytes" -ge 1000000000 ]; then
        echo "$bytes" | awk '{printf "%.2f GB", $1/1000000000}'
    elif [ "$bytes" -ge 1000000 ]; then
        echo "$bytes" | awk '{printf "%.2f MB", $1/1000000}'
    elif [ "$bytes" -ge 1000 ]; then
        echo "$bytes" | awk '{printf "%.2f KB", $1/1000}'
    else
        echo "$bytes B"
    fi
}

# Clean stats monitoring display
show_clean_statistics() {
    fix_terminal
    
    # Check if pipeline is running
    local prog_count=$(check_bpf_program)
    if [ "$prog_count" -eq 0 ]; then
        print_color "red" "✗ No XDP programs loaded"
        return 1
    fi
    
    # Python script for clean stats display
    python3 - <<'EOF'
import subprocess
import json
import time
import sys

class VXLANStatsMonitor:
    def __init__(self):
        self.prev_stats = {}
        
    def get_bpf_stats(self):
        """Extract statistics from eBPF maps"""
        try:
            result = subprocess.run(['sudo', 'bpftool', 'map', 'dump', 'name', 'stats_map'], 
                                  capture_output=True, text=True, check=True)
            raw_data = json.loads(result.stdout)
            
            # Sum across all CPUs for each statistic
            stats = {}
            for entry in raw_data:
                key = entry['key']
                total = sum(cpu_data['value'] for cpu_data in entry['values'])
                stats[key] = total
                
            return stats
        except Exception as e:
            print(f"Error reading BPF stats: {e}")
            return {}
    
    def calculate_rates(self, current_stats, interval=5):
        """Calculate per-second rates from counters"""
        rates = {}
        for key, current in current_stats.items():
            if key in self.prev_stats:
                rates[key] = max(0, (current - self.prev_stats[key]) // interval)
            else:
                rates[key] = 0
        return rates
    
    def format_number(self, num):
        """Format large numbers with appropriate units"""
        if num >= 1_000_000:
            return f"{num/1_000_000:.1f}M"
        elif num >= 1_000:
            return f"{num/1_000:.1f}K"
        else:
            return str(num)
    
    def display_stats(self, stats, rates):
        """Display clean statistics"""
        if not stats:
            return
            
        # Core packet processing metrics
        total_packets = stats.get(0, 0)
        vxlan_packets = stats.get(1, 0)  
        inner_packets = stats.get(2, 0)
        nat_applied = stats.get(3, 0)
        df_cleared = stats.get(4, 0)
        forwarded = stats.get(5, 0)
        redirected = stats.get(6, 0)
        errors = stats.get(7, 0)
        bytes_processed = stats.get(8, 0)
        ip_len_updated = stats.get(9, 0)
        length_corrections = stats.get(15, 0) if 15 in stats else 0
        
        # Calculate percentages and rates
        vxlan_pct = (vxlan_packets / total_packets * 100) if total_packets > 0 else 0
        nat_efficiency = (nat_applied / vxlan_packets * 100) if vxlan_packets > 0 else 0
        error_rate = (errors / total_packets * 100) if total_packets > 0 else 0
        
        # Throughput calculation (bytes to Mbps)
        throughput_mbps = (rates.get(8, 0) * 8) / 1_000_000
        
        # Performance assessment
        total_pps = rates.get(0, 0)
        if total_pps >= 85000:
            perf_status = f"🎯 TARGET ACHIEVED! ({self.format_number(total_pps)} PPS)"
        elif total_pps >= 50000:
            perf_status = f"⚡ HIGH PERFORMANCE ({self.format_number(total_pps)} PPS)"
        else:
            perf_status = f"📊 Performance: {self.format_number(total_pps)} PPS (target: 85K+)"
        
        print("\n" + "="*60)
        print("🚀 === VXLAN Pipeline Performance Dashboard ===")
        print("="*60)
        print(f"📦 Total Packets:      {self.format_number(total_packets):>8} ({self.format_number(rates.get(0, 0)):>6} pps)")
        print(f"🔗 VXLAN Packets:      {self.format_number(vxlan_packets):>8} ({vxlan_pct:>5.1f}%)")
        print(f"🔄 NAT Applied:        {self.format_number(nat_applied):>8} ({nat_efficiency:>5.1f}% efficiency)")
        print(f"📤 Forwarded:          {self.format_number(forwarded):>8}")
        print(f"🎯 Redirected:         {self.format_number(redirected):>8} (XDP_REDIRECT)")
        
        # Show length corrections if any
        if length_corrections > 0:
            print(f"🔧 Length Fixed:       {self.format_number(length_corrections):>8} (truncation repair)")
        
        # Error summary (only show if significant)
        if error_rate > 0.1:  # Only show if > 0.1%
            print(f"⚠️  Errors:             {self.format_number(errors):>8} ({error_rate:.2f}%)")
        
        print(f"🌐 Throughput:         {throughput_mbps:>8.2f} Mbps")
        print(f"{perf_status}")
        print("="*60)
    
    def run(self):
        """Main monitoring loop"""
        print("🚀 Starting VXLAN Pipeline Clean Monitor")
        print("Press Ctrl+C to stop...")
        
        try:
            while True:
                current_stats = self.get_bpf_stats()
                rates = self.calculate_rates(current_stats)
                
                self.display_stats(current_stats, rates)
                self.prev_stats = current_stats.copy()
                
                time.sleep(5)
                
        except KeyboardInterrupt:
            print("\n👋 Monitoring stopped by user")
        except Exception as e:
            print(f"💥 Error: {e}")

if __name__ == "__main__":
    monitor = VXLANStatsMonitor()
    monitor.run()
EOF
}

# Show comprehensive real-time statistics
show_statistics() {
    fix_terminal
    
    # Check if pipeline is running
    local prog_count=$(check_bpf_program)
    if [ "$prog_count" -eq 0 ]; then
        print_color "red" "✗ No XDP programs loaded"
        return 1
    fi
    
    print_color "green" "🚀 === XDP VXLAN Pipeline Comprehensive Statistics ==="
    echo "=============================================================="
    
    # Get BPF statistics using bpftool and jq
    if ! sudo bpftool map show name stats_map >/dev/null 2>&1; then
        print_color "red" "✗ Statistics map not found"
        return 1
    fi
    
    # Extract statistics from eBPF maps
    local stats_json=$(sudo bpftool map dump name stats_map --json 2>/dev/null)
    if [ -z "$stats_json" ]; then
        print_color "red" "✗ Unable to retrieve statistics"
        return 1
    fi
    
    # Sum statistics across all CPUs using jq
    local total_packets=$(echo "$stats_json" | jq -r '[.[] | select(.key == 0) | .values[].value] | add // 0')
    local vxlan_packets=$(echo "$stats_json" | jq -r '[.[] | select(.key == 1) | .values[].value] | add // 0')
    local inner_packets=$(echo "$stats_json" | jq -r '[.[] | select(.key == 2) | .values[].value] | add // 0')
    local nat_applied=$(echo "$stats_json" | jq -r '[.[] | select(.key == 3) | .values[].value] | add // 0')
    local df_cleared=$(echo "$stats_json" | jq -r '[.[] | select(.key == 4) | .values[].value] | add // 0')
    local forwarded=$(echo "$stats_json" | jq -r '[.[] | select(.key == 5) | .values[].value] | add // 0')
    local redirected=$(echo "$stats_json" | jq -r '[.[] | select(.key == 6) | .values[].value] | add // 0')
    local errors=$(echo "$stats_json" | jq -r '[.[] | select(.key == 7) | .values[].value] | add // 0')
    local bytes_processed=$(echo "$stats_json" | jq -r '[.[] | select(.key == 8) | .values[].value] | add // 0')
    local ip_len_updated=$(echo "$stats_json" | jq -r '[.[] | select(.key == 9) | .values[].value] | add // 0')
    local udp_len_updated=$(echo "$stats_json" | jq -r '[.[] | select(.key == 10) | .values[].value] | add // 0')
    local ip_checksum_updated=$(echo "$stats_json" | jq -r '[.[] | select(.key == 11) | .values[].value] | add // 0')
    local bounds_check_failed=$(echo "$stats_json" | jq -r '[.[] | select(.key == 12) | .values[].value] | add // 0')
    local ringbuf_submitted=$(echo "$stats_json" | jq -r '[.[] | select(.key == 13) | .values[].value] | add // 0')
    local length_corrections=$(echo "$stats_json" | jq -r '[.[] | select(.key == 15) | .values[].value] | add // 0')
    
    # Calculate percentages and rates
    local vxlan_pct=0
    local nat_efficiency=0
    local error_rate=0
    local success_rate=0
    
    if [ "$total_packets" -gt 0 ]; then
        vxlan_pct=$(echo "$vxlan_packets $total_packets" | awk '{printf "%.1f", ($1/$2)*100}')
        error_rate=$(echo "$errors $total_packets" | awk '{printf "%.3f", ($1/$2)*100}')
        success_rate=$(echo "$forwarded $redirected $total_packets" | awk '{printf "%.1f", (($1+$2)/$3)*100}')
    fi
    
    if [ "$vxlan_packets" -gt 0 ]; then
        nat_efficiency=$(echo "$nat_applied $vxlan_packets" | awk '{printf "%.1f", ($1/$2)*100}')
    fi
    
    # Performance assessment
    local perf_status="📊 MONITORING"
    if [ "$total_packets" -ge 85000 ]; then
        perf_status="🎯 TARGET ACHIEVED"
    elif [ "$total_packets" -ge 50000 ]; then
        perf_status="⚡ HIGH PERFORMANCE"
    elif [ "$total_packets" -ge 25000 ]; then
        perf_status="📈 GOOD PERFORMANCE"
    elif [ "$total_packets" -gt 0 ]; then
        perf_status="🔧 MODERATE PERFORMANCE"
    fi
    
    # System Overview
    echo ""
    print_color "cyan" "📊 SYSTEM OVERVIEW"
    printf "├─ Performance Status: %s\n" "$perf_status"
    printf "├─ Total Processed:    %s packets\n" "$(format_number "$total_packets")"
    printf "└─ Success Rate:       %s%%\n" "$success_rate"
    
    # Packet Flow Pipeline
    echo ""
    print_color "cyan" "📦 PACKET FLOW PIPELINE"
    printf "├─ Total Received:     %10s\n" "$(format_number "$total_packets")"
    printf "├─ VXLAN Packets:      %10s (%s%%)\n" "$(format_number "$vxlan_packets")" "$vxlan_pct"
    printf "├─ Inner Extracted:    %10s\n" "$(format_number "$inner_packets")"
    printf "├─ NAT Applied:        %10s (%s%% efficiency)\n" "$(format_number "$nat_applied")" "$nat_efficiency"
    printf "├─ DF Bits Cleared:    %10s\n" "$(format_number "$df_cleared")"
    printf "├─ Successfully Fwd:   %10s\n" "$(format_number "$forwarded")"
    printf "└─ XDP Redirected:     %10s\n" "$(format_number "$redirected")"
    
    # Header Processing (only show if there's activity)
    if [ "$ip_len_updated" -gt 0 ] || [ "$udp_len_updated" -gt 0 ] || [ "$length_corrections" -gt 0 ]; then
        echo ""
        print_color "cyan" "🔧 HEADER PROCESSING"
        if [ "$length_corrections" -gt 0 ]; then
            printf "├─ Length Corrections:  %10s (AWS truncation fixes)\n" "$(format_number "$length_corrections")"
        fi
        if [ "$ip_len_updated" -gt 0 ]; then
            printf "├─ IP Length Updates:   %10s\n" "$(format_number "$ip_len_updated")"
        fi
        if [ "$udp_len_updated" -gt 0 ]; then
            printf "├─ UDP Length Updates:  %10s\n" "$(format_number "$udp_len_updated")"
        fi
        if [ "$ip_checksum_updated" -gt 0 ]; then
            printf "└─ IP Checksum Calcs:   %10s\n" "$(format_number "$ip_checksum_updated")"
        fi
    fi
    
    # Performance Metrics
    echo ""
    print_color "cyan" "🌐 PERFORMANCE METRICS"
    local bytes_formatted=$(format_bytes "$bytes_processed")
    printf "├─ Bytes Processed:    %s\n" "$bytes_formatted"
    if [ "$ringbuf_submitted" -gt 0 ]; then
        printf "└─ Ring Buffer Sent:   %10s\n" "$(format_number "$ringbuf_submitted")"
    else
        printf "└─ Ring Buffer Sent:   %10s\n" "0"
    fi
    
    # Error Analysis (only show if errors exist)
    if [ "$errors" -gt 0 ] || [ "$bounds_check_failed" -gt 0 ]; then
        echo ""
        print_color "yellow" "⚠️  ERROR ANALYSIS"
        printf "├─ Total Errors:       %10s (%s%%)\n" "$(format_number "$errors")" "$error_rate"
        if [ "$bounds_check_failed" -gt 0 ]; then
            printf "├─ Bounds Failures:    %10s\n" "$(format_number "$bounds_check_failed")"
        fi
        
        local error_impact="MINIMAL"
        if (( $(echo "$error_rate > 1.0" | bc -l 2>/dev/null || echo 0) )); then
            error_impact="HIGH"
        elif (( $(echo "$error_rate > 0.1" | bc -l 2>/dev/null || echo 0) )); then
            error_impact="MODERATE"
        fi
        printf "└─ Error Impact:       %s\n" "$error_impact"
    fi
    
    # Pipeline Status Summary
    echo ""
    print_color "cyan" "✅ PIPELINE STATUS"
    local status_emoji="🟢"
    local status_text="EXCELLENT"
    
    if (( $(echo "$success_rate < 99.9" | bc -l 2>/dev/null || echo 0) )); then
        if (( $(echo "$success_rate < 99.0" | bc -l 2>/dev/null || echo 0) )); then
            if (( $(echo "$success_rate < 95.0" | bc -l 2>/dev/null || echo 0) )); then
                status_emoji="🔴"
                status_text="CRITICAL"
            else
                status_emoji="🟠"
                status_text="NEEDS ATTENTION"
            fi
        else
            status_emoji="🟡"
            status_text="GOOD"
        fi
    fi
    
    printf "└─ Overall Status:     %s %s (%s%% success rate)\n" "$status_emoji" "$status_text" "$success_rate"
    
    echo "=============================================================="
    
    # Process status
    echo ""
    print_color "yellow" "Process Status:"
    
    if pgrep -f "vxlan_loader" >/dev/null; then
        local loader_pids=$(pgrep -f "vxlan_loader" | tr '\n' ' ')
        print_color "green" "✓ vxlan_loader: Running (PID: ${loader_pids%% })"
    else
        print_color "red" "✗ vxlan_loader: Not running"
    fi
    
    if pgrep -f "packet_injector" >/dev/null; then
        local injector_pids=$(pgrep -f "packet_injector" | tr '\n' ' ')
        print_color "green" "✓ packet_injector: Running (PID: ${injector_pids%% })"
    else
        print_color "red" "✗ packet_injector: Not running"
    fi
}

# Monitor pipeline in real-time
monitor_pipeline() {
    if ! pgrep -f "vxlan_loader" >/dev/null; then
        print_color "red" "Pipeline not running. Start with: ./xdp.sh start"
        exit 1
    fi
    
    fix_terminal
    clear
    
    print_color "blue" "Live Monitor (Ctrl+C to stop)"
    printf "%-10s | %-10s | %s\n" "TIME" "PPS" "STATUS"
    echo "-----------------------------------"
    
    # Set trap for Ctrl+C
    trap 'fix_terminal; echo; exit 0' INT
    
    local last_rx=""
    
    while true; do
        local rx1=$(cat "/sys/class/net/$INTERFACE/statistics/rx_packets" 2>/dev/null || echo "0")
        sleep 2
        local rx2=$(cat "/sys/class/net/$INTERFACE/statistics/rx_packets" 2>/dev/null || echo "0")
        local pps=$(( (rx2 - rx1) / 2 ))
        local time=$(date +%H:%M:%S)
        
        # Use performance threshold from config
        if [ "$pps" -ge "${TARGET_PPS:-85000}" ]; then
            local color="green"; local stat="OPTIMAL"
        elif [ "$pps" -ge "${PERFORMANCE_THRESHOLD:-60000}" ]; then
            local color="yellow"; local stat="GOOD"
        elif [ "$pps" -gt 0 ]; then
            local color="yellow"; local stat="LOW"
        else
            local color="red"; local stat="IDLE"
        fi
        
        case "$color" in
            "green") printf "%s | \033[0;32m%-10d\033[0m | \033[0;32m%s\033[0m\n" "$time" "$pps" "$stat" ;;
            "yellow") printf "%s | \033[1;33m%-10d\033[0m | \033[1;33m%s\033[0m\n" "$time" "$pps" "$stat" ;;
            "red") printf "%s | \033[0;31m%-10d\033[0m | \033[0;31m%s\033[0m\n" "$time" "$pps" "$stat" ;;
        esac
    done
}

# Show pipeline status
show_pipeline_status() {
    fix_terminal
    clear
    
    print_color "cyan" "--- XDP VXLAN PIPELINE STATUS ---"
    echo ""
    
    # Check vxlan_loader
    local loader_pid=$(pgrep -f "vxlan_loader" | head -1)
    
    if [ -n "$loader_pid" ]; then
        print_color "green" "vxlan_loader: RUNNING (PID: $loader_pid)"
        
        if check_xdp_attached "$INTERFACE"; then
            print_color "green" "XDP Hook:     ATTACHED ($INTERFACE)"
        else
            print_color "red" "XDP Hook:     DETACHED (Error)"
        fi
    else
        print_color "red" "vxlan_loader: STOPPED"
        print_color "red" "XDP Hook:     DETACHED"
    fi
    
    # Check packet_injector
    local injector_pid=$(pgrep -f "packet_injector" | head -1)
    
    if [ -n "$injector_pid" ]; then
        print_color "green" "packet_injector: RUNNING (PID: $injector_pid)"
    else
        print_color "red" "packet_injector: STOPPED"
    fi
    
    if [ -n "$loader_pid" ]; then
        echo ""
        print_color "blue" "Configuration:"
        echo "  Inbound:  $INTERFACE (Port $SOURCE_PORT)"
        echo "  Outbound: $TARGET_INTERFACE -> $NAT_IP:$NAT_PORT"
        
        echo ""
        print_color "blue" "Traffic Load:"
        local rx1=$(cat "/sys/class/net/$INTERFACE/statistics/rx_packets" 2>/dev/null || echo "0")
        sleep 1
        local rx2=$(cat "/sys/class/net/$INTERFACE/statistics/rx_packets" 2>/dev/null || echo "0")
        local pps=$((rx2 - rx1))
        
        if [ "$pps" -gt 0 ]; then
             print_color "green" "  Rate:     $pps pps"
        else
             print_color "yellow" "  Rate:     0 pps (Idle)"
        fi
    else
        print_color "red" "Service:  STOPPED"
        local status_link
        if check_xdp_attached "$INTERFACE"; then
            status_link="ORPHANED"
        else
            status_link="CLEAN"
        fi
        echo "XDP Hook: $status_link"
    fi
    echo ""
}

# Show comprehensive pipeline information - Fixed version
show_detailed_info() {
    fix_terminal
    
    print_color "green" "XDP VXLAN Pipeline - Debug Information"
    echo "======================================="
    
    # XDP Programs Summary
    echo ""
    print_color "yellow" "=== XDP PROGRAM STATUS ==="
    local prog_count=$(check_bpf_program)
    
    if [ "$prog_count" -gt 0 ]; then
        print_color "green" "✓ Active XDP Programs: $prog_count"
        echo ""
        
        echo "┌─────────────────────────────────────────────────────────────────────┐"
        echo "│                         XDP Program Details                         │"
        echo "├──────┬─────────┬────────────────┬─────────┬──────────┬─────────────┤"
        echo "│  ID  │   Tag   │     Size       │  Maps   │   PID    │   Status    │"
        echo "├──────┼─────────┼────────────────┼─────────┼──────────┼─────────────┤"
        
        # Parse XDP program details
        get_bpf_program_details | while IFS= read -r line; do
            local prog_id=$(echo "$line" | awk '{print $1}' | tr -d ':')
            local tag=$(echo "$line" | grep -o 'tag [a-f0-9]*' | cut -d' ' -f2 | head -1)
            
            # Extract size (xlated bytes)
            local size=$(echo "$line" | grep -o 'xlated [0-9]*B' | cut -d' ' -f2 | head -1)
            [ -z "$size" ] && size="N/A"
            
            # Count maps by parsing map_ids
            local map_ids_raw=$(echo "$line" | grep -o 'map_ids [0-9,]*' | cut -d' ' -f2)
            local map_count=0
            if [ -n "$map_ids_raw" ]; then
                map_count=$(echo "$map_ids_raw" | tr ',' '\n' | wc -l)
            fi
            
            # Extract process name from pids line
            local pid_info=$(echo "$line" | grep -o 'pids [^(]*' | cut -d' ' -f2- | head -1)
            if [ -z "$pid_info" ] || [ "$pid_info" = "systemd(1)" ]; then
                pid_info="kernel"
            fi
            
            printf "│ %4s │ %7s │ %14s │ %7d │ %8s │ %-11s │\n" \
                "$prog_id" "${tag:0:7}" "$size" "$map_count" "${pid_info}" "Active"
        done
        echo "└──────┴─────────┴────────────────┴─────────┴──────────┴─────────────┘"
    else
        print_color "red" "✗ No XDP programs loaded"
    fi
    
    # Network Interface Attachment
    echo ""
    print_color "yellow" "=== NETWORK ATTACHMENT ==="
    local attachment=$(get_xdp_attachment "$INTERFACE")
    if [ -n "$attachment" ]; then
        echo "$attachment"
    else
        echo "No XDP programs attached to interfaces"
    fi
    
    # NAT Rules Table
    echo ""
    print_color "yellow" "=== NAT CONFIGURATION ==="
    
    # First check if nat_map exists and has entries
    local nat_map_exists=$(sudo bpftool map show name nat_map 2>/dev/null)
    if [ -z "$nat_map_exists" ]; then
        echo "NAT map not found"
        return
    fi
    
    local nat_entries=$(count_bpf_map_entries "nat_map")
    echo "NAT map entries: $nat_entries"
    
    if [ "$nat_entries" -gt 0 ]; then
        # Try to get formatted rules
        local nat_rules=$(get_nat_rules 2>/dev/null)
        local nat_count=0
        
        if [ -n "$nat_rules" ] && [ "$nat_rules" != "" ]; then
            nat_count=$(echo "$nat_rules" | grep -c "->")
        fi
        
        if [ "$nat_count" -gt 0 ]; then
            echo "Active NAT Rules: $nat_count"
            echo ""
            echo "┌─────────────┬─────────────────┬──────────────┬────────────────────┐"
            echo "│ Source Port │   Target IP     │ Target Port  │      Status        │"
            echo "├─────────────┼─────────────────┼──────────────┼────────────────────┤"
            
            echo "$nat_rules" | while IFS= read -r rule; do
                if [[ "$rule" =~ ([0-9]+)\ -\>\ ([0-9.]+):([0-9]+) ]]; then
                    local src_port="${BASH_REMATCH[1]}"
                    local target_ip="${BASH_REMATCH[2]}"
                    local target_port="${BASH_REMATCH[3]}"
                    printf "│    %5d    │ %15s │    %6d    │       Active       │\n" \
                        "$src_port" "$target_ip" "$target_port"
                fi
            done
            echo "└─────────────┴─────────────────┴──────────────┴────────────────────┘"
        else
            # Debug: Show raw NAT map content for troubleshooting
            echo "NAT rules parsing failed. Debug information:"
            echo ""
            echo "Raw NAT map dump (first few lines):"
            local raw_nat=$(sudo bpftool map dump name nat_map 2>/dev/null | head -10)
            if [ -n "$raw_nat" ]; then
                echo "$raw_nat"
            else
                echo "Failed to dump NAT map"
            fi
            
            echo ""
            echo "JSON NAT map dump (first 500 chars):"
            local json_nat=$(dump_bpf_map "nat_map" "json" 2>/dev/null)
            if [ -n "$json_nat" ]; then
                echo "$json_nat" | cut -c1-500
                if [ ${#json_nat} -gt 500 ]; then
                    echo "... (truncated)"
                fi
            else
                echo "Failed to get JSON dump"
            fi
        fi
    else
        echo "No NAT rules configured (empty map)"
    fi
    
    # IP Allowlist Table
    echo ""
    print_color "yellow" "=== IP ALLOWLIST ==="
    local ip_count=$(get_ip_allowlist_count)
    
    if [ "$ip_count" -gt 0 ]; then
        echo "Allowed IP Addresses: $ip_count total"
        
        # Show sample IPs if available
        local ip_data=$(dump_bpf_map "ip_allowlist" "json")
        if [ -n "$ip_data" ] && command -v jq >/dev/null 2>&1; then
            echo ""
            echo "┌─────────────────┬────────────────────────────────────────────────┐"
            echo "│   IP Address    │                   Status                       │"
            echo "├─────────────────┼────────────────────────────────────────────────┤"
            
            # Show first 15 IPs to keep output manageable - handle multiple maps
            local ip_entries=$(echo "$ip_data" | jq -r 'if (type == "array") then [.[] | select(.elements != null and (.elements | length) > 0) | .elements[].key] else [] end | sort | .[:15] | .[]' 2>/dev/null)
            
            if [ -n "$ip_entries" ]; then
                local displayed_count=0
                echo "$ip_entries" | while read -r ip_int; do
                    if [ -n "$ip_int" ] && [[ "$ip_int" =~ ^[0-9]+$ ]]; then
                        local ip_addr=$(int_to_ip "$ip_int")
                        printf "│ %15s │                    Allowed                     │\n" "$ip_addr"
                        ((displayed_count++))
                        # Break after 15 to avoid too much output
                        [ $displayed_count -ge 15 ] && break
                    fi
                done
                
                if [ "$ip_count" -gt 15 ]; then
                    printf "│       ...       │              ... (%d more IPs)                │\n" $((ip_count - 15))
                fi
            fi
            echo "└─────────────────┴────────────────────────────────────────────────┘"
        fi
    else
        echo "No IPs in allowlist"
    fi
    
    # BPF Maps Summary
    echo ""
    print_color "yellow" "=== BPF MAPS SUMMARY ==="
    echo "┌─────────────────┬─────┬──────────┬─────────┬─────────────────────────┐"
    echo "│   Map Name      │ ID  │   Type   │ Elements│         Purpose         │"
    echo "├─────────────────┼─────┼──────────┼─────────┼─────────────────────────┤"
    
    get_bpf_map_list | while IFS= read -r line; do
        local map_id=$(echo "$line" | awk '{print $1}' | tr -d ':')
        local map_type=$(echo "$line" | awk '{print $2}')
        local map_name=$(echo "$line" | grep -o 'name [^ ]*' | cut -d' ' -f2)
        
        # Get element count
        local elements=$(count_bpf_map_entries "$map_name")
        
        # Set purpose
        local purpose
        case "$map_name" in
            "nat_map") purpose="NAT rule storage" ;;
            "stats_map") purpose="Packet statistics" ;;
            "ip_allowlist") purpose="IP access control" ;;
            "redirect_map") purpose="Interface redirect" ;;
            "interface_map") purpose="Interface info" ;;
            *) purpose="Unknown" ;;
        esac
        
        printf "│ %-15s │ %3s │ %-8s │ %7s │ %-23s │\n" \
            "$map_name" "$map_id" "$map_type" "$elements" "$purpose"
    done
    echo "└─────────────────┴─────┴──────────┴─────────┴─────────────────────────┘"
    
    # Interface Statistics
    echo ""
    print_color "yellow" "=== INTERFACE STATISTICS ==="
    show_interface_info "$INTERFACE" "$TARGET_INTERFACE"
    
    # Process Status
    echo ""
    print_color "yellow" "=== PROCESS STATUS ==="
    echo "┌─────────────────┬─────────────┬─────────────────┬────────────────────────┐"
    echo "│    Process      │   Status    │      PID(s)     │        Command         │"
    echo "├─────────────────┼─────────────┼─────────────────┼────────────────────────┤"
    
    # vxlan_loader status
    local loader_pids=$(pgrep -f "vxlan_loader" 2>/dev/null | tr '\n' ',' | sed 's/,$//')
    if [ -n "$loader_pids" ]; then
        local loader_cmd=$(ps -p "$(echo "$loader_pids" | cut -d',' -f1)" -o args= 2>/dev/null | cut -c1-22)
        printf "│ vxlan_loader    │ \033[0;32m%-11s\033[0m │ %-15s │ %-22s │\n" "Running" "$loader_pids" "$loader_cmd"
    else
        printf "│ vxlan_loader    │ \033[0;31m%-11s\033[0m │ %-15s │ %-22s │\n" "Stopped" "N/A" "Not running"
    fi
    
    # packet_injector status
    local injector_pids=$(pgrep -f "packet_injector" 2>/dev/null | tr '\n' ',' | sed 's/,$//')
    if [ -n "$injector_pids" ]; then
        local injector_cmd=$(ps -p "$(echo "$injector_pids" | cut -d',' -f1)" -o args= 2>/dev/null | cut -c1-22)
        printf "│ packet_injector │ \033[0;32m%-11s\033[0m │ %-15s │ %-22s │\n" "Running" "$injector_pids" "$injector_cmd"
    else
        printf "│ packet_injector │ \033[1;33m%-11s\033[0m │ %-15s │ %-22s │\n" "Stopped" "N/A" "Not running"
    fi
    
    echo "└─────────────────┴─────────────┴─────────────────┴────────────────────────┘"
    
    # Dynamic Scaling Status
    echo ""
    print_color "yellow" "=== DYNAMIC SCALING STATUS ==="
    
    # Source the dynamic scaling script to get scaling status
    if [ -f "$SCRIPT_DIR/xdp_functions/dynamic_scaling.sh" ]; then
        local scaling_status=$("$SCRIPT_DIR/xdp_functions/dynamic_scaling.sh" status 2>/dev/null)
        if [ $? -eq 0 ] && [ -n "$scaling_status" ]; then
            echo "$scaling_status"
        else
            echo "Dynamic scaling information not available"
        fi
    else
        echo "Dynamic scaling module not found"
    fi
}