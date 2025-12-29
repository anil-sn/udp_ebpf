#!/usr/bin/env python3
"""
XDP Pipeline Monitor - Unified Python Implementation
Handles all monitoring functionality with correct endianness
"""

import sys
import subprocess
import json
import re
import time
import signal
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from collections import Counter

class XDPPipelineMonitor:
    def __init__(self):
        self.allowlist_paths = [
            "/home/asrirang/udp_ebpf/src/ip_allowlist.json",
            "./src/ip_allowlist.json", 
            "src/ip_allowlist.json"
        ]
        
    def run_command(self, cmd: List[str], capture_output=True, timeout=30) -> Tuple[str, str, int]:
        """Run command and return stdout, stderr, returncode"""
        try:
            result = subprocess.run(cmd, capture_output=capture_output, text=True, timeout=timeout)
            return result.stdout, result.stderr, result.returncode
        except Exception as e:
            return "", str(e), 1
    
    def get_bpf_map_data(self, map_name: str) -> List[Dict]:
        """Get BPF map data as JSON"""
        stdout, stderr, rc = self.run_command(["sudo", "bpftool", "map", "dump", "name", map_name, "--json"])
        if rc == 0:
            try:
                return json.loads(stdout)
            except json.JSONDecodeError:
                pass
        return []
    
    def convert_bpf_ip_correct(self, ip_int: int) -> str:
        """Convert BPF integer IP to dotted decimal (little-endian from bpftool)"""
        # bpftool outputs IP integers in little-endian format
        # Extract bytes in little-endian order
        a = ip_int & 0xFF          # First octet (172)
        b = (ip_int >> 8) & 0xFF   # Second octet (30)  
        c = (ip_int >> 16) & 0xFF  # Third octet (83)
        d = (ip_int >> 24) & 0xFF  # Fourth octet (192)
        return f"{a}.{b}.{c}.{d}"  # Correct order: 172.30.83.192
    
    def load_allowlist_json(self) -> Optional[Dict]:
        """Load allowlist from JSON file"""
        for path in self.allowlist_paths:
            try:
                with open(path, 'r') as f:
                    return json.load(f)
            except:
                continue
        return None
    
    def display_header(self):
        """Display monitoring header"""
        print("📊 VXLAN Pipeline - Per-IP Statistics Analysis")
        print("=" * 61)
        print()
    
    def check_bpf_programs(self) -> int:
        """Check how many XDP programs are loaded"""
        stdout, stderr, rc = self.run_command(["sudo", "bpftool", "prog", "list", "type", "xdp"])
        if rc == 0:
            return len([line for line in stdout.split('\n') if 'xdp' in line.lower()])
        return 0
    
    def display_bpf_status(self):
        """Display BPF program status"""
        prog_count = self.check_bpf_programs()
        if prog_count == 0:
            print("❌ No XDP programs loaded")
            return False
        else:
            print(f"✅ {prog_count} XDP program(s) loaded")
            return True
    
    def display_ip_allowlist(self):
        """Display current IP allowlist from BPF map with CORRECT endianness"""
        print("🎯 Current IP Allowlist:")
        
        # Get IP allowlist from BPF map
        ip_data = self.get_bpf_map_data("ip_allowlist")
        
        if not ip_data:
            print("  ❌ No IPs found in allowlist map")
            return
        
        # Convert and display IPs with correct endianness
        ips = []
        for entry in ip_data:
            if "formatted" in entry and "key" in entry["formatted"]:
                ip_int = entry["formatted"]["key"]
                ip_str = self.convert_bpf_ip_correct(ip_int)  # Fixed function
                ips.append(ip_str)
        
        # Sort IPs for consistent display
        ips.sort()
        
        for ip in ips:
            print(f"  ✅ {ip}")
        
        print()
    
    def get_pipeline_statistics(self):
        """Get pipeline statistics from BPF maps"""
        stats_data = self.get_bpf_map_data("stats_map")
        
        if not stats_data:
            print("❌ Unable to retrieve pipeline statistics")
            return {}
        
        # Parse statistics (sum across all CPUs)
        stats = {}
        stat_keys = {
            0: "total_packets",
            1: "vxlan_packets", 
            2: "inner_packets",
            3: "nat_applied",
            4: "df_cleared",
            5: "forwarded",
            6: "redirected", 
            7: "errors",
            8: "bytes_processed",
            15: "length_corrections"
        }
        
        for entry in stats_data:
            if "formatted" in entry:
                key = entry["formatted"]["key"]
                if key in stat_keys:
                    # Sum values across all CPUs
                    values = entry["formatted"]["values"]
                    total = sum(v["value"] for v in values if isinstance(v, dict) and "value" in v)
                    stats[stat_keys[key]] = total
        
        return stats
    
    def display_pipeline_statistics(self):
        """Display pipeline statistics"""
        stats = self.get_pipeline_statistics()
        if not stats:
            return
        
        # Extract values
        total_packets = stats.get("total_packets", 0)
        vxlan_packets = stats.get("vxlan_packets", 0)
        inner_packets = stats.get("inner_packets", 0)
        nat_applied = stats.get("nat_applied", 0)
        forwarded = stats.get("forwarded", 0)
        
        vxlan_pct = (vxlan_packets / total_packets * 100) if total_packets > 0 else 0
        nat_efficiency = (nat_applied / vxlan_packets * 100) if vxlan_packets > 0 else 0
        
        print("📈 Pipeline Statistics Summary:")
        print(f"  Total Packets:     {total_packets:,}")
        print(f"  VXLAN Packets:     {vxlan_packets:,} ({vxlan_pct:.1f}%)")
        print(f"  Inner Packets:     {inner_packets:,}")
        print(f"  NAT Applied:       {nat_applied:,}")
        print(f"  Forwarded:         {forwarded:,}")
        print(f"  NAT Efficiency:    {nat_efficiency:.1f}%")
        print()
    
    def real_time_monitor(self, interval=5):
        """Real-time statistics monitoring"""
        previous_stats = {}
        
        def signal_handler(signum, frame):
            print("\n👋 Monitoring stopped by user")
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        print("🔍 VXLAN Pipeline Monitor - Real-time Statistics")
        print("Press Ctrl+C to stop monitoring...")
        print()
        
        try:
            while True:
                # Clear screen
                print("\033[2J\033[H", end="")
                
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"{timestamp} - VXLAN Pipeline Statistics")
                print("=" * 60)
                
                stats = self.get_pipeline_statistics()
                if not stats:
                    print("❌ Unable to retrieve statistics")
                    time.sleep(interval)
                    continue
                
                # Calculate rates
                rates = {}
                if previous_stats:
                    for key, value in stats.items():
                        if key in previous_stats:
                            rate = max(0, (value - previous_stats[key]) // interval)
                            rates[key] = rate
                        else:
                            rates[key] = 0
                else:
                    rates = {k: 0 for k in stats.keys()}
                
                # Display metrics
                total_packets = stats.get("total_packets", 0)
                vxlan_packets = stats.get("vxlan_packets", 0)
                inner_packets = stats.get("inner_packets", 0)
                nat_applied = stats.get("nat_applied", 0)
                forwarded = stats.get("forwarded", 0)
                
                total_pps = rates.get("total_packets", 0)
                vxlan_pps = rates.get("vxlan_packets", 0)
                nat_pps = rates.get("nat_applied", 0)
                
                vxlan_pct = (vxlan_packets / total_packets * 100) if total_packets > 0 else 0
                nat_efficiency = (nat_applied / vxlan_packets * 100) if vxlan_packets > 0 else 0
                
                print(f"Total Packets:         {total_packets:8,} ({total_pps:7,} pps)")
                print(f"VXLAN Packets:         {vxlan_packets:8,} ({vxlan_pps:7,} pps, {vxlan_pct:5.1f}%)")
                print(f"Inner Extracted:       {inner_packets:8,} (decapsulated)")
                print(f"NAT Applied:           {nat_applied:8,} ({nat_pps:7,}/s)")
                print(f"Forwarded:             {forwarded:8,} (to target)")
                
                # Performance status
                if total_pps >= 85000:
                    status = "🎯 TARGET ACHIEVED"
                elif total_pps >= 60000:
                    status = "🔥 HIGH PERFORMANCE"
                elif total_pps >= 30000:
                    status = "✅ GOOD PERFORMANCE"
                elif total_pps > 0:
                    status = "⚡ MODERATE PERFORMANCE"
                else:
                    status = "⏸️  IDLE"
                
                print(f"\nStatus: {status}")
                
                previous_stats = stats.copy()
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\n👋 Monitoring stopped by user")


def main():
    if len(sys.argv) < 2:
        print("Usage: xdp_monitor.py <command> [options]")
        print("Commands:")
        print("  status     - Show current status (header + allowlist + stats)")
        print("  allowlist  - Display IP allowlist from BPF map")
        print("  stats      - Display pipeline statistics")
        print("  realtime   - Real-time monitoring with live updates")
        print("  header     - Display header and check BPF programs")
        sys.exit(1)
    
    command = sys.argv[1]
    monitor = XDPPipelineMonitor()
    
    if command == "header":
        monitor.display_header()
        if not monitor.display_bpf_status():
            sys.exit(1)
            
    elif command == "allowlist":
        monitor.display_ip_allowlist()
        
    elif command == "stats":
        monitor.display_pipeline_statistics()
        
    elif command == "realtime":
        monitor.real_time_monitor()
        
    elif command == "status":
        monitor.display_header()
        if not monitor.display_bpf_status():
            sys.exit(1)
        print()
        monitor.display_ip_allowlist()
        monitor.display_pipeline_statistics()
        
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()