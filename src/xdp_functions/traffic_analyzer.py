#!/usr/bin/env python3
"""
Traffic Analyzer for VXLAN and IPSec monitoring
Parses tcpdump/xdpdump output and checks against IP allowlist
"""

import sys
import re
import json
import os
from collections import defaultdict, Counter
from typing import Dict, List, Tuple, Set

class TrafficAnalyzer:
    def __init__(self, allowlist_paths: List[str]):
        self.allowlist_ips: Set[str] = set()
        self.load_allowlist(allowlist_paths)
    
    def load_allowlist(self, paths: List[str]):
        """Load IP allowlist from JSON file"""
        for path in paths:
            if os.path.isfile(path):
                try:
                    with open(path, 'r') as f:
                        data = json.load(f)
                        # Get IPs from flat_ip_list
                        if 'flat_ip_list' in data:
                            for ip in data['flat_ip_list']:
                                # Skip CIDR entries for now
                                if '/' not in ip:
                                    self.allowlist_ips.add(ip)
                        print(f"   ✅ Loaded allowlist from: {path}", file=sys.stderr)
                        print(f"   📄 Allowlist contains {len(self.allowlist_ips)} IPs", file=sys.stderr)
                        return
                except Exception as e:
                    print(f"   ❌ Error loading {path}: {e}", file=sys.stderr)
        print(f"   ❌ No allowlist file found in: {paths}", file=sys.stderr)
    
    def parse_vxlan_traffic(self, vxlan_file: str) -> Dict[str, int]:
        """Parse VXLAN traffic and extract inner source IPs"""
        ip_counts = Counter()
        
        if not os.path.isfile(vxlan_file):
            return {}
        
        try:
            with open(vxlan_file, 'r') as f:
                content = f.read()
                
            # Pattern to match VXLAN inner packets
            # Looking for lines after "VXLAN, flags [I]" that contain IP traffic
            vxlan_pattern = r'VXLAN, flags \[I\].*?vni \d+\s*\n\s*IP.*?(\d+\.\d+\.\d+\.\d+)\.\d+\s*>\s*(\d+\.\d+\.\d+\.\d+)'
            
            matches = re.findall(vxlan_pattern, content, re.MULTILINE | re.DOTALL)
            for src_ip, dst_ip in matches:
                ip_counts[src_ip] += 1
                
        except Exception as e:
            print(f"   ❌ Error parsing VXLAN file: {e}", file=sys.stderr)
            
        return dict(ip_counts)
    
    def parse_ipsec_traffic(self, ipsec_file: str) -> Dict[str, int]:
        """Parse IPSec/ESP traffic and extract source IPs"""
        ip_counts = Counter()
        
        if not os.path.isfile(ipsec_file):
            return {}
        
        try:
            with open(ipsec_file, 'r') as f:
                lines = f.readlines()
                
            # Pattern to match IPSec ESP traffic
            # Example: 172.30.83.216.4500 > 34.56.248.50.4500: UDP-encap: ESP
            ipsec_pattern = r'(\d+\.\d+\.\d+\.\d+)\.\d+\s*>\s*(\d+\.\d+\.\d+\.\d+)\.\d+.*UDP-encap: ESP'
            
            for line in lines:
                match = re.search(ipsec_pattern, line)
                if match:
                    src_ip = match.group(1)
                    ip_counts[src_ip] += 1
                    
        except Exception as e:
            print(f"   ❌ Error parsing IPSec file: {e}", file=sys.stderr)
            
        return dict(ip_counts)
    
    def parse_tap_traffic(self, tap_file: str) -> Dict[str, int]:
        """Parse TAP interface traffic"""
        ip_counts = Counter()
        
        if not os.path.isfile(tap_file):
            return {}
        
        try:
            with open(tap_file, 'r') as f:
                lines = f.readlines()
                
            # Pattern to match regular IP traffic
            # Example: 61.155.115.2.58611 > 100.68.16.35.8081
            ip_pattern = r'(\d+\.\d+\.\d+\.\d+)\.\d+\s*>\s*(\d+\.\d+\.\d+\.\d+)'
            
            for line in lines:
                match = re.search(ip_pattern, line)
                if match:
                    src_ip = match.group(1)
                    ip_counts[src_ip] += 1
                    
        except Exception as e:
            print(f"   ❌ Error parsing TAP file: {e}", file=sys.stderr)
            
        return dict(ip_counts)
    
    def check_allowlist_status(self, ip: str) -> str:
        """Check if IP is in allowlist"""
        if ip in self.allowlist_ips:
            return "✅ ALLOWED"
        else:
            return "❌ DENIED"
    
    def analyze_and_display(self, vxlan_file: str, ipsec_file: str, tap_file: str, duration: int = 30):
        """Main analysis function"""
        
        # Parse all traffic types
        vxlan_ips = self.parse_vxlan_traffic(vxlan_file)
        ipsec_ips = self.parse_ipsec_traffic(ipsec_file)
        tap_ips = self.parse_tap_traffic(tap_file)
        
        # Calculate totals
        total_vxlan = sum(vxlan_ips.values())
        total_ipsec = sum(ipsec_ips.values())
        total_tap = sum(tap_ips.values())
        
        print(f"\n   📊 MULTI-PROTOCOL TRAFFIC ANALYSIS ({duration}s capture):")
        print("   ┌─────────────────┬─────────┬─────────┬──────────────────┐")
        print("   │ Source IP       │ Packets │   PPS   │ Status/Protocol  │")
        print("   ├─────────────────┼─────────┼─────────┼──────────────────┤")
        
        # Combine all unique IPs for analysis
        all_ips = set(vxlan_ips.keys()) | set(ipsec_ips.keys()) | set(tap_ips.keys())
        found_traffic = False
        
        # Sort by total packet count (VXLAN + TAP)
        ip_totals = []
        for ip in all_ips:
            vxlan_count = vxlan_ips.get(ip, 0)
            ipsec_count = ipsec_ips.get(ip, 0)
            tap_count = tap_ips.get(ip, 0)
            total_count = vxlan_count + ipsec_count + tap_count
            ip_totals.append((ip, total_count, vxlan_count, ipsec_count, tap_count))
        
        # Sort by total count descending
        ip_totals.sort(key=lambda x: x[1], reverse=True)
        
        # Display results
        for ip, total_count, vxlan_count, ipsec_count, tap_count in ip_totals[:10]:
            pps = total_count / duration
            
            # Determine protocol and status
            if vxlan_count > 0:
                status = self.check_allowlist_status(ip)
                protocol = "VXLAN Inner"
            elif ipsec_count > 0:
                status = "🔐 IPSec/ESP"
                protocol = "Encrypted"
            elif tap_count > 0:
                status = self.check_allowlist_status(ip)
                protocol = "TAP Output"
            else:
                status = "❓ Unknown"
                protocol = "Mixed"
            
            print(f"   │ {ip:<15} │ {total_count:>7} │ {pps:>7.1f} │ {status:<16} │")
            found_traffic = True
        
        if not found_traffic:
            print("   │ No traffic      │       0 │     0.0 │ No data captured │")
        
        print("   └─────────────────┴─────────┴─────────┴──────────────────┘")
        
        # Summary
        print(f"\n   📈 SUMMARY:")
        print(f"   • VXLAN Inner: {total_vxlan} packets (~{total_vxlan/duration:.0f} pps) from {len(vxlan_ips)} IPs")
        print(f"   • IPSec/ESP: {total_ipsec} packets (~{total_ipsec/duration:.0f} pps) from {len(ipsec_ips)} IPs")
        print(f"   • TAP Output: {total_tap} packets (~{total_tap/duration:.0f} pps) from {len(tap_ips)} IPs")
        
        # Allowlist effectiveness
        allowed_vxlan = sum(1 for ip in vxlan_ips if ip in self.allowlist_ips)
        denied_vxlan = len(vxlan_ips) - allowed_vxlan
        
        if vxlan_ips:
            print(f"   • Allowlist: {allowed_vxlan} allowed, {denied_vxlan} denied VXLAN IPs")


def main():
    if len(sys.argv) < 4:
        print("Usage: traffic_analyzer.py <vxlan_file> <ipsec_file> <tap_file> [duration]")
        sys.exit(1)
    
    vxlan_file = sys.argv[1]
    ipsec_file = sys.argv[2] 
    tap_file = sys.argv[3]
    duration = int(sys.argv[4]) if len(sys.argv) > 4 else 30
    
    # Common allowlist file locations
    allowlist_paths = [
        "/home/asrirang/udp_ebpf/src/ip_allowlist.json",
        "./src/ip_allowlist.json",
        "src/ip_allowlist.json"
    ]
    
    analyzer = TrafficAnalyzer(allowlist_paths)
    analyzer.analyze_and_display(vxlan_file, ipsec_file, tap_file, duration)


if __name__ == "__main__":
    main()