#!/usr/bin/env python3
"""
Simple Packet Monitor for XDP VXLAN Pipeline
Reads from your existing xdpdump | tcpdump pipeline

Usage:
    sudo xdpdump -i ens5 -w - | tcpdump -r - -n -XX | python3 simple_packet_monitor.py

Or pipe directly:
    sudo xdpdump -i ens5 -w - | tcpdump -r - -n -XX | python3 simple_packet_monitor.py
"""

import sys
import re
from collections import defaultdict
from datetime import datetime

class SimplePacketMonitor:
    def __init__(self):
        self.packet_count = 0
        self.vxlan_count = 0
        self.processed_count = 0
        self.nat_matches = 0
        self.errors = defaultdict(int)
        
        # Configuration from .env
        self.config_source_port = 31765
        self.config_target_ip = "172.30.82.95"
        self.config_target_port = 8081
        
        print("🔍 XDP VXLAN Packet Monitor")
        print(f"📋 Config: Match port {self.config_source_port} → {self.config_target_ip}:{self.config_target_port}")
        print("📊 Monitoring packets...\n")
    
    def process_line(self, line):
        """Process each line from tcpdump output"""
        line = line.strip()
        
        # Detect new packet by timestamp
        if re.match(r'\d{2}:\d{2}:\d{2}\.\d+', line):
            self.packet_count += 1
            
            # Check for VXLAN packet
            if '.4789:' in line and 'VXLAN' in line:
                self.vxlan_count += 1
                self.analyze_vxlan_line(line)
                
        # Look for inner packet info in subsequent lines
        elif 'IP ' in line and '>' in line and '.4789' not in line:
            # This might be inner packet info
            self.check_inner_packet(line)
    
    def analyze_vxlan_line(self, line):
        """Analyze VXLAN packet line"""
        timestamp_match = re.search(r'(\d{2}:\d{2}:\d{2}\.\d+)', line)
        timestamp = timestamp_match.group(1) if timestamp_match else "Unknown"
        
        # Extract VNI
        vni_match = re.search(r'vni (\d+)', line)
        vni = int(vni_match.group(1)) if vni_match else None
        
        # Extract outer addresses
        outer_match = re.search(r'IP (\S+)\.(\d+) > (\S+)\.4789', line)
        
        status = "🔵 VXLAN"
        details = []
        
        if vni != 1:
            status = "❌ DROP"
            details.append(f"Bad VNI: {vni}")
            self.errors[f"bad_vni_{vni}"] += 1
        
        if outer_match:
            outer_src = outer_match.group(1)
            outer_src_port = outer_match.group(2)
            outer_dst = outer_match.group(3)
            details.append(f"Outer: {outer_src}:{outer_src_port}→{outer_dst}:4789")
        
        print(f"[{timestamp}] {status} {' | '.join(details)}")
    
    def check_inner_packet(self, line):
        """Check if inner packet matches NAT rules"""
        # Look for UDP packet with destination port matching config
        inner_match = re.search(r'IP (\S+)\.(\d+) > (\S+)\.(\d+): UDP', line)
        
        if inner_match:
            inner_src = inner_match.group(1)
            inner_src_port = int(inner_match.group(2))
            inner_dst = inner_match.group(3) 
            inner_dst_port = int(inner_match.group(4))
            
            # Check NAT match (destination port)
            if inner_dst_port == self.config_source_port:
                self.nat_matches += 1
                self.processed_count += 1
                print(f"         ✅ PROCESS | Inner: {inner_src}:{inner_src_port}→{inner_dst}:{inner_dst_port} | NAT: →{self.config_target_ip}:{self.config_target_port}")
            else:
                self.errors[f"nat_miss_port_{inner_dst_port}"] += 1
                print(f"         ❌ NAT_MISS | Inner: {inner_src}:{inner_src_port}→{inner_dst}:{inner_dst_port} | Expected port: {self.config_source_port}")
    
    def print_summary(self):
        """Print statistics summary"""
        print(f"\n📊 PACKET SUMMARY")
        print(f"{'='*50}")
        print(f"Total packets:      {self.packet_count:>8}")
        print(f"VXLAN packets:      {self.vxlan_count:>8}")
        print(f"Would process:      {self.processed_count:>8}")
        print(f"NAT matches:        {self.nat_matches:>8}")
        
        if self.errors:
            print(f"\nErrors/Issues:")
            for error, count in self.errors.items():
                print(f"  {error}: {count}")
        
        success_rate = (self.processed_count / self.vxlan_count * 100) if self.vxlan_count > 0 else 0
        print(f"\nProcessing rate: {success_rate:.1f}% of VXLAN packets")
    
    def run(self):
        """Main processing loop"""
        try:
            for line in sys.stdin:
                self.process_line(line)
                
                # Print periodic stats
                if self.packet_count > 0 and self.packet_count % 100 == 0:
                    print(f"\n📈 Packets processed: {self.packet_count} (VXLAN: {self.vxlan_count}, Processed: {self.processed_count})")
                    
        except KeyboardInterrupt:
            pass
        finally:
            self.print_summary()

if __name__ == "__main__":
    monitor = SimplePacketMonitor()
    monitor.run()