#!/usr/bin/env python3
"""
Real-time XDP Packet Analyzer for VXLAN Pipeline Debugging

This script captures packets using xdpdump/tcpdump and analyzes them in real-time
to debug why the VXLAN eBPF pipeline is or isn't processing specific packets.

Usage:
    sudo python3 realtime_packet_analyzer.py

Requirements:
    - Root privileges (for xdpdump)
    - xdp-tools package installed
    - tcpdump installed
"""

import subprocess
import sys
import re
import time
import signal
from datetime import datetime
from collections import defaultdict, deque
import threading
import queue

class PacketStats:
    def __init__(self):
        self.total_packets = 0
        self.vxlan_packets = 0
        self.processed_packets = 0
        self.nat_matches = 0
        self.errors = defaultdict(int)
        self.start_time = time.time()
        
    def print_stats(self):
        elapsed = time.time() - self.start_time
        pps = self.total_packets / elapsed if elapsed > 0 else 0
        
        print(f"\n{'='*60}")
        print(f"PACKET STATISTICS (Runtime: {elapsed:.1f}s)")
        print(f"{'='*60}")
        print(f"Total packets seen:      {self.total_packets:>8} ({pps:.1f} pps)")
        print(f"VXLAN packets:          {self.vxlan_packets:>8}")
        print(f"Would be processed:     {self.processed_packets:>8}")
        print(f"NAT rule matches:       {self.nat_matches:>8}")
        
        if self.errors:
            print(f"\nERRORS:")
            for error, count in self.errors.items():
                print(f"  {error}: {count}")
        print(f"{'='*60}\n")

class VXLANPacketAnalyzer:
    def __init__(self, interface="ens5", config_source_port=31765, 
                 config_target_ip="172.30.82.95", config_target_port=8081):
        self.interface = interface
        self.config_source_port = config_source_port
        self.config_target_ip = config_target_ip
        self.config_target_port = config_target_port
        self.stats = PacketStats()
        self.packet_queue = queue.Queue()
        self.running = True
        
        # Recent packet buffer for debugging
        self.recent_packets = deque(maxlen=10)
        
        print(f"XDP VXLAN Packet Analyzer Starting...")
        print(f"Interface: {interface}")
        print(f"Config - Source Port: {config_source_port}, Target: {config_target_ip}:{config_target_port}")
        print(f"Press Ctrl+C to stop\n")
        
    def parse_packet_header(self, lines):
        """Parse tcpdump output to extract packet information"""
        packet_info = {
            'timestamp': None,
            'outer_src': None,
            'outer_dst': None,
            'outer_src_port': None,
            'outer_dst_port': None,
            'inner_src': None,
            'inner_dst': None,
            'inner_src_port': None,
            'inner_dst_port': None,
            'vni': None,
            'hex_data': '',
            'is_vxlan': False,
            'vxlan_valid': False,
            'would_process': False,
            'nat_match': False,
            'errors': []
        }
        
        # Parse timestamp and basic packet info
        for line in lines:
            if 'IP ' in line and '>' in line:
                # Extract timestamp
                time_match = re.search(r'(\d{2}:\d{2}:\d{2}\.\d+)', line)
                if time_match:
                    packet_info['timestamp'] = time_match.group(1)
                
                # Check for VXLAN (port 4789)
                if '.4789:' in line:
                    packet_info['is_vxlan'] = True
                    # Parse outer addresses
                    ip_match = re.search(r'IP (\S+)\.(\d+) > (\S+)\.(\d+):', line)
                    if ip_match:
                        packet_info['outer_src'] = ip_match.group(1)
                        packet_info['outer_src_port'] = int(ip_match.group(2))
                        packet_info['outer_dst'] = ip_match.group(3)
                        packet_info['outer_dst_port'] = int(ip_match.group(4))
                
                # Look for VXLAN VNI
                vni_match = re.search(r'vni (\d+)', line)
                if vni_match:
                    packet_info['vni'] = int(vni_match.group(1))
                
                # Look for inner packet
                inner_match = re.search(r'IP (\S+)\.(\d+) > (\S+)\.(\d+):', line)
                if inner_match and packet_info['is_vxlan']:
                    # This might be the inner packet line
                    if not packet_info['inner_src']:  # Only take the first inner match
                        packet_info['inner_src'] = inner_match.group(1)
                        packet_info['inner_src_port'] = int(inner_match.group(2))
                        packet_info['inner_dst'] = inner_match.group(3) 
                        packet_info['inner_dst_port'] = int(inner_match.group(4))
            
            # Collect hex data
            if re.match(r'\s+0x[0-9a-f]+:', line):
                hex_part = re.sub(r'\s+0x[0-9a-f]+:\s+', '', line)
                hex_part = re.sub(r'\s+.*$', '', hex_part)  # Remove ASCII part
                packet_info['hex_data'] += hex_part.replace(' ', '')
        
        return packet_info
    
    def analyze_vxlan_packet(self, packet_info):
        """Analyze if a VXLAN packet would be processed by the eBPF code"""
        if not packet_info['is_vxlan']:
            packet_info['errors'].append("Not VXLAN (port != 4789)")
            return
        
        if packet_info['outer_dst_port'] != 4789:
            packet_info['errors'].append(f"Wrong VXLAN port: {packet_info['outer_dst_port']}")
            return
            
        # Check VNI
        if packet_info['vni'] != 1:
            packet_info['errors'].append(f"Wrong VNI: {packet_info['vni']} (expected 1)")
            return
        
        packet_info['vxlan_valid'] = True
        
        # Check if we have inner packet info
        if not packet_info['inner_dst_port']:
            packet_info['errors'].append("Could not extract inner UDP port")
            return
        
        # Check NAT rule match (destination port based)
        if packet_info['inner_dst_port'] == self.config_source_port:
            packet_info['nat_match'] = True
            packet_info['would_process'] = True
        else:
            packet_info['errors'].append(
                f"NAT miss: dest_port={packet_info['inner_dst_port']}, "
                f"config_port={self.config_source_port}"
            )
    
    def print_packet_analysis(self, packet_info):
        """Print detailed analysis of a packet"""
        timestamp = packet_info['timestamp'] or datetime.now().strftime("%H:%M:%S.%f")[:-3]
        
        if packet_info['is_vxlan']:
            status = "✅ PROCESS" if packet_info['would_process'] else "❌ DROP/PASS"
            print(f"\n[{timestamp}] VXLAN Packet - {status}")
            
            if packet_info['outer_src']:
                print(f"  Outer: {packet_info['outer_src']}:{packet_info['outer_src_port']} → "
                      f"{packet_info['outer_dst']}:{packet_info['outer_dst_port']}")
            
            if packet_info['vni'] is not None:
                print(f"  VNI: {packet_info['vni']}")
            
            if packet_info['inner_src']:
                print(f"  Inner: {packet_info['inner_src']}:{packet_info['inner_src_port']} → "
                      f"{packet_info['inner_dst']}:{packet_info['inner_dst_port']}")
            
            if packet_info['nat_match']:
                print(f"  NAT: ✅ Match (port {packet_info['inner_dst_port']}) → "
                      f"{self.config_target_ip}:{self.config_target_port}")
            
            if packet_info['errors']:
                print(f"  Errors: {', '.join(packet_info['errors'])}")
        
        else:
            print(f"[{timestamp}] Non-VXLAN packet (passing through)")
    
    def capture_packets(self):
        """Capture packets using xdpdump + tcpdump"""
        cmd = [
            'sudo', 'xdpdump', '-i', self.interface, '-w', '-'
        ]
        
        tcpdump_cmd = [
            'tcpdump', '-r', '-', '-n', '-XX', '-v'
        ]
        
        try:
            # Start xdpdump process
            xdpdump_proc = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE
            )
            
            # Start tcpdump process
            tcpdump_proc = subprocess.Popen(
                tcpdump_cmd,
                stdin=xdpdump_proc.stdout,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            xdpdump_proc.stdout.close()  # Allow xdpdump to receive SIGPIPE if tcpdump exits
            
            packet_lines = []
            
            for line in tcpdump_proc.stdout:
                if not self.running:
                    break
                
                line = line.strip()
                
                # Check if this is a new packet (timestamp line)
                if re.match(r'\d{2}:\d{2}:\d{2}\.\d+', line):
                    # Process previous packet if we have one
                    if packet_lines:
                        self.process_packet_lines(packet_lines)
                    
                    # Start new packet
                    packet_lines = [line]
                else:
                    # Add line to current packet
                    packet_lines.append(line)
            
            # Process last packet
            if packet_lines:
                self.process_packet_lines(packet_lines)
                
        except KeyboardInterrupt:
            self.running = False
        except Exception as e:
            print(f"Error in packet capture: {e}")
        finally:
            try:
                tcpdump_proc.terminate()
                xdpdump_proc.terminate()
            except:
                pass
    
    def process_packet_lines(self, lines):
        """Process a group of lines representing one packet"""
        try:
            packet_info = self.parse_packet_header(lines)
            self.analyze_vxlan_packet(packet_info)
            
            # Update statistics
            self.stats.total_packets += 1
            
            if packet_info['is_vxlan']:
                self.stats.vxlan_packets += 1
                
            if packet_info['would_process']:
                self.stats.processed_packets += 1
                
            if packet_info['nat_match']:
                self.stats.nat_matches += 1
            
            for error in packet_info['errors']:
                self.stats.errors[error] += 1
            
            # Print analysis for VXLAN packets or interesting ones
            if packet_info['is_vxlan'] or packet_info['errors']:
                self.print_packet_analysis(packet_info)
            
            # Store recent packet for debugging
            self.recent_packets.append(packet_info)
            
            # Print stats every 50 packets
            if self.stats.total_packets % 50 == 0:
                self.stats.print_stats()
                
        except Exception as e:
            print(f"Error processing packet: {e}")
    
    def run(self):
        """Main run loop"""
        # Set up signal handler for clean shutdown
        def signal_handler(sig, frame):
            print("\n\nShutting down...")
            self.running = False
            
        signal.signal(signal.SIGINT, signal_handler)
        
        try:
            self.capture_packets()
        finally:
            print("\nFinal Statistics:")
            self.stats.print_stats()
            
            if self.recent_packets:
                print("Recent packet summary:")
                for i, pkt in enumerate(list(self.recent_packets)[-5:]):
                    status = "PROCESS" if pkt['would_process'] else "DROP/PASS"
                    vxlan_info = f"VNI:{pkt['vni']}" if pkt['vni'] else "Non-VXLAN"
                    inner_port = f"→{pkt['inner_dst_port']}" if pkt['inner_dst_port'] else ""
                    print(f"  {i+1}. {status} | {vxlan_info} {inner_port}")

def main():
    if len(sys.argv) > 1:
        interface = sys.argv[1]
    else:
        interface = "ens5"
    
    # Configuration from your .env file
    analyzer = VXLANPacketAnalyzer(
        interface=interface,
        config_source_port=31765,  # SOURCE_PORT from .env
        config_target_ip="172.30.82.95",  # NAT_IP from .env  
        config_target_port=8081    # NAT_PORT from .env
    )
    
    analyzer.run()

if __name__ == "__main__":
    main()