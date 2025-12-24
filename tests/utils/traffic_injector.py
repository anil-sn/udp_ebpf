#!/usr/bin/env python3
"""
Multi-threaded VXLAN Traffic Injector
Generates real network traffic to test XDP pipeline with actual statistics
"""

import socket
import threading
import time
import struct
import argparse
import signal
import sys
from concurrent.futures import ThreadPoolExecutor
from scapy.all import *
from scapy.layers.vxlan import VXLAN

class VXLANTrafficInjector:
    def __init__(self, target_ip=None, target_port=4789, 
                 interface=None, threads=8, pps=1000):
        if not target_ip or not interface:
            raise ValueError("target_ip and interface must be specified")
        self.target_ip = target_ip
        self.target_port = target_port 
        self.interface = interface
        self.threads = threads
        self.pps = pps
        self.running = False
        self.stats = {
            'sent': 0,
            'errors': 0,
            'start_time': 0
        }
        self.stats_lock = threading.Lock()

    def create_vxlan_packet(self, src_port=42844, dst_ip="10.2.41.17", dst_port=8081):
        """Create a VXLAN packet that matches our NAT rules"""
        
        # Inner packet (the one that will be processed after VXLAN decap)
        inner_ip = IP(src="192.168.1.100", dst="192.168.1.200")
        inner_udp = UDP(sport=src_port, dport=dst_port)  # This should match NAT rule
        inner_payload = Raw(b"VXLAN test payload " + b"A" * 100)  # Make it substantial
        inner_packet = inner_ip / inner_udp / inner_payload
        
        # VXLAN encapsulation
        vxlan = VXLAN(vni=1, flags=0x08)  # VNI=1, flags=0x08 for valid VXLAN
        
        # Outer packet (VXLAN tunnel) - Use actual MAC addresses
        # Get interface MAC address for proper L2 forwarding
        try:
            import netifaces
            mac_addr = netifaces.ifaddresses(self.interface)[netifaces.AF_LINK][0]['addr']
            outer_eth = Ether(dst=mac_addr, src=mac_addr)
        except:
            # Fallback to broadcast if we can't get MAC
            outer_eth = Ether(dst="ff:ff:ff:ff:ff:ff", src="aa:bb:cc:dd:ee:ff")
            
        outer_ip = IP(src="10.0.0.1", dst=self.target_ip)
        outer_udp = UDP(sport=12345, dport=self.target_port)  # Port 4789 for VXLAN
        
        # Complete VXLAN packet
        packet = outer_eth / outer_ip / outer_udp / vxlan / inner_packet
        
        return packet

    def worker_thread(self, worker_id, duration):
        """Worker thread that sends packets at specified rate"""
        sock = None
        try:
            # Use UDP socket for better VM compatibility
            # This ensures packets actually reach the interface where XDP is attached
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            packets_per_thread = self.pps // self.threads
            interval = 1.0 / packets_per_thread if packets_per_thread > 0 else 1.0
            
            print(f"Worker {worker_id}: Sending {packets_per_thread} PPS to {self.target_ip} via UDP")
            
            sent_count = 0
            start_time = time.time()
            
            while self.running and (time.time() - start_time < duration):
                try:
                    # Create proper VXLAN packet with inner Ethernet frame
                    # Inner packet (the one that will be processed after VXLAN decap)
                    inner_eth = Ether(dst="aa:bb:cc:dd:ee:11", src="aa:bb:cc:dd:ee:22")
                    inner_ip = IP(src="192.168.1.100", dst="192.168.1.200")
                    inner_udp = UDP(sport=42844, dport=8081)  # Matches NAT rule
                    inner_payload = Raw(b"VXLAN test payload " + b"A" * 200)  # Larger payload
                    inner_packet = inner_eth / inner_ip / inner_udp / inner_payload
                    
                    # VXLAN header - ensure proper format
                    vxlan = VXLAN(vni=1, flags=0x08)  # Standard VXLAN flags
                    
                    # Variation for testing different scenarios
                    if sent_count % 10 == 0:
                        # Large packet to test DF bit clearing
                        inner_payload_large = Raw(b"LARGE" + b"X" * 1500)
                        inner_packet = inner_eth / inner_ip / inner_udp / inner_payload_large
                    
                    # Complete VXLAN payload (VXLAN header + Inner Ethernet frame)
                    vxlan_payload = bytes(vxlan / inner_packet)
                    
                    # Ensure minimum packet size for XDP processing
                    if len(vxlan_payload) < 100:
                        vxlan_payload += b'\x00' * (100 - len(vxlan_payload))
                    
                    # Send via UDP socket
                    sock.sendto(vxlan_payload, (self.target_ip, self.target_port))
                    sent_count += 1
                    
                    # Update stats
                    with self.stats_lock:
                        self.stats['sent'] += 1
                    
                    # Rate limiting
                    time.sleep(interval)
                    
                except Exception as e:
                    with self.stats_lock:
                        self.stats['errors'] += 1
                    if "Network is unreachable" not in str(e):
                        print(f"Worker {worker_id} error: {e}")
                        
        except Exception as e:
            print(f"Worker {worker_id} failed to create socket: {e}")
            print(f"Note: Sending to {self.target_ip}:{self.target_port}")
        finally:
            if sock:
                sock.close()
                
        print(f"Worker {worker_id}: Sent {sent_count} packets")

    def stats_monitor(self, duration):
        """Monitor and display traffic statistics"""
        last_sent = 0
        while self.running and time.time() - self.stats['start_time'] < duration:
            time.sleep(2)  # Update every 2 seconds
            
            with self.stats_lock:
                current_sent = self.stats['sent']
                errors = self.stats['errors']
            
            elapsed = time.time() - self.stats['start_time']
            total_pps = current_sent / elapsed if elapsed > 0 else 0
            recent_pps = (current_sent - last_sent) / 2  # Over last 2 seconds
            
            print(f"📊 Traffic: {current_sent:6d} packets | "
                  f"{total_pps:6.0f} avg PPS | {recent_pps:6.0f} recent PPS | "
                  f"{errors:3d} errors")
            
            last_sent = current_sent

    def inject_traffic(self, duration=30):
        """Start multi-threaded traffic injection"""
        print(f"🚀 Starting VXLAN traffic injection (UDP Method)")
        print(f"   Target: {self.target_ip}:{self.target_port}")
        print(f"   Interface: {self.interface}")  
        print(f"   Threads: {self.threads}")
        print(f"   Target PPS: {self.pps}")
        print(f"   Duration: {duration}s")
        print(f"   Method: UDP socket (VM-optimized)")
        print(f"   VXLAN VNI: 1, Inner ports: 42844->8081 (NAT rule)")
        print()
        
        self.running = True
        self.stats['start_time'] = time.time()
        
        # Start worker threads
        with ThreadPoolExecutor(max_workers=self.threads + 1) as executor:
            # Start packet sending threads
            futures = []
            for i in range(self.threads):
                future = executor.submit(self.worker_thread, i, duration)
                futures.append(future)
            
            # Start stats monitoring thread
            stats_future = executor.submit(self.stats_monitor, duration)
            futures.append(stats_future)
            
            # Wait for duration or interruption
            try:
                time.sleep(duration)
            except KeyboardInterrupt:
                print("\n⏹️  Stopping traffic injection...")
            
            self.running = False
            
            # Wait for all threads to complete
            for future in futures:
                try:
                    future.result(timeout=5)
                except Exception as e:
                    print(f"Thread error: {e}")
        
        # Final statistics
        total_time = time.time() - self.stats['start_time']
        print(f"\n📈 Final Stats:")
        print(f"   Total packets: {self.stats['sent']}")
        print(f"   Total time: {total_time:.1f}s")
        print(f"   Average PPS: {self.stats['sent']/total_time:.0f}")
        print(f"   Errors: {self.stats['errors']}")

def main():
    parser = argparse.ArgumentParser(description="Multi-threaded VXLAN traffic injector")
    parser.add_argument("--target-ip", required=True, help="Target IP address")
    parser.add_argument("--target-port", type=int, default=4789, help="Target port")
    parser.add_argument("--interface", required=True, help="Network interface")
    parser.add_argument("--threads", type=int, default=8, help="Number of threads")
    parser.add_argument("--pps", type=int, default=1000, help="Packets per second")
    parser.add_argument("--duration", type=int, default=30, help="Test duration in seconds")
    
    args = parser.parse_args()
    
    # Signal handler for clean shutdown
    def signal_handler(sig, frame):
        print('\n🛑 Received interrupt signal, stopping...')
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Create and run injector
    injector = VXLANTrafficInjector(
        target_ip=args.target_ip,
        target_port=args.target_port,
        interface=args.interface,
        threads=args.threads,
        pps=args.pps
    )
    
    injector.inject_traffic(args.duration)

if __name__ == "__main__":
    main()