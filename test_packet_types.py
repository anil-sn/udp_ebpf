#!/usr/bin/env python3

from scapy.all import *
import sys

def test_packet_types():
    """Test different packet types to see what gets through AWS filtering"""
    
    # Standard Layer 3 approach (bypass Layer 2)
    print("=== Testing Layer 3 (IP only) ===")
    ip_packet = IP(src="172.30.82.13", dst="172.30.82.95") / UDP(sport=19458, dport=8081) / Raw(b'L3_TEST' * 100)
    
    try:
        send(ip_packet, iface="ens5", verbose=1)
        print("✅ Layer 3 packet sent")
    except Exception as e:
        print(f"❌ Layer 3 failed: {e}")
    
    print("\n=== Testing ICMP (often allowed) ===")
    icmp_packet = IP(src="172.30.82.13", dst="172.30.82.95") / ICMP(type=8, code=0) / Raw(b'ICMP_TEST')
    
    try:
        send(icmp_packet, iface="ens5", verbose=1)
        print("✅ ICMP packet sent")
    except Exception as e:
        print(f"❌ ICMP failed: {e}")
    
    print("\n=== Testing TCP SYN ===")
    tcp_packet = IP(src="172.30.82.13", dst="172.30.82.95") / TCP(sport=19458, dport=8081, flags="S")
    
    try:
        send(tcp_packet, iface="ens5", verbose=1)  
        print("✅ TCP SYN sent")
    except Exception as e:
        print(f"❌ TCP failed: {e}")

if __name__ == "__main__":
    print("Testing different packet types through AWS...")
    test_packet_types()
    print("\nMonitor with: sudo tcpdump -i ens5 host 172.30.82.13")