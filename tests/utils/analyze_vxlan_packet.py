#!/usr/bin/env python3
"""
Simple VXLAN packet analyzer to debug packet structure
"""

import socket
from scapy.all import *
from scapy.layers.vxlan import VXLAN

def create_test_packet():
    """Create a test VXLAN packet matching our traffic injector"""
    # Inner packet with Ethernet frame  
    inner_eth = Ether(dst="aa:bb:cc:dd:ee:11", src="aa:bb:cc:dd:ee:22")
    inner_ip = IP(src="192.168.1.100", dst="192.168.1.200")
    inner_udp = UDP(sport=42844, dport=8081)  # NAT rule ports
    inner_payload = Raw(b"VXLAN test payload " + b"A" * 100)
    inner_packet = inner_eth / inner_ip / inner_udp / inner_payload
    
    # VXLAN header
    vxlan = VXLAN(vni=1, flags=0x08)
    
    # Complete VXLAN payload
    vxlan_payload = vxlan / inner_packet
    
    return vxlan_payload

def analyze_packet(packet):
    """Analyze packet structure"""
    print("🔍 Packet Analysis:")
    print("==================")
    
    if VXLAN in packet:
        vxlan_layer = packet[VXLAN]
        print(f"✅ VXLAN Header Found:")
        print(f"   VNI: {vxlan_layer.vni}")
        print(f"   Flags: {vxlan_layer.flags} (raw: {int(vxlan_layer.flags)})")
        
        # Check inner packet
        if Ether in vxlan_layer.payload:
            inner_eth = vxlan_layer.payload[Ether]
            print(f"✅ Inner Ethernet:")
            print(f"   Src: {inner_eth.src}")  
            print(f"   Dst: {inner_eth.dst}")
            
            if IP in inner_eth.payload:
                inner_ip = inner_eth.payload[IP]
                print(f"✅ Inner IP:")
                print(f"   Src: {inner_ip.src}")
                print(f"   Dst: {inner_ip.dst}")
                print(f"   Protocol: {inner_ip.proto}")
                
                if UDP in inner_ip.payload:
                    inner_udp = inner_ip.payload[UDP]
                    print(f"✅ Inner UDP:")
                    print(f"   Sport: {inner_udp.sport} (should be 42844)")
                    print(f"   Dport: {inner_udp.dport} (should be 8081)")
                    
                    if inner_udp.sport == 42844:
                        print(f"🎯 NAT Rule Match: ✅ Port 42844 found!")
                    else:
                        print(f"❌ NAT Rule Mismatch: Expected 42844, got {inner_udp.sport}")
                else:
                    print("❌ No inner UDP found")
            else:
                print("❌ No inner IP found")
        else:
            print("❌ No inner Ethernet found")
    else:
        print("❌ No VXLAN header found")
    
    print(f"\n📏 Total packet size: {len(bytes(packet))} bytes")
    print("🔢 Raw packet (first 64 bytes):")
    raw_bytes = bytes(packet)
    print(" ".join(f"{b:02x}" for b in raw_bytes[:64]))

if __name__ == "__main__":
    print("🧪 VXLAN Packet Structure Test")
    print("==============================")
    
    packet = create_test_packet()
    analyze_packet(packet)
    
    print("\n💾 This matches what our traffic injector sends to XDP")