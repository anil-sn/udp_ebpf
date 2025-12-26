#!/usr/bin/env python3

from scapy.all import *
import sys

def send_exact_packet_scapy():
    """
    Send the exact packet using Scapy for Layer 2 transmission
    Based on Wireshark analysis, targeting 172.30.82.95:8081
    """
    
    # Ethernet layer - AWS gateway routing
    eth = Ether(
        dst="0a:2c:e3:32:fb:b9",  # Gateway MAC from ARP table
        src="0a:77:55:c2:07:b3"   # ens5 MAC address
    )
    
    # IP layer
    ip = IP(
        src="172.30.82.13",       # Source IP
        dst="172.30.82.95",       # Destination IP  
        id=0xd729,                # IP ID from Wireshark
        flags="DF",               # Don't Fragment
        ttl=64                    # TTL
    )
    
    # UDP layer
    udp = UDP(
        sport=19458,              # Source port from Wireshark
        dport=8081                # Target port (confirmed open)
    )
    
    # Payload - 1333 bytes to match Wireshark
    payload = Raw(b'\x00' * 1333)
    
    # Build complete packet
    packet = eth / ip / udp / payload
    
    print(f"Built Scapy packet:")
    print(f"  Ethernet: {eth.dst} <- {eth.src}")
    print(f"  IP: {ip.src} -> {ip.dst} (ID: {hex(ip.id)})")
    print(f"  UDP: {udp.sport} -> {udp.dport}")
    print(f"  Payload: {len(payload)} bytes")
    print(f"  Total packet size: {len(packet)} bytes")
    
    # Show packet summary
    packet.show2()
    
    print(f"\n🚀 Sending packet via ens5...")
    
    # Send packet on Layer 2 via specific interface
    try:
        sendp(packet, iface="ens5", verbose=1)
        print(f"✅ Packet sent successfully!")
        print(f"Check tcpdump on 172.30.82.95 for incoming packet...")
        
    except Exception as e:
        print(f"❌ Error sending packet: {e}")
        return False
        
    return True

if __name__ == "__main__":
    print("=== Scapy Layer 2 Packet Sender ===")
    print("Targeting: 172.30.82.13:19458 -> 172.30.82.95:8081")
    print("Interface: ens5 (via gateway MAC)")
    print()
    
    # Check if running as root
    if os.geteuid() != 0:
        print("❌ This script requires root privileges for raw socket access")
        print("Run with: sudo python3 send_scapy_packet.py")
        sys.exit(1)
    
    # Send the packet
    success = send_exact_packet_scapy()
    
    if success:
        print("\n📋 Next steps:")
        print("1. Check tcpdump output on 172.30.82.95")
        print("2. Verify packet reception with: sudo tcpdump -i ens5 -envv host 172.30.82.13 and port 8081")
    else:
        print("\n🔧 Troubleshooting needed - check network interface and permissions")