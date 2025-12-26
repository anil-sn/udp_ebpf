#!/usr/bin/env python3

from scapy.all import *
import sys

def send_udp_with_correct_mac():
    """
    Send UDP packet using the CORRECT destination MAC from ARP
    Key fix: Use direct MAC (0a:5f:38:11:aa:af) instead of gateway MAC
    """
    
    print("=== UDP Test with Correct MAC Address ===")
    print("Using MAC from ARP response: 0a:5f:38:11:aa:af")
    
    # Ethernet layer - USE DIRECT MAC, NOT GATEWAY MAC
    eth = Ether(
        dst="0a:5f:38:11:aa:af",   # CORRECT: Direct MAC from ARP response
        src="0a:77:55:c2:07:b3"    # ens5 MAC address
    )
    
    # IP layer
    ip = IP(
        src="172.30.82.13",        # Source IP
        dst="172.30.82.95",        # Destination IP  
        id=0xd729,                 # IP ID from Wireshark
        flags="DF",                # Don't Fragment
        ttl=64                     # TTL
    )
    
    # UDP layer
    udp = UDP(
        sport=19458,               # Source port
        dport=8081                 # Target port (confirmed open)
    )
    
    # Payload - smaller for initial test
    payload = Raw(b'DIRECT_MAC_TEST_' + b'A' * 100)
    
    # Build complete packet
    packet = eth / ip / udp / payload
    
    print(f"Built packet with DIRECT MAC:")
    print(f"  Ethernet: {eth.src} -> {eth.dst}")
    print(f"  IP: {ip.src} -> {ip.dst}")
    print(f"  UDP: {udp.sport} -> {udp.dport}")
    print(f"  Payload: {len(payload)} bytes")
    print(f"  Total: {len(packet)} bytes")
    
    # Show packet summary
    packet.show2()
    
    print(f"\n🚀 Sending UDP with correct MAC...")
    
    try:
        # Send packet on Layer 2
        sendp(packet, iface="ens5", verbose=1)
        print(f"✅ UDP packet sent with direct MAC!")
        print(f"Check tcpdump on 172.30.82.95...")
        return True
        
    except Exception as e:
        print(f"❌ Error sending UDP: {e}")
        return False

def send_continuous_udp():
    """Send multiple UDP packets for better detection"""
    
    print(f"\n=== Continuous UDP Test ===")
    
    # Same packet as above but in a loop
    eth = Ether(dst="0a:5f:38:11:aa:af", src="0a:77:55:c2:07:b3")
    ip = IP(src="172.30.82.13", dst="172.30.82.95", ttl=64)
    udp = UDP(sport=19458, dport=8081)
    payload = Raw(b'CONTINUOUS_TEST')
    
    packet = eth / ip / udp / payload
    
    print(f"Sending 10 UDP packets with direct MAC...")
    
    try:
        for i in range(10):
            sendp(packet, iface="ens5", verbose=0)
            print(f"📤 Sent packet {i+1}/10")
            time.sleep(0.5)
            
        print(f"✅ Sent 10 UDP packets!")
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

if __name__ == "__main__":
    print("=== UDP Test with Correct MAC Address ===")
    print("Key Fix: Using direct MAC (0a:5f:38:11:aa:af) instead of gateway MAC")
    print()
    
    # Check if running as root
    if os.geteuid() != 0:
        print("❌ This script requires root privileges")
        sys.exit(1)
    
    # Test single packet first
    success1 = send_udp_with_correct_mac()
    
    if success1:
        print(f"\n" + "="*40)
        input("Press Enter to send continuous packets (or Ctrl+C to stop)...")
        success2 = send_continuous_udp()
    
    print(f"\n📋 Next: Monitor with 'sudo tcpdump -i ens5 host 172.30.82.13 and port 8081'")