#!/usr/bin/env python3

from scapy.all import *
import sys

def send_udp_correct_routing():
    """
    Send UDP using correct routing: ens6 + src IP 172.30.82.173
    Based on: ip route get 172.30.82.95 → dev ens6 src 172.30.82.173
    """
    
    print("=== UDP Test with CORRECT Routing ===")
    print("Key Fix: Using ens6 interface + source IP 172.30.82.173")
    print("From routing table: 172.30.82.95 dev ens6 src 172.30.82.173")
    
    # First, get the MAC address of ens6
    import subprocess
    try:
        result = subprocess.run(['cat', '/sys/class/net/ens6/address'], capture_output=True, text=True)
        ens6_mac = result.stdout.strip()
        print(f"ens6 MAC: {ens6_mac}")
    except:
        ens6_mac = "02:00:00:00:00:00"  # fallback
        print(f"Using fallback MAC: {ens6_mac}")
    
    # Ethernet layer - correct destination MAC from ARP
    eth = Ether(
        dst="0a:5f:38:11:aa:af",   # Target MAC from ARP (same as before)
        src=ens6_mac               # ens6 MAC address (not ens5!)
    )
    
    # IP layer - CORRECT SOURCE IP from routing table
    ip = IP(
        src="172.30.82.173",       # CORRECT: Source IP from routing table
        dst="172.30.82.95",        # Destination IP  
        ttl=64                     # TTL
    )
    
    # UDP layer
    udp = UDP(
        sport=19458,               # Source port
        dport=8081                 # Target port
    )
    
    # Payload
    payload = Raw(b'CORRECT_ROUTING_TEST_' + b'B' * 50)
    
    # Build complete packet
    packet = eth / ip / udp / payload
    
    print(f"\nBuilt packet with CORRECT routing:")
    print(f"  Interface: ens6 (from routing table)")
    print(f"  Ethernet: {ens6_mac} -> 0a:5f:38:11:aa:af")
    print(f"  IP: 172.30.82.173 -> 172.30.82.95 (from routing table)")
    print(f"  UDP: {udp.sport} -> {udp.dport}")
    print(f"  Total: {len(packet)} bytes")
    
    packet.show2()
    
    print(f"\n🚀 Sending UDP via ens6...")
    
    try:
        # Send via CORRECT interface (ens6)
        sendp(packet, iface="ens6", verbose=1)
        print(f"✅ UDP sent via ens6 with correct routing!")
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def compare_routing():
    """Show the difference between what we were doing vs correct routing"""
    
    print(f"\n=== Routing Comparison ===")
    print(f"❌ What we were doing:")
    print(f"   Interface: ens5")
    print(f"   Source IP: 172.30.82.13")
    print(f"   → Wrong interface, wrong source IP!")
    
    print(f"\n✅ Correct routing (from 'ip route get'):")
    print(f"   Interface: ens6") 
    print(f"   Source IP: 172.30.82.173")
    print(f"   → Matches kernel routing decision")

if __name__ == "__main__":
    print("=== UDP Test with Correct Routing ===")
    
    compare_routing()
    
    if os.geteuid() != 0:
        print("\n❌ Requires root privileges")
        sys.exit(1)
    
    print(f"\n" + "="*50)
    success = send_udp_correct_routing()
    
    if success:
        print(f"\n📋 Monitor on 172.30.82.95:")
        print(f"sudo tcpdump -i ens5 host 172.30.82.173 and port 8081")
        print(f"                    ^^^^^^^^^^^^^^")
        print(f"Note: Source IP changed to 172.30.82.173!")
    
    print(f"\n🔍 This should work because:")
    print(f"1. ✅ ARP proved Layer 2 communication works")
    print(f"2. ✅ Using correct interface (ens6) from routing table") 
    print(f"3. ✅ Using correct source IP (172.30.82.173) from routing table")