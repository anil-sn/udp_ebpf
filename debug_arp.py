#!/usr/bin/env python3

from scapy.all import *
import sys
import time

def test_arp_basic():
    """Test basic ARP functionality step by step"""
    
    print("=== Step 1: Basic ARP Request ===")
    print("Sending ARP: Who has 172.30.82.95? Tell 172.30.82.13")
    
    # Create ARP request
    arp_request = ARP(
        op=1,                    # ARP request (1 = request, 2 = reply)
        psrc="172.30.82.13",     # Source IP (sender)
        pdst="172.30.82.95",     # Target IP (who we're looking for)
        hwsrc="0a:77:55:c2:07:b3",  # Source MAC (ens5)
        hwdst="00:00:00:00:00:00"   # Target MAC (unknown, asking for this)
    )
    
    # Wrap in Ethernet frame
    eth_frame = Ether(
        src="0a:77:55:c2:07:b3",    # Source MAC (ens5)
        dst="ff:ff:ff:ff:ff:ff"     # Broadcast destination
    )
    
    packet = eth_frame / arp_request
    
    print(f"\nPacket details:")
    packet.show2()
    
    print(f"\n🚀 Sending ARP request...")
    
    try:
        # Send and wait for response (srp = send/receive at layer 2)
        answered, unanswered = srp(packet, iface="ens5", timeout=3, verbose=1)
        
        if answered:
            print(f"✅ Got {len(answered)} ARP response(s)!")
            for sent, received in answered:
                print(f"Response from {received[ARP].psrc} at MAC {received[ARP].hwsrc}")
                return True
        else:
            print(f"❌ No ARP responses received")
            return False
            
    except Exception as e:
        print(f"❌ ARP request failed: {e}")
        return False

def test_arp_simple():
    """Simple one-liner ARP test"""
    print("\n=== Step 2: Simple ARP Test ===")
    
    try:
        # Use Scapy's built-in ARP function
        result = arping("172.30.82.95", iface="ens5", timeout=3, verbose=1)
        if result:
            print("✅ arping() worked!")
            return True
        else:
            print("❌ arping() failed")
            return False
    except Exception as e:
        print(f"❌ Simple ARP failed: {e}")
        return False

def check_arp_table():
    """Check current ARP table"""
    print("\n=== Step 3: Check ARP Table ===")
    import subprocess
    
    try:
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
        print("Current ARP table:")
        print(result.stdout)
        
        # Look specifically for our target
        if "172.30.82.95" in result.stdout:
            print("✅ 172.30.82.95 is already in ARP table")
            return True
        else:
            print("❌ 172.30.82.95 not in ARP table")
            return False
            
    except Exception as e:
        print(f"❌ ARP table check failed: {e}")
        return False

if __name__ == "__main__":
    print("=== Basic Network Debugging: ARP Test ===")
    print("Testing Layer 2 communication between AWS instances")
    print("Source: 172.30.82.13 (ens5: 0a:77:55:c2:07:b3)")
    print("Target: 172.30.82.95")
    print()
    
    # Check if running as root
    if os.geteuid() != 0:
        print("❌ This script requires root privileges")
        print("Run with: sudo python3 test_arp.py")
        sys.exit(1)
    
    # Run tests step by step
    results = []
    
    results.append(("ARP Table Check", check_arp_table()))
    results.append(("Basic ARP Request", test_arp_basic()))
    results.append(("Simple ARP Test", test_arp_simple()))
    
    print(f"\n" + "="*50)
    print("RESULTS SUMMARY:")
    for test_name, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"  {test_name}: {status}")
    
    if any(result[1] for result in results):
        print(f"\n🎉 At least one ARP test worked - Layer 2 communication possible!")
    else:
        print(f"\n❌ All ARP tests failed - AWS may be blocking Layer 2 raw packets")
        print(f"Next: Try Layer 3 tests (ping, traceroute)")