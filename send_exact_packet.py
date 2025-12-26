#!/usr/bin/env python3
"""
Test packet generator for network debugging
Sends UDP packets from 172.30.82.13 to 172.30.82.95:1035
"""

import socket
import struct
import sys
import os

try:
    from scapy.all import *
except ImportError:
    print("❌ Scapy not installed. Install with: pip install scapy")
    sys.exit(1)

def create_test_packet():
    """Create a test UDP packet with specific characteristics"""
    
    # Network configuration
    src_ip = "172.30.82.13"
    dst_ip = "172.30.82.95"
    src_port = 19458
    dst_port = 1035
    
    # Create payload (1333 bytes as seen in tcpdump)
    payload_size = 1333
    payload = b'A' * payload_size
    
    # Build packet layers
    eth = Ether(dst="0a:5f:38:11:aa:af", src="0a:fe:93:86:93:53")
    ip = IP(src=src_ip, dst=dst_ip, flags="DF")  # Don't Fragment flag
    udp = UDP(sport=src_port, dport=dst_port)
    
    # Combine layers
    packet = eth / ip / udp / payload
    
    return packet

def send_via_raw_socket():
    """Send packet using raw socket (requires root)"""
    
    try:
        # Verify interface exists
        interface = "ens6"
        if not os.path.exists(f"/sys/class/net/{interface}"):
            print(f"❌ Interface {interface} not found. Available interfaces:")
            for iface in os.listdir("/sys/class/net/"):
                print(f"   - {iface}")
            return False
            
        # Create raw socket 
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        sock.bind((interface, 0))  # Bind to interface
        
        # Create packet
        packet = create_test_packet()
        
        # Display packet info
        print(f"Built packet: {len(packet)} bytes")
        print(f"Should be {14+20+8+1333} bytes: {'✅' if len(packet) == 1375 else '❌'}")
        
        # Show packet details
        print(f"Ethernet ({len(packet[Ether])}): {packet[Ether].dst.replace(':', '')}{packet[Ether].src.replace(':', '')}{packet[Ether].type:04x}")
        print(f"IP header ({len(packet[IP])}): {bytes(packet[IP])[:20].hex()}")
        print(f"UDP header ({len(packet[UDP])}): {bytes(packet[UDP])[:8].hex()}")
        payload_len = len(packet.getlayer(Raw)) if packet.haslayer(Raw) else len(payload)
        print(f"Payload ({payload_len}): {payload_len} bytes")
        
        # Packet verification
        print(f"\nPacket verification:")
        print(f"Dest MAC: {packet[Ether].dst.replace(':', '').lower()} (should be 0a5f3811aaaf)")
        print(f"Src MAC: {packet[Ether].src.replace(':', '').lower()} (should be 0afe93869353)")
        print(f"EtherType: {packet[Ether].type:04x} (should be 0800)")
        print(f"IP Total Length: {packet[IP].len} (should be {20+8+1333})")
        print(f"UDP Src Port: {packet[UDP].sport} (should be 19458)")
        print(f"UDP Dst Port: {packet[UDP].dport} (should be 1035)")
        
        # Send packet
        sock.send(bytes(packet))
        
        print(f"\n✅ Sent {len(packet)} bytes via ens6!")
        print(f"Packet details:")
        print(f"  {packet[IP].src}:{packet[UDP].sport} -> {packet[IP].dst}:{packet[UDP].dport}")
        print(f"  UDP payload: {len(packet[Raw])} bytes")
        print(f"  Total frame: {len(packet)} bytes")
        
        sock.close()
        return True
        
    except PermissionError:
        print("❌ Permission denied. Run with sudo for raw socket access.")
        return False
    except Exception as e:
        print(f"❌ Error sending packet: {e}")
        return False

def send_via_normal_socket():
    """Send packet using normal UDP socket (fallback)"""
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Bind to specific source IP if possible
        try:
            sock.bind(("172.30.82.13", 19458))
        except:
            sock.bind(("0.0.0.0", 0))  # Let system choose
            
        payload = b'A' * 1333
        sock.sendto(payload, ("172.30.82.95", 1035))
        
        local_addr = sock.getsockname()
        print(f"✅ Sent {len(payload)} bytes via normal socket")
        print(f"From: {local_addr[0]}:{local_addr[1]} -> 172.30.82.95:1035")
        
        sock.close()
        return True
        
    except Exception as e:
        print(f"❌ Error with normal socket: {e}")
        return False

def main():
    """Main function"""
    
    print("🧪 Network Packet Test Generator")
    print("=" * 50)
    
    # Check if running as root
    if os.geteuid() == 0:
        print("🔧 Running as root - using raw socket for precise control")
        success = send_via_raw_socket()
    else:
        print("ℹ️  Running as user - using normal UDP socket")
        success = send_via_normal_socket()
    
    if success:
        print(f"\n💡 Now check tcpdump on 172.30.82.95...")
        print("   On destination host run:")
        print("   sudo tcpdump -i any -envv host 172.30.82.13 and port 1035")
    else:
        print("\n❌ Packet sending failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()