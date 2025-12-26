#!/usr/bin/env python3
"""
Test packet generator for VXLAN pipeline debugging
Generates test packets matching the VXLAN pipeline configuration
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

def load_env_config():
    """Load configuration from .env file"""
    config = {
        'NAT_IP': '172.30.82.95',
        'NAT_PORT': '8081', 
        'SOURCE_PORT': '31765',
        'TARGET_INTERFACE': 'ens6',
        'INTERFACE': 'ens5'
    }
    
    try:
        if os.path.exists('.env'):
            print("📁 Loading configuration from .env file...")
            with open('.env', 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        value = value.strip('"\'')  # Remove quotes
                        config[key] = value
        else:
            print("⚠️  No .env file found, using defaults")
    except Exception as e:
        print(f"⚠️  Error reading .env: {e}, using defaults")
    
    return config

def create_vxlan_test_packet():
    """Create a test UDP packet that matches VXLAN pipeline expectations"""
    
    config = load_env_config()
    
    # Network configuration from .env
    src_ip = "172.30.82.13"  # This host's IP on ens5
    dst_ip = config['NAT_IP']
    src_port = 19458  # Random source port
    dst_port = int(config['SOURCE_PORT'])  # The port VXLAN pipeline matches (31765)
    
    print(f"🎯 Creating packet for VXLAN pipeline:")
    print(f"   📥 Packet: {src_ip}:{src_port} → {dst_ip}:{dst_port}")
    print(f"   🔄 Expected NAT: {src_ip}:{src_port} → {dst_ip}:{config['NAT_PORT']}")
    
    # Create payload matching typical inner packet size
    payload_size = 1400  # Typical inner packet size
    payload = b'VXLAN_TEST_PACKET_' + b'A' * (payload_size - 18)
    
    # Build packet layers - use actual MAC addresses from ARP
    eth = Ether(dst="0a:5f:38:11:aa:af", src="0a:fe:93:86:93:53")
    ip = IP(src=src_ip, dst=dst_ip, flags="DF")  # Don't Fragment flag
    udp = UDP(sport=src_port, dport=dst_port)
    
    # Combine layers
    packet = eth / ip / udp / payload
    
    return packet, config

def send_via_raw_socket():
    """Send packet using raw socket (requires root)"""
    
    try:
        # Verify interface exists
        packet, config = create_vxlan_test_packet()
        interface = config['TARGET_INTERFACE']
        if not os.path.exists(f"/sys/class/net/{interface}"):
            print(f"❌ Interface {interface} not found. Available interfaces:")
            for iface in os.listdir("/sys/class/net/"):
                print(f"   - {iface}")
            return False
            
        # Create raw socket 
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        sock.bind((interface, 0))  # Bind to interface
        
        # Create packet
        packet, config = create_vxlan_test_packet()
        
        # Display packet info
        print(f"\n📊 Packet Details:")
        print(f"Built packet: {len(packet)} bytes")
        payload_len = len(packet.getlayer(Raw)) if packet.haslayer(Raw) else 0
        expected_size = 14+20+8+payload_len
        print(f"Expected size: {expected_size} bytes: {'✅' if len(packet) == expected_size else '❌'}")
        
        # Show packet details
        print(f"Ethernet ({14}): {packet[Ether].dst.replace(':', '')}{packet[Ether].src.replace(':', '')}{packet[Ether].type:04x}")
        print(f"IP header ({20}): {bytes(packet[IP])[:20].hex()}")
        print(f"UDP header ({8}): {bytes(packet[UDP])[:8].hex()}")
        print(f"Payload ({payload_len}): {payload_len} bytes")
        
        # Packet verification
        print(f"\n🔍 Packet Verification:")
        print(f"Dest MAC: {packet[Ether].dst.replace(':', '').lower()} (should be 0a5f3811aaaf)")
        print(f"Src MAC: {packet[Ether].src.replace(':', '').lower()} (should be 0afe93869353)")
        print(f"EtherType: {packet[Ether].type:04x} (should be 0800)")
        print(f"IP Total Length: {packet[IP].len}")
        print(f"UDP Src Port: {packet[UDP].sport} (random)")
        print(f"UDP Dst Port: {packet[UDP].dport} (should be {config['SOURCE_PORT']})")
        
        # Send packet
        sock.send(bytes(packet))
        
        print(f"\n✅ Sent {len(packet)} bytes via {interface}!")
        print(f"📤 Packet flow:")
        print(f"   📥 Sent: {packet[IP].src}:{packet[UDP].sport} → {packet[IP].dst}:{packet[UDP].dport}")
        print(f"   🔄 Expected NAT: {packet[IP].src}:{packet[UDP].sport} → {packet[IP].dst}:{config['NAT_PORT']}")
        print(f"   📊 Payload: {payload_len} bytes")
        print(f"   📡 Interface: {interface}")
        
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
        config = load_env_config()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Bind to specific source IP if possible
        src_ip = "172.30.82.13"
        src_port = 19458
        dst_ip = config['NAT_IP']
        dst_port = int(config['SOURCE_PORT'])
        
        try:
            sock.bind((src_ip, src_port))
        except:
            sock.bind(("0.0.0.0", 0))  # Let system choose
            
        payload = b'VXLAN_TEST_PACKET_' + b'A' * 1400
        sock.sendto(payload, (dst_ip, dst_port))
        
        local_addr = sock.getsockname()
        print(f"✅ Sent {len(payload)} bytes via normal socket")
        print(f"📤 From: {local_addr[0]}:{local_addr[1]} → {dst_ip}:{dst_port}")
        print(f"🔄 Expected NAT: {local_addr[0]}:{local_addr[1]} → {dst_ip}:{config['NAT_PORT']}")
        
        sock.close()
        return True
        
    except Exception as e:
        print(f"❌ Error with normal socket: {e}")
        return False

def main():
    """Main function"""
    
    print("🧪 VXLAN Pipeline Packet Test Generator")
    print("=" * 50)
    
    config = load_env_config()
    print(f"🎯 Testing VXLAN pipeline configuration:")
    print(f"   📥 Target: {config['NAT_IP']}:{config['SOURCE_PORT']}")
    print(f"   🔄 Expected NAT: {config['NAT_IP']}:{config['NAT_PORT']}")
    print(f"   📡 Interface: {config['TARGET_INTERFACE']}")
    
    # Check if running as root
    if os.geteuid() == 0:
        print("\n🔧 Running as root - using raw socket for precise control")
        success = send_via_raw_socket()
    else:
        print("\nℹ️  Running as user - using normal UDP socket")
        success = send_via_normal_socket()
    
    if success:
        print(f"\n💡 Now check packet flow...")
        print("   📊 Monitor netfilter: sudo ./debug_packet_flow.sh monitor")
        print(f"   🔍 Check tcpdump on {config['NAT_IP']}:")
        print(f"   sudo tcpdump -i any -envv port {config['SOURCE_PORT']} or port {config['NAT_PORT']}")
    else:
        print("\n❌ Packet sending failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()