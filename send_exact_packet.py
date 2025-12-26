#!/usr/bin/env python3
"""
Send exact packet based on Wireshark analysis
Frame 1: 1375 bytes - UDP packet 4.37.49.193:19458 -> 172.30.82.95:8081
"""
import socket
import struct

def build_exact_packet():
    # Ethernet Header (14 bytes)
    dst_mac = bytes.fromhex('0afe93869353')  # Destination MAC
    src_mac = bytes.fromhex('0a205587cbdd')  # Source MAC  
    ethertype = struct.pack('!H', 0x0800)   # IPv4
    
    # IPv4 Header (20 bytes) 
    version_ihl = 0x45        # Version=4, IHL=5 (20 bytes)
    dscp_ecn = 0x00          # DSCP=CS0, ECN=Not-ECT
    total_length = 1361      # Total Length from Wireshark
    identification = 0xd729   # ID: 55081
    flags_fragment = 0x4000  # Flags=0x2 (Don't fragment), Fragment=0
    ttl = 64                 # Time to Live
    protocol = 17            # UDP
    checksum = 0x0d7f        # Header Checksum from Wireshark
    src_ip = struct.pack('!I', 0x042531c1)  # 4.37.49.193
    dst_ip = struct.pack('!I', 0xac1e525f)  # 172.30.82.95
    
    ip_header = struct.pack('!BBHHHBBH',
        version_ihl, dscp_ecn, total_length, identification,
        flags_fragment, ttl, protocol, checksum
    ) + src_ip + dst_ip
    
    # UDP Header (8 bytes)
    src_port = 19458         # Source Port
    dst_port = 8081          # Destination Port  
    udp_length = 1341        # UDP Length
    udp_checksum = 0x0000    # Checksum (zero-value)
    
    udp_header = struct.pack('!HHHH', src_port, dst_port, udp_length, udp_checksum)
    
    # UDP Payload (1333 bytes) - create dummy payload
    payload = b'\x00' * 1333
    
    # Assemble complete packet
    packet = dst_mac + src_mac + ethertype + ip_header + udp_header + payload
    
    return packet

def send_exact_packet():
    try:
        # Build the exact packet
        packet = build_exact_packet()
        
        print(f"Built packet: {len(packet)} bytes")
        print(f"Should be 1375 bytes: {'✅' if len(packet) == 1375 else '❌'}")
        
        # Show packet structure  
        print(f"Ethernet (14): {packet[:14].hex()}")
        print(f"IP header (20): {packet[14:34].hex()}")
        print(f"UDP header (8): {packet[34:42].hex()}")
        print(f"Payload (1333): {len(packet[42:])} bytes")
        
        # Verify key fields
        print("\nPacket verification:")
        print(f"Dest MAC: {packet[:6].hex()} (should be 0afe93869353)")
        print(f"Src MAC: {packet[6:12].hex()} (should be 0a205587cbdd)")
        print(f"EtherType: {packet[12:14].hex()} (should be 0800)")
        print(f"IP Total Length: {struct.unpack('!H', packet[16:18])[0]} (should be 1361)")
        print(f"UDP Src Port: {struct.unpack('!H', packet[34:36])[0]} (should be 19458)")
        print(f"UDP Dst Port: {struct.unpack('!H', packet[36:38])[0]} (should be 8081)")
        
        # Create raw socket
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
        sock.bind(('ens6', 0))
        
        # Send packet
        bytes_sent = sock.send(packet)
        print(f"\n✅ Sent {bytes_sent} bytes via ens6!")
        print("Packet details:")
        print(f"  4.37.49.193:19458 -> 172.30.82.95:8081")
        print(f"  UDP payload: 1333 bytes")
        print(f"  Total frame: 1375 bytes")
        print("\nNow check tcpdump on 172.30.82.95...")
        
        sock.close()
        
    except Exception as e:
        print(f"❌ Error: {e}")
        print("Run with: sudo python3 send_exact_packet.py")

if __name__ == "__main__":
    send_exact_packet()