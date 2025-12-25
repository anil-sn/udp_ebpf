#!/usr/bin/env python3
"""
Debug packet analysis tool to understand why the VXLAN packet is not being processed
"""

def analyze_hex_packet():
    # Raw packet data from the user's hex dump
    hex_data = """
0a63 c28f 07ed 0ae5 1661 b06d 0800 4500
02de 0000 0000 fe11 bbc6 ac1e 53c0 ac1e
524b ffee 12b5 02ca 0000 0800 0000 0000
0100 0a2c e332 fbb9 0a20 5587 cbdd 0800
4500 02ac 0dea 4000 4011 34ed ac1e 529d
ac1e 4a90 4c18 7c15 0298 4bce 000a 0290
    """
    
    # Remove spaces and newlines, convert to bytes
    hex_clean = ''.join(hex_data.split())
    packet_bytes = bytes.fromhex(hex_clean)
    
    print("=== PACKET ANALYSIS ===\n")
    print(f"Total packet length: {len(packet_bytes)} bytes")
    
    offset = 0
    
    # Parse outer Ethernet header (14 bytes)
    print("OUTER ETHERNET HEADER:")
    eth_dst = packet_bytes[0:6]
    eth_src = packet_bytes[6:12] 
    eth_type = int.from_bytes(packet_bytes[12:14], 'big')
    print(f"  Destination MAC: {':'.join(['%02x' % b for b in eth_dst])}")
    print(f"  Source MAC: {':'.join(['%02x' % b for b in eth_src])}")
    print(f"  EtherType: 0x{eth_type:04x} ({'IPv4' if eth_type == 0x0800 else 'Unknown'})")
    offset += 14
    
    if eth_type != 0x0800:
        print("ERROR: Not an IPv4 packet!")
        return
    
    # Parse outer IP header (20+ bytes)
    print("\nOUTER IP HEADER:")
    ip_version_ihl = packet_bytes[offset]
    ip_version = (ip_version_ihl >> 4) & 0x0F
    ip_ihl = ip_version_ihl & 0x0F
    ip_header_len = ip_ihl * 4
    
    if ip_version != 4:
        print(f"ERROR: IP version {ip_version} is not IPv4!")
        return
        
    ip_tos = packet_bytes[offset + 1]
    ip_total_len = int.from_bytes(packet_bytes[offset + 2:offset + 4], 'big')
    ip_id = int.from_bytes(packet_bytes[offset + 4:offset + 6], 'big') 
    ip_flags_frag = int.from_bytes(packet_bytes[offset + 6:offset + 8], 'big')
    ip_ttl = packet_bytes[offset + 8]
    ip_proto = packet_bytes[offset + 9]
    ip_checksum = int.from_bytes(packet_bytes[offset + 10:offset + 12], 'big')
    ip_src = packet_bytes[offset + 12:offset + 16]
    ip_dst = packet_bytes[offset + 16:offset + 20]
    
    print(f"  Version: {ip_version}, IHL: {ip_ihl} ({ip_header_len} bytes)")
    print(f"  ToS: 0x{ip_tos:02x}")
    print(f"  Total Length: {ip_total_len}")
    print(f"  ID: {ip_id}")
    print(f"  Flags/Frag: 0x{ip_flags_frag:04x}")
    print(f"  TTL: {ip_ttl}")
    print(f"  Protocol: {ip_proto} ({'UDP' if ip_proto == 17 else 'Other'})")
    print(f"  Checksum: 0x{ip_checksum:04x}")
    print(f"  Source IP: {'.'.join([str(b) for b in ip_src])}")
    print(f"  Dest IP: {'.'.join([str(b) for b in ip_dst])}")
    
    if ip_proto != 17:
        print("ERROR: Not a UDP packet!")
        return
        
    offset += ip_header_len
    
    # Parse outer UDP header (8 bytes)
    print("\nOUTER UDP HEADER:")
    udp_src_port = int.from_bytes(packet_bytes[offset:offset + 2], 'big')
    udp_dst_port = int.from_bytes(packet_bytes[offset + 2:offset + 4], 'big') 
    udp_len = int.from_bytes(packet_bytes[offset + 4:offset + 6], 'big')
    udp_checksum = int.from_bytes(packet_bytes[offset + 6:offset + 8], 'big')
    
    print(f"  Source Port: {udp_src_port}")
    print(f"  Dest Port: {udp_dst_port} ({'VXLAN' if udp_dst_port == 4789 else 'Not VXLAN'})")
    print(f"  Length: {udp_len}")
    print(f"  Checksum: 0x{udp_checksum:04x}")
    
    if udp_dst_port != 4789:
        print("ERROR: Destination port is not VXLAN (4789)!")
        return
        
    offset += 8
    
    # Parse VXLAN header (8 bytes)
    print("\nVXLAN HEADER:")
    vxlan_flags = packet_bytes[offset]
    vxlan_reserved1 = packet_bytes[offset + 1:offset + 4]
    vxlan_vni = packet_bytes[offset + 4:offset + 7]  # 3 bytes
    vxlan_reserved2 = packet_bytes[offset + 7]
    
    print(f"  Flags: 0x{vxlan_flags:02x} (VNI flag set: {bool(vxlan_flags & 0x08)})")
    print(f"  Reserved1: {' '.join(['%02x' % b for b in vxlan_reserved1])}")
    vni_value = int.from_bytes(vxlan_vni, 'big')
    print(f"  VNI: {vni_value} (bytes: {' '.join(['%02x' % b for b in vxlan_vni])})")
    print(f"  Reserved2: 0x{vxlan_reserved2:02x}")
    
    # Check VXLAN validation conditions
    print("\n=== VXLAN VALIDATION CHECKS ===")
    print(f"1. VNI flag set (0x08): {vxlan_flags & 0x08 != 0} (actual: 0x{vxlan_flags:02x})")
    print(f"2. VNI == 1: {vni_value == 1} (actual: {vni_value})")
    
    # Expected values from config
    expected_vni = 1
    expected_vni_flag = 0x08
    
    if (vxlan_flags & expected_vni_flag) == 0:
        print("❌ ISSUE: VNI flag is not set!")
    else:
        print("✅ VNI flag is correctly set")
        
    if vni_value != expected_vni:
        print(f"❌ ISSUE: VNI is {vni_value}, expected {expected_vni}")
    else:
        print("✅ VNI is correct")
    
    offset += 8
    
    # Parse inner Ethernet header
    print("\nINNER ETHERNET HEADER:")
    if offset + 14 <= len(packet_bytes):
        inner_eth_dst = packet_bytes[offset:offset + 6]
        inner_eth_src = packet_bytes[offset + 6:offset + 12]
        inner_eth_type = int.from_bytes(packet_bytes[offset + 12:offset + 14], 'big')
        print(f"  Destination MAC: {':'.join(['%02x' % b for b in inner_eth_dst])}")
        print(f"  Source MAC: {':'.join(['%02x' % b for b in inner_eth_src])}")
        print(f"  EtherType: 0x{inner_eth_type:04x} ({'IPv4' if inner_eth_type == 0x0800 else 'Unknown'})")
        offset += 14
        
        # Parse inner IP header
        if inner_eth_type == 0x0800 and offset + 20 <= len(packet_bytes):
            print("\nINNER IP HEADER:")
            inner_ip_version_ihl = packet_bytes[offset]
            inner_ip_version = (inner_ip_version_ihl >> 4) & 0x0F
            inner_ip_ihl = inner_ip_version_ihl & 0x0F
            inner_ip_header_len = inner_ip_ihl * 4
            
            inner_ip_proto = packet_bytes[offset + 9]
            inner_ip_src = packet_bytes[offset + 12:offset + 16]
            inner_ip_dst = packet_bytes[offset + 16:offset + 20]
            
            print(f"  Version: {inner_ip_version}, IHL: {inner_ip_ihl}")
            print(f"  Protocol: {inner_ip_proto} ({'UDP' if inner_ip_proto == 17 else 'Other'})")
            print(f"  Source IP: {'.'.join([str(b) for b in inner_ip_src])}")
            print(f"  Dest IP: {'.'.join([str(b) for b in inner_ip_dst])}")
            
            if inner_ip_proto == 17:
                offset += inner_ip_header_len
                if offset + 8 <= len(packet_bytes):
                    print("\nINNER UDP HEADER:")
                    inner_udp_src = int.from_bytes(packet_bytes[offset:offset + 2], 'big')
                    inner_udp_dst = int.from_bytes(packet_bytes[offset + 2:offset + 4], 'big')
                    print(f"  Source Port: {inner_udp_src}")
                    print(f"  Dest Port: {inner_udp_dst}")
                    
                    # Check NAT conditions
                    print("\n=== NAT CONDITIONS ===")
                    expected_src_port = 31765  # From config
                    print(f"Expected NAT source port: {expected_src_port}")
                    print(f"Actual destination port: {inner_udp_dst}")
                    print(f"NAT match: {inner_udp_dst == expected_src_port}")

if __name__ == "__main__":
    analyze_hex_packet()