#!/usr/bin/env python3
"""
VXLAN Test Packet Generator with Advanced Scapy Construction and Validation
Generates and validates various types of VXLAN packets for testing the XDP pipeline
"""
import sys
import argparse
import os
import json
from datetime import datetime

# Add common pip installation paths for scapy
def add_scapy_paths():
    """Add common scapy installation paths to sys.path"""
    import site
    # Add standard site packages
    sys.path.extend(site.getsitepackages())
    
    # Add user site packages (for --user installs)
    user_site = site.getusersitepackages()
    if user_site and os.path.exists(user_site) and user_site not in sys.path:
        sys.path.insert(0, user_site)
    
    # Add common pip installation locations
    common_paths = [
        '/usr/local/lib/python3.10/dist-packages',
        '/usr/local/lib/python3.11/dist-packages', 
        '/usr/local/lib/python3.9/dist-packages',
        '/usr/lib/python3/dist-packages'
    ]
    
    for path in common_paths:
        if os.path.exists(path) and path not in sys.path:
            sys.path.insert(0, path)

# Try to import scapy with path adjustments
try:
    from scapy.all import *
    from scapy.contrib.vxlan import VXLAN
    from scapy.layers.inet import IP, UDP, TCP, ICMP
    from scapy.layers.l2 import Ether, ARP
    import scapy.utils
except ImportError:
    # Try with additional paths
    add_scapy_paths()
    try:
        from scapy.all import *
        from scapy.contrib.vxlan import VXLAN
        from scapy.layers.inet import IP, UDP, TCP, ICMP
        from scapy.layers.l2 import Ether, ARP
        import scapy.utils
    except ImportError:
        print("ERROR: scapy not installed. Install with: pip3 install scapy")
        sys.exit(1)

class VXLANPacketConstructor:
    """Advanced VXLAN packet construction with validation"""
    
    def __init__(self, config=None):
        self.config = config or {}
        self.validation_errors = []
        
    def create_ethernet_header(self, src_mac="11:22:33:44:55:66", dst_mac="aa:bb:cc:dd:ee:ff"):
        """Create and validate Ethernet header"""
        try:
            eth = Ether(src=src_mac, dst=dst_mac)
            # Validate MAC address format
            if not self._validate_mac(src_mac) or not self._validate_mac(dst_mac):
                self.validation_errors.append(f"Invalid MAC address format: {src_mac} or {dst_mac}")
            return eth
        except Exception as e:
            self.validation_errors.append(f"Ethernet header creation failed: {e}")
            return None
    
    def create_ip_header(self, src_ip, dst_ip, ttl=64, flags=None, frag_offset=0):
        """Create and validate IP header with optional DF bit manipulation"""
        try:
            # Calculate flags value
            ip_flags = 0
            if flags:
                if 'DF' in flags:
                    ip_flags |= 0x4000  # Don't Fragment
                if 'MF' in flags:
                    ip_flags |= 0x2000  # More Fragments
            
            ip = IP(src=src_ip, dst=dst_ip, ttl=ttl, flags=ip_flags >> 13, frag=frag_offset)
            
            # Validate IP addresses
            if not self._validate_ip(src_ip) or not self._validate_ip(dst_ip):
                self.validation_errors.append(f"Invalid IP address: {src_ip} or {dst_ip}")
            
            return ip
        except Exception as e:
            self.validation_errors.append(f"IP header creation failed: {e}")
            return None
    
    def create_udp_header(self, src_port, dst_port, checksum_override=None):
        """Create and validate UDP header"""
        try:
            udp = UDP(sport=src_port, dport=dst_port)
            
            # Override checksum if specified (useful for testing checksum handling)
            if checksum_override is not None:
                udp.chksum = checksum_override
            
            # Validate port ranges
            if not (1 <= src_port <= 65535) or not (1 <= dst_port <= 65535):
                self.validation_errors.append(f"Invalid port range: {src_port}:{dst_port}")
            
            return udp
        except Exception as e:
            self.validation_errors.append(f"UDP header creation failed: {e}")
            return None
    
    def create_vxlan_header(self, vni=1, flags=0x08):
        """Create and validate VXLAN header"""
        try:
            vxlan = VXLAN(vni=vni, flags=flags)
            
            # Validate VXLAN parameters
            if not (0 <= vni <= 16777215):  # 24-bit VNI
                self.validation_errors.append(f"Invalid VNI: {vni} (must be 0-16777215)")
            
            if flags != 0x08:  # Standard VXLAN flags
                self.validation_errors.append(f"Non-standard VXLAN flags: 0x{flags:02x}")
            
            return vxlan
        except Exception as e:
            self.validation_errors.append(f"VXLAN header creation failed: {e}")
            return None
    
    def create_payload(self, size=1000, pattern="random"):
        """Create payload with various patterns for testing"""
        try:
            if pattern == "random":
                payload = Raw(RandString(size))
            elif pattern == "zeros":
                payload = Raw(b'\x00' * size)
            elif pattern == "ones":
                payload = Raw(b'\xff' * size)
            elif pattern == "sequence":
                data = bytes([(i % 256) for i in range(size)])
                payload = Raw(data)
            elif pattern == "text":
                text = f"TEST_PACKET_PAYLOAD_SIZE_{size}_BYTES_" * (size // 30 + 1)
                payload = Raw(text[:size].encode())
            else:
                payload = Raw("A" * size)
            
            return payload
        except Exception as e:
            self.validation_errors.append(f"Payload creation failed: {e}")
            return None
    
    def create_vxlan_packet(self, 
                           # Outer packet parameters
                           outer_src_ip="172.31.1.10", 
                           outer_dst_ip="172.31.1.20",
                           outer_src_mac="aa:aa:aa:aa:aa:aa",
                           outer_dst_mac="ff:ff:ff:ff:ff:ff",
                           outer_src_port=12345,
                           # Inner packet parameters  
                           inner_src_ip="10.2.41.20", 
                           inner_dst_ip="10.2.41.21",
                           inner_src_port=42844, 
                           inner_dst_port=80,
                           inner_src_mac="11:22:33:44:55:66",
                           inner_dst_mac="aa:bb:cc:dd:ee:ff",
                           # VXLAN parameters
                           vni=1, 
                           # Packet parameters
                           payload_size=1000,
                           payload_pattern="random",
                           inner_protocol="udp",
                           df_bit=False):
        """Create a complete VXLAN packet with full validation"""
        
        self.validation_errors.clear()
        
        # Create inner packet based on protocol
        inner_eth = self.create_ethernet_header(inner_src_mac, inner_dst_mac)
        inner_ip_flags = ['DF'] if df_bit else None
        inner_ip = self.create_ip_header(inner_src_ip, inner_dst_ip, flags=inner_ip_flags)
        
        if inner_protocol.lower() == "udp":
            inner_l4 = self.create_udp_header(inner_src_port, inner_dst_port)
        elif inner_protocol.lower() == "tcp":
            inner_l4 = TCP(sport=inner_src_port, dport=inner_dst_port, flags="S")
        elif inner_protocol.lower() == "icmp":
            inner_l4 = ICMP()
        else:
            inner_l4 = self.create_udp_header(inner_src_port, inner_dst_port)
        
        inner_payload = self.create_payload(payload_size, payload_pattern)
        
        # Construct inner packet
        if not all([inner_eth, inner_ip, inner_l4, inner_payload]):
            return None, self.validation_errors
        
        inner_packet = inner_eth / inner_ip / inner_l4 / inner_payload
        
        # Create outer VXLAN packet
        outer_eth = self.create_ethernet_header(outer_src_mac, outer_dst_mac)
        outer_ip = self.create_ip_header(outer_src_ip, outer_dst_ip)
        outer_udp = self.create_udp_header(outer_src_port, 4789)  # VXLAN port
        vxlan = self.create_vxlan_header(vni)
        
        if not all([outer_eth, outer_ip, outer_udp, vxlan]):
            return None, self.validation_errors
        
        # Construct complete VXLAN packet
        complete_packet = outer_eth / outer_ip / outer_udp / vxlan / inner_packet
        
        # Validate the complete packet
        validation_result = self.validate_packet(complete_packet)
        
        return complete_packet, self.validation_errors
    
    def validate_packet(self, packet):
        """Comprehensive packet validation using scapy"""
        validation_results = {
            'valid': True,
            'size': len(packet),
            'layers': [],
            'errors': [],
            'warnings': []
        }
        
        try:
            # Analyze packet layers
            layer = packet
            while layer:
                validation_results['layers'].append(layer.__class__.__name__)
                layer = layer.payload if hasattr(layer, 'payload') else None
            
            # Check packet size constraints
            if validation_results['size'] < 64:
                validation_results['warnings'].append("Packet smaller than minimum Ethernet frame (64 bytes)")
            elif validation_results['size'] > 9000:
                validation_results['warnings'].append("Jumbo frame detected (>9000 bytes)")
            
            # VXLAN-specific validation
            if VXLAN in packet:
                vxlan_layer = packet[VXLAN]
                
                # Check VNI range
                if not (0 <= vxlan_layer.vni <= 16777215):
                    validation_results['errors'].append(f"Invalid VXLAN VNI: {vxlan_layer.vni}")
                
                # Check VXLAN flags
                if vxlan_layer.flags != 0x08:
                    validation_results['warnings'].append(f"Non-standard VXLAN flags: 0x{vxlan_layer.flags:02x}")
                
                # Validate inner packet exists
                if not vxlan_layer.payload:
                    validation_results['errors'].append("VXLAN packet missing inner payload")
            
            # IP layer validation
            if IP in packet:
                ip_layers = [layer for layer in packet.layers() if layer == IP]
                for i, ip in enumerate([packet[IP]] if len(ip_layers) == 1 else [packet.getlayer(IP, i) for i in range(len(ip_layers))]):
                    layer_name = f"IP[{i}]" if len(ip_layers) > 1 else "IP"
                    
                    # Check IP version
                    if ip.version != 4:
                        validation_results['errors'].append(f"{layer_name}: Unsupported IP version {ip.version}")
                    
                    # Check header length
                    if ip.ihl < 5:
                        validation_results['errors'].append(f"{layer_name}: Invalid header length {ip.ihl}")
                    
                    # Check TTL
                    if ip.ttl == 0:
                        validation_results['warnings'].append(f"{layer_name}: TTL is zero")
            
            # UDP layer validation
            if UDP in packet:
                udp_layers = packet.getlayer(UDP)
                if isinstance(udp_layers, list):
                    udp_layers = [udp_layers]
                else:
                    udp_layers = [udp_layers]
                
                for i, udp in enumerate(udp_layers):
                    layer_name = f"UDP[{i}]" if len(udp_layers) > 1 else "UDP"
                    
                    # Check for VXLAN port
                    if udp.dport == 4789:
                        validation_results['layers'].append("VXLAN_PORT")
            
            # Check for truncated packets
            if hasattr(packet, 'original') and len(packet.original) != len(packet):
                validation_results['warnings'].append("Packet appears to be truncated")
            
            # Set overall validity
            validation_results['valid'] = len(validation_results['errors']) == 0
            
        except Exception as e:
            validation_results['valid'] = False
            validation_results['errors'].append(f"Validation exception: {str(e)}")
        
        return validation_results
    
    def _validate_ip(self, ip_str):
        """Validate IP address format"""
        try:
            parts = ip_str.split('.')
            return (len(parts) == 4 and 
                   all(0 <= int(part) <= 255 for part in parts))
        except:
            return False
    
    def _validate_mac(self, mac_str):
        """Validate MAC address format"""
        try:
            parts = mac_str.split(':')
            return (len(parts) == 6 and 
                   all(len(part) == 2 and int(part, 16) <= 255 for part in parts))
        except:
            return False

def create_test_packets(output_dir=".", config=None):
    """Create a comprehensive set of test packets with full validation"""
    
    packets = []
    validation_reports = []
    
    # Default configuration
    if config is None:
        config = {
            'nat_source_port': 42844,
            'nat_target_ip': '10.2.41.17',
            'nat_target_port': 8081,
            'vni': 1
        }
    
    print(f"Generating test packets with config: {config}")
    
    constructor = VXLANPacketConstructor(config)
    
    # Test Case 1: Normal VXLAN packet matching NAT rule
    print("  - Creating normal VXLAN packet (NAT match)")
    pkt1, errors1 = constructor.create_vxlan_packet(
        inner_src_port=config['nat_source_port'], 
        inner_dst_port=80,
        payload_size=800,
        vni=config['vni'],
        payload_pattern="text",
        df_bit=False
    )
    if pkt1:
        validation1 = constructor.validate_packet(pkt1)
        packets.append(("normal_nat_match", pkt1))
        validation_reports.append(("normal_nat_match", validation1, errors1))
    else:
        print(f"    ✗ Failed to create packet: {errors1}")
    
    # Test Case 2: Large packet requiring DF bit clearing (>1400 bytes)
    print("  - Creating large VXLAN packet (DF bit test)")
    pkt2, errors2 = constructor.create_vxlan_packet(
        inner_src_port=config['nat_source_port'],
        inner_dst_port=80, 
        payload_size=2800,  # Large payload to trigger DF bit clearing
        vni=config['vni'],
        payload_pattern="sequence",
        df_bit=True  # Set DF bit to test clearing
    )
    if pkt2:
        validation2 = constructor.validate_packet(pkt2)
        packets.append(("large_packet_df", pkt2))
        validation_reports.append(("large_packet_df", validation2, errors2))
    else:
        print(f"    ✗ Failed to create packet: {errors2}")
    
    # Test Case 3: Different source port (should not match NAT)
    print("  - Creating non-matching source port packet")
    pkt3, errors3 = constructor.create_vxlan_packet(
        inner_src_port=12345,  # Different port, should not match NAT rule
        inner_dst_port=80,
        payload_size=500,
        vni=config['vni'],
        payload_pattern="random"
    )
    if pkt3:
        validation3 = constructor.validate_packet(pkt3)
        packets.append(("no_nat_match", pkt3))
        validation_reports.append(("no_nat_match", validation3, errors3))
    else:
        print(f"    ✗ Failed to create packet: {errors3}")
    
    # Test Case 4: Invalid VNI (should be dropped)
    print("  - Creating invalid VNI packet")
    pkt4, errors4 = constructor.create_vxlan_packet(
        inner_src_port=config['nat_source_port'],
        inner_dst_port=80,
        payload_size=600,
        vni=2,  # Different VNI, should be dropped
        payload_pattern="zeros"
    )
    if pkt4:
        validation4 = constructor.validate_packet(pkt4)
        packets.append(("invalid_vni", pkt4))
        validation_reports.append(("invalid_vni", validation4, errors4))
    else:
        print(f"    ✗ Failed to create packet: {errors4}")
    
    # Test Case 5: Non-VXLAN UDP packet (should pass through)
    print("  - Creating non-VXLAN packet")
    non_vxlan = Ether(dst="aa:bb:cc:dd:ee:ff", src="11:22:33:44:55:66") / \
                IP(src="10.0.0.1", dst="10.0.0.2") / \
                UDP(sport=1234, dport=5678) / \
                Raw("test non-vxlan packet")
    validation5 = constructor.validate_packet(non_vxlan)
    packets.append(("non_vxlan", non_vxlan))
    validation_reports.append(("non_vxlan", validation5, []))
    
    # Test Case 6: VXLAN packet with TCP inner protocol
    print("  - Creating VXLAN packet with TCP inner protocol")
    pkt6, errors6 = constructor.create_vxlan_packet(
        inner_src_port=config['nat_source_port'],
        inner_dst_port=443,
        payload_size=400,
        vni=config['vni'],
        inner_protocol="tcp",
        payload_pattern="text"
    )
    if pkt6:
        validation6 = constructor.validate_packet(pkt6)
        packets.append(("vxlan_tcp", pkt6))
        validation_reports.append(("vxlan_tcp", validation6, errors6))
    else:
        print(f"    ✗ Failed to create packet: {errors6}")
    
    # Test Case 7: VXLAN packet with ICMP inner protocol  
    print("  - Creating VXLAN packet with ICMP inner protocol")
    pkt7, errors7 = constructor.create_vxlan_packet(
        inner_src_port=0,  # ICMP doesn't use ports
        inner_dst_port=0,
        payload_size=100,
        vni=config['vni'],
        inner_protocol="icmp",
        payload_pattern="ones"
    )
    if pkt7:
        validation7 = constructor.validate_packet(pkt7)
        packets.append(("vxlan_icmp", pkt7))
        validation_reports.append(("vxlan_icmp", validation7, errors7))
    else:
        print(f"    ✗ Failed to create packet: {errors7}")
    
    # Test Case 8: Edge case - minimum size packet
    print("  - Creating minimum size VXLAN packet")
    pkt8, errors8 = constructor.create_vxlan_packet(
        inner_src_port=config['nat_source_port'],
        inner_dst_port=80,
        payload_size=1,  # Minimal payload
        vni=config['vni'],
        payload_pattern="zeros"
    )
    if pkt8:
        validation8 = constructor.validate_packet(pkt8)
        packets.append(("minimal_size", pkt8))
        validation_reports.append(("minimal_size", validation8, errors8))
    else:
        print(f"    ✗ Failed to create packet: {errors8}")
    
    # Test Case 9: Malformed VXLAN (wrong port but VXLAN header)
    print("  - Creating malformed VXLAN packet (wrong port)")
    malformed_eth = Ether(dst="ff:ff:ff:ff:ff:ff", src="aa:aa:aa:aa:aa:aa")
    malformed_ip = IP(src="172.31.1.10", dst="172.31.1.20")
    malformed_udp = UDP(sport=12345, dport=1234)  # Not port 4789
    malformed_vxlan = VXLAN(vni=1)
    malformed_inner = Ether() / IP() / UDP() / Raw("test")
    malformed_packet = malformed_eth / malformed_ip / malformed_udp / malformed_vxlan / malformed_inner
    validation9 = constructor.validate_packet(malformed_packet)
    packets.append(("malformed_vxlan_port", malformed_packet))
    validation_reports.append(("malformed_vxlan_port", validation9, []))
    
    # Write combined pcap file
    all_packets = [pkt for _, pkt in packets]
    output_file = os.path.join(output_dir, "test_vxlan.pcap")
    wrpcap(output_file, all_packets)
    print(f"\nGenerated {len(packets)} test packets in {output_file}")
    
    # Create individual packet files for detailed testing
    for i, (name, pkt) in enumerate(packets):
        individual_file = os.path.join(output_dir, f"test_packet_{i+1:02d}_{name}.pcap")
        wrpcap(individual_file, [pkt])
    
    print(f"Individual packet files created in {output_dir}")
    
    # Create detailed packet analysis and validation report
    create_validation_report(output_dir, packets, validation_reports, config)
    
    return len(packets)

def create_validation_report(output_dir, packets, validation_reports, config):
    """Create comprehensive validation report with detailed packet analysis"""
    
    report_file = os.path.join(output_dir, "validation_report.json")
    text_report_file = os.path.join(output_dir, "packet_analysis.txt")
    
    # JSON report for programmatic analysis
    json_report = {
        "generation_time": datetime.now().isoformat(),
        "config": config,
        "total_packets": len(packets),
        "validation_summary": {
            "valid_packets": 0,
            "invalid_packets": 0,
            "warnings": 0
        },
        "packets": []
    }
    
    # Text report for human reading
    with open(text_report_file, 'w') as f:
        f.write("VXLAN Test Packet Validation Report\n")
        f.write("=" * 50 + "\n\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total Packets: {len(packets)}\n")
        f.write(f"Configuration: {json.dumps(config, indent=2)}\n\n")
        
        for i, ((name, pkt), (_, validation, errors)) in enumerate(zip(packets, validation_reports)):
            packet_info = {
                "index": i + 1,
                "name": name,
                "file": f"test_packet_{i+1:02d}_{name}.pcap",
                "size_bytes": len(pkt),
                "layers": validation.get('layers', []),
                "valid": validation.get('valid', False),
                "errors": validation.get('errors', []),
                "warnings": validation.get('warnings', []),
                "construction_errors": errors
            }
            
            # Update summary counts
            if packet_info["valid"]:
                json_report["validation_summary"]["valid_packets"] += 1
            else:
                json_report["validation_summary"]["invalid_packets"] += 1
            
            json_report["validation_summary"]["warnings"] += len(packet_info["warnings"])
            json_report["packets"].append(packet_info)
            
            # Write detailed text analysis
            f.write(f"Packet {i+1:02d}: {name}\n")
            f.write("-" * 30 + "\n")
            f.write(f"  File: test_packet_{i+1:02d}_{name}.pcap\n")
            f.write(f"  Size: {len(pkt)} bytes\n")
            f.write(f"  Valid: {'✓' if packet_info['valid'] else '✗'}\n")
            f.write(f"  Layers: {' → '.join(packet_info['layers'])}\n")
            
            # Detailed packet structure analysis
            if VXLAN in pkt:
                vxlan_layer = pkt[VXLAN]
                outer_ip = pkt[IP] if IP in pkt else None
                outer_udp = pkt[UDP] if UDP in pkt else None
                
                f.write(f"  VXLAN Details:\n")
                f.write(f"    VNI: {vxlan_layer.vni}\n")
                f.write(f"    Flags: 0x{vxlan_layer.flags:02x}\n")
                
                if outer_ip and outer_udp:
                    f.write(f"    Outer: {outer_ip.src}:{outer_udp.sport} → {outer_ip.dst}:{outer_udp.dport}\n")
                
                # Inner packet analysis
                inner_packet = vxlan_layer.payload
                if Ether in inner_packet and IP in inner_packet:
                    inner_ip = inner_packet[IP]
                    inner_l4 = None
                    
                    if UDP in inner_packet:
                        inner_l4 = inner_packet[UDP]
                        protocol = "UDP"
                    elif TCP in inner_packet:
                        inner_l4 = inner_packet[TCP]
                        protocol = "TCP"
                    elif ICMP in inner_packet:
                        inner_l4 = inner_packet[ICMP]
                        protocol = "ICMP"
                    else:
                        protocol = "Unknown"
                    
                    f.write(f"    Inner: {inner_ip.src}")
                    if inner_l4 and hasattr(inner_l4, 'sport'):
                        f.write(f":{inner_l4.sport}")
                    f.write(f" → {inner_ip.dst}")
                    if inner_l4 and hasattr(inner_l4, 'dport'):
                        f.write(f":{inner_l4.dport}")
                    f.write(f" ({protocol})\n")
                    
                    # Check DF bit
                    if hasattr(inner_ip, 'flags') and (inner_ip.flags & 0x2):
                        f.write(f"    DF Bit: Set (may trigger clearing for large packets)\n")
            
            elif IP in pkt:
                ip_layer = pkt[IP]
                if UDP in pkt:
                    udp_layer = pkt[UDP]
                    f.write(f"  Non-VXLAN UDP: {ip_layer.src}:{udp_layer.sport} → {ip_layer.dst}:{udp_layer.dport}\n")
                else:
                    f.write(f"  Non-VXLAN IP: {ip_layer.src} → {ip_layer.dst}\n")
            
            # Expected XDP behavior
            f.write("  Expected XDP Behavior:\n")
            if "nat_match" in name:
                f.write(f"    - NAT applied: Port {config.get('nat_source_port', 'N/A')} → {config.get('nat_target_ip', 'N/A')}:{config.get('nat_target_port', 'N/A')}\n")
                f.write("    - Packet forwarded\n")
            elif "df" in name:
                f.write("    - DF bit cleared (packet >1400 bytes)\n")
                f.write("    - NAT applied\n") 
                f.write("    - Packet forwarded\n")
            elif "no_nat" in name:
                f.write("    - No NAT applied (source port mismatch)\n")
                f.write("    - Packet forwarded as-is\n")
            elif "invalid_vni" in name:
                f.write("    - Packet dropped (invalid VNI)\n")
            elif "non_vxlan" in name or "wrong_port" in name or "malformed" in name:
                f.write("    - Passed through (non-VXLAN or malformed)\n")
            elif "tcp" in name or "icmp" in name:
                f.write("    - Inner protocol processed\n")
                f.write("    - NAT may be applied if port matches\n")
            else:
                f.write("    - Standard VXLAN processing\n")
            
            # Construction and validation errors
            if errors:
                f.write(f"  Construction Errors:\n")
                for error in errors:
                    f.write(f"    ✗ {error}\n")
            
            if validation.get('errors'):
                f.write(f"  Validation Errors:\n")
                for error in validation['errors']:
                    f.write(f"    ✗ {error}\n")
            
            if validation.get('warnings'):
                f.write(f"  Warnings:\n")
                for warning in validation['warnings']:
                    f.write(f"    ⚠ {warning}\n")
            
            f.write("\n")
    
    # Save JSON report
    with open(report_file, 'w') as f:
        json.dump(json_report, f, indent=2)
    
    print(f"Validation report saved:")
    print(f"  - JSON: {report_file}")
    print(f"  - Text: {text_report_file}")
    print(f"  - Valid packets: {json_report['validation_summary']['valid_packets']}/{len(packets)}")
    
    if json_report['validation_summary']['invalid_packets'] > 0:
        print(f"  - Invalid packets: {json_report['validation_summary']['invalid_packets']}")
    
    if json_report['validation_summary']['warnings'] > 0:
        print(f"  - Total warnings: {json_report['validation_summary']['warnings']}")

def create_performance_packets(output_dir=".", count=1000, config=None):
    """Create packets for performance testing with validation"""
    
    if config is None:
        config = {'nat_source_port': 42844, 'vni': 1}
    
    print(f"Generating {count} performance test packets...")
    
    constructor = VXLANPacketConstructor(config)
    packets = []
    validation_errors = 0
    
    # Predefined patterns for realistic testing
    size_patterns = [64, 128, 256, 512, 1000, 1400, 2800]
    payload_patterns = ["random", "zeros", "ones", "sequence", "text"]
    protocols = ["udp", "tcp", "icmp"]
    
    for i in range(count):
        # Vary packet characteristics for realistic traffic
        size = size_patterns[i % len(size_patterns)]
        pattern = payload_patterns[i % len(payload_patterns)]
        protocol = protocols[i % len(protocols)]
        
        # Create varying source IPs for more realistic traffic
        src_ip = f"10.2.41.{20 + (i % 50)}"
        dst_ip = f"10.2.41.{100 + (i % 100)}"
        
        # Vary source ports to test NAT rules
        if i % 3 == 0:
            src_port = config['nat_source_port']  # Will match NAT
        else:
            src_port = 10000 + (i % 50000)  # Won't match NAT
        
        pkt, errors = constructor.create_vxlan_packet(
            inner_src_ip=src_ip,
            inner_dst_ip=dst_ip,
            inner_src_port=src_port,
            inner_dst_port=80 + (i % 1000),  # Vary destination ports
            payload_size=size,
            vni=config['vni'],
            payload_pattern=pattern,
            inner_protocol=protocol,
            df_bit=(size > 1400)  # Set DF bit for large packets
        )
        
        if pkt:
            # Quick validation
            validation = constructor.validate_packet(pkt)
            if not validation['valid']:
                validation_errors += 1
                print(f"  ⚠ Packet {i+1} validation failed: {validation['errors']}")
            
            packets.append(pkt)
        else:
            validation_errors += 1
            print(f"  ✗ Failed to create packet {i+1}: {errors}")
    
    # Write performance test file
    perf_file = os.path.join(output_dir, "performance_test.pcap")
    wrpcap(perf_file, packets)
    
    # Create performance packet analysis
    perf_analysis = {
        "generation_time": datetime.now().isoformat(),
        "total_requested": count,
        "total_created": len(packets),
        "validation_errors": validation_errors,
        "size_distribution": {},
        "protocol_distribution": {},
        "nat_match_ratio": 0
    }
    
    # Analyze created packets
    nat_matches = 0
    for i, pkt in enumerate(packets):
        # Size analysis
        size = len(pkt)
        size_category = "small" if size < 512 else "medium" if size < 1500 else "large"
        perf_analysis["size_distribution"][size_category] = perf_analysis["size_distribution"].get(size_category, 0) + 1
        
        # Protocol analysis  
        if VXLAN in pkt:
            inner = pkt[VXLAN].payload
            if TCP in inner:
                protocol = "TCP"
            elif UDP in inner:
                protocol = "UDP"
            elif ICMP in inner:
                protocol = "ICMP"
            else:
                protocol = "Other"
            
            perf_analysis["protocol_distribution"][protocol] = perf_analysis["protocol_distribution"].get(protocol, 0) + 1
            
            # Check NAT match potential
            if UDP in inner and inner[UDP].sport == config['nat_source_port']:
                nat_matches += 1
    
    perf_analysis["nat_match_ratio"] = nat_matches / len(packets) if packets else 0
    
    # Save analysis
    analysis_file = os.path.join(output_dir, "performance_analysis.json")
    with open(analysis_file, 'w') as f:
        json.dump(perf_analysis, f, indent=2)
    
    print(f"Performance test file created: {perf_file}")
    print(f"  - Total packets: {len(packets)}")
    print(f"  - Validation errors: {validation_errors}")
    print(f"  - NAT match ratio: {perf_analysis['nat_match_ratio']:.1%}")
    print(f"Analysis saved: {analysis_file}")
    
    return len(packets)

def main():
    parser = argparse.ArgumentParser(description="Generate VXLAN test packets")
    parser.add_argument("-o", "--output", default=".", 
                       help="Output directory for packet files")
    parser.add_argument("--nat-source-port", type=int, default=42844,
                       help="Source port for NAT matching")
    parser.add_argument("--nat-target-ip", default="10.2.41.17",
                       help="Target IP for NAT")
    parser.add_argument("--nat-target-port", type=int, default=8081,
                       help="Target port for NAT")
    parser.add_argument("--vni", type=int, default=1,
                       help="VXLAN Network Identifier")
    parser.add_argument("--performance", action="store_true",
                       help="Generate performance test packets")
    parser.add_argument("--count", type=int, default=1000,
                       help="Number of performance test packets")
    
    args = parser.parse_args()
    
    # Create output directory if it doesn't exist
    os.makedirs(args.output, exist_ok=True)
    
    # Configuration from arguments
    config = {
        'nat_source_port': args.nat_source_port,
        'nat_target_ip': args.nat_target_ip,
        'nat_target_port': args.nat_target_port,
        'vni': args.vni
    }
    
    if args.performance:
        create_performance_packets(args.output, args.count, config)
    else:
        create_test_packets(args.output, config)
    
    print("\nPacket generation complete!")

if __name__ == "__main__":
    main()