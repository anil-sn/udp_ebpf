#!/usr/bin/env python3
"""
Advanced Packet Analysis Tool for XDP VXLAN Pipeline Testing
Provides comprehensive packet analysis, validation, and comparison using Scapy
"""

import sys
import argparse
import os
import json
from collections import defaultdict, Counter
from datetime import datetime

try:
    from scapy.all import *
    from scapy.contrib.vxlan import VXLAN
    from scapy.layers.inet import IP, UDP, TCP, ICMP
    from scapy.layers.l2 import Ether, ARP
except ImportError:
    print("ERROR: scapy not installed. Install with: pip3 install scapy")
    sys.exit(1)

class AdvancedPacketAnalyzer:
    """Advanced packet analyzer with comprehensive validation using Scapy"""
    
    def __init__(self, config=None):
        self.config = config or {}
        self.stats = {
            'total_packets': 0,
            'vxlan_packets': 0,
            'non_vxlan_packets': 0,
            'invalid_packets': 0,
            'malformed_packets': 0,
            'size_distribution': Counter(),
            'port_distribution': Counter(),
            'vni_distribution': Counter(),
            'inner_ports': Counter(),
            'protocols': Counter(),
            'df_bit_set': 0,
            'df_bit_cleared': 0,
            'nat_candidates': 0,
            'checksum_errors': 0,
            'validation_details': [],
            'errors': []
        }
        
    def analyze_packet(self, packet, packet_index=None):
        """Comprehensive packet analysis with Scapy validation"""
        self.stats['total_packets'] += 1
        
        analysis_result = {
            'index': packet_index or self.stats['total_packets'],
            'timestamp': datetime.now().isoformat(),
            'size': len(packet),
            'valid': True,
            'layers': [],
            'protocols': [],
            'vxlan_analysis': None,
            'nat_analysis': None,
            'validation_errors': [],
            'warnings': [],
            'recommendations': []
        }
        
        try:
            # Extract layer information
            layer = packet
            while layer:
                layer_name = layer.__class__.__name__
                analysis_result['layers'].append(layer_name)
                if hasattr(layer, 'name'):
                    analysis_result['protocols'].append(layer.name)
                layer = layer.payload if hasattr(layer, 'payload') and layer.payload else None
            
            # Basic packet size validation
            pkt_size = len(packet)
            if pkt_size < 64:
                analysis_result['warnings'].append("Packet smaller than minimum Ethernet frame (64 bytes)")
                size_category = 'undersize'
            elif pkt_size < 128:
                size_category = 'small'
            elif pkt_size < 512:
                size_category = 'medium'
            elif pkt_size < 1500:
                size_category = 'large'
            elif pkt_size <= 9000:
                size_category = 'jumbo'
            else:
                analysis_result['warnings'].append("Packet larger than typical jumbo frame (>9000 bytes)")
                size_category = 'oversized'
            
            self.stats['size_distribution'][size_category] += 1
            
            # Layer-specific analysis
            self._analyze_ethernet_layer(packet, analysis_result)
            self._analyze_ip_layers(packet, analysis_result)
            self._analyze_udp_layers(packet, analysis_result)
            self._analyze_vxlan_layer(packet, analysis_result)
            
            # Protocol classification
            if VXLAN in packet:
                self.stats['vxlan_packets'] += 1
                self._perform_vxlan_analysis(packet, analysis_result)
            else:
                self.stats['non_vxlan_packets'] += 1
                self._analyze_non_vxlan_packet(packet, analysis_result)
            
            # Validation check
            if analysis_result['validation_errors']:
                analysis_result['valid'] = False
                self.stats['invalid_packets'] += 1
            
            # Store detailed analysis
            self.stats['validation_details'].append(analysis_result)
            
        except Exception as e:
            self.stats['invalid_packets'] += 1
            self.stats['malformed_packets'] += 1
            error_msg = f"Analysis exception for packet {analysis_result['index']}: {str(e)}"
            self.stats['errors'].append(error_msg)
            analysis_result['valid'] = False
            analysis_result['validation_errors'].append(error_msg)
        
        return analysis_result
    
    def _analyze_ethernet_layer(self, packet, result):
        """Analyze Ethernet layer"""
        if Ether in packet:
            eth = packet[Ether]
            
            # Check for broadcast/multicast
            if eth.dst == "ff:ff:ff:ff:ff:ff":
                result['warnings'].append("Broadcast destination MAC")
            elif int(eth.dst.split(':')[0], 16) & 1:
                result['warnings'].append("Multicast destination MAC")
            
            # Validate EtherType
            if eth.type not in [0x0800, 0x86dd, 0x0806]:  # IPv4, IPv6, ARP
                result['warnings'].append(f"Non-standard EtherType: 0x{eth.type:04x}")
    
    def _analyze_ip_layers(self, packet, result):
        """Analyze IP layers (outer and inner)"""
        ip_layers = []
        
        # Get all IP layers in packet
        layer = packet
        while layer:
            if IP in layer:
                ip_layers.append(layer[IP])
            layer = layer.payload if hasattr(layer, 'payload') else None
        
        for i, ip in enumerate(ip_layers):
            layer_name = f"IP[{i}]" if len(ip_layers) > 1 else "IP"
            
            # Basic IP validation
            if ip.version != 4:
                result['validation_errors'].append(f"{layer_name}: Invalid IP version {ip.version}")
            
            if ip.ihl < 5 or ip.ihl > 15:
                result['validation_errors'].append(f"{layer_name}: Invalid header length {ip.ihl}")
            
            if ip.ttl == 0:
                result['warnings'].append(f"{layer_name}: TTL is zero")
            elif ip.ttl < 10:
                result['warnings'].append(f"{layer_name}: Low TTL value {ip.ttl}")
            
            # DF bit analysis
            if ip.flags & 0x2:  # Don't Fragment bit
                self.stats['df_bit_set'] += 1
                result['warnings'].append(f"{layer_name}: DF bit set")
                
                # Check if packet is large enough to potentially need fragmentation
                if len(packet) > 1400:
                    result['recommendations'].append(f"{layer_name}: Large packet with DF bit may need clearing")
            
            # Checksum validation (if available)
            try:
                if hasattr(ip, 'chksum') and ip.chksum != 0:
                    # Scapy can recalculate checksum for validation
                    original_chksum = ip.chksum
                    ip.chksum = None
                    calculated_chksum = IP(bytes(ip)).chksum
                    ip.chksum = original_chksum
                    
                    if original_chksum != calculated_chksum:
                        self.stats['checksum_errors'] += 1
                        result['validation_errors'].append(f"{layer_name}: Invalid checksum")
            except:
                pass  # Checksum validation failed, but don't crash
    
    def _analyze_udp_layers(self, packet, result):
        """Analyze UDP layers"""
        if UDP in packet:
            udp_layers = packet.getlayer(UDP, nb=1)  # Get first UDP layer
            layer_count = 1
            
            # Try to get additional UDP layers (in case of VXLAN)
            try:
                udp2 = packet.getlayer(UDP, nb=2)
                if udp2:
                    layer_count = 2
            except:
                pass
            
            for i in range(layer_count):
                try:
                    udp = packet.getlayer(UDP, nb=i+1)
                    if not udp:
                        break
                        
                    layer_name = f"UDP[{i}]" if layer_count > 1 else "UDP"
                    
                    # Port analysis
                    self.stats['port_distribution'][udp.dport] += 1
                    
                    # VXLAN port detection
                    if udp.dport == 4789:
                        result['protocols'].append("VXLAN_PORT")
                        
                    # Common service ports
                    well_known_ports = {
                        53: "DNS", 67: "DHCP", 68: "DHCP", 123: "NTP",
                        161: "SNMP", 162: "SNMP", 514: "Syslog", 4789: "VXLAN"
                    }
                    
                    if udp.dport in well_known_ports:
                        result['protocols'].append(well_known_ports[udp.dport])
                    
                    # Validate port ranges
                    if udp.sport == 0 or udp.dport == 0:
                        result['warnings'].append(f"{layer_name}: Zero port detected")
                    
                    # UDP length validation
                    if hasattr(udp, 'len') and udp.len > 0:
                        expected_len = len(udp)
                        if udp.len != expected_len:
                            result['validation_errors'].append(f"{layer_name}: UDP length mismatch")
                
                except:
                    break
    
    def _analyze_vxlan_layer(self, packet, result):
        """Analyze VXLAN layer specifically"""
        if VXLAN in packet:
            vxlan = packet[VXLAN]
            
            # VNI analysis
            self.stats['vni_distribution'][vxlan.vni] += 1
            
            # VXLAN flags validation
            if vxlan.flags != 0x08:
                result['validation_errors'].append(f"Invalid VXLAN flags: 0x{vxlan.flags:02x} (expected 0x08)")
            
            # VNI range validation
            if not (0 <= vxlan.vni <= 16777215):
                result['validation_errors'].append(f"Invalid VNI: {vxlan.vni} (must be 0-16777215)")
            
            # Reserved fields should be zero
            if hasattr(vxlan, 'reserved1') and vxlan.reserved1 != 0:
                result['warnings'].append("VXLAN reserved1 field is not zero")
            
            if hasattr(vxlan, 'reserved2') and vxlan.reserved2 != 0:
                result['warnings'].append("VXLAN reserved2 field is not zero")
    
    def _perform_vxlan_analysis(self, packet, result):
        """Perform comprehensive VXLAN packet analysis"""
        vxlan_analysis = {
            'outer_headers': {},
            'vxlan_header': {},
            'inner_packet': {},
            'nat_potential': False,
            'df_bit_clearing_candidate': False
        }
        
        try:
            # Outer packet analysis
            if IP in packet:
                outer_ip = packet[IP]
                vxlan_analysis['outer_headers']['ip'] = {
                    'src': str(outer_ip.src),
                    'dst': str(outer_ip.dst),
                    'ttl': outer_ip.ttl,
                    'flags': outer_ip.flags
                }
            
            if UDP in packet:
                outer_udp = packet[UDP]
                vxlan_analysis['outer_headers']['udp'] = {
                    'sport': outer_udp.sport,
                    'dport': outer_udp.dport
                }
            
            # VXLAN header analysis
            vxlan = packet[VXLAN]
            vxlan_analysis['vxlan_header'] = {
                'vni': vxlan.vni,
                'flags': vxlan.flags
            }
            
            # Inner packet analysis
            inner_packet = vxlan.payload
            if Ether in inner_packet:
                inner_eth = inner_packet[Ether]
                
                if IP in inner_packet:
                    inner_ip = inner_packet[IP]
                    vxlan_analysis['inner_packet']['ip'] = {
                        'src': str(inner_ip.src),
                        'dst': str(inner_ip.dst),
                        'ttl': inner_ip.ttl,
                        'flags': inner_ip.flags,
                        'size': inner_ip.len if hasattr(inner_ip, 'len') else len(inner_ip)
                    }
                    
                    # DF bit clearing analysis
                    if (inner_ip.flags & 0x2) and len(packet) > 1400:
                        vxlan_analysis['df_bit_clearing_candidate'] = True
                        result['recommendations'].append("Packet candidate for DF bit clearing (>1400 bytes)")
                    
                    if UDP in inner_packet:
                        inner_udp = inner_packet[UDP]
                        vxlan_analysis['inner_packet']['udp'] = {
                            'sport': inner_udp.sport,
                            'dport': inner_udp.dport
                        }
                        
                        # NAT analysis based on configuration
                        nat_source_port = self.config.get('nat_source_port', 42844)
                        if inner_udp.sport == nat_source_port:
                            vxlan_analysis['nat_potential'] = True
                            self.stats['nat_candidates'] += 1
                            result['recommendations'].append(f"Packet matches NAT source port {nat_source_port}")
                        
                        self.stats['inner_ports'][inner_udp.sport] += 1
                        self.stats['inner_ports'][inner_udp.dport] += 1
                    
                    elif TCP in inner_packet:
                        inner_tcp = inner_packet[TCP]
                        vxlan_analysis['inner_packet']['tcp'] = {
                            'sport': inner_tcp.sport,
                            'dport': inner_tcp.dport,
                            'flags': inner_tcp.flags
                        }
                    
                    elif ICMP in inner_packet:
                        inner_icmp = inner_packet[ICMP]
                        vxlan_analysis['inner_packet']['icmp'] = {
                            'type': inner_icmp.type,
                            'code': inner_icmp.code
                        }
        
        except Exception as e:
            result['validation_errors'].append(f"VXLAN analysis failed: {str(e)}")
        
        result['vxlan_analysis'] = vxlan_analysis
    
    def _analyze_non_vxlan_packet(self, packet, result):
        """Analyze non-VXLAN packets"""
        if IP in packet:
            self.stats['protocols']['IPv4'] += 1
            
            if UDP in packet:
                self.stats['protocols']['UDP'] += 1
                udp_layer = packet[UDP]
                self.stats['port_distribution'][udp_layer.dport] += 1
                
                # Check if it looks like VXLAN but on wrong port
                if udp_layer.dport != 4789 and len(packet) > 50:
                    # Try to decode as VXLAN anyway
                    try:
                        potential_vxlan = packet[UDP].payload
                        if len(potential_vxlan) >= 8:  # Minimum VXLAN header size
                            result['warnings'].append(f"UDP packet on port {udp_layer.dport} might contain VXLAN-like data")
                    except:
                        pass
            
            elif TCP in packet:
                self.stats['protocols']['TCP'] += 1
            
            elif ICMP in packet:
                self.stats['protocols']['ICMP'] += 1
        
        elif IPv6 in packet:
            self.stats['protocols']['IPv6'] += 1
        
        else:
            self.stats['protocols']['Other'] += 1
    
    def print_statistics(self, output_file=None):
        """Print comprehensive statistics with enhanced analysis"""
        
        def print_line(text, file=None):
            print(text)
            if file:
                file.write(text + '\n')
        
        output = open(output_file, 'w') if output_file else None
        
        try:
            print_line("=" * 70, output)
            print_line("ADVANCED PACKET ANALYSIS REPORT", output)
            print_line("=" * 70, output)
            
            # Basic statistics
            print_line(f"\n📊 BASIC STATISTICS", output)
            print_line(f"   Total Packets:        {self.stats['total_packets']:,}", output)
            print_line(f"   VXLAN Packets:        {self.stats['vxlan_packets']:,}", output)
            print_line(f"   Non-VXLAN Packets:    {self.stats['non_vxlan_packets']:,}", output)
            print_line(f"   Invalid Packets:      {self.stats['invalid_packets']:,}", output)
            print_line(f"   Malformed Packets:    {self.stats['malformed_packets']:,}", output)
            
            if self.stats['total_packets'] > 0:
                vxlan_pct = (self.stats['vxlan_packets'] / self.stats['total_packets']) * 100
                invalid_pct = (self.stats['invalid_packets'] / self.stats['total_packets']) * 100
                print_line(f"   VXLAN Percentage:     {vxlan_pct:.1f}%", output)
                print_line(f"   Invalid Percentage:   {invalid_pct:.1f}%", output)
            
            # Size distribution with detailed analysis
            print_line(f"\n📏 SIZE DISTRIBUTION", output)
            total_bytes = 0
            for size, count in self.stats['size_distribution'].most_common():
                pct = (count / self.stats['total_packets']) * 100
                print_line(f"   {size.capitalize():>10}: {count:>6,} ({pct:>5.1f}%)", output)
            
            # Protocol distribution
            print_line(f"\n🌐 PROTOCOL DISTRIBUTION", output)
            for proto, count in self.stats['protocols'].most_common():
                pct = (count / self.stats['total_packets']) * 100
                print_line(f"   {proto:>10}: {count:>6,} ({pct:>5.1f}%)", output)
            
            # Enhanced VXLAN analysis
            if self.stats['vxlan_packets'] > 0:
                print_line(f"\n🔗 ENHANCED VXLAN ANALYSIS", output)
                
                # VNI distribution
                print_line(f"   VNI Distribution:", output)
                for vni, count in self.stats['vni_distribution'].most_common():
                    pct = (count / self.stats['vxlan_packets']) * 100
                    print_line(f"     VNI {vni:>5}: {count:>6,} ({pct:>5.1f}%)", output)
                
                # DF bit analysis
                print_line(f"   DF Bit Analysis:", output)
                print_line(f"     DF Bit Set:    {self.stats['df_bit_set']:>6,}", output)
                print_line(f"     DF Bit Clear:  {self.stats['df_bit_cleared']:>6,}", output)
                
                # NAT analysis
                if self.stats['nat_candidates'] > 0:
                    print_line(f"   NAT Analysis:", output)
                    print_line(f"     NAT Candidates: {self.stats['nat_candidates']:>6,}", output)
                    nat_pct = (self.stats['nat_candidates'] / self.stats['vxlan_packets']) * 100
                    print_line(f"     NAT Match Rate: {nat_pct:>6.1f}%", output)
                
                # Top inner ports
                print_line(f"   Top Inner Ports:", output)
                for port, count in self.stats['inner_ports'].most_common(10):
                    service = self._get_service_name(port)
                    print_line(f"     Port {port:>5}: {count:>6,} {service}", output)
            
            # Quality metrics
            print_line(f"\n🔍 QUALITY METRICS", output)
            if self.stats['checksum_errors'] > 0:
                print_line(f"   Checksum Errors:      {self.stats['checksum_errors']:,}", output)
            
            # Non-VXLAN analysis
            if self.stats['non_vxlan_packets'] > 0:
                print_line(f"\n🔌 NON-VXLAN ANALYSIS", output)
                print_line(f"   Top Destination Ports:", output)
                for port, count in self.stats['port_distribution'].most_common(10):
                    service = self._get_service_name(port)
                    print_line(f"     Port {port:>5}: {count:>6,} {service}", output)
            
            # Validation summary
            if self.stats['validation_details']:
                valid_count = sum(1 for detail in self.stats['validation_details'] if detail['valid'])
                print_line(f"\n✅ VALIDATION SUMMARY", output)
                print_line(f"   Valid Packets:        {valid_count:,}", output)
                print_line(f"   Invalid Packets:      {len(self.stats['validation_details']) - valid_count:,}", output)
                
                # Most common validation errors
                error_counts = Counter()
                warning_counts = Counter()
                
                for detail in self.stats['validation_details']:
                    for error in detail.get('validation_errors', []):
                        error_counts[error] += 1
                    for warning in detail.get('warnings', []):
                        warning_counts[warning] += 1
                
                if error_counts:
                    print_line(f"   Common Errors:", output)
                    for error, count in error_counts.most_common(5):
                        print_line(f"     {error} ({count})", output)
                
                if warning_counts:
                    print_line(f"   Common Warnings:", output)
                    for warning, count in warning_counts.most_common(5):
                        print_line(f"     {warning} ({count})", output)
            
            # Errors and recommendations
            if self.stats['errors']:
                print_line(f"\n⚠️  ANALYSIS ERRORS ({len(self.stats['errors'])})", output)
                for i, error in enumerate(self.stats['errors'][:10]):
                    print_line(f"   {i+1:>2}: {error}", output)
                if len(self.stats['errors']) > 10:
                    print_line(f"   ... and {len(self.stats['errors']) - 10} more errors", output)
            
            print_line("=" * 70, output)
            
        finally:
            if output:
                output.close()
    
    def _get_service_name(self, port):
        """Get service name for well-known ports"""
        well_known = {
            53: "(DNS)", 67: "(DHCP)", 68: "(DHCP)", 80: "(HTTP)",
            123: "(NTP)", 161: "(SNMP)", 443: "(HTTPS)", 514: "(Syslog)",
            4789: "(VXLAN)", 8080: "(HTTP-Alt)", 8081: "(HTTP-Alt)"
        }
        return well_known.get(port, "")
    
    def export_detailed_analysis(self, output_file):
        """Export detailed analysis to JSON file"""
        detailed_report = {
            "analysis_time": datetime.now().isoformat(),
            "summary_statistics": self.stats,
            "detailed_validations": self.stats['validation_details'],
            "recommendations": self._generate_recommendations()
        }
        
        with open(output_file, 'w') as f:
            json.dump(detailed_report, f, indent=2, default=str)
        
        print(f"Detailed analysis exported to: {output_file}")
    
    def _generate_recommendations(self):
        """Generate recommendations based on analysis"""
        recommendations = []
        
        # Performance recommendations
        if self.stats['vxlan_packets'] > 0:
            error_rate = self.stats['invalid_packets'] / self.stats['total_packets']
            if error_rate > 0.05:  # > 5% error rate
                recommendations.append("High error rate detected - review packet generation or capture process")
            
            # NAT efficiency
            if self.stats['nat_candidates'] > 0:
                nat_rate = self.stats['nat_candidates'] / self.stats['vxlan_packets']
                if nat_rate < 0.1:  # < 10% NAT match rate
                    recommendations.append("Low NAT match rate - verify source port configuration")
            
            # DF bit analysis
            if self.stats['df_bit_set'] > 0:
                recommendations.append(f"{self.stats['df_bit_set']} packets with DF bit set - may need clearing for large packets")
        
        # Quality recommendations
        if self.stats['checksum_errors'] > 0:
            recommendations.append("Checksum errors detected - verify packet integrity")
        
        if self.stats['malformed_packets'] > 0:
            recommendations.append("Malformed packets detected - review capture or generation process")
        
        return recommendations

def analyze_pcap_file(filename, config=None, verbose=False, output_file=None):
    """Analyze a pcap file with enhanced validation"""
    
    if not os.path.exists(filename):
        print(f"ERROR: File not found: {filename}")
        return 1
    
    print(f"Analyzing: {filename}")
    
    try:
        # Read packets from pcap file
        packets = rdpcap(filename)
        print(f"Loaded {len(packets)} packets")
        
        # Initialize enhanced analyzer
        analyzer = AdvancedPacketAnalyzer(config or {})
        
        # Analyze each packet
        for i, packet in enumerate(packets):
            if verbose and (i + 1) % 1000 == 0:
                print(f"Processed {i + 1:,} packets...", end='\r')
            
            analyzer.analyze_packet(packet, i + 1)
        
        if verbose:
            print()  # New line after progress
        
        # Print results
        analyzer.print_statistics(output_file)
        
        # Export detailed analysis if requested
        if output_file:
            json_file = output_file.replace('.txt', '.json') if output_file.endswith('.txt') else output_file + '.json'
            analyzer.export_detailed_analysis(json_file)
        
        return 0
        
    except Exception as e:
        print(f"ERROR: Failed to analyze file: {str(e)}")
        return 1

def compare_before_after(before_file, after_file, config=None):
    """Enhanced before/after comparison with detailed analysis"""
    
    print("ENHANCED BEFORE/AFTER COMPARISON")
    print("=" * 50)
    
    # Analyze both files
    analyzers = {}
    
    for label, filename in [("BEFORE", before_file), ("AFTER", after_file)]:
        if not os.path.exists(filename):
            print(f"ERROR: File not found: {filename}")
            return 1
        
        print(f"Analyzing {label} file: {filename}")
        packets = rdpcap(filename)
        analyzer = AdvancedPacketAnalyzer(config or {})
        
        for i, packet in enumerate(packets):
            analyzer.analyze_packet(packet, i + 1)
        
        analyzers[label] = analyzer
    
    # Compare statistics
    before_stats = analyzers["BEFORE"].stats
    after_stats = analyzers["AFTER"].stats
    
    print(f"\n📊 PACKET COUNT COMPARISON:")
    print(f"  Before: {before_stats['total_packets']:,}")
    print(f"  After:  {after_stats['total_packets']:,}")
    
    packet_diff = after_stats['total_packets'] - before_stats['total_packets']
    if packet_diff != 0:
        print(f"  Change: {packet_diff:+,} ({packet_diff/before_stats['total_packets']*100:+.1f}%)")
    
    # VXLAN processing analysis
    print(f"\n🔗 VXLAN PROCESSING ANALYSIS:")
    print(f"  VXLAN Before: {before_stats['vxlan_packets']:,}")
    print(f"  VXLAN After:  {after_stats['vxlan_packets']:,}")
    
    if before_stats['vxlan_packets'] > 0:
        vxlan_retention = after_stats['vxlan_packets'] / before_stats['vxlan_packets']
        print(f"  VXLAN Retention: {vxlan_retention:.1%}")
        
        # Calculate processing efficiency
        if after_stats['total_packets'] > 0:
            processing_ratio = after_stats['total_packets'] / before_stats['vxlan_packets']
            print(f"  Processing Ratio: {processing_ratio:.2f} output packets per input VXLAN packet")
    
    # NAT analysis comparison
    if before_stats.get('nat_candidates', 0) > 0 or after_stats.get('nat_candidates', 0) > 0:
        print(f"\n🔄 NAT PROCESSING COMPARISON:")
        print(f"  NAT Candidates Before: {before_stats.get('nat_candidates', 0):,}")
        print(f"  NAT Candidates After:  {after_stats.get('nat_candidates', 0):,}")
        
        nat_processing_rate = (before_stats.get('nat_candidates', 0) - after_stats.get('nat_candidates', 0)) / max(before_stats.get('nat_candidates', 1), 1)
        print(f"  NAT Processing Rate: {nat_processing_rate:.1%}")
    
    # Quality comparison
    print(f"\n🔍 QUALITY COMPARISON:")
    print(f"  Invalid Before: {before_stats['invalid_packets']:,}")
    print(f"  Invalid After:  {after_stats['invalid_packets']:,}")
    
    if before_stats.get('checksum_errors', 0) > 0 or after_stats.get('checksum_errors', 0) > 0:
        print(f"  Checksum Errors Before: {before_stats.get('checksum_errors', 0):,}")
        print(f"  Checksum Errors After:  {after_stats.get('checksum_errors', 0):,}")
    
    # Size distribution comparison
    print(f"\n📏 SIZE DISTRIBUTION COMPARISON:")
    all_sizes = set(before_stats['size_distribution'].keys()) | set(after_stats['size_distribution'].keys())
    
    for size in sorted(all_sizes):
        before_count = before_stats['size_distribution'][size]
        after_count = after_stats['size_distribution'][size]
        
        if before_count > 0 or after_count > 0:
            change = after_count - before_count
            print(f"  {size.capitalize():>10}: {before_count:>6,} → {after_count:>6,} ({change:+,})")
    
    # DF bit analysis
    if before_stats.get('df_bit_set', 0) > 0:
        print(f"\n🚫 DF BIT PROCESSING:")
        print(f"  DF Bits Set Before: {before_stats.get('df_bit_set', 0):,}")
        print(f"  DF Bits Set After:  {after_stats.get('df_bit_set', 0):,}")
        
        df_cleared = before_stats.get('df_bit_set', 0) - after_stats.get('df_bit_set', 0)
        if df_cleared > 0:
            print(f"  DF Bits Cleared: {df_cleared:,}")
    
    # VNI distribution comparison
    if before_stats['vni_distribution'] or after_stats['vni_distribution']:
        print(f"\n🏷️  VNI DISTRIBUTION COMPARISON:")
        all_vnis = set(before_stats['vni_distribution'].keys()) | set(after_stats['vni_distribution'].keys())
        
        for vni in sorted(all_vnis):
            before_count = before_stats['vni_distribution'][vni]
            after_count = after_stats['vni_distribution'][vni]
            print(f"  VNI {vni:>3}: {before_count:>6,} → {after_count:>6,}")
    
    return 0

def validate_xdp_processing(input_file, output_file, config=None):
    """Validate that XDP processing worked correctly"""
    
    print("XDP PROCESSING VALIDATION")
    print("=" * 30)
    
    # Load expected configuration
    expected_config = config or {
        'nat_source_port': 42844,
        'nat_target_ip': '10.2.41.17', 
        'nat_target_port': 8081,
        'vni': 1
    }
    
    # Analyze input packets
    print("Analyzing input packets...")
    input_packets = rdpcap(input_file)
    input_analyzer = AdvancedPacketAnalyzer(expected_config)
    
    for packet in input_packets:
        input_analyzer.analyze_packet(packet)
    
    # Analyze output packets  
    print("Analyzing output packets...")
    output_packets = rdpcap(output_file)
    output_analyzer = AdvancedPacketAnalyzer(expected_config)
    
    for packet in output_packets:
        output_analyzer.analyze_packet(packet)
    
    # Validation checks
    validation_results = {
        'total_score': 0,
        'max_score': 0,
        'checks': []
    }
    
    def add_check(name, expected, actual, weight=1):
        passed = expected == actual
        validation_results['checks'].append({
            'name': name,
            'expected': expected,
            'actual': actual,
            'passed': passed,
            'weight': weight
        })
        validation_results['max_score'] += weight
        if passed:
            validation_results['total_score'] += weight
        return passed
    
    # Check packet counts
    add_check("No packets lost", 
             input_analyzer.stats['vxlan_packets'], 
             output_analyzer.stats['total_packets'])
    
    # Check NAT processing
    expected_nat_processed = input_analyzer.stats.get('nat_candidates', 0)
    # NAT candidates should be processed (transformed), so they shouldn't appear as candidates in output
    actual_nat_remaining = output_analyzer.stats.get('nat_candidates', 0)
    add_check("NAT rules applied", 
             0,  # Expect no NAT candidates remaining
             actual_nat_remaining, 
             weight=2)
    
    # Check error rates
    input_error_rate = input_analyzer.stats['invalid_packets'] / max(input_analyzer.stats['total_packets'], 1)
    output_error_rate = output_analyzer.stats['invalid_packets'] / max(output_analyzer.stats['total_packets'], 1)
    add_check("Error rate not increased", 
             True,
             output_error_rate <= input_error_rate,
             weight=2)
    
    # Print validation results
    print(f"\n✅ VALIDATION RESULTS:")
    for check in validation_results['checks']:
        status = "✓ PASS" if check['passed'] else "✗ FAIL"
        print(f"  {status}: {check['name']}")
        if not check['passed']:
            print(f"    Expected: {check['expected']}, Got: {check['actual']}")
    
    score_pct = (validation_results['total_score'] / validation_results['max_score']) * 100
    print(f"\nOverall Score: {validation_results['total_score']}/{validation_results['max_score']} ({score_pct:.1f}%)")
    
    if score_pct >= 80:
        print("🎉 XDP processing validation PASSED!")
    else:
        print("⚠️ XDP processing validation FAILED - review configuration and processing logic")
    
    return 0 if score_pct >= 80 else 1

def main():
    parser = argparse.ArgumentParser(description="Advanced VXLAN pipeline packet analysis")
    parser.add_argument("pcap_file", help="PCAP file to analyze")
    parser.add_argument("--compare", metavar="AFTER_FILE", 
                       help="Compare with another PCAP file (before/after analysis)")
    parser.add_argument("--validate", metavar="OUTPUT_FILE",
                       help="Validate XDP processing (input vs output)")
    parser.add_argument("--config", metavar="CONFIG_FILE",
                       help="JSON configuration file for analysis")
    parser.add_argument("--nat-source-port", type=int, default=42844,
                       help="Expected NAT source port")
    parser.add_argument("--nat-target-ip", default="10.2.41.17",
                       help="Expected NAT target IP")
    parser.add_argument("--nat-target-port", type=int, default=8081,
                       help="Expected NAT target port")
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="Verbose output with progress")
    parser.add_argument("-o", "--output", metavar="OUTPUT_FILE",
                       help="Save analysis to file")
    parser.add_argument("--json", action="store_true",
                       help="Output in JSON format")
    
    args = parser.parse_args()
    
    # Load configuration
    config = {}
    if args.config and os.path.exists(args.config):
        with open(args.config, 'r') as f:
            config = json.load(f)
    else:
        config = {
            'nat_source_port': args.nat_source_port,
            'nat_target_ip': args.nat_target_ip,
            'nat_target_port': args.nat_target_port,
            'vni': 1
        }
    
    # Determine operation mode
    if args.validate:
        return validate_xdp_processing(args.pcap_file, args.validate, config)
    elif args.compare:
        return compare_before_after(args.pcap_file, args.compare, config)
    else:
        return analyze_pcap_file(args.pcap_file, config, args.verbose, args.output)

if __name__ == "__main__":
    sys.exit(main())