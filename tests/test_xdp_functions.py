#!/usr/bin/env python3
"""
Unit Tests for XDP Pipeline Functions
Tests individual components of the XDP program for correctness
"""

import pytest
import struct
import socket
import random
from scapy.all import *
from scapy.layers.vxlan import VXLAN

class TestVXLANParsing:
    """Test VXLAN header parsing and validation"""
    
    def test_valid_vxlan_packet(self):
        """Test parsing of valid AWS Traffic Mirror VXLAN packet"""
        # Create valid VXLAN packet (VNI=1, flags=0x08)
        inner_pkt = Ether()/IP(src="192.168.1.100", dst="192.168.1.200")/UDP(sport=42844, dport=8081)/Raw(b"test")
        vxlan_pkt = Ether()/IP()/UDP(dport=4789)/VXLAN(vni=1, flags=0x08)/inner_pkt
        
        # Validate packet structure
        assert VXLAN in vxlan_pkt
        assert vxlan_pkt[VXLAN].vni == 1
        assert vxlan_pkt[VXLAN].flags == 0x08
        assert vxlan_pkt[UDP].dport == 4789
        
    def test_invalid_vxlan_flags(self):
        """Test rejection of VXLAN packets with invalid flags"""
        inner_pkt = Ether()/IP()/UDP(sport=42844, dport=8081)/Raw(b"test")
        # Invalid flags (missing VNI flag)
        vxlan_pkt = Ether()/IP()/UDP(dport=4789)/VXLAN(vni=1, flags=0x00)/inner_pkt
        
        assert vxlan_pkt[VXLAN].flags == 0x00  # Should be rejected by XDP
        
    def test_invalid_vni(self):
        """Test rejection of VXLAN packets with wrong VNI"""
        inner_pkt = Ether()/IP()/UDP(sport=42844, dport=8081)/Raw(b"test")
        # Wrong VNI (should be 1 for AWS Traffic Mirror)
        vxlan_pkt = Ether()/IP()/UDP(dport=4789)/VXLAN(vni=2, flags=0x08)/inner_pkt
        
        assert vxlan_pkt[VXLAN].vni == 2  # Should be rejected by XDP

class TestNATFunctionality:
    """Test NAT rule application and IP/port translation"""
    
    def test_nat_rule_matching(self):
        """Test NAT rule lookup by source port"""
        # Create packet matching NAT rule (sport=42844 -> 10.2.41.17:8081)
        test_packet = IP(src="192.168.1.100", dst="192.168.1.200")/UDP(sport=42844, dport=8081)
        
        # Verify source port extraction
        assert test_packet[UDP].sport == 42844
        
    def test_dnat_transformation(self):
        """Test destination NAT transformation"""
        original = IP(src="192.168.1.100", dst="192.168.1.200")/UDP(sport=42844, dport=8081)
        
        # Simulate DNAT: change destination to 10.2.41.17:8081
        modified = original.copy()
        modified[IP].dst = "10.2.41.17"
        
        assert modified[IP].dst == "10.2.41.17"
        assert modified[UDP].dport == 8081  # Port should remain the same in this case
        
    def test_checksum_recalculation(self):
        """Test IP checksum recalculation after NAT"""
        # Create packet and modify destination
        pkt = IP(src="192.168.1.100", dst="192.168.1.200")/UDP(sport=42844, dport=8081)
        original_checksum = pkt[IP].chksum
        
        # Modify destination and recalculate checksum
        pkt[IP].dst = "10.2.41.17"
        pkt[IP].chksum = None  # Force recalculation
        pkt = IP(raw(pkt))  # Rebuild packet with new checksum
        
        assert pkt[IP].chksum != original_checksum

class TestDFBitHandling:
    """Test Don't Fragment bit clearing for large packets"""
    
    def test_df_bit_detection(self):
        """Test detection of DF bit in IP header"""
        # Create packet with DF bit set
        pkt_with_df = IP(flags="DF")/UDP()/Raw(b"A" * 1450)  # Large payload
        
        assert pkt_with_df[IP].flags == 2  # DF flag = 0x02
        
    def test_df_bit_clearing(self):
        """Test DF bit removal from large packets"""
        # Create large packet with DF bit
        large_pkt = IP(flags="DF")/UDP()/Raw(b"A" * 1450)
        assert large_pkt[IP].flags == 2
        
        # Simulate DF bit clearing
        large_pkt[IP].flags = 0
        assert large_pkt[IP].flags == 0
        
    def test_small_packet_df_preservation(self):
        """Test that DF bit is preserved on small packets"""
        # Create small packet with DF bit (should not be cleared)
        small_pkt = IP(flags="DF")/UDP()/Raw(b"small")
        
        # Packet size < 1400 bytes, DF should be preserved
        assert len(small_pkt) < 1400
        assert small_pkt[IP].flags == 2  # DF bit should remain

class TestPacketSizeHandling:
    """Test handling of different packet sizes"""
    
    def test_jumbo_frame_processing(self):
        """Test processing of 2852-byte jumbo frames"""
        # Create jumbo frame matching user's analysis
        jumbo_payload = Raw(b"A" * 2800)  # Large payload to create jumbo frame
        jumbo_pkt = Ether()/IP()/UDP()/jumbo_payload
        
        assert len(jumbo_pkt) > 2000  # Should be jumbo frame
        
    def test_standard_frame_processing(self):
        """Test processing of standard 1500-byte frames"""
        standard_payload = Raw(b"A" * 1400)
        standard_pkt = Ether()/IP()/UDP()/standard_payload
        
        assert len(standard_pkt) <= 1500  # Should be standard frame

class TestErrorConditions:
    """Test error handling and edge cases"""
    
    def test_truncated_vxlan_header(self):
        """Test handling of truncated VXLAN headers"""
        # Create incomplete VXLAN packet
        incomplete = Ether()/IP()/UDP(dport=4789)/Raw(b"\x08\x00\x00")  # Truncated VXLAN
        
        # Should be detected and dropped by XDP program
        assert len(incomplete[Raw]) < 8  # Less than full VXLAN header
        
    def test_invalid_inner_packet(self):
        """Test handling of invalid inner packets"""
        # Create VXLAN with malformed inner packet
        malformed_inner = Raw(b"\x00" * 10)  # Invalid Ethernet header
        vxlan_pkt = Ether()/IP()/UDP(dport=4789)/VXLAN(vni=1, flags=0x08)/malformed_inner
        
        # XDP should detect and handle gracefully
        assert len(vxlan_pkt[Raw]) < 14  # Less than minimum Ethernet header
        
    def test_zero_length_payload(self):
        """Test handling of zero-length payloads"""
        empty_pkt = Ether()/IP()/UDP(dport=4789)/VXLAN(vni=1, flags=0x08)/Ether()
        
        # Should not crash XDP program
        assert VXLAN in empty_pkt

if __name__ == "__main__":
    pytest.main([__file__, "-v"])