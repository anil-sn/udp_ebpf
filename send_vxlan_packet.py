#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Simple VXLAN Packet Injector - Send exact packet from hex dump
Usage: sudo python3 send_vxlan_packet.py eth5
"""

import sys
import socket
import struct
from scapy.all import *


def hex_to_packet(hex_data):
    """Convert hex dump to raw packet data"""

    # Remove spaces, newlines and hex formatting

    clean_hex = ''
    for line in hex_data.strip().split('\n'):
        if '0x' in line and ':' in line:

            # Extract hex part after the colon

            hex_part = line.split(':')[1].strip()

            # Remove ASCII part (after two spaces)

            if '  ' in hex_part:
                hex_part = hex_part.split('  ')[0]

            # Remove spaces

            clean_hex += hex_part.replace(' ', '')

    # Convert hex string to bytes

    return bytes.fromhex(clean_hex)


def send_packet_on_interface(interface, packet_data):
    """Send raw packet on specified interface"""

    try:

        # Create raw socket

        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        s.bind((interface, 0))

        # Send the packet

        s.send(packet_data)
        print('\xe2\x9c\x85 Sent {} bytes on {}'.format(len(packet_data),
                interface))

        s.close()
        return True
    except Exception as e:
        print('\xe2\x9d\x8c Failed to send packet: {}'.format(e))
        return False


def main():
    if len(sys.argv) != 2:
        print('Usage: sudo python3 send_vxlan_packet.py <interface>')
        print('Example: sudo python3 send_vxlan_packet.py ens5')
        sys.exit(1)

    interface = sys.argv[1]

    # Create packet matching .env configuration:
    # SOURCE_PORT="31765" - inner source port should be 31765
    # Inner IP 172.30.82.157 is already in allowlist

    hex_dump = \
        """
  0x0000:  0a63 c28f 07ed 0ae5 1661 b06d 0800 4500
  0x0010:  02de 0000 0000 fe11 bbc6 ac1e 53c0 ac1e
  0x0020:  524b ffee 12b5 02ca 0000 0800 0000 0000
  0x0030:  0100 0a2c e332 fbb9 0a20 5587 cbdd 0800
  0x0040:  4500 02ac 0dea 4000 4011 34ed ac1e 529d
  0x0050:  ac1e 4a90 7c05 7bc5 0298 4bce 000a 0290
  0x0060:  694b f476 45d3 a350 0000 2070 0002 002c
  0x0070:  0100 0009 0096 0004 0097 0004 0008 0004
  0x0080:  000c 0004 0007 0002 000b 0002 0004 0001
  0x0090:  0001 0008 0002 0008 0100 0254 694b f43a
  0x00a0:  694b f476 72b6 0296 3753 0202 bb56 0c02
  0x00b0:  0600 0000 0027 56cd 0000 0000 0006 8e77
  0x00c0:  8069 4bf4 3a69 4bf4 7637 5302 0272 b602
  0x00d0:  960c 02bb 5606 0000 0000 2625 a000 0000
  0x00e0:  0000 05f5 e100 694b f43a 694b f476 72b6
  0x00f0:  0296 3753 0203 bb56 0386 0600 0000 0027
  0x0100:  56cd 0000 0000 0006 8e77 8069 4bf4 3a69
  0x0110:  4bf4 7637 5302 0372 b602 9603 86bb 5606
  0x0120:  0000 0000 2625 a000 0000 0000 05f5 e100
  0x0130:  694b f43a 694b f476 72b6 0296 3753 0206
  0x0140:  bb56 0386 0600 0000 0027 56cd 0000 0000
  0x0150:  0006 8e77 8069 4bf4 3a69 4bf4 7637 5302
  0x0160:  0672 b602 9603 86bb 5606 0000 0000 2625
  0x0170:  a000 0000 0000 05f5 e100 694b f43a 694b
  0x0180:  f476 72b6 0296 3753 0208 bb56 0035 0600
  0x0190:  0000 0027 56cd 0000 0000 0006 8e77 8069
  0x01a0:  4bf4 3a69 4bf4 7637 5302 0872 b602 9600
  0x01b0:  35bb 5606 0000 0000 2625 a000 0000 0000
  0x01c0:  05f5 e100 694b f43a 694b f476 72b6 0296
  0x01d0:  3753 0209 bb56 63dd 0600 0000 0027 56cd
  0x01e0:  0000 0000 0006 8e77 8069 4bf4 3a69 4bf4
  0x01f0:  7637 5302 0972 b602 9663 ddbb 5606 0000
  0x0200:  0000 2625 a000 0000 0000 05f5 e100 694b
  0x0210:  f43a 694b f476 72b6 0296 3753 0205 bb56
  0x0220:  0386 0600 0000 0027 56cd 0000 0000 0006
  0x0230:  8e77 8069 4bf4 3a69 4bf4 7637 5302 0572
  0x0240:  b602 9603 86bb 5606 0000 0000 2625 a000
  0x0250:  0000 0000 05f5 e100 694b f43a 694b f476
  0x0260:  72b6 0296 3753 020a bb56 01bb 0600 0000
  0x0270:  0027 56cd 0000 0000 0006 8e77 8069 4bf4
  0x0280:  3a69 4bf4 7637 5302 0a72 b602 9601 bbbb
  0x0290:  5606 0000 0000 2625 a000 0000 0000 05f5
  0x02a0:  e100 694b f43a 694b f476 72b6 0296 3753
  0x02b0:  0207 bb56 0386 0600 0000 0027 56cd 0000
  0x02c0:  0000 0006 8e77 8069 4bf4 3a69 4bf4 7637
  0x02d0:  5302 0772 b602 9603 86bb 5606 0000 0000
  0x02e0:  2625 a000 0000 0000 05f5 e100
"""

    print('🚀 VXLAN Packet Injector')
    print('📡 Sending packet on interface: {}'.format(interface))

    # Convert hex dump to packet
    packet_data = hex_to_packet(hex_dump)
    print('📦 Packet size: {} bytes'.format(len(packet_data)))

    # Parse and display packet info
    try:
        pkt = Ether(packet_data)
        print('\xf0\x9f\x93\x8b Packet summary: {}'.format(pkt.summary()))
        if hasattr(pkt, 'src'):
            print('   \xe2\x94\x94\xe2\x94\x80 Src MAC: {}'.format(pkt.src))
            print('   \xe2\x94\x94\xe2\x94\x80 Dst MAC: {}'.format(pkt.dst))
        if pkt.haslayer(IP):
            ip_layer = pkt[IP]
            print('   \xe2\x94\x94\xe2\x94\x80 Outer IP: {} \xe2\x86\x92 {}'.format(ip_layer.src,
                    ip_layer.dst))
        if pkt.haslayer(VXLAN):
            vxlan_layer = pkt[VXLAN]
            print('   \xe2\x94\x94\xe2\x94\x80 VXLAN VNI: {}'.format(vxlan_layer.vni))

            # Check inner packet
            if vxlan_layer.payload and vxlan_layer.payload.haslayer(IP):
                inner_ip = vxlan_layer.payload[IP]
                print('   \xe2\x94\x94\xe2\x94\x80 Inner IP: {} \xe2\x86\x92 {}'.format(inner_ip.src,
                        inner_ip.dst))
    except:
        print('   \xe2\x94\x94\xe2\x94\x80 Raw packet (could not parse with Scapy)')

    # Send the packet
    if send_packet_on_interface(interface, packet_data):
        print('\xe2\x9c\x85 SUCCESS: Packet sent on {}'.format(interface))
        print('\xf0\x9f\x94\x8d Monitor {} and ens6 to see the packet processing:'.format(interface))
        print('   sudo tcpdump -i {} -n -X'.format(interface))
        print('   sudo tcpdump -i ens6 -n -X')
    else:
        print('\xe2\x9d\x8c FAILED: Could not send packet')
        sys.exit(1)

if __name__ == '__main__':
    main()
