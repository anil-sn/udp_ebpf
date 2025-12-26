#!/usr/bin/env python3

import subprocess
import sys

def debug_network_topology():
    """Debug network configuration to understand routing"""
    
    print("=== Network Topology Debug ===")
    
    commands = [
        ("IP addresses", ["ip", "addr", "show"]),
        ("Routing table", ["ip", "route", "show"]),  
        ("ARP table", ["arp", "-a"]),
        ("Network namespaces", ["ip", "netns", "list"]),
        ("Interface stats", ["cat", "/proc/net/dev"]),
    ]
    
    for name, cmd in commands:
        print(f"\n=== {name} ===")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            print(result.stdout)
            if result.stderr:
                print(f"STDERR: {result.stderr}")
        except Exception as e:
            print(f"Error running {' '.join(cmd)}: {e}")
    
    # Check subnet relationships
    print(f"\n=== Subnet Analysis ===")
    print("172.30.82.13  - Original source IP")
    print("172.30.82.173 - Routing table source IP")  
    print("172.30.82.95  - Destination IP")
    print()
    print("Question: Are these in the same subnet or different subnets?")
    print("If different subnets, AWS might have additional routing rules.")

if __name__ == "__main__":
    debug_network_topology()