#!/usr/bin/env python3

import subprocess
import sys
import os
from datetime import datetime

def run_command(name, cmd, timeout=10):
    """Run a command and return formatted output"""
    print(f"\n=== {name} ===")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=isinstance(cmd, str))
        if result.stdout:
            print(result.stdout.strip())
        if result.stderr:
            print(f"STDERR: {result.stderr.strip()}")
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        print(f"Command timed out after {timeout}s")
        return False
    except Exception as e:
        print(f"Error running {cmd if isinstance(cmd, str) else ' '.join(cmd)}: {e}")
        return False

def check_file_exists(filepath):
    """Check if file exists and is readable"""
    return os.path.exists(filepath) and os.access(filepath, os.R_OK)

def debug_network_comprehensive():
    """Comprehensive network configuration debugging for Linux/Ubuntu"""
    
    print("=" * 80)
    print(f"COMPREHENSIVE NETWORK DIAGNOSTICS - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80)
    
    # Basic Network Interface Information
    interface_commands = [
        ("Network Interfaces (detailed)", ["ip", "addr", "show"]),
        ("Interface Link Status", ["ip", "link", "show"]),
        ("Interface Statistics", ["ip", "-s", "link", "show"]),
        ("Interface Hardware Info", ["lshw", "-class", "network"]),
        ("Network Interface Cards", ["lspci", "|", "grep", "-i", "network"]),
        ("USB Network Devices", ["lsusb", "|", "grep", "-i", "network"]),
    ]
    
    print("\n" + "="*50)
    print("NETWORK INTERFACES & HARDWARE")
    print("="*50)
    
    for name, cmd in interface_commands:
        if isinstance(cmd, list) and "|" in cmd:
            cmd_str = " ".join(cmd)
            run_command(name, cmd_str)
        else:
            run_command(name, cmd)
    
    # Routing Information
    routing_commands = [
        ("IPv4 Routing Table", ["ip", "route", "show"]),
        ("IPv6 Routing Table", ["ip", "-6", "route", "show"]),
        ("Routing Table (detailed)", ["ip", "route", "show", "table", "all"]),
        ("Policy Routing Rules", ["ip", "rule", "show"]),
        ("IPv6 Policy Routing Rules", ["ip", "-6", "rule", "show"]),
    ]
    
    print("\n" + "="*50)
    print("ROUTING INFORMATION")
    print("="*50)
    
    for name, cmd in routing_commands:
        run_command(name, cmd)
    
    # Neighbor/ARP Information
    neighbor_commands = [
        ("IPv4 ARP/Neighbor Table", ["ip", "neigh", "show"]),
        ("IPv6 Neighbor Table", ["ip", "-6", "neigh", "show"]),
        ("ARP Table (legacy)", ["arp", "-a"]),
        ("Bridge FDB Entries", ["bridge", "fdb", "show"]),
    ]
    
    print("\n" + "="*50)
    print("NEIGHBOR/ARP TABLES")
    print("="*50)
    
    for name, cmd in neighbor_commands:
        run_command(name, cmd)
    
    # Firewall Configuration
    firewall_commands = [
        ("IPTables - Filter Table", ["iptables", "-L", "-v", "-n"]),
        ("IPTables - NAT Table", ["iptables", "-t", "nat", "-L", "-v", "-n"]),
        ("IPTables - Mangle Table", ["iptables", "-t", "mangle", "-L", "-v", "-n"]),
        ("IPTables - Raw Table", ["iptables", "-t", "raw", "-L", "-v", "-n"]),
        ("IP6Tables Rules", ["ip6tables", "-L", "-v", "-n"]),
        ("UFW Status", ["ufw", "status", "verbose"]),
        ("NFTables Rules", ["nft", "list", "ruleset"]),
    ]
    
    print("\n" + "="*50)
    print("FIREWALL CONFIGURATION")
    print("="*50)
    
    for name, cmd in firewall_commands:
        run_command(name, cmd)
    
    # Network Connections and Sockets
    connection_commands = [
        ("Active Network Connections", ["ss", "-tulpn"]),
        ("Listening Services", ["ss", "-tlnp"]),
        ("Network Statistics", ["ss", "-s"]),
        ("Netstat Active Connections", ["netstat", "-tulpn"]),
        ("Unix Domain Sockets", ["ss", "-xlp"]),
    ]
    
    print("\n" + "="*50)
    print("NETWORK CONNECTIONS & SOCKETS")
    print("="*50)
    
    for name, cmd in connection_commands:
        run_command(name, cmd)
    
    # DNS Configuration
    dns_commands = [
        ("DNS Resolvers", ["systemd-resolve", "--status"]),
        ("DNS Configuration", ["cat", "/etc/resolv.conf"]),
        ("Systemd Network Config", "find /etc/systemd/network -name '*.network' -exec echo '=== {} ===' \\; -exec cat {} \\;"),
        ("NetworkManager Status", ["nmcli", "general", "status"]),
        ("NetworkManager Connections", ["nmcli", "connection", "show"]),
    ]
    
    print("\n" + "="*50)
    print("DNS & NETWORK MANAGEMENT")
    print("="*50)
    
    for name, cmd in dns_commands:
        run_command(name, cmd)
    
    # Bridge and VLAN Information
    bridge_vlan_commands = [
        ("Bridge Interfaces", ["brctl", "show"]),
        ("Bridge Details (ip)", ["ip", "link", "show", "type", "bridge"]),
        ("VLAN Interfaces", ["ip", "link", "show", "type", "vlan"]),
        ("Bridge VLAN Info", ["bridge", "vlan", "show"]),
        ("Open vSwitch Bridges", ["ovs-vsctl", "show"]),
    ]
    
    print("\n" + "="*50)
    print("BRIDGES & VLANS")
    print("="*50)
    
    for name, cmd in bridge_vlan_commands:
        run_command(name, cmd)
    
    # Network Namespaces and Containers
    namespace_commands = [
        ("Network Namespaces", ["ip", "netns", "list"]),
        ("Docker Networks", ["docker", "network", "ls"]),
        ("Container Network Info", ["docker", "network", "inspect", "bridge"]),
    ]
    
    print("\n" + "="*50)
    print("NETWORK NAMESPACES & CONTAINERS")
    print("="*50)
    
    for name, cmd in namespace_commands:
        run_command(name, cmd)
    
    # System Network Files
    print("\n" + "="*50)
    print("SYSTEM NETWORK CONFIGURATION FILES")
    print("="*50)
    
    config_files = [
        ("/etc/hosts", "Host File"),
        ("/etc/hostname", "System Hostname"),
        ("/etc/networks", "Network Names"),
        ("/etc/protocols", "Protocol Definitions"),
        ("/etc/services", "Service Port Mappings"),
        ("/proc/net/dev", "Network Device Statistics"),
        ("/proc/net/route", "Kernel Routing Table"),
        ("/proc/net/arp", "Kernel ARP Table"),
        ("/proc/sys/net/ipv4/ip_forward", "IPv4 Forwarding"),
        ("/proc/sys/net/ipv6/conf/all/forwarding", "IPv6 Forwarding"),
    ]
    
    for filepath, description in config_files:
        if check_file_exists(filepath):
            run_command(f"{description} ({filepath})", ["cat", filepath])
        else:
            print(f"\n=== {description} ({filepath}) ===")
            print("File not found or not readable")
    
    # Network Performance and Statistics
    performance_commands = [
        ("Network Interface Statistics", ["cat", "/proc/net/dev"]),
        ("Network Protocol Statistics", ["cat", "/proc/net/snmp"]),
        ("TCP Connection Statistics", ["cat", "/proc/net/sockstat"]),
        ("Network Memory Usage", ["cat", "/proc/net/protocols"]),
    ]
    
    print("\n" + "="*50)
    print("NETWORK PERFORMANCE & STATISTICS")
    print("="*50)
    
    for name, cmd in performance_commands:
        run_command(name, cmd)

    
    # Advanced Network Diagnostics
    advanced_commands = [
        ("Network Traffic Control (TC) Rules", ["tc", "qdisc", "show"]),
        ("Traffic Control Filters", ["tc", "filter", "show", "dev", "eth0"]),
        ("Multicast Groups", ["ip", "maddress", "show"]),
        ("Network Device Queues", "find /sys/class/net -name 'queues' -exec echo '=== {} ===' \\; -exec ls -la {} \\;"),
        ("XDP Programs", ["ip", "link", "show", "xdp"]),
        ("BPF Programs", ["bpftool", "prog", "show"]),
        ("Loaded Kernel Modules (network)", "lsmod | grep -E '(net|eth|wlan|wifi|bridge|vlan)'"),
    ]
    
    print("\n" + "="*50)
    print("ADVANCED NETWORK DIAGNOSTICS")
    print("="*50)
    
    for name, cmd in advanced_commands:
        run_command(name, cmd)
    
    # Security and Access Control
    security_commands = [
        ("SELinux Network Contexts", ["semanage", "port", "-l"]),
        ("AppArmor Network Profiles", "find /etc/apparmor.d -name '*network*' -exec cat {} \\;"),
        ("Network Capabilities", ["getcap", "-r", "/usr/bin/*", "|", "grep", "net"]),
    ]
    
    print("\n" + "="*50)
    print("NETWORK SECURITY & ACCESS CONTROL")
    print("="*50)
    
    for name, cmd in security_commands:
        if isinstance(cmd, str):
            run_command(name, cmd)
        else:
            run_command(name, cmd)
    
    # Final Summary
    print("\n" + "="*80)
    print("NETWORK DIAGNOSTIC SUMMARY")
    print("="*80)
    
    print("This comprehensive network diagnostic has collected:")
    print("• Network interface information and hardware details")
    print("• IPv4/IPv6 routing tables and policy rules") 
    print("• ARP/Neighbor tables and bridge forwarding database")
    print("• Firewall rules (iptables, ip6tables, ufw, nftables)")
    print("• Active connections, listening services, and socket statistics")
    print("• DNS configuration and network management settings")
    print("• Bridge, VLAN, and virtual network configurations")
    print("• Network namespaces and container networking")
    print("• System network configuration files")
    print("• Network performance statistics and protocol information")
    print("• Advanced networking features (TC, XDP, BPF)")
    print("• Network security and access control settings")
    print(f"\nDiagnostic completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    try:
        debug_network_comprehensive()
    except KeyboardInterrupt:
        print("\n\nDiagnostic interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        sys.exit(1)