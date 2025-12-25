#!/usr/bin/env python3
"""
Load IP allowlist from JSON file into BPF hash map
Usage: sudo python3 load_ip_allowlist.py <ip_data.json>
       sudo python3 load_ip_allowlist.py --display  # Show loaded IPs
       sudo python3 load_ip_allowlist.py --clear    # Clear all IPs
"""

import sys
import subprocess
import ipaddress
import json
import argparse

def ip_to_bytes(ip_str):
    """Convert IP string to 4-byte representation for BPF map"""
    try:
        ip = ipaddress.IPv4Address(ip_str)
        return ip.packed.hex()
    except ValueError as e:
        print(f"Invalid IP address {ip_str}: {e}")
        return None

def load_from_json(json_file):
    """Load IPs from JSON file and populate BPF map"""
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
        
        # Extract IPs from flat_ip_list for efficiency
        if 'flat_ip_list' in data:
            ip_list = data['flat_ip_list']
            total_expected = len(ip_list)
        else:
            # Extract from organizations structure
            ip_list = []
            for org in data.get('organizations', []):
                ip_list.extend(org.get('ips', []))
            total_expected = len(ip_list)
        
        print(f"Loading {total_expected} IPs from {json_file}")
        loaded_count = 0
        
        for ip_str in ip_list:
            ip_bytes = ip_to_bytes(ip_str.strip())
            if ip_bytes:
                # Add to BPF map (value 1 = allowed)
                cmd = ['bpftool', 'map', 'update', 'name', 'ip_allowlist', 
                       'key', 'hex'] + [ip_bytes[i:i+2] for i in range(0, 8, 2)] + ['value', 'hex', '01']
                
                try:
                    subprocess.run(cmd, check=True, capture_output=True, text=True)
                    loaded_count += 1
                except subprocess.CalledProcessError as e:
                    print(f"Failed to add IP {ip_str}: {e.stderr}")
        
        print(f"Successfully loaded {loaded_count}/{total_expected} IPs into allowlist")
        return loaded_count
    
    except FileNotFoundError:
        print(f"Error: JSON file {json_file} not found")
        return 0
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON format in {json_file}: {e}")
        return 0
    except Exception as e:
        print(f"Error loading JSON file: {e}")
        return 0

def display_loaded_ips():
    """Display all IPs currently loaded in the BPF map"""
    try:
        cmd = ['bpftool', 'map', 'dump', 'name', 'ip_allowlist']
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        
        lines = result.stdout.strip().split('\n')
        ip_count = 0
        
        print("Currently loaded IP addresses:")
        print("-" * 40)
        
        for line in lines:
            if 'key:' in line and 'value:' in line:
                # Extract hex key
                key_part = line.split('key:')[1].split('value:')[0].strip()
                hex_bytes = key_part.replace(' ', '')
                
                try:
                    # Convert hex to IP
                    ip_bytes = bytes.fromhex(hex_bytes)
                    if len(ip_bytes) == 4:
                        ip = ipaddress.IPv4Address(ip_bytes)
                        print(f"{ip_count+1:3d}. {ip}")
                        ip_count += 1
                except Exception as e:
                    print(f"Error parsing IP from {hex_bytes}: {e}")
        
        print("-" * 40)
        print(f"Total IPs loaded: {ip_count}")
        
    except subprocess.CalledProcessError as e:
        if 'No such file or directory' in e.stderr:
            print("BPF map 'ip_allowlist' not found. Is the XDP program loaded?")
        else:
            print(f"Error reading BPF map: {e.stderr}")
    except Exception as e:
        print(f"Error displaying IPs: {e}")

def clear_all_ips():
    """Clear all IPs from the BPF map"""
    try:
        # First get all keys
        cmd = ['bpftool', 'map', 'dump', 'name', 'ip_allowlist']
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        
        lines = result.stdout.strip().split('\n')
        deleted_count = 0
        
        print("Clearing all IPs from allowlist...")
        
        for line in lines:
            if 'key:' in line:
                # Extract hex key
                key_part = line.split('key:')[1].split('value:')[0].strip()
                hex_bytes = key_part.replace(' ', '').replace('0x', '')
                
                # Delete from map
                cmd = ['bpftool', 'map', 'delete', 'name', 'ip_allowlist', 'key', 'hex'] + \
                      [hex_bytes[i:i+2] for i in range(0, len(hex_bytes), 2)]
                
                try:
                    subprocess.run(cmd, check=True, capture_output=True)
                    deleted_count += 1
                except subprocess.CalledProcessError:
                    pass  # Key might already be deleted
        
        print(f"Cleared {deleted_count} IPs from allowlist")
        
    except subprocess.CalledProcessError as e:
        if 'No such file or directory' in e.stderr:
            print("BPF map 'ip_allowlist' not found. Is the XDP program loaded?")
        else:
            print(f"Error accessing BPF map: {e.stderr}")

def main():
    parser = argparse.ArgumentParser(description='Manage IP allowlist for XDP program')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('json_file', nargs='?', help='JSON file to load IPs from')
    group.add_argument('--display', action='store_true', help='Display currently loaded IPs')
    group.add_argument('--clear', action='store_true', help='Clear all loaded IPs')
    
    args = parser.parse_args()
    
    if args.display:
        display_loaded_ips()
    elif args.clear:
        clear_all_ips()
    elif args.json_file:
        load_from_json(args.json_file)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()