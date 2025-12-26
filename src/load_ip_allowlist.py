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
import re
import time

def parse_bpf_key_robust(line):
    """More robust parsing of bpftool output using regex"""
    # Match various hex key formats that bpftool might output
    hex_patterns = [
        r'key:\s*([0-9a-f\s]+)\s*value:',  # Standard format
        r'"key":\s*\[([0-9a-f,\s]+)\]',    # JSON format
        r'key\s*=\s*([0-9a-f\s]+)\s*value', # Alternative format
    ]
    
    for pattern in hex_patterns:
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            hex_str = match.group(1)
            # Clean up hex string - remove spaces, commas, 0x prefixes
            cleaned = re.sub(r'[^0-9a-f]', '', hex_str, flags=re.IGNORECASE)
            return cleaned
    return None

def ip_to_hex_key(ip_str):
    """Convert IP string to hex key format for bpftool"""
    ip_bytes = ip_to_bytes(ip_str)
    if ip_bytes:
        return ' '.join([f'{b:02x}' for b in ip_bytes])
    return None

def ip_to_bytes(ip_str):
    """Convert IP string to 4-byte representation for BPF map"""
    try:
        ip = ipaddress.IPv4Address(ip_str)
        return ip.packed
    except ValueError as e:
        print(f"Invalid IP address {ip_str}: {e}")
        return None

def load_from_json(json_file):
    """Load IPs from JSON file and populate BPF map with enhanced error recovery"""
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
        
        # Check if BPF map exists first
        check_cmd = ['bpftool', 'map', 'show', 'name', 'ip_allowlist']
        try:
            subprocess.run(check_cmd, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError:
            print("Error: BPF map 'ip_allowlist' not found. Please load the XDP program first.")
            print("Run: sudo ./vxlan_loader -i <interface> --load-xdp")
            return 0
        
        loaded_count = 0
        failed_count = 0
        failed_ips = []
        start_time = time.time()
        
        for i, ip_str in enumerate(ip_list, 1):
            ip_str = ip_str.strip()
            hex_key = ip_to_hex_key(ip_str)
            
            if not hex_key:
                failed_count += 1
                failed_ips.append(f"{ip_str} (invalid format)")
                continue
                
            # Add to BPF map (value 1 = allowed)
            cmd = ['bpftool', 'map', 'update', 'name', 'ip_allowlist', 
                   'key', 'hex'] + hex_key.split() + ['value', 'hex', '01']
            
            try:
                subprocess.run(cmd, check=True, capture_output=True, text=True)
                loaded_count += 1
                
                # Enhanced progress reporting with ETA
                if loaded_count % 25 == 0 or i == total_expected:
                    elapsed = time.time() - start_time
                    rate = loaded_count / elapsed if elapsed > 0 else 0
                    eta = (total_expected - loaded_count) / rate if rate > 0 else 0
                    print(f"Progress: {loaded_count}/{total_expected} IPs ({rate:.1f}/sec, ETA: {eta:.1f}s)")
                    
            except subprocess.CalledProcessError as e:
                failed_count += 1
                error_msg = e.stderr.strip() if e.stderr else 'Unknown error'
                failed_ips.append(f"{ip_str} ({error_msg})")
                
                # Show command for first failure only
                if failed_count == 1:
                    print(f"Debug: First failure command: {' '.join(cmd)}")
        
        # Summary report
        elapsed_total = time.time() - start_time
        success_rate = (loaded_count / total_expected * 100) if total_expected > 0 else 0
        
        print(f"\nLoad Summary:")
        print(f"  Successfully loaded: {loaded_count}/{total_expected} ({success_rate:.1f}%)")
        print(f"  Failed: {failed_count}")
        print(f"  Total time: {elapsed_total:.2f}s")
        print(f"  Average rate: {loaded_count/elapsed_total:.1f} IPs/sec")
        
        # Show failed IPs if any (limit to first 10)
        if failed_ips:
            print(f"\nFailed IPs (showing first {min(10, len(failed_ips))}):")
            for ip_error in failed_ips[:10]:
                print(f"  - {ip_error}")
            if len(failed_ips) > 10:
                print(f"  ... and {len(failed_ips) - 10} more")
        
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
    """Display all IPs currently loaded in the BPF map with enhanced parsing"""
    try:
        cmd = ['bpftool', 'map', 'dump', 'name', 'ip_allowlist']
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        
        lines = result.stdout.strip().split('\n')
        ip_addresses = []
        parse_errors = 0
        
        print("Currently loaded IP addresses:")
        print("-" * 50)
        
        for line in lines:
            if 'key:' in line and 'value:' in line:
                # Use robust parsing function
                hex_key = parse_bpf_key_robust(line)
                
                if hex_key and len(hex_key) == 8:  # Exactly 4 bytes = 8 hex chars
                    try:
                        ip_bytes = bytes.fromhex(hex_key)
                        ip = ipaddress.IPv4Address(ip_bytes)
                        ip_addresses.append(str(ip))
                    except (ValueError, ipaddress.AddressValueError) as e:
                        parse_errors += 1
                        print(f"Warning: Could not parse IP from hex '{hex_key}': {e}")
                elif hex_key:
                    parse_errors += 1
                    print(f"Warning: Unexpected key length {len(hex_key)} chars for: {hex_key}")
        
        # Sort IPs for better readability
        try:
            ip_addresses.sort(key=lambda x: ipaddress.IPv4Address(x))
        except:
            ip_addresses.sort()  # Fallback to string sort
        
        # Display IPs in columns for better readability
        for i, ip in enumerate(ip_addresses, 1):
            if i % 3 == 1:
                print(f"{i:3d}. {ip:<15}", end="")
            elif i % 3 == 2:
                print(f" {i:3d}. {ip:<15}", end="")
            else:
                print(f" {i:3d}. {ip:<15}")
        
        # Handle last line if not complete
        if len(ip_addresses) % 3 != 0:
            print()
        
        print("-" * 50)
        print(f"Total IPs loaded: {len(ip_addresses)}")
        if parse_errors > 0:
            print(f"Parse errors: {parse_errors}")
        
    except subprocess.CalledProcessError as e:
        if 'No such file or directory' in e.stderr:
            print("BPF map 'ip_allowlist' not found. Is the XDP program loaded?")
        else:
            print(f"Error reading BPF map: {e.stderr}")
    except Exception as e:
        print(f"Error displaying IPs: {e}")

def clear_all_ips():
    """Clear all IPs from the BPF map with enhanced error handling"""
    try:
        # First get all keys
        cmd = ['bpftool', 'map', 'dump', 'name', 'ip_allowlist']
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        
        lines = result.stdout.strip().split('\n')
        deleted_count = 0
        failed_count = 0
        
        print("Clearing all IPs from allowlist...")
        
        for line in lines:
            if 'key:' in line:
                # Use robust parsing function
                hex_key = parse_bpf_key_robust(line)
                
                if hex_key and len(hex_key) == 8:  # 4 bytes = 8 hex chars
                    # Convert to space-separated hex bytes for bpftool
                    hex_bytes = [hex_key[i:i+2] for i in range(0, 8, 2)]
                    
                    # Delete from map
                    cmd = ['bpftool', 'map', 'delete', 'name', 'ip_allowlist', 'key', 'hex'] + hex_bytes
                    
                    try:
                        subprocess.run(cmd, check=True, capture_output=True)
                        deleted_count += 1
                        
                        # Progress indicator for large maps
                        if deleted_count % 100 == 0:
                            print(f"Cleared {deleted_count} IPs so far...")
                            
                    except subprocess.CalledProcessError:
                        failed_count += 1
                        # Key might already be deleted or invalid - continue processing
        
        print(f"Successfully cleared {deleted_count} IPs from allowlist")
        if failed_count > 0:
            print(f"Failed to clear {failed_count} entries (may already be deleted)")
        
    except subprocess.CalledProcessError as e:
        if 'No such file or directory' in e.stderr:
            print("BPF map 'ip_allowlist' not found. Is the XDP program loaded?")
        else:
            print(f"Error accessing BPF map: {e.stderr}")
    except Exception as e:
        print(f"Error clearing IPs: {e}")
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