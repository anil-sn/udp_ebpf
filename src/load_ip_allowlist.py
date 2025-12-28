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
import os

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
                
                # Enhanced progress reporting with ETA (overwrite same line)
                if loaded_count % 25 == 0 or i == total_expected:
                    elapsed = time.time() - start_time
                    rate = loaded_count / elapsed if elapsed > 0 else 0
                    eta = (total_expected - loaded_count) / rate if rate > 0 else 0
                    print(f"\rProgress: {loaded_count}/{total_expected} IPs ({rate:.1f}/sec, ETA: {eta:.1f}s)", end="", flush=True)
                    
            except subprocess.CalledProcessError as e:
                failed_count += 1
                error_msg = e.stderr.strip() if e.stderr else 'Unknown error'
                failed_ips.append(f"{ip_str} ({error_msg})")
                
                # Show command for first failure only
                if failed_count == 1:
                    print(f"Debug: First failure command: {' '.join(cmd)}")
        
        # Finalize progress line before summary
        print()
        
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
    """Display all IPs currently loaded in the BPF map with organization information"""
    try:
        # Load organization information from JSON file
        org_mapping = {}
        try:
            with open('ip_allowlist.json', 'r') as f:
                data = json.load(f)
                for org in data.get('organizations', []):
                    org_name = org.get('org_name', 'Unknown')
                    org_id = org.get('org_id', 'N/A')
                    # Don't truncate org names - let table handle full width
                    for ip in org.get('ips', []):
                        org_mapping[ip] = {
                            'name': org_name,
                            'id': org_id
                        }
        except FileNotFoundError:
            print("Warning: ip_allowlist.json not found, showing IPs without organization info")
        except Exception as e:
            print(f"Warning: Could not load organization info: {e}")
        
        # Use JSON format directly instead of parsing text
        cmd = ['bpftool', 'map', 'dump', 'name', 'ip_allowlist', '--json']
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        
        ip_addresses = []
        
        try:
            json_data = json.loads(result.stdout)
            
            for entry in json_data:
                # The bpftool JSON structure has 'formatted' key with the actual data
                if 'formatted' in entry and 'key' in entry['formatted']:
                    try:
                        key_val = entry['formatted']['key']
                        
                        if isinstance(key_val, int):
                            # Manual bit manipulation for little-endian BPF map format
                            ip_str = f"{key_val & 0xFF}.{(key_val >> 8) & 0xFF}.{(key_val >> 16) & 0xFF}.{(key_val >> 24) & 0xFF}"
                            ip_addresses.append(ip_str)
                        
                    except (ValueError, OverflowError) as e:
                        print(f"Warning: Could not parse IP from {entry}: {e}")
                        
        except json.JSONDecodeError as e:
            print(f"ERROR: JSON parsing failed: {e}")
            # Show raw output for debugging
            print("Raw output:")
            print(result.stdout[:500])
            return
        print("Currently loaded IP addresses:")
        print("-" * 50)
        
        # Sort IPs for better readability
        try:
            ip_addresses.sort(key=lambda x: ipaddress.IPv4Address(x))
        except Exception as e:
            print(f"Warning: Could not sort IPs: {e}")
            ip_addresses.sort()  # Fallback to string sort
        
        # Group IPs by organization and display in a grouped table format
        if ip_addresses:
            print("=== IP ALLOWLIST ===")
            print(f"Allowed IP Addresses: {len(ip_addresses)} total")
            print()
            
            # Group IPs by organization
            org_groups = {}
            unmatched_ips = []
            
            for ip in ip_addresses:
                if ip in org_mapping:
                    org_info = org_mapping[ip]
                    org_key = f"{org_info['name']} (ID: {org_info['id']})"
                    if org_key not in org_groups:
                        org_groups[org_key] = []
                    org_groups[org_key].append(ip)
                else:
                    unmatched_ips.append(ip)
            
            # Display grouped by organization
            for org_name, org_ips in sorted(org_groups.items()):
                print(f"┌{'─' * 80}┐")
                print(f"│ {org_name:<78} │")
                print(f"├{'─' * 80}┤")
                
                # Display IPs in rows of 4 for this organization
                for i in range(0, len(org_ips), 4):
                    row_ips = org_ips[i:i+4]
                    ip_row = "  ".join(f"{ip:<17}" for ip in row_ips)
                    print(f"│ {ip_row:<78} │")
                
                print(f"└{'─' * 80}┘")
                print()
            
            # Display unmatched IPs if any
            if unmatched_ips:
                print(f"┌{'─' * 80}┐")
                print(f"│ {'Unknown Organizations':<78} │")
                print(f"├{'─' * 80}┤")
                
                for i in range(0, len(unmatched_ips), 4):
                    row_ips = unmatched_ips[i:i+4]
                    ip_row = "  ".join(f"{ip:<17}" for ip in row_ips)
                    print(f"│ {ip_row:<78} │")
                
                print(f"└{'─' * 80}┘")
                print()
            
            # Show summary
            first_ip = ipaddress.IPv4Address(ip_addresses[0])
            last_ip = ipaddress.IPv4Address(ip_addresses[-1])
            unique_orgs = len(org_groups)
            print(f"Summary:")
            print(f"  • IP Range: {first_ip} → {last_ip}")
            print(f"  • Organizations: {unique_orgs} unique organizations")
            print(f"  • Unmatched IPs: {len(unmatched_ips)}")
        else:
            print("No IP addresses found in allowlist")
        
        print("-" * 50)
        print(f"Total IPs loaded: {len(ip_addresses)}")
        
    except subprocess.CalledProcessError as e:
        if 'No such file or directory' in e.stderr:
            print("BPF map 'ip_allowlist' not found. Is the XDP program loaded?")
        else:
            print(f"Error reading BPF map: {e.stderr}")
            print(f"DEBUG: Command output: {e.stdout}")
    except Exception as e:
        print(f"Error displaying IPs: {e}")

def check_ip_status():
    """Check status of IPs comparing JSON file with eBPF map"""
    try:
        # Load IPs from JSON file
        json_file = 'ip_allowlist.json'
        if not os.path.exists(json_file):
            print(f"Error: {json_file} not found")
            return
            
        with open(json_file, 'r') as f:
            data = json.load(f)
        
        # Get IPs from JSON
        if 'flat_ip_list' in data:
            json_ips = set(data['flat_ip_list'])
        else:
            json_ips = set()
            for org in data.get('organizations', []):
                json_ips.update(org.get('ips', []))
        
        # Get IPs from eBPF map
        map_ips = get_ips_from_map()
        
        # Create organization mapping
        org_mapping = {}
        for org in data.get('organizations', []):
            org_name = org.get('org_name', 'Unknown')
            org_id = org.get('org_id', 'N/A')
            for ip in org.get('ips', []):
                org_mapping[ip] = {'name': org_name, 'id': org_id}
        
        print("=== IP ALLOWLIST STATUS CHECK ===")
        print(f"JSON File: {json_file}")
        print(f"JSON IPs: {len(json_ips)}")
        print(f"Map IPs: {len(map_ips)}")
        print()
        
        # Check each JSON IP against map
        active_count = 0
        inactive_count = 0
        
        print("┌─── IP STATUS REPORT ───────────────────────────────────────────────────────┐")
        print("│ Status │ IP Address      │ Organization                                    │")
        print("├────────┼─────────────────┼─────────────────────────────────────────────────┤")
        
        for ip in sorted(json_ips, key=lambda x: ipaddress.IPv4Address(x)):
            status = "ACTIVE" if ip in map_ips else "INACTIVE"
            if status == "ACTIVE":
                active_count += 1
            else:
                inactive_count += 1
                
            org_info = org_mapping.get(ip, {'name': 'Unknown', 'id': 'N/A'})
            org_display = f"{org_info['name'][:40]}{'...' if len(org_info['name']) > 40 else ''}"
            
            print(f"│ {status:6} │ {ip:15} │ {org_display:47} │")
        
        print("└────────┴─────────────────┴─────────────────────────────────────────────────┘")
        print()
        print(f"Summary:")
        print(f"  • Active IPs (in both JSON and map): {active_count}")
        print(f"  • Inactive IPs (in JSON but not in map): {inactive_count}")
        
        # Show orphaned IPs (in map but not in JSON)
        orphaned_ips = map_ips - json_ips
        if orphaned_ips:
            print(f"  • Orphaned IPs (in map but not in JSON): {len(orphaned_ips)}")
            print("\n--- ORPHANED IPs (in eBPF map but not in JSON) ---")
            for ip in sorted(orphaned_ips, key=lambda x: ipaddress.IPv4Address(x)):
                print(f"    {ip} (source unknown - manually added or from old config)")
        
        # Show recommendations
        print("\nRecommendations:")
        if inactive_count > 0:
            print(f"  • Run 'sudo python3 load_ip_allowlist.py --reload' to activate {inactive_count} inactive IPs")
        if orphaned_ips:
            print(f"  • Consider updating JSON file or clearing orphaned IPs")
        if active_count == len(json_ips) and not orphaned_ips:
            print(f"  • ✓ Perfect sync: All {active_count} IPs are properly configured")
            
    except Exception as e:
        print(f"Error checking IP status: {e}")

def reload_ips_from_json():
    """Reload IPs from JSON file (clear and reload)"""
    json_file = 'ip_allowlist.json'
    if not os.path.exists(json_file):
        print(f"Error: {json_file} not found")
        return
        
    print("=== RELOADING IP ALLOWLIST ===")
    print("Step 1: Clearing existing IPs...")
    clear_all_ips()
    print("\nStep 2: Loading IPs from JSON...")
    loaded_count = load_from_json(json_file)
    print(f"\n✓ Reload complete: {loaded_count} IPs loaded from {json_file}")

def show_orphaned_ips():
    """Show IPs that are in the eBPF map but not in the JSON file"""
    try:
        # Load IPs from JSON file
        json_file = 'ip_allowlist.json'
        json_ips = set()
        
        if os.path.exists(json_file):
            with open(json_file, 'r') as f:
                data = json.load(f)
            
            if 'flat_ip_list' in data:
                json_ips = set(data['flat_ip_list'])
            else:
                for org in data.get('organizations', []):
                    json_ips.update(org.get('ips', []))
        
        # Get IPs from eBPF map
        map_ips = get_ips_from_map()
        
        # Find orphaned IPs
        orphaned_ips = map_ips - json_ips
        
        print("=== ORPHANED IPs (in eBPF map but not in JSON) ===")
        if orphaned_ips:
            print(f"Found {len(orphaned_ips)} orphaned IP addresses:")
            print()
            for i, ip in enumerate(sorted(orphaned_ips, key=lambda x: ipaddress.IPv4Address(x)), 1):
                print(f"  {i:2}. {ip:15} (source: unknown - manually added or from old config)")
            print()
            print("These IPs are active in the eBPF map but not defined in the JSON configuration.")
            print("They may have been:")
            print("  • Manually added via bpftool")
            print("  • Left over from a previous configuration")
            print("  • Added by a different script")
            print()
            print("To clean up: sudo python3 load_ip_allowlist.py --clear && sudo python3 load_ip_allowlist.py ip_allowlist.json")
        else:
            print("✓ No orphaned IPs found. All active IPs are properly defined in the JSON file.")
            print(f"JSON IPs: {len(json_ips)}, Map IPs: {len(map_ips)}")
            
    except Exception as e:
        print(f"Error checking orphaned IPs: {e}")

def get_ips_from_map():
    """Get set of IP addresses currently loaded in the eBPF map"""
    try:
        # Use JSON format for reliable parsing
        cmd = ['bpftool', 'map', 'dump', 'name', 'ip_allowlist', '--json']
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        
        ip_addresses = set()
        
        if result.stdout.strip():
            try:
                json_data = json.loads(result.stdout)
                
                for entry in json_data:
                    if 'formatted' in entry and 'key' in entry['formatted']:
                        try:
                            key_val = entry['formatted']['key']
                            if isinstance(key_val, int):
                                ip_int = key_val
                            else:
                                continue
                                
                            # Convert integer IP to dotted decimal notation
                            ip1 = ip_int & 0xFF
                            ip2 = (ip_int >> 8) & 0xFF
                            ip3 = (ip_int >> 16) & 0xFF
                            ip4 = (ip_int >> 24) & 0xFF
                            ip_str = f"{ip1}.{ip2}.{ip3}.{ip4}"
                            
                            # Validate IP
                            ipaddress.IPv4Address(ip_str)
                            ip_addresses.add(ip_str)
                            
                        except (ValueError, OverflowError):
                            continue
                            
            except json.JSONDecodeError:
                pass
                
        return ip_addresses
        
    except subprocess.CalledProcessError:
        return set()

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
def sync_ips_with_json(json_file='ip_allowlist.json', dry_run=False):
    """
    Synchronize eBPF map with JSON file using mark and sweep approach.
    Adds new IPs and removes orphaned ones.
    """
    print(f"Synchronizing IP allowlist with {json_file}...")
    
    # Load target IPs from JSON
    target_ips = set()
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
        
        if 'flat_ip_list' in data:
            target_ips = set(data['flat_ip_list'])
        else:
            for org in data.get('organizations', []):
                target_ips.update(org.get('ips', []))
    except Exception as e:
        print(f"Error loading JSON file: {e}")
        return False
    
    # Get currently loaded IPs from eBPF map
    current_ips = set()
    try:
        cmd = ['bpftool', 'map', 'dump', 'name', 'ip_allowlist', '--json']
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        
        json_data = json.loads(result.stdout)
        for entry in json_data:
            if 'formatted' in entry and 'key' in entry['formatted']:
                key_val = entry['formatted']['key']
                if isinstance(key_val, int):
                    ip_str = f"{key_val & 0xFF}.{(key_val >> 8) & 0xFF}.{(key_val >> 16) & 0xFF}.{(key_val >> 24) & 0xFF}"
                    current_ips.add(ip_str)
    except Exception as e:
        print(f"Error reading current eBPF map: {e}")
        return False
    
    # Calculate differences
    ips_to_add = target_ips - current_ips
    ips_to_remove = current_ips - target_ips
    
    print(f"Current state:")
    print(f"  - IPs in JSON: {len(target_ips)}")
    print(f"  - IPs in eBPF map: {len(current_ips)}")
    print(f"  - IPs to add: {len(ips_to_add)}")
    print(f"  - IPs to remove: {len(ips_to_remove)}")
    
    if dry_run:
        if ips_to_add:
            print(f"\\nWould ADD {len(ips_to_add)} IPs:")
            for ip in sorted(ips_to_add)[:10]:  # Show first 10
                print(f"  + {ip}")
            if len(ips_to_add) > 10:
                print(f"  ... and {len(ips_to_add) - 10} more")
        
        if ips_to_remove:
            print(f"\\nWould REMOVE {len(ips_to_remove)} IPs:")
            for ip in sorted(ips_to_remove)[:10]:  # Show first 10
                print(f"  - {ip}")
            if len(ips_to_remove) > 10:
                print(f"  ... and {len(ips_to_remove) - 10} more")
        
        return True
    
    # Perform actual sync
    success_count = 0
    fail_count = 0
    
    # Add new IPs
    if ips_to_add:
        print(f"\\nAdding {len(ips_to_add)} new IPs...")
        for ip in ips_to_add:
            if add_single_ip(ip):
                success_count += 1
                print(f"  + Added: {ip}")
            else:
                fail_count += 1
                print(f"  × Failed to add: {ip}")
    
    # Remove orphaned IPs (mark and sweep)
    if ips_to_remove:
        print(f"\\nRemoving {len(ips_to_remove)} orphaned IPs...")
        for ip in ips_to_remove:
            if remove_single_ip(ip):
                success_count += 1
                print(f"  - Removed: {ip}")
            else:
                fail_count += 1
                print(f"  × Failed to remove: {ip}")
    
    print(f"\\nSync complete: {success_count} operations successful, {fail_count} failed")
    return fail_count == 0

def add_single_ip(ip_str):
    """Add a single IP to the eBPF map"""
    hex_key = ip_to_hex_key(ip_str)
    if not hex_key:
        return False
    
    cmd = ['bpftool', 'map', 'update', 'name', 'ip_allowlist', 
           'key', 'hex'] + hex_key.split() + ['value', 'hex', '01']
    
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        return True
    except subprocess.CalledProcessError:
        return False

def remove_single_ip(ip_str):
    """Remove a single IP from the eBPF map"""
    hex_key = ip_to_hex_key(ip_str)
    if not hex_key:
        return False
    
    cmd = ['bpftool', 'map', 'delete', 'name', 'ip_allowlist', 
           'key', 'hex'] + hex_key.split()
    
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        return True
    except subprocess.CalledProcessError:
        return False

def watch_json_and_sync(json_file='ip_allowlist.json', interval=30):
    """
    Watch JSON file for changes and automatically sync with eBPF map
    """
    import hashlib
    import os
    
    print(f"Watching {json_file} for changes (checking every {interval} seconds)...")
    print("Press Ctrl+C to stop watching")
    
    last_hash = None
    
    try:
        while True:
            # Calculate file hash to detect changes
            if os.path.exists(json_file):
                with open(json_file, 'rb') as f:
                    current_hash = hashlib.md5(f.read()).hexdigest()
                
                if last_hash is None:
                    # First run - do initial sync
                    print(f"Initial sync with {json_file}")
                    sync_ips_with_json(json_file)
                    last_hash = current_hash
                elif current_hash != last_hash:
                    # File changed - resync
                    print(f"\\n{json_file} changed, resyncing...")
                    sync_ips_with_json(json_file)
                    last_hash = current_hash
            else:
                print(f"Warning: {json_file} not found")
            
            time.sleep(interval)
            
    except KeyboardInterrupt:
        print(f"\\nStopped watching {json_file}")

def bulk_add_ips(ip_list):
    """Add multiple IPs efficiently"""
    print(f"Adding {len(ip_list)} IPs to allowlist...")
    
    success_count = 0
    fail_count = 0
    
    for ip in ip_list:
        if add_single_ip(ip.strip()):
            success_count += 1
            if success_count % 50 == 0:
                print(f"Added {success_count} IPs...")
        else:
            fail_count += 1
    
    print(f"Bulk add complete: {success_count} added, {fail_count} failed")
    return success_count, fail_count

def bulk_remove_ips(ip_list):
    """Remove multiple IPs efficiently"""
    print(f"Removing {len(ip_list)} IPs from allowlist...")
    
    success_count = 0
    fail_count = 0
    
    for ip in ip_list:
        if remove_single_ip(ip.strip()):
            success_count += 1
            if success_count % 50 == 0:
                print(f"Removed {success_count} IPs...")
        else:
            fail_count += 1
    
    print(f"Bulk remove complete: {success_count} removed, {fail_count} failed")
    return success_count, fail_count

def main():
    parser = argparse.ArgumentParser(description='Manage IP allowlist for XDP program with runtime add/delete')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('json_file', nargs='?', help='JSON file to load IPs from')
    group.add_argument('--display', action='store_true', help='Display currently loaded IPs')
    group.add_argument('--clear', action='store_true', help='Clear all loaded IPs')
    group.add_argument('--check-status', action='store_true', help='Check status of IPs (JSON vs eBPF map)')
    group.add_argument('--reload', action='store_true', help='Reload IPs from JSON file (clears and reloads)')
    group.add_argument('--show-orphaned', action='store_true', help='Show IPs in map but not in JSON file')
    
    # New runtime management options
    group.add_argument('--sync', metavar='JSON_FILE', help='Sync eBPF map with JSON file (mark and sweep)')
    group.add_argument('--sync-dry-run', metavar='JSON_FILE', help='Show what would be synced without making changes')
    group.add_argument('--add-ip', metavar='IP', help='Add a single IP to the allowlist')
    group.add_argument('--remove-ip', metavar='IP', help='Remove a single IP from the allowlist')
    group.add_argument('--add-ips', metavar='IP_LIST', help='Add comma-separated list of IPs')
    group.add_argument('--remove-ips', metavar='IP_LIST', help='Remove comma-separated list of IPs')
    group.add_argument('--watch', metavar='JSON_FILE', help='Watch JSON file for changes and auto-sync')
    
    # Optional arguments
    parser.add_argument('--interval', type=int, default=30, help='Watch interval in seconds (default: 30)')
    
    args = parser.parse_args()
    
    try:
        if args.display:
            display_loaded_ips()
        elif args.clear:
            clear_all_ips()
        elif args.check_status:
            check_ip_status()
        elif args.reload:
            reload_ips_from_json()
        elif args.show_orphaned:
            show_orphaned_ips()
        elif args.sync:
            success = sync_ips_with_json(args.sync)
            sys.exit(0 if success else 1)
        elif args.sync_dry_run:
            sync_ips_with_json(args.sync_dry_run, dry_run=True)
        elif args.add_ip:
            if add_single_ip(args.add_ip):
                print(f"Successfully added {args.add_ip}")
            else:
                print(f"Failed to add {args.add_ip}")
                sys.exit(1)
        elif args.remove_ip:
            if remove_single_ip(args.remove_ip):
                print(f"Successfully removed {args.remove_ip}")
            else:
                print(f"Failed to remove {args.remove_ip}")
                sys.exit(1)
        elif args.add_ips:
            ip_list = [ip.strip() for ip in args.add_ips.split(',')]
            success_count, fail_count = bulk_add_ips(ip_list)
            sys.exit(0 if fail_count == 0 else 1)
        elif args.remove_ips:
            ip_list = [ip.strip() for ip in args.remove_ips.split(',')]
            success_count, fail_count = bulk_remove_ips(ip_list)
            sys.exit(0 if fail_count == 0 else 1)
        elif args.watch:
            watch_json_and_sync(args.watch, args.interval)
        elif args.json_file:
            load_from_json(args.json_file)
        else:
            parser.print_help()
            
    except KeyboardInterrupt:
        print("\\nOperation interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()