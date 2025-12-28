"""
BPF map operations, management, and inspection utilities
Combines map operations with advanced inspection capabilities
"""

import json
import struct
import ipaddress
from typing import List, Dict, Optional, Any, Tuple
from dataclasses import dataclass
from .models import BPFMapInfo, PipelineStats, BPFMapType
from .utils import CommandRunner, Logger

@dataclass 
class BPFMapEntry:
    """BPF map entry with key/value data"""
    key: Any
    value: Any
    formatted_key: str = ""
    formatted_value: str = ""

class BPFMapManager:
    """BPF map operations and statistics management - matches working solution"""
    
    # Statistics map constants (from working vxlan_pipeline.h)
    STATS = {
        'STAT_TOTAL_PACKETS': 0,
        'STAT_VXLAN_PACKETS': 1,
        'STAT_INNER_PACKETS': 2,
        'STAT_NAT_APPLIED': 3,
        'STAT_DF_CLEARED': 4,
        'STAT_FORWARDED': 5,
        'STAT_REDIRECTED': 6,
        'STAT_ERRORS': 7,
        'STAT_BYTES_PROCESSED': 8,
        'STAT_IP_LEN_UPDATED': 9,
        'STAT_UDP_LEN_UPDATED': 10,
        'STAT_IP_CHECKSUM_UPDATED': 11,
        'STAT_BOUNDS_CHECK_FAILED': 12,
        'STAT_RINGBUF_SUBMITTED': 13,
        'STAT_PACKET_SIZE_DEBUG': 14,
        'STAT_LENGTH_CORRECTIONS': 15,
        'STAT_IP_ALLOWLIST_HITS': 16,     # Filter stats - packets allowed
        'STAT_IP_ALLOWLIST_MISSES': 17,   # Filter stats - packets blocked
        'STAT_DROPPED': 18,
        'STAT_MAX_ENTRIES': 19
    }
    
    def __init__(self, runner: Optional[CommandRunner] = None, logger: Optional[Logger] = None):
        self.runner = runner or CommandRunner()
        self.logger = logger or Logger("bpf_maps")
        self.map_fds = {}  # Store map file descriptors like working solution
        
    def list_maps(self) -> List[BPFMapInfo]:
        """Get list of all BPF maps"""
        maps = []
        
        try:
            result = self.runner.run(['sudo', 'bpftool', 'map', 'list', '--json'], capture=True)
            map_data = json.loads(result.stdout)
            
            for map_info in map_data:
                # Get entry count for each map
                entry_count = self._count_map_entries(map_info['id'])
                
                maps.append(BPFMapInfo(
                    id=map_info['id'],
                    name=map_info.get('name', f"map_{map_info['id']}"),
                    type=map_info['type'],
                    key_size=map_info['key_size'],
                    value_size=map_info['value_size'],
                    max_entries=map_info['max_entries'],
                    entries_count=entry_count,
                    flags=map_info.get('flags', 0)
                ))
                
        except Exception as e:
            self.logger.error(f"Error listing BPF maps: {e}")
            
        return maps
    
    def get_map_by_name(self, name: str) -> Optional[BPFMapInfo]:
        """Get specific map by name"""
        maps = self.list_maps()
        return next((m for m in maps if m.name == name), None)
    
    def map_exists(self, name: str) -> bool:
        """Check if map exists"""
        return self.get_map_by_name(name) is not None
    
    def dump_map(self, name: str, format: str = 'json') -> Optional[Any]:
        """Dump map contents"""
        try:
            cmd = ['sudo', 'bpftool', 'map', 'dump', 'name', name]
            if format == 'json':
                cmd.append('--json')
            
            result = self.runner.run(cmd, capture=True)
            
            if format == 'json':
                return json.loads(result.stdout) if result.stdout.strip() else []
            else:
                return result.stdout
                
        except Exception as e:
            self.logger.error(f"Error dumping map {name}: {e}")
            return None
    
    def get_map_entries(self, name: str) -> List[Dict[str, Any]]:
        """Get map entries as list of key-value pairs"""
        entries = []
        
        try:
            dump_data = self.dump_map(name, 'json')
            if dump_data:
                for entry in dump_data:
                    if 'formatted' in entry:
                        entries.append({
                            'key': entry['formatted'].get('key'),
                            'value': entry['formatted'].get('value'),
                            'raw_key': entry.get('key', []),
                            'raw_value': entry.get('value', [])
                        })
                        
        except Exception as e:
            self.logger.error(f"Error getting entries for map {name}: {e}")
            
    def initialize_maps(self, interface_config: Dict[str, Any]) -> bool:
        """Initialize BPF maps with configuration - matches working solution"""
        try:
            # Initialize NAT map (like working solution)
            self._setup_nat_map(interface_config)
            
            # Initialize interface map 
            self._setup_interface_map(interface_config)
            
            # Initialize redirect map
            self._setup_redirect_map(interface_config)
            
            # Initialize stats map (zero counters)
            self._initialize_stats_map()
            
            self.logger.info("BPF maps initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize BPF maps: {e}")
            return False
    
    def _setup_nat_map(self, config: Dict[str, Any]) -> None:
        """Setup NAT map like working vxlan_loader"""
        try:
            # NAT configuration from working solution
            nat_target_ip = config.get('nat_target_ip', '127.0.0.1')
            nat_target_port = config.get('nat_target_port', 8080)
            source_port = config.get('source_port', 31765)
            
            # CRITICAL: Resolve MAC address first (like working solution)
            target_mac = self._resolve_ip_to_mac(nat_target_ip, config.get('target_interface', 'ens6'))
            if not target_mac:
                raise Exception(f"Failed to resolve MAC address for NAT target IP {nat_target_ip}")
            
            self.logger.info(f"NAT target MAC resolved: {target_mac}")
            
            # Convert IP to network byte order (like inet_pton in working solution)
            import socket
            import struct
            ip_bytes = socket.inet_aton(nat_target_ip)  # Already in network byte order
            
            # Create NAT entry (matches working solution struct nat_entry exactly)
            # target_ip: network byte order, target_port: host byte order, flags: 0  
            nat_entry = ip_bytes + struct.pack('=HH', nat_target_port, 0)  # IP + port + flags
            nat_key = struct.pack('!H', source_port)  # network byte order like htons() in C
            
            self._update_map_entry('nat_map', nat_key, nat_entry)
            
            # CRITICAL: Also setup NAT target MAC map (missing from original)
            self._setup_nat_target_mac(nat_target_ip, target_mac)
            
            self.logger.debug(f"NAT mapping: port {source_port} -> {nat_target_ip}:{nat_target_port}")
            
        except Exception as e:
            self.logger.error(f"Failed to setup NAT map: {e}")
            raise
    
    def _resolve_ip_to_mac(self, ip_address: str, interface: str) -> Optional[str]:
        """Resolve IP address to MAC address like working solution resolve_ip_to_mac()"""
        try:
            import subprocess
            import re
            
            # First try ARP table
            self.logger.debug(f"Looking up MAC for {ip_address} in ARP table...")
            try:
                with open('/proc/net/arp', 'r') as f:
                    lines = f.readlines()[1:]  # Skip header
                    for line in lines:
                        parts = line.strip().split()
                        if len(parts) >= 4 and parts[0] == ip_address:
                            mac = parts[3]
                            if mac != '00:00:00:00:00:00' and ':' in mac:
                                self.logger.debug(f"Found MAC in ARP table: {mac}")
                                return mac
            except Exception as e:
                self.logger.debug(f"Failed to read ARP table: {e}")
            
            # If not in ARP table, try to populate it (like working solution)
            self.logger.info(f"MAC address for {ip_address} not found in ARP table, attempting ARP resolution...")
            
            # Method 1: arping (primary method like working solution)
            try:
                result = subprocess.run(['which', 'arping'], capture_output=True)
                if result.returncode == 0:
                    self.logger.debug("Trying arping method (primary)...")
                    arping_cmd = ['arping', '-c', '3', '-w', '3', '-I', interface, ip_address]
                    subprocess.run(arping_cmd, capture_output=True, timeout=10)
            except:
                pass
            
            # Method 2: ip neigh probe (like working solution)
            try:
                self.logger.debug("Trying ip neigh probe method...")
                subprocess.run(['ip', 'neigh', 'add', ip_address, 'dev', interface, 'nud', 'probe'], 
                              capture_output=True)
            except:
                try:
                    subprocess.run(['ip', 'neigh', 'replace', ip_address, 'dev', interface, 'nud', 'probe'], 
                                  capture_output=True)
                except:
                    pass
            
            # Method 3: TCP connections to multiple ports (like working solution)
            try:
                self.logger.debug("Trying TCP connection method...")
                ports = [80, 443, 22, 8080, 8081]  # Same ports as working solution
                for port in ports:
                    try:
                        nc_cmd = ['timeout', '2', 'nc', '-w', '1', ip_address, str(port)]
                        subprocess.run(nc_cmd, capture_output=True, timeout=3)
                    except:
                        pass
            except:
                pass
            
            # Method 4: UDP connection to target port (like working solution)
            try:
                if hasattr(self.config.pipeline_config, 'nat_target_port') and self.config.pipeline_config.nat_target_port > 0:
                    self.logger.debug(f"Trying UDP connection to port {self.config.pipeline_config.nat_target_port}...")
                    udp_cmd = ['timeout', '2', 'nc', '-u', '-w', '1', ip_address, str(self.config.pipeline_config.nat_target_port)]
                    subprocess.run(udp_cmd, capture_output=True, timeout=3)
            except:
                pass
            
            # Wait for ARP resolution (3 seconds like working solution) 
            self.logger.debug("Waiting for ARP resolution...")
            import time
            time.sleep(3)  # Match working solution's 3-second wait
            
            try:
                with open('/proc/net/arp', 'r') as f:
                    lines = f.readlines()[1:]
                    for line in lines:
                        parts = line.strip().split()
                        if len(parts) >= 4 and parts[0] == ip_address:
                            mac = parts[3]
                            if mac != '00:00:00:00:00:00' and ':' in mac:
                                self.logger.info(f"Successfully resolved MAC: {ip_address} -> {mac}")
                                return mac
            except:
                pass
            
            self.logger.error(f"Failed to resolve MAC address for {ip_address} after multiple attempts")
            return None
            
        except Exception as e:
            self.logger.error(f"Error resolving MAC address for {ip_address}: {e}")
            return None
    
    def _setup_nat_target_mac(self, ip_address: str, mac_address: str) -> None:
        """Setup NAT target MAC map like working solution configure_nat_target_mac()"""
        try:
            # Convert MAC string to bytes
            mac_bytes = bytes.fromhex(mac_address.replace(':', ''))
            
            # Convert IP to network byte order (like working solution)
            import socket
            import struct
            ip_bytes = socket.inet_aton(ip_address)  # Already in network byte order
            
            # Create NAT target entry (matches working solution struct nat_target_config)
            nat_target_entry = mac_bytes + ip_bytes  # MAC + IP (both as bytes)
            nat_target_key = struct.pack('=I', 0)  # key = 0, native byte order
            
            self._update_map_entry('nat_target_map', nat_target_key, nat_target_entry)
            self.logger.debug(f"NAT target MAC mapping: {ip_address} -> {mac_address}")
            
        except Exception as e:
            self.logger.error(f"Failed to setup NAT target MAC map: {e}")
    
    def _setup_interface_map(self, config: Dict[str, Any]) -> None:
        """Setup interface map like working solution"""
        try:
            target_interface = config.get('target_interface', 'ens6')
            
            # Get interface info
            import subprocess
            
            # Get interface index
            result = subprocess.run(['ip', 'link', 'show', target_interface], 
                                  capture_output=True, text=True)
            if result.returncode != 0:
                raise Exception(f"Interface {target_interface} not found")
            
            # Parse interface index from ip output
            line = result.stdout.split('\n')[0]
            ifindex = int(line.split(':')[0])
            
            # Get MAC address 
            result = subprocess.run(['ip', 'link', 'show', target_interface], 
                                  capture_output=True, text=True)
            mac_line = [l for l in result.stdout.split('\n') if 'link/ether' in l][0]
            mac_str = mac_line.split()[1]
            mac_bytes = bytes.fromhex(mac_str.replace(':', ''))
            
            # Create interface entry (matches working solution struct interface_config)
            interface_entry = mac_bytes + struct.pack('=I', ifindex)  # native byte order for ifindex
            interface_key = struct.pack('=I', 0)  # key = 0, native byte order
            
            self._update_map_entry('interface_map', interface_key, interface_entry)
            self.logger.debug(f"Interface mapping: {target_interface} (ifindex={ifindex}, mac={mac_str})")
            
        except Exception as e:
            self.logger.error(f"Failed to setup interface map: {e}")
    
    def _setup_redirect_map(self, config: Dict[str, Any]) -> None:
        """Setup redirect map like working solution"""
        try:
            target_interface = config.get('target_interface', 'ens6')
            
            # Get target interface index
            import subprocess
            result = subprocess.run(['ip', 'link', 'show', target_interface], 
                                  capture_output=True, text=True)
            if result.returncode != 0:
                raise Exception(f"Target interface {target_interface} not found")
                
            line = result.stdout.split('\n')[0] 
            target_ifindex = int(line.split(':')[0])
            
            # Update redirect map (native byte order for consistency)
            redirect_key = struct.pack('=I', 0)  # key = 0, native byte order  
            redirect_value = struct.pack('=I', target_ifindex)  # native byte order
            
            self._update_map_entry('redirect_map', redirect_key, redirect_value)
            self.logger.debug(f"Redirect mapping: -> {target_interface} (ifindex={target_ifindex})")
            
        except Exception as e:
            self.logger.error(f"Failed to setup redirect map: {e}")
    
    def _initialize_stats_map(self) -> None:
        """Initialize statistics map with zero counters"""
        try:
            # Initialize all stat counters to zero (matches working solution)
            for stat_name, stat_index in self.STATS.items():
                if stat_name != 'STAT_MAX_ENTRIES':  # Skip the max marker
                    key = struct.pack('=I', stat_index)  # native byte order
                    value = struct.pack('=Q', 0)  # 64-bit counter = 0, native byte order
                    self._update_map_entry('stats_map', key, value)
            
            self.logger.debug("Statistics map initialized with zero counters")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize stats map: {e}")
    
    def _update_map_entry(self, map_name: str, key: bytes, value: bytes) -> None:
        """Update BPF map entry using bpftool"""
        try:
            # Convert bytes to hex strings for bpftool
            key_hex = ' '.join(f'0x{b:02x}' for b in key)
            value_hex = ' '.join(f'0x{b:02x}' for b in value)
            
            cmd = ['sudo', 'bpftool', 'map', 'update', 'name', map_name,
                   'key', 'hex'] + key_hex.split() + ['value', 'hex'] + value_hex.split()
            
            self.runner.run(cmd)
            
        except Exception as e:
            self.logger.debug(f"Map update failed for {map_name}: {e}")
            
        return entries
    
    def update_map_entry(self, map_name: str, key_bytes: bytes, value_bytes: bytes) -> bool:
        """Update map entry with raw bytes"""
        try:
            # Convert bytes to hex strings for bpftool
            key_hex = ' '.join(f'{b:02x}' for b in key_bytes)
            value_hex = ' '.join(f'{b:02x}' for b in value_bytes)
            
            self.runner.run([
                'sudo', 'bpftool', 'map', 'update', 'name', map_name,
                'key', 'hex', key_hex,
                'value', 'hex', value_hex
            ])
            
            self.logger.debug(f"Updated entry in map {map_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error updating map {map_name}: {e}")
            return False
    
    def delete_map_entry(self, map_name: str, key_bytes: bytes) -> bool:
        """Delete map entry"""
        try:
            key_hex = ' '.join(f'{b:02x}' for b in key_bytes)
            
            self.runner.run([
                'sudo', 'bpftool', 'map', 'delete', 'name', map_name,
                'key', 'hex', key_hex
            ])
            
            self.logger.debug(f"Deleted entry from map {map_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error deleting from map {map_name}: {e}")
            return False
    
    def clear_map(self, map_name: str) -> bool:
        """Clear all entries from map"""
        try:
            entries = self.get_map_entries(map_name)
            deleted = 0
            
            for entry in entries:
                if entry['raw_key']:
                    key_bytes = bytes(entry['raw_key'])
                    if self.delete_map_entry(map_name, key_bytes):
                        deleted += 1
            
            self.logger.info(f"Cleared {deleted} entries from map {map_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error clearing map {map_name}: {e}")
            return False
    
    def get_pipeline_stats(self) -> PipelineStats:
        """Get pipeline statistics - matches working solution format"""
        stats = PipelineStats()
        
        try:
            # Get statistics from stats_map (like working solution)
            stats_data = self.dump_map('stats_map', 'json')
            if not stats_data:
                return stats
                
            # Process statistics like working vxlan_loader
            for entry in stats_data:
                if 'key' in entry and 'value' in entry:
                    # Parse key (stat index)
                    key_bytes = bytes(entry['key'])
                    if len(key_bytes) >= 4:
                        stat_index = struct.unpack('I', key_bytes[:4])[0]
                        
                        # Parse value (counter) - handle per-CPU arrays
                        value_bytes = bytes(entry['value'])
                        counter = 0
                        
                        # Sum per-CPU values like working solution
                        for i in range(0, len(value_bytes), 8):
                            if i + 8 <= len(value_bytes):
                                cpu_counter = struct.unpack('Q', value_bytes[i:i+8])[0]
                                counter += cpu_counter
                        
                        # Map to stats structure (like working solution)
                        if stat_index == self.STATS['STAT_TOTAL_PACKETS']:
                            stats.packets_processed = counter
                        elif stat_index == self.STATS['STAT_VXLAN_PACKETS']:
                            stats.vxlan_packets = counter
                        elif stat_index == self.STATS['STAT_INNER_PACKETS']:
                            stats.inner_packets = counter
                        elif stat_index == self.STATS['STAT_NAT_APPLIED']:
                            stats.nat_applied = counter
                        elif stat_index == self.STATS['STAT_DF_CLEARED']:
                            stats.df_cleared = counter
                        elif stat_index == self.STATS['STAT_FORWARDED']:
                            stats.forwarded = counter
                        elif stat_index == self.STATS['STAT_REDIRECTED']:
                            stats.redirected = counter
                        elif stat_index == self.STATS['STAT_ERRORS']:
                            stats.errors = counter
                        elif stat_index == self.STATS['STAT_BYTES_PROCESSED']:
                            stats.bytes_processed = counter
                        elif stat_index == self.STATS['STAT_IP_LEN_UPDATED']:
                            stats.ip_len_updated = counter
                        elif stat_index == self.STATS['STAT_UDP_LEN_UPDATED']:
                            stats.udp_len_updated = counter
                        elif stat_index == self.STATS['STAT_IP_CHECKSUM_UPDATED']:
                            stats.ip_checksum_updated = counter
                        elif stat_index == self.STATS['STAT_BOUNDS_CHECK_FAILED']:
                            stats.bounds_check_failed = counter
                        elif stat_index == self.STATS['STAT_RINGBUF_SUBMITTED']:
                            stats.ringbuf_submitted = counter
                        elif stat_index == self.STATS['STAT_PACKET_SIZE_DEBUG']:
                            stats.packet_size_debug = counter
                        elif stat_index == self.STATS['STAT_LENGTH_CORRECTIONS']:
                            stats.length_corrections = counter
                        elif stat_index == self.STATS['STAT_IP_ALLOWLIST_HITS']:
                            stats.allowlist_hits = counter  # Filter stats - allowed
                        elif stat_index == self.STATS['STAT_IP_ALLOWLIST_MISSES']:
                            stats.allowlist_misses = counter  # Filter stats - blocked
                        elif stat_index == self.STATS['STAT_DROPPED']:
                            stats.packets_dropped = counter
                                
            # Calculate derived statistics (like working solution)
            if stats.packets_processed > 0:
                stats.error_rate = (stats.errors / stats.packets_processed) * 100
                stats.drop_rate = (stats.packets_dropped / stats.packets_processed) * 100
            
            # Calculate filter statistics
            total_filter_checks = stats.allowlist_hits + stats.allowlist_misses
            if total_filter_checks > 0:
                stats.allowlist_hit_rate = (stats.allowlist_hits / total_filter_checks) * 100
            
            # Add timestamp
            import time
            stats.timestamp = int(time.time())
            
        except Exception as e:
            self.logger.error(f"Error getting pipeline statistics: {e}")
            
        return stats
    
    def get_filter_stats(self) -> Dict[str, int]:
        """Get detailed filter statistics"""
        filter_stats = {}
        
        try:
            # Get specific filter-related statistics
            stats_data = self.dump_map('stats_map', 'json')
            if not stats_data:
                return filter_stats
                
            for entry in stats_data:
                if 'key' in entry and 'value' in entry:
                    key_bytes = bytes(entry['key'])
                    if len(key_bytes) >= 4:
                        stat_index = struct.unpack('I', key_bytes[:4])[0]
                        
                        # Parse value (sum per-CPU counters)
                        value_bytes = bytes(entry['value'])
                        counter = 0
                        for i in range(0, len(value_bytes), 8):
                            if i + 8 <= len(value_bytes):
                                cpu_counter = struct.unpack('Q', value_bytes[i:i+8])[0]
                                counter += cpu_counter
                        
                        # Collect filter-related statistics
                        if stat_index == self.STATS['STAT_IP_ALLOWLIST_HITS']:
                            filter_stats['allowlist_hits'] = counter
                        elif stat_index == self.STATS['STAT_IP_ALLOWLIST_MISSES']:
                            filter_stats['allowlist_misses'] = counter
                        elif stat_index == self.STATS['STAT_DROPPED']:
                            filter_stats['total_dropped'] = counter
                        elif stat_index == self.STATS['STAT_BOUNDS_CHECK_FAILED']:
                            filter_stats['bounds_check_failed'] = counter
            
            # Calculate filter effectiveness
            total_checks = filter_stats.get('allowlist_hits', 0) + filter_stats.get('allowlist_misses', 0)
            if total_checks > 0:
                filter_stats['filter_hit_rate'] = (filter_stats.get('allowlist_hits', 0) / total_checks) * 100
                filter_stats['filter_block_rate'] = (filter_stats.get('allowlist_misses', 0) / total_checks) * 100
            else:
                filter_stats['filter_hit_rate'] = 0.0
                filter_stats['filter_block_rate'] = 0.0
                
        except Exception as e:
            self.logger.error(f"Error getting filter statistics: {e}")
            
        return filter_stats
    
    def get_allowlist_lpm_entries(self) -> List[Tuple[str, int]]:
        """Get entries from LPM trie allowlist map"""
        entries = []
        
        try:
            map_entries = self.get_map_entries('ip_allowlist_lpm')
            
            for entry in map_entries:
                if entry['raw_key'] and len(entry['raw_key']) >= 8:
                    # LPM key format: prefix_len (4 bytes) + IP (4 bytes)
                    key_bytes = bytes(entry['raw_key'])
                    
                    # Extract prefix length (little-endian)
                    prefix_len = struct.unpack('<I', key_bytes[:4])[0]
                    
                    # Extract IP address
                    ip_bytes = key_bytes[4:8]
                    ip_addr = '.'.join(str(b) for b in ip_bytes)
                    
                    entries.append((ip_addr, prefix_len))
                    
        except Exception as e:
            self.logger.error(f"Error getting LMP allowlist entries: {e}")
            
        return entries
    
    def add_lmp_entry(self, ip_address: str, prefix_len: int) -> bool:
        """Add entry to LMP trie"""
        try:
            import ipaddress
            
            # Validate IP address
            ip_obj = ipaddress.IPv4Address(ip_address)
            ip_int = int(ip_obj)
            
            # Create LMP key: prefix_len (4 bytes) + IP (4 bytes)
            key_bytes = struct.pack('<I', prefix_len) + struct.pack('>I', ip_int)
            
            # Value is simple allowed flag
            value_bytes = struct.pack('B', 1)  # IP_ALLOWED = 1
            
            return self.update_map_entry('ip_allowlist_lpm', key_bytes, value_bytes)
            
        except Exception as e:
            self.logger.error(f"Error adding LMP entry {ip_address}/{prefix_len}: {e}")
            return False
    
    def remove_lmp_entry(self, ip_address: str, prefix_len: int) -> bool:
        """Remove entry from LMP trie"""
        try:
            import ipaddress
            
            # Validate IP address
            ip_obj = ipaddress.IPv4Address(ip_address)
            ip_int = int(ip_obj)
            
            # Create LMP key
            key_bytes = struct.pack('<I', prefix_len) + struct.pack('>I', ip_int)
            
            return self.delete_map_entry('ip_allowlist_lpm', key_bytes)
            
        except Exception as e:
            self.logger.error(f"Error removing LMP entry {ip_address}/{prefix_len}: {e}")
            return False
    
    def _count_map_entries(self, map_id: int) -> int:
        """Count entries in map by ID"""
        try:
            result = self.runner.run(['sudo', 'bpftool', 'map', 'dump', 'id', str(map_id)], 
                                   capture=True, check=False)
            if result.returncode == 0:
                # Count lines with 'key:'
                return len([line for line in result.stdout.split('\n') if 'key:' in line])
        except:
            pass
        return 0
    
    def get_map_memory_usage(self) -> Dict[str, int]:
        """Estimate memory usage of maps"""
        usage = {}
        
        for map_info in self.list_maps():
            # Estimate: (key_size + value_size) * entries + overhead
            entry_size = map_info.key_size + map_info.value_size
            estimated_bytes = entry_size * map_info.entries_count + 1024  # 1KB overhead
            usage[map_info.name] = estimated_bytes
            
        return usage
    
    def validate_maps(self) -> Dict[str, bool]:
        """Validate expected maps exist"""
        expected_maps = [
            'stats_map',
            'ip_allowlist_lpm',
            'vxlan_stats',
            'error_map'
        ]
        
        existing_maps = {m.name for m in self.list_maps()}
        validation = {}
        
        for map_name in expected_maps:
            validation[map_name] = map_name in existing_maps
            
        return validation
    
    def export_map_data(self, map_name: str) -> Optional[Dict[str, Any]]:
        """Export map data for backup/analysis"""
        try:
            map_info = self.get_map_by_name(map_name)
            if not map_info:
                return None
            
            return {
                'map_info': map_info.__dict__,
                'entries': self.get_map_entries(map_name),
                'memory_usage': self.get_map_memory_usage().get(map_name, 0),
                'export_timestamp': time.time()
            }
            
        except Exception as e:
            self.logger.error(f"Error exporting map {map_name}: {e}")
            return None

    def show_bpf_maps(self, detailed: bool = True) -> None:
        """Show comprehensive BPF maps information (enhanced display)"""
        
        print("BPF Maps - VXLAN Pipeline Status")
        print("=" * 50)
        
        # Get all BPF maps
        maps_info = self.list_maps()
        if not maps_info:
            print("❌ No BPF maps found or bpftool not available")
            return
        
        # Filter VXLAN pipeline maps
        pipeline_maps = [m for m in maps_info if self._is_pipeline_map(m.name)]
        
        if not pipeline_maps:
            print("❌ No VXLAN pipeline maps found")
            return
        
        print(f"Found {len(pipeline_maps)} pipeline maps:")
        print()
        
        for map_info in pipeline_maps:
            self._display_map_info(map_info, detailed)

    def show_nat_map(self) -> None:
        """Show NAT map contents with formatted output"""
        
        print("NAT Configuration Map")
        print("=" * 30)
        
        try:
            entries = self.get_map_entries('nat_map')
            if not entries:
                print("❌ No NAT entries found")
                return
            
            print("Port Mappings:")
            for entry in entries:
                if entry['raw_key'] and entry['raw_value']:
                    # Parse key (source port)
                    key_bytes = bytes(entry['raw_key'])
                    if len(key_bytes) >= 2:
                        source_port = struct.unpack('!H', key_bytes[:2])[0]
                    
                    # Parse value (target IP + port + flags)
                    value_bytes = bytes(entry['raw_value'])
                    if len(value_bytes) >= 8:
                        ip_bytes = value_bytes[:4]
                        target_ip = '.'.join(str(b) for b in ip_bytes)
                        target_port, flags = struct.unpack('=HH', value_bytes[4:8])
                        
                        print(f"  {source_port:5d} -> {target_ip}:{target_port} (flags: {flags})")
        
        except Exception as e:
            print(f"❌ Error reading NAT map: {e}")

    def show_ip_allowlist(self) -> None:
        """Show IP allowlist map contents"""
        
        print("IP Allowlist (LPM Trie)")
        print("=" * 25)
        
        try:
            entries = self.get_allowlist_lpm_entries()
            if not entries:
                print("❌ No allowlist entries found")
                return
            
            print("Allowed IP Prefixes:")
            for ip_addr, prefix_len in sorted(entries):
                print(f"  {ip_addr}/{prefix_len}")
        
        except Exception as e:
            print(f"❌ Error reading allowlist: {e}")

    def show_statistics_map(self) -> None:
        """Show statistics map with formatted output"""
        
        print("Pipeline Statistics")
        print("=" * 20)
        
        try:
            stats = self.get_pipeline_stats()
            
            print("Packet Processing:")
            print(f"  Total Packets:      {stats.packets_processed:,}")
            print(f"  VXLAN Packets:      {stats.vxlan_packets:,}")
            print(f"  Inner Packets:      {stats.inner_packets:,}")
            print(f"  Redirected:         {stats.redirected:,}")
            print(f"  Dropped:            {stats.packets_dropped:,}")
            print(f"  Errors:             {stats.errors:,}")
            
            print(f"\nNAT Processing:")
            print(f"  NAT Applied:        {stats.nat_applied:,}")
            print(f"  DF Cleared:         {stats.df_cleared:,}")
            
            print(f"\nData Processing:")
            print(f"  Bytes Processed:    {stats.bytes_processed:,}")
            print(f"  IP Len Updated:     {stats.ip_len_updated:,}")
            print(f"  UDP Len Updated:    {stats.udp_len_updated:,}")
            print(f"  IP Checksum Upd:    {stats.ip_checksum_updated:,}")
            
            print(f"\nFilter Statistics:")
            print(f"  Allowlist Hits:     {stats.allowlist_hits:,}")
            print(f"  Allowlist Misses:   {stats.allowlist_misses:,}")
            print(f"  Hit Rate:           {stats.allowlist_hit_rate:.1f}%")
            
            print(f"\nPerformance:")
            print(f"  Error Rate:         {stats.error_rate:.2f}%")
            print(f"  Drop Rate:          {stats.drop_rate:.2f}%")
            
        except Exception as e:
            print(f"❌ Error reading statistics: {e}")

    def count_bpf_map_entries(self, map_name: str) -> int:
        """Count entries in a specific BPF map"""
        try:
            entries = self.get_map_entries(map_name)
            return len(entries)
        except Exception as e:
            self.logger.error(f"Error counting entries in {map_name}: {e}")
            return 0

    def get_nat_rules(self) -> List[Dict[str, Any]]:
        """Get NAT rules in structured format"""
        rules = []
        
        try:
            entries = self.get_map_entries('nat_map')
            
            for entry in entries:
                if entry['raw_key'] and entry['raw_value']:
                    key_bytes = bytes(entry['raw_key'])
                    value_bytes = bytes(entry['raw_value'])
                    
                    if len(key_bytes) >= 2 and len(value_bytes) >= 8:
                        source_port = struct.unpack('!H', key_bytes[:2])[0]
                        ip_bytes = value_bytes[:4]
                        target_ip = '.'.join(str(b) for b in ip_bytes)
                        target_port, flags = struct.unpack('=HH', value_bytes[4:8])
                        
                        rules.append({
                            'source_port': source_port,
                            'target_ip': target_ip,
                            'target_port': target_port,
                            'flags': flags
                        })
        
        except Exception as e:
            self.logger.error(f"Error getting NAT rules: {e}")
        
        return rules

    def _is_pipeline_map(self, map_name: str) -> bool:
        """Check if map belongs to VXLAN pipeline"""
        pipeline_map_names = [
            'nat_map', 'nat_target_map', 'interface_map', 'redirect_map',
            'stats_map', 'ip_allowlist_lpm', 'vxlan_stats', 'error_map'
        ]
        return map_name in pipeline_map_names

    def _display_map_info(self, map_info: BPFMapInfo, detailed: bool = True) -> None:
        """Display formatted map information"""
        
        print(f"📋 Map: {map_info.name} (ID: {map_info.id})")
        print(f"   Type: {map_info.type}")
        print(f"   Entries: {map_info.entries_count:,} / {map_info.max_entries:,}")
        
        if detailed:
            print(f"   Key Size: {map_info.key_size} bytes")
            print(f"   Value Size: {map_info.value_size} bytes")
            
            # Estimate memory usage
            entry_size = map_info.key_size + map_info.value_size
            estimated_bytes = entry_size * map_info.entries_count
            if estimated_bytes > 1024:
                memory_str = f"{estimated_bytes / 1024:.1f} KB"
            else:
                memory_str = f"{estimated_bytes} bytes"
            print(f"   Est. Memory: {memory_str}")
        
        print()
    
    def export_map_data(self, map_name: str) -> Optional[Dict[str, Any]]:
        """Export map data for external processing"""
        try:
            map_info = self.get_map_by_name(map_name)
            if not map_info:
                return None
            
            entries = self.get_map_entries(map_name)
            
            return {
                'map_info': {
                    'name': map_info.name,
                    'type': map_info.type,
                    'key_size': map_info.key_size,
                    'value_size': map_info.value_size,
                    'max_entries': map_info.max_entries
                },
                'entries': entries,
                'entry_count': len(entries),
                'export_timestamp': json.dumps(None, default=str)  # Current time
            }
            
        except Exception as e:
            self.logger.error(f"Error exporting map {map_name}: {e}")
            return None
    
    def get_map_entries_with_metadata(self, map_name: str) -> List[BPFMapEntry]:
        """Get all entries from a specific map with metadata"""
        try:
            result = self.runner.run(
                ["sudo", "bpftool", "map", "dump", "name", map_name, "--json"], 
                check=False
            )
            if result.returncode != 0:
                return []
            
            entries_data = json.loads(result.stdout)
            entries = []
            
            for entry_data in entries_data:
                entry = BPFMapEntry(
                    key=entry_data.get("key", []),
                    value=entry_data.get("value", []),
                    formatted_key=entry_data.get("formatted", {}).get("key", ""),
                    formatted_value=entry_data.get("formatted", {}).get("value", "")
                )
                entries.append(entry)
            
            return entries
            
        except Exception as e:
            self.logger.error(f"Failed to get map entries for {map_name}: {e}")
            return []
    
    def show_nat_map(self) -> None:
        """Display NAT map entries in human-readable format"""
        print("\n" + "="*60)
        print("NAT Map (Network Address Translation Rules)")
        print("="*60)
        
        entries = self.get_map_entries_with_metadata("nat_map")
        if not entries:
            print("✗ NAT map is empty or not found")
            return
        
        print(f"Entries: {len(entries)}")
        print()
        print(f"{'Source Port':<12} | {'Target IP':<15} | {'Target Port':<12}")
        print(f"{'-'*12} | {'-'*15} | {'-'*12}")
        
        for entry in entries:
            try:
                # Parse NAT entry (assuming source_port -> target_ip:target_port)
                key_data = entry.key
                value_data = entry.value
                
                if isinstance(key_data, list) and len(key_data) >= 2:
                    source_port = (key_data[1] << 8) | key_data[0]  # Little-endian
                else:
                    source_port = entry.formatted_key
                
                if isinstance(value_data, list) and len(value_data) >= 6:
                    # Parse IP address (4 bytes) and port (2 bytes)
                    ip_bytes = value_data[:4]
                    port_bytes = value_data[4:6]
                    target_ip = f"{ip_bytes[0]}.{ip_bytes[1]}.{ip_bytes[2]}.{ip_bytes[3]}"
                    target_port = (port_bytes[1] << 8) | port_bytes[0]  # Little-endian
                else:
                    target_ip = entry.formatted_value
                    target_port = "N/A"
                
                print(f"{source_port:<12} | {target_ip:<15} | {target_port:<12}")
                
            except Exception as e:
                self.logger.debug(f"Error parsing NAT entry: {e}")
                print(f"{entry.formatted_key:<12} | {entry.formatted_value:<27}")
    
    def show_ip_allowlist_map(self) -> None:
        """Display IP allowlist map entries"""
        print("\n" + "="*60)
        print("IP Allowlist Map")
        print("="*60)
        
        entries = self.get_map_entries_with_metadata("ip_allowlist")
        if not entries:
            print("✗ IP allowlist map is empty or not found")
            return
        
        print(f"Entries: {len(entries)}")
        print()
        print(f"{'IP Address':<15} | {'Status':<8}")
        print(f"{'-'*15} | {'-'*8}")
        
        for entry in entries:
            try:
                # Parse IP address from key
                key_data = entry.key
                if isinstance(key_data, list) and len(key_data) >= 4:
                    ip_addr = f"{key_data[0]}.{key_data[1]}.{key_data[2]}.{key_data[3]}"
                else:
                    ip_addr = entry.formatted_key
                
                # Parse status from value
                value_data = entry.value
                if isinstance(value_data, list) and len(value_data) > 0:
                    status = "ALLOWED" if value_data[0] == 1 else "BLOCKED"
                else:
                    status = entry.formatted_value
                
                print(f"{ip_addr:<15} | {status:<8}")
                
            except Exception as e:
                self.logger.debug(f"Error parsing IP allowlist entry: {e}")
                print(f"{entry.formatted_key:<15} | {entry.formatted_value:<8}")
    
    def show_stats_map(self) -> None:
        """Display statistics map with detailed breakdown"""
        print("\n" + "="*60)
        print("Statistics Map (Per-CPU Counters)")
        print("="*60)
        
        entries = self.get_map_entries_with_metadata("stats_map")
        if not entries:
            print("✗ Stats map is empty or not found")
            return
        
        print(f"Entries: {len(entries)}")
        print()
        print(f"{'Stat Name':<25} | {'Total':<10} | {'Per-CPU Breakdown'}")
        print(f"{'-'*25} | {'-'*10} | {'-'*20}")
        
        # Parse statistics entries
        stats_data = {}
        for entry in entries:
            try:
                key_data = entry.key
                if isinstance(key_data, list) and len(key_data) > 0:
                    stat_id = key_data[0] if isinstance(key_data[0], int) else int(key_data[0], 16)
                else:
                    continue
                
                value_data = entry.value
                if isinstance(value_data, list):
                    total = sum(value_data)
                    per_cpu = value_data
                else:
                    total = value_data
                    per_cpu = [value_data]
                
                stat_name = self._get_stat_name(stat_id)
                stats_data[stat_name] = {'total': total, 'per_cpu': per_cpu}
                
            except Exception as e:
                self.logger.debug(f"Error parsing stats entry: {e}")
        
        # Display sorted statistics
        for stat_name in sorted(stats_data.keys()):
            data = stats_data[stat_name]
            total = data['total']
            per_cpu = data['per_cpu']
            
            if total > 0:  # Only show non-zero stats
                cpu_breakdown = ', '.join(f"CPU{i}:{v}" for i, v in enumerate(per_cpu) if v > 0)
                if len(cpu_breakdown) > 30:
                    cpu_breakdown = cpu_breakdown[:27] + "..."
                print(f"{stat_name:<25} | {total:<10,} | {cpu_breakdown}")
    
    def _get_stat_name(self, stat_id: int) -> str:
        """Get human-readable name for statistics ID"""
        stat_names = {
            0: "TOTAL_PACKETS",
            1: "VXLAN_PACKETS", 
            2: "INNER_PACKETS",
            3: "NAT_APPLIED",
            4: "DF_CLEARED",
            5: "FORWARDED",
            6: "REDIRECTED",
            7: "ERRORS",
            8: "BYTES_PROCESSED",
            9: "IP_LEN_UPDATED",
            10: "UDP_LEN_UPDATED",
            11: "IP_CHECKSUM_UPDATED",
            12: "BOUNDS_CHECK_FAILED",
            13: "RINGBUF_SUBMITTED",
            14: "PACKET_SIZE_DEBUG",
            15: "LENGTH_CORRECTIONS",
            16: "IP_ALLOWLIST_HITS",
            17: "IP_ALLOWLIST_MISSES"
        }
        return stat_names.get(stat_id, f"UNKNOWN_0x{stat_id:02x}")