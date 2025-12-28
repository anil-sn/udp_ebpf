"""
BPF map operations and management
"""

import json
import struct
from typing import List, Dict, Optional, Any, Tuple
from .models import BPFMapInfo, PipelineStats, BPFMapType
from .utils import CommandRunner, Logger

class BPFMapManager:
    """BPF map operations and statistics management"""
    
    # Statistics map constants (from vxlan_pipeline.h)
    STATS = {
        'STAT_PACKETS_PROCESSED': 0,
        'STAT_PACKETS_DROPPED': 1, 
        'STAT_VXLAN_PACKETS': 2,
        'STAT_IP_ALLOWLIST_HITS': 16,
        'STAT_IP_ALLOWLIST_MISSES': 17,
        'STAT_ERRORS': 20
    }
    
    def __init__(self, runner: Optional[CommandRunner] = None, logger: Optional[Logger] = None):
        self.runner = runner or CommandRunner()
        self.logger = logger or Logger("bpf_maps")
        
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
        """Get pipeline statistics from stats map"""
        stats = PipelineStats()
        
        try:
            entries = self.get_map_entries('stats_map')
            
            # Parse statistics based on key values
            for entry in entries:
                if entry['raw_key'] and len(entry['raw_key']) >= 4:
                    # Extract key as uint32
                    key = struct.unpack('<I', bytes(entry['raw_key'][:4]))[0]
                    
                    # Extract value (handle percpu arrays)
                    if entry['raw_value']:
                        if len(entry['raw_value']) >= 8:
                            # Percpu array - sum all CPU values
                            value = 0
                            for i in range(0, len(entry['raw_value']), 8):
                                if i + 8 <= len(entry['raw_value']):
                                    cpu_val = struct.unpack('<Q', bytes(entry['raw_value'][i:i+8]))[0]
                                    value += cpu_val
                        else:
                            # Simple value
                            value = struct.unpack('<Q', bytes(entry['raw_value'][:8]))[0]
                        
                        # Map to stats fields
                        if key == self.STATS['STAT_PACKETS_PROCESSED']:
                            stats.packets_processed = value
                        elif key == self.STATS['STAT_PACKETS_DROPPED']:
                            stats.packets_dropped = value
                        elif key == self.STATS['STAT_VXLAN_PACKETS']:
                            stats.vxlan_packets = value
                        elif key == self.STATS['STAT_IP_ALLOWLIST_HITS']:
                            stats.allowlist_hits = value
                        elif key == self.STATS['STAT_IP_ALLOWLIST_MISSES']:
                            stats.allowlist_misses = value
                        elif key == self.STATS['STAT_ERRORS']:
                            stats.errors = value
                            
        except Exception as e:
            self.logger.error(f"Error getting pipeline stats: {e}")
            
        return stats
    
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