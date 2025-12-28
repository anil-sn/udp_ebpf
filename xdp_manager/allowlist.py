"""
IP allowlist management with LPM trie integration
"""

import json
import ipaddress
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple
from datetime import datetime
from .models import AllowlistEntry, ValidationResult, SyncResult
from .utils import CommandRunner, Logger, FileOperations
from .network import IPAddressValidator
from .bpf import BPFMapManager

class AllowlistManager:
    """Advanced IP allowlist management with validation and sync"""
    
    def __init__(self, 
                 config_file: str = "ip_allowlist.json",
                 runner: Optional[CommandRunner] = None,
                 logger: Optional[Logger] = None):
        self.config_file = Path(config_file)
        self.runner = runner or CommandRunner()
        self.logger = logger or Logger("allowlist_manager")
        self.file_ops = FileOperations(self.logger)
        self.validator = IPAddressValidator()
        self.bpf_maps = BPFMapManager(self.runner, self.logger)
        
    def load_from_json(self) -> List[AllowlistEntry]:
        """Load allowlist entries from JSON configuration"""
        entries = []
        
        if not self.config_file.exists():
            self.logger.warning(f"Allowlist file not found: {self.config_file}")
            return entries
        
        try:
            with open(self.config_file) as f:
                data = json.load(f)
            
            # Handle simple format with 'entries' array
            raw_entries = data.get('entries', [])
            
            # Also support legacy formats
            if not raw_entries:
                # Try flat_ip_list
                raw_entries.extend(data.get('flat_ip_list', []))
                raw_entries.extend(data.get('flat_subnet_list', []))
                
                # Try organizations structure
                for org in data.get('organizations', []):
                    raw_entries.extend(org.get('ips', []))
                    raw_entries.extend(org.get('subnets', []))
            
            # Parse entries
            for entry_str in raw_entries:
                entry = self._parse_entry(entry_str.strip())
                if entry:
                    entries.append(entry)
                    
            self.logger.info(f"Loaded {len(entries)} entries from {self.config_file}")
            
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON in {self.config_file}: {e}")
        except Exception as e:
            self.logger.error(f"Error loading allowlist: {e}")
            
        return entries
    
    def save_to_json(self, entries: List[AllowlistEntry], create_backup: bool = True) -> bool:
        """Save allowlist entries to JSON file"""
        try:
            # Convert entries to simple string list
            entry_strings = []
            for entry in entries:
                if entry.is_subnet:
                    entry_strings.append(f"{entry.address}/{entry.prefix_len}")
                else:
                    entry_strings.append(entry.address)
            
            # Create JSON structure
            data = {
                "entries": sorted(set(entry_strings)),  # Remove duplicates and sort
                "metadata": {
                    "last_updated": datetime.now().isoformat(),
                    "total_entries": len(entry_strings),
                    "generated_by": "xdp_manager"
                }
            }
            
            # Save to file
            json_content = json.dumps(data, indent=2)
            success = self.file_ops.safe_write(self.config_file, json_content, create_backup)
            
            if success:
                self.logger.info(f"Saved {len(entries)} entries to {self.config_file}")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error saving allowlist: {e}")
            return False
    
    def validate_entries(self, entries: List[AllowlistEntry]) -> ValidationResult:
        """Validate all allowlist entries"""
        result = ValidationResult(valid=True)
        
        seen_networks = []
        
        for i, entry in enumerate(entries):
            # Validate IP address format
            if entry.is_subnet:
                net_result = self.validator.validate_network(f"{entry.address}/{entry.prefix_len}")
            else:
                net_result = self.validator.validate_ip(entry.address)
            
            if not net_result.valid:
                for error in net_result.errors:
                    result.add_error(f"Entry {i+1}: {error}")
            
            # Check for overlapping networks
            current_network = f"{entry.address}/{entry.prefix_len}"
            seen_networks.append(current_network)
        
        # Check for overlaps
        overlaps = self.validator.find_overlapping_networks(seen_networks)
        for net1, net2 in overlaps:
            result.add_warning(f"Overlapping networks: {net1} and {net2}")
        
        # Check for duplicates
        duplicates = self._find_duplicates(entries)
        for dup in duplicates:
            result.add_warning(f"Duplicate entry: {dup}")
        
        return result
    
    def sync_to_bpf(self, entries: Optional[List[AllowlistEntry]] = None) -> SyncResult:
        """Sync allowlist entries to BPF LPM trie"""
        if entries is None:
            entries = self.load_from_json()
        
        start_time = datetime.now()
        result = SyncResult(success=False)
        
        try:
            # Validate entries first
            validation = self.validate_entries(entries)
            if not validation.valid:
                result.errors.extend(validation.errors)
                self.logger.error("Validation failed, aborting sync")
                return result
            
            # Log warnings
            for warning in validation.warnings:
                self.logger.warning(warning)
            
            # Get current BPF entries
            current_entries = set(self.bpf_maps.get_allowlist_lpm_entries())
            
            # Convert new entries to tuples for comparison
            new_entries = set()
            for entry in entries:
                new_entries.add((entry.address, entry.prefix_len))
            
            # Calculate changes
            to_add = new_entries - current_entries
            to_remove = current_entries - new_entries
            
            # Remove old entries
            removed_count = 0
            for ip_addr, prefix_len in to_remove:
                if self.bpf_maps.remove_lmp_entry(ip_addr, prefix_len):
                    removed_count += 1
                else:
                    result.errors.append(f"Failed to remove {ip_addr}/{prefix_len}")
            
            # Add new entries
            added_count = 0
            for ip_addr, prefix_len in to_add:
                if self.bpf_maps.add_lmp_entry(ip_addr, prefix_len):
                    added_count += 1
                else:
                    result.errors.append(f"Failed to add {ip_addr}/{prefix_len}")
            
            # Update result
            result.success = len(result.errors) == 0
            result.entries_added = added_count
            result.entries_removed = removed_count
            result.total_entries = len(new_entries)
            result.duration_seconds = (datetime.now() - start_time).total_seconds()
            
            self.logger.info(f"Sync completed: +{added_count} -{removed_count} entries in {result.duration_seconds:.2f}s")
            
            if result.errors:
                self.logger.warning(f"Sync had {len(result.errors)} errors")
            
        except Exception as e:
            result.errors.append(f"Sync failed: {e}")
            self.logger.error(f"Sync failed: {e}")
            
        return result
    
    def add_entry(self, address: str, sync_immediately: bool = True) -> bool:
        """Add single entry to allowlist"""
        try:
            # Parse and validate entry
            entry = self._parse_entry(address)
            if not entry:
                self.logger.error(f"Invalid address format: {address}")
                return False
            
            # Load current entries
            entries = self.load_from_json()
            
            # Check if already exists
            existing = self._find_entry(entries, entry.address, entry.prefix_len)
            if existing:
                self.logger.warning(f"Entry already exists: {address}")
                return True  # Not an error
            
            # Add new entry
            entries.append(entry)
            
            # Save to file
            if not self.save_to_json(entries):
                return False
            
            # Sync to BPF if requested
            if sync_immediately and self.bpf_maps.map_exists('ip_allowlist_lpm'):
                sync_result = self.sync_to_bpf(entries)
                if not sync_result.success:
                    self.logger.warning("Entry added to file but BPF sync failed")
            
            self.logger.info(f"Added entry: {address}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error adding entry {address}: {e}")
            return False
    
    def remove_entry(self, address: str, sync_immediately: bool = True) -> bool:
        """Remove entry from allowlist"""
        try:
            # Parse entry for consistent format
            entry = self._parse_entry(address)
            if not entry:
                self.logger.error(f"Invalid address format: {address}")
                return False
            
            # Load current entries
            entries = self.load_from_json()
            
            # Find and remove entry
            original_count = len(entries)
            entries = [e for e in entries if not (e.address == entry.address and e.prefix_len == entry.prefix_len)]
            
            if len(entries) == original_count:
                self.logger.warning(f"Entry not found: {address}")
                return False
            
            # Save to file
            if not self.save_to_json(entries):
                return False
            
            # Sync to BPF if requested
            if sync_immediately and self.bpf_maps.map_exists('ip_allowlist_lmp'):
                sync_result = self.sync_to_bpf(entries)
                if not sync_result.success:
                    self.logger.warning("Entry removed from file but BPF sync failed")
            
            self.logger.info(f"Removed entry: {address}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error removing entry {address}: {e}")
            return False
    
    def bulk_add(self, addresses: List[str]) -> Dict[str, bool]:
        """Add multiple entries in bulk"""
        results = {}
        entries = self.load_from_json()
        modified = False
        
        for address in addresses:
            try:
                entry = self._parse_entry(address)
                if entry and not self._find_entry(entries, entry.address, entry.prefix_len):
                    entries.append(entry)
                    results[address] = True
                    modified = True
                else:
                    results[address] = False
            except:
                results[address] = False
        
        # Save and sync once if any changes
        if modified:
            if self.save_to_json(entries):
                if self.bpf_maps.map_exists('ip_allowlist_lpm'):
                    self.sync_to_bpf(entries)
                self.logger.info(f"Bulk added {sum(results.values())} entries")
            else:
                # Mark all as failed if save failed
                results = {addr: False for addr in addresses}
        
        return results
    
    def get_status(self) -> Dict[str, any]:
        """Get comprehensive allowlist status"""
        entries = self.load_from_json()
        bpf_entries = self.bpf_maps.get_allowlist_lpm_entries()
        
        individual_ips = [e for e in entries if not e.is_subnet]
        subnets = [e for e in entries if e.is_subnet]
        
        return {
            'file_path': str(self.config_file),
            'file_exists': self.config_file.exists(),
            'total_entries': len(entries),
            'individual_ips': len(individual_ips),
            'subnets': len(subnets),
            'bpf_entries': len(bpf_entries),
            'in_sync': len(entries) == len(bpf_entries),
            'validation': self.validate_entries(entries),
            'last_modified': self.config_file.stat().st_mtime if self.config_file.exists() else None
        }
    
    def export_entries(self, format: str = 'json') -> Optional[str]:
        """Export entries in various formats"""
        entries = self.load_from_json()
        
        if format == 'json':
            return json.dumps([{
                'address': e.address,
                'prefix_len': e.prefix_len,
                'is_subnet': e.is_subnet,
                'cidr': e.cidr_notation
            } for e in entries], indent=2)
        
        elif format == 'csv':
            lines = ['address,prefix_len,type,cidr']
            for e in entries:
                entry_type = 'subnet' if e.is_subnet else 'ip'
                lines.append(f"{e.address},{e.prefix_len},{entry_type},{e.cidr_notation}")
            return '\n'.join(lines)
        
        elif format == 'text':
            return '\n'.join(e.cidr_notation for e in entries)
        
        return None
    
    def _parse_entry(self, entry_str: str) -> Optional[AllowlistEntry]:
        """Parse string entry into AllowlistEntry object"""
        try:
            entry_str = entry_str.strip()
            
            if '/' in entry_str:
                # Network with prefix
                ip_str, prefix_str = entry_str.split('/')
                prefix_len = int(prefix_str)
                
                # Validate
                ipaddress.ip_network(entry_str, strict=False)
                
                return AllowlistEntry(
                    address=ip_str,
                    prefix_len=prefix_len,
                    is_subnet=prefix_len < 32
                )
            else:
                # Individual IP
                ipaddress.ip_address(entry_str)  # Validate
                
                return AllowlistEntry(
                    address=entry_str,
                    prefix_len=32,
                    is_subnet=False
                )
                
        except (ValueError, IndexError) as e:
            self.logger.debug(f"Failed to parse entry '{entry_str}': {e}")
            return None
    
    def _find_entry(self, entries: List[AllowlistEntry], address: str, prefix_len: int) -> Optional[AllowlistEntry]:
        """Find entry in list by address and prefix"""
        return next((e for e in entries if e.address == address and e.prefix_len == prefix_len), None)
    
    def _find_duplicates(self, entries: List[AllowlistEntry]) -> List[str]:
        """Find duplicate entries"""
        seen = set()
        duplicates = []
        
        for entry in entries:
            key = (entry.address, entry.prefix_len)
            if key in seen:
                duplicates.append(f"{entry.address}/{entry.prefix_len}")
            seen.add(key)
        
        return duplicates