"""
Network interface management and operations
"""

import re
import ipaddress
from pathlib import Path
from typing import List, Dict, Optional, Set
from .models import NetworkInterface, ValidationResult
from .utils import CommandRunner, Logger

class NetworkManager:
    """Network interface management and validation"""
    
    def __init__(self, runner: Optional[CommandRunner] = None, logger: Optional[Logger] = None):
        self.runner = runner or CommandRunner()
        self.logger = logger or Logger("network_manager")
        
    def get_interfaces(self) -> List[NetworkInterface]:
        """Get detailed information about all network interfaces"""
        interfaces = []
        
        try:
            # Get interface list with ip command
            result = self.runner.run(['ip', 'link', 'show'], capture=True)
            self.logger.debug(f"ip link show output: {result.stdout}")
            interface_blocks = self._parse_ip_link_output(result.stdout)
            self.logger.debug(f"Parsed {len(interface_blocks)} interface blocks")
            
            for i, block in enumerate(interface_blocks):
                self.logger.debug(f"Processing block {i}: {block[:100]}...")
                interface = self._parse_interface_block(block)
                if interface:
                    self.logger.debug(f"Successfully parsed interface: {interface.name}")
                    # Get IP addresses for this interface
                    interface.ip_addresses = self._get_interface_ips(interface.name)
                    
                    # Check XDP attachment
                    interface.xdp_attached = self._check_xdp_attached(interface.name)
                    
                    interfaces.append(interface)
                else:
                    self.logger.warning(f"Failed to parse interface block {i}")
                    
        except Exception as e:
            self.logger.error(f"Error getting interfaces: {e}")
            import traceback
            self.logger.error(f"Traceback: {traceback.format_exc()}")
            
        self.logger.info(f"Found {len(interfaces)} interfaces: {[iface.name for iface in interfaces]}")
        return interfaces
    
    def get_interface_names(self) -> List[str]:
        """Get list of interface names only"""
        return [iface.name for iface in self.get_interfaces()]
    
    def get_interface(self, name: str) -> Optional[NetworkInterface]:
        """Get specific interface information"""
        interfaces = self.get_interfaces()
        return next((iface for iface in interfaces if iface.name == name), None)
    
    def interface_exists(self, name: str) -> bool:
        """Check if interface exists"""
        return name in self.get_interface_names()
    
    def is_interface_up(self, name: str) -> bool:
        """Check if interface is up"""
        interface = self.get_interface(name)
        return interface.is_up if interface else False
    
    def validate_interface(self, name: str) -> ValidationResult:
        """Validate interface for XDP usage"""
        result = ValidationResult(valid=True)
        
        if not name:
            result.add_error("Interface name cannot be empty")
            return result
            
        interface = self.get_interface(name)
        if not interface:
            result.add_error(f"Interface '{name}' does not exist")
            return result
        
        # Check if interface is up
        if not interface.is_up:
            result.add_warning(f"Interface '{name}' is down")
        
        # Check if XDP is already attached
        if interface.xdp_attached:
            result.add_warning(f"XDP program already attached to '{name}'")
        
        # Check if interface is loopback
        if name == 'lo':
            result.add_error("Cannot attach XDP to loopback interface")
        
        # Check interface type (avoid virtual interfaces when possible)
        if self._is_virtual_interface(name):
            result.add_warning(f"Interface '{name}' appears to be virtual")
        
        return result
    
    def get_recommended_interface(self) -> Optional[str]:
        """Get recommended interface for XDP attachment"""
        interfaces = self.get_interfaces()
        
        # Filter out loopback and virtual interfaces
        candidates = []
        for iface in interfaces:
            if (iface.name != 'lo' and 
                iface.is_up and 
                not iface.xdp_attached and
                not self._is_virtual_interface(iface.name)):
                candidates.append(iface)
        
        # Prefer interfaces with IP addresses
        with_ips = [iface for iface in candidates if iface.ip_addresses]
        if with_ips:
            candidates = with_ips
        
        # Return first suitable interface
        return candidates[0].name if candidates else None
    
    def attach_xdp(self, interface: str, program_path: str) -> bool:
        """Attach XDP program to interface"""
        try:
            self.logger.info(f"Attaching XDP program to {interface}")
            
            # Validate interface first
            validation = self.validate_interface(interface)
            if not validation.valid:
                for error in validation.errors:
                    self.logger.error(error)
                return False
            
            # Log any warnings
            for warning in validation.warnings:
                self.logger.warning(warning)
            
            # Attach XDP program
            self.runner.run([
                'sudo', 'ip', 'link', 'set', 'dev', interface, 
                'xdp', 'obj', program_path
            ])
            
            self.logger.info(f"Successfully attached XDP to {interface}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to attach XDP to {interface}: {e}")
            return False
    
    def detach_xdp(self, interface: str) -> bool:
        """Detach XDP program from interface"""
        try:
            self.logger.info(f"Detaching XDP program from {interface}")
            
            self.runner.run([
                'sudo', 'ip', 'link', 'set', 'dev', interface, 'xdp', 'off'
            ])
            
            self.logger.info(f"Successfully detached XDP from {interface}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to detach XDP from {interface}: {e}")
            return False
    
    def detach_all_xdp(self) -> List[str]:
        """Detach XDP programs from all interfaces"""
        detached = []
        
        interfaces = self.get_interfaces()
        for interface in interfaces:
            if interface.xdp_attached:
                if self.detach_xdp(interface.name):
                    detached.append(interface.name)
        
        return detached
    
    def _parse_ip_link_output(self, output: str) -> List[str]:
        """Parse 'ip link show' output into interface blocks"""
        blocks = []
        current_block = []
        
        for line in output.split('\n'):
            if re.match(r'^\d+:', line):
                # Start of new interface
                if current_block:
                    blocks.append('\n'.join(current_block))
                current_block = [line]
            elif current_block and line.strip():
                current_block.append(line)
        
        # Add last block
        if current_block:
            blocks.append('\n'.join(current_block))
        
        return blocks
    
    def _parse_interface_block(self, block: str) -> Optional[NetworkInterface]:
        """Parse individual interface block"""
        lines = block.split('\n')
        if not lines:
            return None
        
        # Parse first line for basic info
        first_line = lines[0]
        match = re.match(r'^\d+:\s+(\S+):\s+<([^>]*)>.*state\s+(\w+).*mtu\s+(\d+)', first_line)
        if not match:
            return None
        
        name = match.group(1).split('@')[0]  # Remove @if suffix
        flags = match.group(2).split(',')
        state = match.group(3)
        mtu = int(match.group(4))
        
        # Parse MAC address from second line
        mac_address = ""
        if len(lines) > 1:
            mac_match = re.search(r'link/\S+\s+([a-f0-9:]{17})', lines[1])
            if mac_match:
                mac_address = mac_match.group(1)
        
        # Determine driver (simplified)
        driver = self._get_interface_driver(name)
        
        return NetworkInterface(
            name=name,
            state=state,
            mtu=mtu,
            mac_address=mac_address,
            driver=driver
        )
    
    def _get_interface_ips(self, interface: str) -> List[str]:
        """Get IP addresses for interface"""
        ips = []
        try:
            result = self.runner.run(['ip', 'addr', 'show', interface], capture=True, check=False)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    match = re.search(r'inet\s+([0-9.]+/\d+)', line)
                    if match:
                        ips.append(match.group(1))
        except:
            pass
        return ips
    
    def _check_xdp_attached(self, interface: str) -> bool:
        """Check if XDP program is attached to interface"""
        try:
            result = self.runner.run(['sudo', 'bpftool', 'net', 'show', 'dev', interface], 
                                   capture=True, check=False)
            return 'xdp' in result.stdout.lower() if result.returncode == 0 else False
        except:
            return False
    
    def _get_interface_driver(self, interface: str) -> str:
        """Get interface driver name"""
        try:
            driver_path = Path(f'/sys/class/net/{interface}/device/driver')
            if driver_path.exists():
                return driver_path.resolve().name
        except:
            pass
        return "unknown"
    
    def _is_virtual_interface(self, interface: str) -> bool:
        """Check if interface is virtual (docker, veth, etc.)"""
        virtual_prefixes = ['docker', 'veth', 'br-', 'virbr', 'tap', 'tun']
        return any(interface.startswith(prefix) for prefix in virtual_prefixes)

class IPAddressValidator:
    """IP address and network validation utilities"""
    
    @staticmethod
    def validate_ip(address: str) -> ValidationResult:
        """Validate IP address format"""
        result = ValidationResult(valid=True)
        
        try:
            ipaddress.ip_address(address)
        except ValueError as e:
            result.add_error(f"Invalid IP address: {e}")
        
        return result
    
    @staticmethod
    def validate_network(network: str) -> ValidationResult:
        """Validate network CIDR format"""
        result = ValidationResult(valid=True)
        
        try:
            net = ipaddress.ip_network(network, strict=False)
            
            # Check for common issues
            if net.num_addresses > 1000000:
                result.add_warning(f"Very large network: {net.num_addresses:,} addresses")
            
        except ValueError as e:
            result.add_error(f"Invalid network: {e}")
        
        return result
    
    @staticmethod
    def normalize_address(address: str) -> str:
        """Normalize IP address or network to standard format"""
        try:
            if '/' in address:
                # Network
                return str(ipaddress.ip_network(address, strict=False))
            else:
                # Individual IP - convert to /32
                ip = ipaddress.ip_address(address)
                return f"{ip}/32"
        except ValueError:
            return address  # Return as-is if invalid
    
    @staticmethod
    def get_network_info(network: str) -> Dict[str, any]:
        """Get detailed information about network"""
        try:
            net = ipaddress.ip_network(network, strict=False)
            return {
                'network': str(net.network_address),
                'netmask': str(net.netmask),
                'prefix_length': net.prefixlen,
                'num_addresses': net.num_addresses,
                'is_private': net.is_private,
                'is_multicast': net.is_multicast,
                'first_host': str(next(net.hosts())) if net.num_addresses > 2 else str(net.network_address),
                'last_host': str(list(net.hosts())[-1]) if net.num_addresses > 2 else str(net.network_address)
            }
        except ValueError:
            return {}
    
    @staticmethod
    def find_overlapping_networks(networks: List[str]) -> List[tuple]:
        """Find overlapping networks in list"""
        overlaps = []
        
        try:
            net_objects = []
            for net_str in networks:
                try:
                    net_objects.append((net_str, ipaddress.ip_network(net_str, strict=False)))
                except ValueError:
                    continue
            
            # Check each pair for overlap
            for i, (net1_str, net1) in enumerate(net_objects):
                for net2_str, net2 in net_objects[i+1:]:
                    if net1.overlaps(net2):
                        overlaps.append((net1_str, net2_str))
        
        except Exception:
            pass
        
        return overlaps