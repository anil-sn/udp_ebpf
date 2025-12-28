"""
Interface management with advanced configuration capabilities
Handles network interface optimization, queue scaling, and XDP management
"""

import glob
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from .utils import CommandRunner, Logger
from .models import ValidationResult

class InterfaceManager:
    """Advanced interface management with performance optimization"""
    
    def __init__(self, runner: Optional[CommandRunner] = None, logger: Optional[Logger] = None):
        self.runner = runner or CommandRunner()
        self.logger = logger or Logger("interface_manager")
    
    def configure_interface_for_xdp(self, interface: str) -> bool:
        """Configure interface for optimal XDP performance"""
        self.logger.info(f"Configuring interface {interface} for XDP...")
        
        if not self._check_interface_exists(interface):
            return False
        
        success = True
        
        # Ensure interface is up
        if not self._ensure_interface_up(interface):
            success = False
        
        # Optimize MTU for XDP compatibility
        if not self._optimize_mtu(interface):
            self.logger.warning(f"Could not optimize MTU for {interface}")
        
        # Configure queue count for performance
        if not self._configure_queues(interface):
            self.logger.warning(f"Could not configure queues for {interface}")
        
        # Disable offload features for better XDP performance
        if not self._disable_offload_features(interface):
            self.logger.warning(f"Could not disable offload features for {interface}")
        
        return success
    
    def scale_interface_queues(self, interface: str, target_queues: int = 8) -> bool:
        """Scale interface queues for maximum performance"""
        self.logger.info(f"Scaling network queues for {interface}...")
        
        try:
            # Get current and maximum queue information
            current_queues, max_queues = self._get_queue_info(interface)
            
            if current_queues is None or max_queues is None:
                self.logger.warning(f"Could not get queue information for {interface}")
                return False
            
            if current_queues < target_queues and max_queues >= target_queues:
                self.logger.info(f"Scaling network queues: {current_queues} → {target_queues}")
                
                result = self.runner.run([
                    "sudo", "ethtool", "-L", interface, "combined", str(target_queues)
                ], check=False)
                
                if result.returncode == 0:
                    self.logger.info("✓ Successfully scaled to 8 queues")
                    return True
                else:
                    self.logger.warning("⚠ Queue scaling failed (AWS ENA limitation)")
                    return False
            
            elif current_queues >= target_queues:
                self.logger.info(f"✓ Already using {current_queues} queues")
                return True
            else:
                self.logger.warning(f"⚠ Cannot scale to {target_queues} queues (max available: {max_queues})")
                return False
                
        except Exception as e:
            self.logger.error(f"Queue scaling failed: {e}")
            return False
    
    def populate_arp_table(self, target_ip: str, interface: str) -> bool:
        """Pre-populate ARP table to help MAC resolution (like bash version)"""
        self.logger.info(f"Pre-populating ARP table for {target_ip}...")
        
        # Check if already in ARP table
        if self._check_arp_entry(target_ip):
            mac = self._get_arp_mac(target_ip)
            self.logger.info(f"✓ MAC address already known: {target_ip} -> {mac}")
            return True
        
        # Method 1: arping (primary method)
        if self._try_arping(target_ip, interface):
            return True
        
        # Method 2: Connection attempts to common ports
        if self._try_tcp_connections(target_ip):
            if self._check_arp_entry(target_ip):
                return True
        
        # Method 3: ip neigh probe
        if self._try_neigh_probe(target_ip, interface):
            return True
        
        self.logger.warning(f"⚠ Could not pre-resolve MAC for {target_ip}")
        self.logger.info("  This may cause startup delays, but vxlan_loader will retry")
        return False
    
    def check_xdp_support(self, interface: str) -> bool:
        """Check if interface supports XDP"""
        try:
            # Check if xdp-loader is available
            result = self.runner.run(["which", "xdp-loader"], check=False)
            if result.returncode != 0:
                self.logger.warning("⚠ xdp-loader not installed, skipping XDP feature check")
                return True  # Assume support
            
            # Check XDP features
            result = self.runner.run([
                "sudo", "xdp-loader", "features", interface
            ], check=False)
            
            if result.returncode == 0 and "NETDEV_XDP_ACT_BASIC.*yes" in result.stdout:
                self.logger.info(f"✓ Interface {interface} supports XDP")
                return True
            else:
                self.logger.warning(f"⚠ Interface {interface} has limited XDP support")
                return True  # Still allow, might work
                
        except Exception as e:
            self.logger.warning(f"XDP support check failed: {e}")
            return True  # Assume support
    
    def get_interface_info(self, interface: str) -> Dict[str, str]:
        """Get comprehensive interface information"""
        info = {
            'name': interface,
            'ip': self._get_interface_ip(interface),
            'mac': self._get_interface_mac(interface),
            'state': self._get_interface_state(interface),
            'mtu': self._get_interface_mtu(interface),
            'queues': str(self._get_queue_info(interface)[0] or 'unknown'),
            'xdp_attached': str(self._check_xdp_attached(interface))
        }
        return info
    
    def _check_interface_exists(self, interface: str) -> bool:
        """Check if network interface exists"""
        try:
            result = self.runner.run(["ip", "link", "show", interface], check=False)
            if result.returncode != 0:
                self.logger.error(f"Network interface '{interface}' not found")
                return False
            return True
        except Exception:
            return False
    
    def _ensure_interface_up(self, interface: str) -> bool:
        """Ensure interface is in UP state"""
        try:
            result = self.runner.run(["ip", "link", "show", interface], check=False)
            if result.returncode != 0:
                return False
            
            if "state UP" not in result.stdout:
                self.logger.info(f"Bringing up interface {interface}...")
                result = self.runner.run(["sudo", "ip", "link", "set", interface, "up"], check=False)
                if result.returncode == 0:
                    import time
                    time.sleep(2)  # Allow interface to stabilize
                    return True
                else:
                    self.logger.error(f"Failed to bring up interface {interface}")
                    return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to check/set interface state: {e}")
            return False
    
    def _optimize_mtu(self, interface: str) -> bool:
        """Optimize MTU for XDP compatibility"""
        try:
            current_mtu = self._get_interface_mtu(interface)
            target_mtu = 3000
            
            if current_mtu and int(current_mtu) != target_mtu:
                result = self.runner.run([
                    "sudo", "ip", "link", "set", interface, "mtu", str(target_mtu)
                ], check=False)
                
                if result.returncode == 0:
                    self.logger.info(f"  SUCCESS: MTU updated: {current_mtu} -> {target_mtu}")
                    return True
                else:
                    self.logger.warning(f"  WARNING: Could not set MTU on {interface}")
                    return False
            else:
                self.logger.info(f"  SUCCESS: MTU already optimal ({target_mtu})")
                return True
                
        except Exception:
            return False
    
    def _configure_queues(self, interface: str) -> bool:
        """Configure optimal queue count"""
        return self.scale_interface_queues(interface, 4)  # Start with 4 queues
    
    def _disable_offload_features(self, interface: str) -> bool:
        """Disable offload features for better XDP performance"""
        try:
            features_to_disable = ["gro", "lro", "gso"]
            
            for feature in features_to_disable:
                self.runner.run([
                    "sudo", "ethtool", "-K", interface, feature, "off"
                ], check=False)
            
            return True
            
        except Exception:
            return False
    
    def _get_queue_info(self, interface: str) -> Tuple[Optional[int], Optional[int]]:
        """Get current and maximum queue counts"""
        try:
            result = self.runner.run(["ethtool", "-l", interface], check=False)
            if result.returncode != 0:
                return None, None
            
            lines = result.stdout.split('\n')
            max_queues = None
            current_queues = None
            
            for line in lines:
                if "Combined:" in line:
                    if max_queues is None:  # First occurrence is maximum
                        max_queues = int(line.split()[-1])
                    else:  # Second occurrence is current
                        current_queues = int(line.split()[-1])
                        break
            
            return current_queues, max_queues
            
        except Exception:
            return None, None
    
    def _check_arp_entry(self, ip: str) -> bool:
        """Check if IP is in ARP table"""
        try:
            result = self.runner.run(["ip", "neighbor", "show", ip], check=False)
            return result.returncode == 0 and "lladdr" in result.stdout
        except Exception:
            return False
    
    def _get_arp_mac(self, ip: str) -> str:
        """Get MAC address from ARP table"""
        try:
            result = self.runner.run(["ip", "neighbor", "show", ip], check=False)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if "lladdr" in line:
                        parts = line.split()
                        mac_idx = parts.index("lladdr") + 1
                        if mac_idx < len(parts):
                            return parts[mac_idx]
        except Exception:
            pass
        return "unknown"
    
    def _try_arping(self, target_ip: str, interface: str) -> bool:
        """Try ARP ping method"""
        try:
            result = self.runner.run(["which", "arping"], check=False)
            if result.returncode != 0:
                return False
            
            self.logger.info("  Using arping method (primary)...")
            result = self.runner.run([
                "timeout", "10", "arping", "-c", "5", "-w", "5", "-I", interface, target_ip
            ], check=False)
            
            if self._check_arp_entry(target_ip):
                mac = self._get_arp_mac(target_ip)
                self.logger.info(f"✓ arping successful: {target_ip} -> {mac}")
                return True
                
        except Exception:
            pass
        return False
    
    def _try_tcp_connections(self, target_ip: str) -> bool:
        """Try TCP connection method"""
        try:
            self.logger.info("  Trying TCP connection method...")
            ports = [80, 443, 22, 8080, 8081, 8443, 3389]
            
            for port in ports:
                self.runner.run([
                    "timeout", "2", "nc", "-w", "1", target_ip, str(port)
                ], check=False, capture=False)
            
            return True
            
        except Exception:
            return False
    
    def _try_neigh_probe(self, target_ip: str, interface: str) -> bool:
        """Try ip neigh probe method"""
        try:
            self.logger.info("  Using ip neigh probe method...")
            
            # Try to add/replace neighbor entry
            self.runner.run([
                "sudo", "ip", "neigh", "add", target_ip, "dev", interface, "nud", "probe"
            ], check=False)
            
            self.runner.run([
                "sudo", "ip", "neigh", "replace", target_ip, "dev", interface, "nud", "probe"
            ], check=False)
            
            import time
            time.sleep(3)
            
            if self._check_arp_entry(target_ip):
                mac = self._get_arp_mac(target_ip)
                self.logger.info(f"✓ Successfully resolved MAC: {target_ip} -> {mac}")
                return True
                
        except Exception:
            pass
        return False
    
    def _get_interface_ip(self, interface: str) -> str:
        """Get interface IP address"""
        try:
            result = self.runner.run([
                "ip", "-4", "addr", "show", interface
            ], check=False)
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if "inet " in line:
                        return line.split()[1].split('/')[0]
        except Exception:
            pass
        return "unknown"
    
    def _get_interface_mac(self, interface: str) -> str:
        """Get interface MAC address"""
        try:
            result = self.runner.run(["ip", "link", "show", interface], check=False)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if "link/ether" in line:
                        return line.split()[1]
        except Exception:
            pass
        return "unknown"
    
    def _get_interface_state(self, interface: str) -> str:
        """Get interface state"""
        try:
            result = self.runner.run(["ip", "link", "show", interface], check=False)
            if result.returncode == 0:
                if "state UP" in result.stdout:
                    return "UP"
                elif "state DOWN" in result.stdout:
                    return "DOWN"
        except Exception:
            pass
        return "unknown"
    
    def _get_interface_mtu(self, interface: str) -> Optional[str]:
        """Get interface MTU"""
        try:
            mtu_path = f"/sys/class/net/{interface}/mtu"
            if Path(mtu_path).exists():
                with open(mtu_path, 'r') as f:
                    return f.read().strip()
        except Exception:
            pass
        return None
    
    def _check_xdp_attached(self, interface: str) -> bool:
        """Check if XDP program is attached to interface"""
        try:
            result = self.runner.run(["ip", "link", "show", interface], check=False)
            return result.returncode == 0 and "xdp" in result.stdout
        except Exception:
            return False