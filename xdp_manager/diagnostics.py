"""
Network diagnostics and debugging tools for XDP pipeline
"""

import json
import socket
import struct
import subprocess
import time
from typing import Dict, List, Tuple, Optional, Any
from datetime import datetime
from .models import NetworkInterface
from .utils import CommandRunner, Logger
from .network import NetworkManager

class NetworkDiagnostics:
    """Comprehensive network diagnostics and debugging"""
    
    def __init__(self, logger: Optional[Logger] = None):
        self.logger = logger or Logger("network_diagnostics")
        self.runner = CommandRunner(self.logger)
        self.network_manager = NetworkManager(self.logger)
    
    def comprehensive_network_check(self) -> Dict[str, Any]:
        """Perform comprehensive network diagnostic check"""
        try:
            diagnostics = {
                'timestamp': datetime.now().isoformat(),
                'network_interfaces': self._check_network_interfaces(),
                'routing_table': self._check_routing_table(),
                'arp_table': self._check_arp_table(),
                'network_statistics': self._get_network_statistics(),
                'xdp_attachment_status': self._check_xdp_attachments(),
                'bpf_program_status': self._check_bpf_programs(),
                'connectivity_tests': self._perform_connectivity_tests(),
                'performance_metrics': self._get_interface_performance(),
                'recommendations': []
            }
            
            # Generate recommendations based on findings
            diagnostics['recommendations'] = self._generate_network_recommendations(diagnostics)
            
            return diagnostics
            
        except Exception as e:
            self.logger.error(f"Comprehensive network check failed: {e}")
            return {}
    
    def debug_packet_flow(self, interface: str, packet_count: int = 100) -> Dict[str, Any]:
        """Debug packet flow on specific interface"""
        try:
            flow_info = {
                'interface': interface,
                'packet_count': packet_count,
                'timestamp': datetime.now().isoformat(),
                'rx_packets': self._capture_rx_packets(interface, packet_count),
                'tx_packets': self._capture_tx_packets(interface, packet_count),
                'drop_analysis': self._analyze_packet_drops(interface),
                'xdp_processing': self._analyze_xdp_processing(interface),
                'performance_counters': self._get_interface_counters(interface)
            }
            
            return flow_info
            
        except Exception as e:
            self.logger.error(f"Packet flow debugging failed: {e}")
            return {}
    
    def analyze_vxlan_traffic(self, interface: str, duration: int = 30) -> Dict[str, Any]:
        """Analyze VXLAN traffic patterns"""
        try:
            analysis = {
                'interface': interface,
                'duration_seconds': duration,
                'timestamp': datetime.now().isoformat(),
                'vxlan_statistics': self._get_vxlan_statistics(interface),
                'tunnel_endpoints': self._discover_tunnel_endpoints(interface),
                'vni_analysis': self._analyze_vni_usage(interface),
                'encapsulation_overhead': self._calculate_encapsulation_overhead(interface),
                'performance_impact': self._assess_vxlan_performance(interface)
            }
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"VXLAN traffic analysis failed: {e}")
            return {}
    
    def test_connectivity(self, targets: List[str], source_interface: Optional[str] = None) -> Dict[str, Any]:
        """Test network connectivity to multiple targets"""
        results = {
            'timestamp': datetime.now().isoformat(),
            'source_interface': source_interface,
            'connectivity_results': {}
        }
        
        for target in targets:
            try:
                # Ping test
                ping_result = self._ping_test(target, source_interface)
                
                # Traceroute test
                traceroute_result = self._traceroute_test(target, source_interface)
                
                # Port scan (if it looks like IP:port)
                port_scan_result = None
                if ':' in target and target.count(':') == 1:
                    ip, port = target.split(':')
                    try:
                        port_num = int(port)
                        port_scan_result = self._port_scan(ip, port_num)
                    except ValueError:
                        pass
                
                results['connectivity_results'][target] = {
                    'ping': ping_result,
                    'traceroute': traceroute_result,
                    'port_scan': port_scan_result
                }
                
            except Exception as e:
                self.logger.error(f"Connectivity test to {target} failed: {e}")
                results['connectivity_results'][target] = {'error': str(e)}
        
        return results
    
    def monitor_interface_realtime(self, interface: str, duration: int = 60) -> List[Dict[str, Any]]:
        """Monitor interface statistics in real-time"""
        samples = []
        interval = 1.0  # 1 second intervals
        
        try:
            start_time = time.time()
            
            while time.time() - start_time < duration:
                timestamp = datetime.now()
                
                # Get current interface statistics
                stats = self._get_interface_stats(interface)
                
                # Get XDP statistics if available
                xdp_stats = self._get_xdp_stats(interface)
                
                sample = {
                    'timestamp': timestamp.isoformat(),
                    'interface_stats': stats,
                    'xdp_stats': xdp_stats,
                    'cpu_usage': self._get_cpu_usage(),
                    'memory_usage': self._get_memory_usage()
                }
                
                samples.append(sample)
                time.sleep(interval)
                
        except KeyboardInterrupt:
            self.logger.info("Real-time monitoring stopped by user")
        
        return samples
    
    def _check_network_interfaces(self) -> List[Dict[str, Any]]:
        """Check status of all network interfaces"""
        interfaces = []
        
        try:
            # Get interface list
            interface_list = self.network_manager.list_interfaces()
            
            for iface in interface_list:
                iface_info = {
                    'name': iface.name,
                    'state': iface.state,
                    'mtu': iface.mtu,
                    'ip_addresses': iface.ip_addresses,
                    'mac_address': iface.mac_address,
                    'link_type': iface.link_type,
                    'statistics': self._get_interface_stats(iface.name),
                    'xdp_attached': self._is_xdp_attached(iface.name)
                }
                interfaces.append(iface_info)
                
        except Exception as e:
            self.logger.error(f"Interface check failed: {e}")
        
        return interfaces
    
    def _check_routing_table(self) -> List[Dict[str, Any]]:
        """Check system routing table"""
        routes = []
        
        try:
            # Get routing table via ip route
            result = self.runner.run_command(['ip', 'route', 'show'], timeout=10)
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        route_info = self._parse_route_line(line)
                        if route_info:
                            routes.append(route_info)
                            
        except Exception as e:
            self.logger.error(f"Routing table check failed: {e}")
        
        return routes
    
    def _check_arp_table(self) -> List[Dict[str, Any]]:
        """Check ARP table entries"""
        arp_entries = []
        
        try:
            result = self.runner.run_command(['ip', 'neigh', 'show'], timeout=10)
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        arp_info = self._parse_arp_line(line)
                        if arp_info:
                            arp_entries.append(arp_info)
                            
        except Exception as e:
            self.logger.error(f"ARP table check failed: {e}")
        
        return arp_entries
    
    def _get_network_statistics(self) -> Dict[str, Any]:
        """Get system-wide network statistics"""
        stats = {}
        
        try:
            # Get /proc/net/dev statistics
            with open('/proc/net/dev', 'r') as f:
                lines = f.readlines()
                
            stats['interfaces'] = {}
            for line in lines[2:]:  # Skip header lines
                if ':' in line:
                    parts = line.split(':')
                    interface = parts[0].strip()
                    values = parts[1].split()
                    
                    if len(values) >= 16:
                        stats['interfaces'][interface] = {
                            'rx_bytes': int(values[0]),
                            'rx_packets': int(values[1]),
                            'rx_errors': int(values[2]),
                            'rx_dropped': int(values[3]),
                            'tx_bytes': int(values[8]),
                            'tx_packets': int(values[9]),
                            'tx_errors': int(values[10]),
                            'tx_dropped': int(values[11])
                        }
            
            # Get /proc/net/netstat
            try:
                with open('/proc/net/netstat', 'r') as f:
                    netstat_lines = f.readlines()
                
                for i in range(0, len(netstat_lines), 2):
                    if i + 1 < len(netstat_lines):
                        headers = netstat_lines[i].split()[1:]
                        values = netstat_lines[i + 1].split()[1:]
                        
                        protocol = netstat_lines[i].split()[0].replace(':', '')
                        stats[protocol] = {}
                        
                        for header, value in zip(headers, values):
                            try:
                                stats[protocol][header] = int(value)
                            except ValueError:
                                stats[protocol][header] = value
                                
            except Exception as e:
                self.logger.warning(f"Could not read /proc/net/netstat: {e}")
                
        except Exception as e:
            self.logger.error(f"Network statistics collection failed: {e}")
        
        return stats
    
    def _check_xdp_attachments(self) -> List[Dict[str, Any]]:
        """Check XDP program attachments"""
        attachments = []
        
        try:
            result = self.runner.run_command(['ip', 'link', 'show'], timeout=10)
            
            if result.returncode == 0:
                current_interface = None
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    
                    # Parse interface lines
                    if ': ' in line and not line.startswith(' '):
                        parts = line.split(': ')
                        if len(parts) >= 2:
                            interface_name = parts[1].split('@')[0]
                            current_interface = interface_name
                    
                    # Check for XDP program
                    elif current_interface and 'prog/xdp' in line:
                        xdp_info = {
                            'interface': current_interface,
                            'attached': True,
                            'program_info': line.strip()
                        }
                        attachments.append(xdp_info)
                        
        except Exception as e:
            self.logger.error(f"XDP attachment check failed: {e}")
        
        return attachments
    
    def _check_bpf_programs(self) -> List[Dict[str, Any]]:
        """Check loaded BPF programs"""
        programs = []
        
        try:
            result = self.runner.run_command(['bpftool', 'prog', 'list'], timeout=10)
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.strip() and ':' in line:
                        prog_info = self._parse_bpf_program_line(line)
                        if prog_info:
                            programs.append(prog_info)
                            
        except Exception as e:
            self.logger.warning(f"BPF program check failed: {e}")
        
        return programs
    
    def _perform_connectivity_tests(self) -> Dict[str, Any]:
        """Perform basic connectivity tests"""
        tests = {
            'localhost': self._ping_test('127.0.0.1'),
            'gateway': None,
            'dns_servers': [],
            'internet': self._ping_test('8.8.8.8')
        }
        
        try:
            # Try to find default gateway
            result = self.runner.run_command(['ip', 'route', 'show', 'default'], timeout=5)
            if result.returncode == 0 and 'via' in result.stdout:
                gateway_ip = result.stdout.split('via')[1].split()[0]
                tests['gateway'] = self._ping_test(gateway_ip)
            
            # Check DNS servers
            try:
                with open('/etc/resolv.conf', 'r') as f:
                    for line in f:
                        if line.startswith('nameserver'):
                            dns_ip = line.split()[1]
                            dns_test = self._ping_test(dns_ip)
                            tests['dns_servers'].append({
                                'server': dns_ip,
                                'result': dns_test
                            })
            except Exception:
                pass
                
        except Exception as e:
            self.logger.warning(f"Connectivity tests had issues: {e}")
        
        return tests
    
    def _get_interface_performance(self) -> Dict[str, Any]:
        """Get interface performance metrics"""
        performance = {}
        
        try:
            interfaces = self.network_manager.list_interfaces()
            
            for iface in interfaces:
                if iface.state == 'UP':
                    stats = self._get_interface_stats(iface.name)
                    
                    # Calculate performance metrics
                    performance[iface.name] = {
                        'mtu': iface.mtu,
                        'link_speed': self._get_link_speed(iface.name),
                        'utilization': self._calculate_utilization(stats),
                        'error_rate': self._calculate_error_rate(stats),
                        'drop_rate': self._calculate_drop_rate(stats)
                    }
                    
        except Exception as e:
            self.logger.error(f"Interface performance check failed: {e}")
        
        return performance
    
    def _generate_network_recommendations(self, diagnostics: Dict[str, Any]) -> List[str]:
        """Generate network recommendations based on diagnostics"""
        recommendations = []
        
        # Check interface status
        interfaces = diagnostics.get('network_interfaces', [])
        down_interfaces = [iface['name'] for iface in interfaces if iface['state'] != 'UP']
        if down_interfaces:
            recommendations.append(f"Interfaces down: {', '.join(down_interfaces)}")
        
        # Check XDP attachments
        xdp_attachments = diagnostics.get('xdp_attachment_status', [])
        if not xdp_attachments:
            recommendations.append("No XDP programs attached - check XDP pipeline deployment")
        
        # Check connectivity
        connectivity = diagnostics.get('connectivity_tests', {})
        if connectivity.get('internet', {}).get('success') is False:
            recommendations.append("Internet connectivity issues detected")
        
        # Check performance
        performance = diagnostics.get('performance_metrics', {})
        for iface, metrics in performance.items():
            if metrics.get('error_rate', 0) > 0.01:  # 1% error rate
                recommendations.append(f"High error rate on {iface}")
            
            if metrics.get('drop_rate', 0) > 0.05:  # 5% drop rate
                recommendations.append(f"High drop rate on {iface}")
        
        return recommendations
    
    # Helper methods for various operations
    def _ping_test(self, target: str, source_interface: Optional[str] = None) -> Dict[str, Any]:
        """Perform ping test"""
        cmd = ['ping', '-c', '4', '-W', '5']
        if source_interface:
            cmd.extend(['-I', source_interface])
        cmd.append(target)
        
        try:
            result = self.runner.run_command(cmd, timeout=10)
            
            ping_result = {
                'target': target,
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr
            }
            
            # Parse ping statistics if successful
            if result.returncode == 0:
                ping_result.update(self._parse_ping_output(result.stdout))
            
            return ping_result
            
        except Exception as e:
            return {
                'target': target,
                'success': False,
                'error': str(e)
            }
    
    def _traceroute_test(self, target: str, source_interface: Optional[str] = None) -> Dict[str, Any]:
        """Perform traceroute test"""
        cmd = ['traceroute', '-n', '-m', '10']
        if source_interface:
            cmd.extend(['-i', source_interface])
        cmd.append(target)
        
        try:
            result = self.runner.run_command(cmd, timeout=30)
            return {
                'target': target,
                'success': result.returncode == 0,
                'hops': self._parse_traceroute_output(result.stdout),
                'output': result.stdout
            }
        except Exception as e:
            return {
                'target': target,
                'success': False,
                'error': str(e)
            }
    
    def _port_scan(self, ip: str, port: int) -> Dict[str, Any]:
        """Test port connectivity"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            return {
                'ip': ip,
                'port': port,
                'open': result == 0
            }
        except Exception as e:
            return {
                'ip': ip,
                'port': port,
                'open': False,
                'error': str(e)
            }
    
    def _get_interface_stats(self, interface: str) -> Dict[str, int]:
        """Get interface statistics"""
        stats = {}
        
        try:
            with open(f'/sys/class/net/{interface}/statistics/rx_packets', 'r') as f:
                stats['rx_packets'] = int(f.read().strip())
            with open(f'/sys/class/net/{interface}/statistics/tx_packets', 'r') as f:
                stats['tx_packets'] = int(f.read().strip())
            with open(f'/sys/class/net/{interface}/statistics/rx_bytes', 'r') as f:
                stats['rx_bytes'] = int(f.read().strip())
            with open(f'/sys/class/net/{interface}/statistics/tx_bytes', 'r') as f:
                stats['tx_bytes'] = int(f.read().strip())
            with open(f'/sys/class/net/{interface}/statistics/rx_errors', 'r') as f:
                stats['rx_errors'] = int(f.read().strip())
            with open(f'/sys/class/net/{interface}/statistics/tx_errors', 'r') as f:
                stats['tx_errors'] = int(f.read().strip())
            with open(f'/sys/class/net/{interface}/statistics/rx_dropped', 'r') as f:
                stats['rx_dropped'] = int(f.read().strip())
            with open(f'/sys/class/net/{interface}/statistics/tx_dropped', 'r') as f:
                stats['tx_dropped'] = int(f.read().strip())
                
        except Exception as e:
            self.logger.warning(f"Could not get stats for {interface}: {e}")
        
        return stats
    
    def _is_xdp_attached(self, interface: str) -> bool:
        """Check if XDP program is attached to interface"""
        try:
            result = self.runner.run_command(['ip', 'link', 'show', interface], timeout=5)
            return 'prog/xdp' in result.stdout
        except Exception:
            return False
    
    def _parse_route_line(self, line: str) -> Optional[Dict[str, str]]:
        """Parse a route line from ip route output"""
        try:
            parts = line.split()
            route_info = {'destination': parts[0]}
            
            i = 1
            while i < len(parts):
                if parts[i] == 'via' and i + 1 < len(parts):
                    route_info['gateway'] = parts[i + 1]
                    i += 2
                elif parts[i] == 'dev' and i + 1 < len(parts):
                    route_info['interface'] = parts[i + 1]
                    i += 2
                elif parts[i] == 'src' and i + 1 < len(parts):
                    route_info['source'] = parts[i + 1]
                    i += 2
                else:
                    i += 1
            
            return route_info
        except Exception:
            return None
    
    def _parse_arp_line(self, line: str) -> Optional[Dict[str, str]]:
        """Parse an ARP line from ip neigh output"""
        try:
            parts = line.split()
            if len(parts) >= 4:
                return {
                    'ip': parts[0],
                    'interface': parts[2],
                    'mac': parts[4] if len(parts) > 4 else 'N/A',
                    'state': parts[5] if len(parts) > 5 else 'UNKNOWN'
                }
        except Exception:
            pass
        return None
    
    def _parse_bpf_program_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse BPF program info line"""
        try:
            parts = line.split()
            if len(parts) >= 3:
                return {
                    'id': parts[0].rstrip(':'),
                    'type': parts[1],
                    'name': parts[2] if len(parts) > 2 else 'unnamed',
                    'full_info': line.strip()
                }
        except Exception:
            pass
        return None
    
    def _parse_ping_output(self, output: str) -> Dict[str, Any]:
        """Parse ping command output for statistics"""
        stats = {}
        
        try:
            lines = output.split('\n')
            for line in lines:
                if 'packets transmitted' in line:
                    # Parse packet statistics
                    parts = line.split(',')
                    for part in parts:
                        part = part.strip()
                        if 'transmitted' in part:
                            stats['packets_sent'] = int(part.split()[0])
                        elif 'received' in part:
                            stats['packets_received'] = int(part.split()[0])
                        elif 'packet loss' in part:
                            stats['packet_loss'] = part
                
                elif 'round-trip' in line or 'rtt' in line:
                    # Parse RTT statistics
                    if '=' in line:
                        rtt_part = line.split('=')[1].strip()
                        rtt_values = rtt_part.split('/')
                        if len(rtt_values) >= 4:
                            stats['rtt_min'] = float(rtt_values[0])
                            stats['rtt_avg'] = float(rtt_values[1])
                            stats['rtt_max'] = float(rtt_values[2])
                            stats['rtt_mdev'] = float(rtt_values[3].split()[0])
        except Exception:
            pass
        
        return stats
    
    def _parse_traceroute_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse traceroute output"""
        hops = []
        
        try:
            lines = output.split('\n')
            for line in lines:
                line = line.strip()
                if line and line[0].isdigit():
                    parts = line.split()
                    if len(parts) >= 2:
                        hop_info = {
                            'hop': int(parts[0]),
                            'ip': parts[1] if parts[1] != '*' else None,
                            'response_times': []
                        }
                        
                        # Extract response times
                        for part in parts[2:]:
                            if part.endswith('ms'):
                                try:
                                    time_val = float(part[:-2])
                                    hop_info['response_times'].append(time_val)
                                except ValueError:
                                    pass
                        
                        hops.append(hop_info)
        except Exception:
            pass
        
        return hops
    
    # Placeholder methods for advanced features
    def _capture_rx_packets(self, interface: str, count: int) -> Dict[str, Any]:
        """Capture and analyze RX packets"""
        # This would use tcpdump or similar
        return {'method': 'tcpdump', 'count': count, 'status': 'not_implemented'}
    
    def _capture_tx_packets(self, interface: str, count: int) -> Dict[str, Any]:
        """Capture and analyze TX packets"""
        return {'method': 'tcpdump', 'count': count, 'status': 'not_implemented'}
    
    def _analyze_packet_drops(self, interface: str) -> Dict[str, Any]:
        """Analyze packet drop patterns"""
        return {'analysis': 'packet_drops', 'status': 'not_implemented'}
    
    def _analyze_xdp_processing(self, interface: str) -> Dict[str, Any]:
        """Analyze XDP packet processing"""
        return {'analysis': 'xdp_processing', 'status': 'not_implemented'}
    
    def _get_interface_counters(self, interface: str) -> Dict[str, int]:
        """Get detailed interface performance counters"""
        return self._get_interface_stats(interface)
    
    def _get_vxlan_statistics(self, interface: str) -> Dict[str, Any]:
        """Get VXLAN-specific statistics"""
        return {'vxlan_stats': 'not_implemented'}
    
    def _discover_tunnel_endpoints(self, interface: str) -> List[str]:
        """Discover VXLAN tunnel endpoints"""
        return []
    
    def _analyze_vni_usage(self, interface: str) -> Dict[str, int]:
        """Analyze VNI (VXLAN Network Identifier) usage"""
        return {}
    
    def _calculate_encapsulation_overhead(self, interface: str) -> float:
        """Calculate VXLAN encapsulation overhead"""
        return 0.0
    
    def _assess_vxlan_performance(self, interface: str) -> Dict[str, Any]:
        """Assess VXLAN performance impact"""
        return {}
    
    def _get_xdp_stats(self, interface: str) -> Dict[str, Any]:
        """Get XDP-specific statistics"""
        return {}
    
    def _get_cpu_usage(self) -> float:
        """Get current CPU usage"""
        try:
            with open('/proc/loadavg', 'r') as f:
                load_avg = f.read().split()[0]
                return float(load_avg)
        except Exception:
            return 0.0
    
    def _get_memory_usage(self) -> Dict[str, int]:
        """Get current memory usage"""
        memory = {}
        try:
            with open('/proc/meminfo', 'r') as f:
                for line in f:
                    if line.startswith(('MemTotal:', 'MemFree:', 'MemAvailable:')):
                        key, value = line.split(':')
                        memory[key.strip()] = int(value.split()[0])
        except Exception:
            pass
        return memory
    
    def _get_link_speed(self, interface: str) -> Optional[int]:
        """Get interface link speed"""
        try:
            with open(f'/sys/class/net/{interface}/speed', 'r') as f:
                return int(f.read().strip())
        except Exception:
            return None
    
    def _calculate_utilization(self, stats: Dict[str, int]) -> float:
        """Calculate interface utilization"""
        # This would need historical data to calculate properly
        return 0.0
    
    def _calculate_error_rate(self, stats: Dict[str, int]) -> float:
        """Calculate interface error rate"""
        total_packets = stats.get('rx_packets', 0) + stats.get('tx_packets', 0)
        total_errors = stats.get('rx_errors', 0) + stats.get('tx_errors', 0)
        
        if total_packets > 0:
            return total_errors / total_packets
        return 0.0
    
    def _calculate_drop_rate(self, stats: Dict[str, int]) -> float:
        """Calculate interface drop rate"""
        total_packets = stats.get('rx_packets', 0) + stats.get('tx_packets', 0)
        total_drops = stats.get('rx_dropped', 0) + stats.get('tx_dropped', 0)
        
        if total_packets > 0:
            return total_drops / total_packets
        return 0.0