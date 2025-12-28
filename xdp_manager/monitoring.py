"""
Real-time performance monitoring for XDP pipeline
Implements advanced monitoring capabilities matching bash version functionality
"""

import time
import json
import subprocess
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from datetime import datetime, timedelta
from .utils import CommandRunner, Logger
from .models import NetworkInterface, PipelineStats
from .bpf import BPFMapManager

@dataclass
class InterfaceStats:
    """Network interface statistics"""
    interface: str
    rx_packets: int
    tx_packets: int
    rx_bytes: int
    tx_bytes: int
    rx_dropped: int
    tx_dropped: int
    timestamp: datetime
    
    @property
    def total_packets(self) -> int:
        return self.rx_packets + self.tx_packets
    
    @property
    def total_bytes(self) -> int:
        return self.rx_bytes + self.tx_bytes

@dataclass
class PPSCalculation:
    """PPS calculation result"""
    interface: str
    rx_pps: int
    tx_pps: int
    total_pps: int
    rx_bytes_per_sec: int
    tx_bytes_per_sec: int
    throughput_mbps: float
    timestamp: datetime

@dataclass
class EBPFMapStats:
    """eBPF map statistics parsed from bpftool"""
    total_packets: int = 0
    vxlan_packets: int = 0
    inner_packets: int = 0
    nat_applied: int = 0
    df_cleared: int = 0
    forwarded: int = 0
    redirected: int = 0
    errors: int = 0
    bytes_processed: int = 0
    ip_len_updated: int = 0
    length_corrections: int = 0

class RealTimeMonitor:
    """Real-time performance monitoring with live statistics display"""
    
    def __init__(self, runner: Optional[CommandRunner] = None, logger: Optional[Logger] = None):
        self.runner = runner or CommandRunner()
        self.logger = logger or Logger("realtime_monitor")
        self._previous_stats = {}
        self._previous_ebpf_stats = None
    
    def get_interface_stats(self, interface: str) -> Optional[InterfaceStats]:
        """Get current interface statistics from sysfs"""
        try:
            stats_path = f"/sys/class/net/{interface}/statistics"
            
            def read_stat(name: str) -> int:
                try:
                    with open(f"{stats_path}/{name}", 'r') as f:
                        return int(f.read().strip())
                except:
                    return 0
            
            return InterfaceStats(
                interface=interface,
                rx_packets=read_stat("rx_packets"),
                tx_packets=read_stat("tx_packets"),
                rx_bytes=read_stat("rx_bytes"),
                tx_bytes=read_stat("tx_bytes"),
                rx_dropped=read_stat("rx_dropped"),
                tx_dropped=read_stat("tx_dropped"),
                timestamp=datetime.now()
            )
            
        except Exception as e:
            self.logger.error(f"Failed to get stats for {interface}: {e}")
            return None
    
    def calculate_pps(self, interface: str, interval: float = 1.0) -> Optional[PPSCalculation]:
        """Calculate PPS for an interface over given interval"""
        current_stats = self.get_interface_stats(interface)
        if not current_stats:
            return None
        
        if interface in self._previous_stats:
            prev_stats = self._previous_stats[interface]
            time_delta = (current_stats.timestamp - prev_stats.timestamp).total_seconds()
            
            if time_delta > 0:
                rx_pps = int((current_stats.rx_packets - prev_stats.rx_packets) / time_delta)
                tx_pps = int((current_stats.tx_packets - prev_stats.tx_packets) / time_delta)
                rx_bps = int((current_stats.rx_bytes - prev_stats.rx_bytes) / time_delta)
                tx_bps = int((current_stats.tx_bytes - prev_stats.tx_bytes) / time_delta)
                
                # Calculate throughput in Mbps
                total_bps = rx_bps + tx_bps
                throughput_mbps = (total_bps * 8) / 1_000_000
                
                result = PPSCalculation(
                    interface=interface,
                    rx_pps=max(0, rx_pps),
                    tx_pps=max(0, tx_pps),
                    total_pps=max(0, rx_pps + tx_pps),
                    rx_bytes_per_sec=max(0, rx_bps),
                    tx_bytes_per_sec=max(0, tx_bps),
                    throughput_mbps=max(0.0, throughput_mbps),
                    timestamp=current_stats.timestamp
                )
                
                self._previous_stats[interface] = current_stats
                return result
        
        # Store first measurement
        self._previous_stats[interface] = current_stats
        return None
    
    def monitor_dual_interface_pps(self, incoming_interface: str, target_interface: str, 
                                  interval: float = 1.0, duration: int = 0) -> None:
        """Monitor PPS on both incoming and target interfaces (like bash version)"""
        self.logger.info("🔍 DUAL INTERFACE PPS MONITOR")
        self.logger.info(f"Incoming: {incoming_interface} | Target: {target_interface} | Interval: {interval}s")
        
        # Initialize
        start_time = datetime.now()
        iterations = 0
        
        # Header
        print(f"{'TIME':<8} | {'INCOMING-RX':<15} | {'INCOMING-TX':<15} | {'TARGET-RX':<15} | {'TARGET-TX':<15}")
        print(f"{'--------':<8} | {'---------------':<15} | {'---------------':<15} | {'---------------':<15} | {'---------------':<15}")
        
        # Initialize previous stats
        self.get_interface_stats(incoming_interface)
        self.get_interface_stats(target_interface)
        
        try:
            while True:
                time.sleep(interval)
                iterations += 1
                
                # Calculate PPS for both interfaces
                incoming_pps = self.calculate_pps(incoming_interface, interval)
                target_pps = self.calculate_pps(target_interface, interval)
                
                # Display results
                timestamp = datetime.now().strftime("%H:%M:%S")
                
                incoming_rx_str = f"{incoming_pps.rx_pps:,} pps" if incoming_pps else "0 pps"
                incoming_tx_str = f"{incoming_pps.tx_pps:,} pps" if incoming_pps else "0 pps"
                target_rx_str = f"{target_pps.rx_pps:,} pps" if target_pps else "0 pps"
                target_tx_str = f"{target_pps.tx_pps:,} pps" if target_pps else "0 pps"
                
                print(f"{timestamp:<8} | {incoming_rx_str:<15} | {incoming_tx_str:<15} | {target_rx_str:<15} | {target_tx_str:<15}")
                
                # Check duration limit
                if duration > 0:
                    elapsed = (datetime.now() - start_time).total_seconds()
                    if elapsed >= duration:
                        break
                        
        except KeyboardInterrupt:
            self.logger.info(f"\n📊 PPS monitoring stopped ({iterations} samples)")
    
    def monitor_single_interface_pps(self, interface: str, interval: float = 1.0, duration: int = 0) -> None:
        """Monitor PPS on single interface with color coding"""
        self.logger.info(f"📊 SINGLE INTERFACE PPS MONITOR: {interface}")
        self.logger.info(f"Interval: {interval}s | Press Ctrl+C to stop")
        
        start_time = datetime.now()
        iterations = 0
        
        # Header
        print(f"{'TIME':<8} | {'RX PPS':<15} | {'TX PPS':<15} | {'TOTAL PPS':<12}")
        print(f"{'--------':<8} | {'---------------':<15} | {'---------------':<15} | {'------------':<12}")
        
        # Initialize
        self.get_interface_stats(interface)
        
        try:
            while True:
                time.sleep(interval)
                iterations += 1
                
                pps_calc = self.calculate_pps(interface, interval)
                if not pps_calc:
                    continue
                
                timestamp = datetime.now().strftime("%H:%M:%S")
                
                # Color coding based on performance
                if pps_calc.total_pps > 50000:
                    # Green for high performance
                    print(f"\033[32m{timestamp:<8} | {pps_calc.rx_pps:,} pps{' ':<6} | {pps_calc.tx_pps:,} pps{' ':<6} | {pps_calc.total_pps:,} pps\033[0m")
                elif pps_calc.total_pps > 10000:
                    # Yellow for medium performance
                    print(f"\033[33m{timestamp:<8} | {pps_calc.rx_pps:,} pps{' ':<6} | {pps_calc.tx_pps:,} pps{' ':<6} | {pps_calc.total_pps:,} pps\033[0m")
                else:
                    # Normal for low performance
                    print(f"{timestamp:<8} | {pps_calc.rx_pps:,} pps{' ':<6} | {pps_calc.tx_pps:,} pps{' ':<6} | {pps_calc.total_pps:,} pps")
                
                # Check duration
                if duration > 0:
                    elapsed = (datetime.now() - start_time).total_seconds()
                    if elapsed >= duration:
                        break
                        
        except KeyboardInterrupt:
            self.logger.info(f"\n📊 PPS monitoring completed ({iterations} samples)")
    
    def get_ebpf_stats(self) -> Optional[EBPFMapStats]:
        """Get eBPF map statistics using bpftool"""
        try:
            # Try to get stats from stats_map
            result = self.runner.run(
                ["sudo", "bpftool", "map", "dump", "name", "stats_map", "--json"],
                check=False
            )
            
            if result.returncode != 0:
                return None
                
            stats_json = json.loads(result.stdout)
            stats = EBPFMapStats()
            
            # Parse statistics (sum across all CPUs)
            for entry in stats_json:
                key = entry.get("formatted", {}).get("key", -1)
                if key == 0:  # total_packets
                    stats.total_packets = sum(val.get("value", 0) for val in entry.get("formatted", {}).get("values", []))
                elif key == 1:  # vxlan_packets
                    stats.vxlan_packets = sum(val.get("value", 0) for val in entry.get("formatted", {}).get("values", []))
                elif key == 2:  # inner_packets
                    stats.inner_packets = sum(val.get("value", 0) for val in entry.get("formatted", {}).get("values", []))
                elif key == 3:  # nat_applied
                    stats.nat_applied = sum(val.get("value", 0) for val in entry.get("formatted", {}).get("values", []))
                elif key == 4:  # df_cleared
                    stats.df_cleared = sum(val.get("value", 0) for val in entry.get("formatted", {}).get("values", []))
                elif key == 5:  # forwarded
                    stats.forwarded = sum(val.get("value", 0) for val in entry.get("formatted", {}).get("values", []))
                elif key == 6:  # redirected
                    stats.redirected = sum(val.get("value", 0) for val in entry.get("formatted", {}).get("values", []))
                elif key == 7:  # errors
                    stats.errors = sum(val.get("value", 0) for val in entry.get("formatted", {}).get("values", []))
                elif key == 8:  # bytes_processed
                    stats.bytes_processed = sum(val.get("value", 0) for val in entry.get("formatted", {}).get("values", []))
                elif key == 9:  # ip_len_updated
                    stats.ip_len_updated = sum(val.get("value", 0) for val in entry.get("formatted", {}).get("values", []))
                elif key == 15:  # length_corrections
                    stats.length_corrections = sum(val.get("value", 0) for val in entry.get("formatted", {}).get("values", []))
            
            return stats
            
        except Exception as e:
            self.logger.debug(f"Failed to get eBPF stats: {e}")
            return None
    
    def calculate_ebpf_rates(self, interval: float = 5.0) -> Optional[Dict[str, int]]:
        """Calculate rates from eBPF statistics"""
        current_stats = self.get_ebpf_stats()
        if not current_stats:
            return None
        
        if self._previous_ebpf_stats:
            prev = self._previous_ebpf_stats
            
            rates = {
                "total_pps": int((current_stats.total_packets - prev.total_packets) / interval),
                "vxlan_pps": int((current_stats.vxlan_packets - prev.vxlan_packets) / interval),
                "nat_pps": int((current_stats.nat_applied - prev.nat_applied) / interval),
                "forwarded_pps": int((current_stats.forwarded - prev.forwarded) / interval)
            }
            
            self._previous_ebpf_stats = current_stats
            return rates
        
        self._previous_ebpf_stats = current_stats
        return None
    
    def show_clean_statistics(self, interval: float = 5.0, duration: int = 0) -> None:
        """Display clean statistics like bash version"""
        self.logger.info("VXLAN Pipeline Performance Dashboard")
        self.logger.info("Press Ctrl+C to stop monitoring...")
        
        start_time = datetime.now()
        
        # Initialize
        self.get_ebpf_stats()  # First reading
        
        try:
            while True:
                time.sleep(interval)
                
                stats = self.get_ebpf_stats()
                rates = self.calculate_ebpf_rates(interval)
                
                if not stats:
                    print("✗ Unable to retrieve statistics")
                    continue
                
                # Calculate percentages
                vxlan_pct = (stats.vxlan_packets / max(stats.total_packets, 1)) * 100
                nat_efficiency = (stats.nat_applied / max(stats.vxlan_packets, 1)) * 100
                error_rate = (stats.errors / max(stats.total_packets, 1)) * 100
                
                # Calculate throughput (estimate ~1000 bytes per packet)
                throughput_mbps = 0.0
                if rates and rates.get("vxlan_pps", 0) > 0:
                    throughput_mbps = (rates["vxlan_pps"] * 1000 * 8) / 1_000_000
                
                # Performance assessment
                total_pps = rates.get("total_pps", 0) if rates else 0
                if total_pps >= 85000:
                    perf_status = f"TARGET ACHIEVED: {self._format_number(total_pps)} PPS"
                elif total_pps >= 50000:
                    perf_status = f"HIGH PERFORMANCE: {self._format_number(total_pps)} PPS"
                else:
                    perf_status = f"Performance: {self._format_number(total_pps)} PPS (target: 85K+)"
                
                # Clear screen and display
                print("\033[2J\033[H")  # Clear screen and move cursor to top
                print(f"{datetime.now().strftime('%H:%M:%S')}")
                print("=" * 60)
                print("VXLAN Pipeline Performance Dashboard")
                print("=" * 60)
                
                print(f"Total Packets:         {self._format_number(stats.total_packets):>8} ({self._format_number(total_pps):>6} pps)")
                print(f"VXLAN Packets:         {self._format_number(stats.vxlan_packets):>8} ({vxlan_pct:4.1f}%)")
                print(f"NAT Applied:           {self._format_number(stats.nat_applied):>8} ({nat_efficiency:4.1f}% efficiency)")
                print(f"Forwarded:             {self._format_number(stats.forwarded):>8}")
                print(f"XDP Redirected:        {self._format_number(stats.redirected):>8}")
                
                if stats.length_corrections > 0:
                    print(f"🔧 Length Fixed:       {self._format_number(stats.length_corrections):>8} (truncation repair)")
                
                print(f"🌐 Throughput:         {throughput_mbps:>8.2f} Mbps")
                print(f"{perf_status}")
                print("=" * 60)
                
                # Check duration
                if duration > 0:
                    elapsed = (datetime.now() - start_time).total_seconds()
                    if elapsed >= duration:
                        break
                        
        except KeyboardInterrupt:
            print("\n👋 Monitoring stopped by user")
    
    def _format_number(self, num: int) -> str:
        """Format large numbers with appropriate units"""
        if num >= 1_000_000_000:
            return f"{num/1_000_000_000:.1f}B"
        elif num >= 1_000_000:
            return f"{num/1_000_000:.1f}M"
        elif num >= 1_000:
            return f"{num/1_000:.1f}K"
        else:
            return str(num)

class UnifiedMonitor(RealTimeMonitor):
    """Unified monitoring interface combining all monitoring capabilities"""
    
    def __init__(self, runner: Optional[CommandRunner] = None, logger: Optional[Logger] = None):
        super().__init__(runner, logger)
        self.bpf_maps = BPFMapManager(runner, logger)
    
    def get_performance_report(self, duration_minutes: int = 15) -> Dict[str, Any]:
        """Generate comprehensive performance report"""
        return {
            "report_period_minutes": duration_minutes,
            "performance_summary": {
                "monitoring_available": True,
                "real_time_pps": "Available via monitor_dual_interface_pps()",
                "bpf_stats": "Available via bpf_maps.get_pipeline_stats()"
            }
        }

# Compatibility aliases for existing code
AdvancedMonitor = UnifiedMonitor
LogMonitor = UnifiedMonitor  
ProfessionalMonitor = UnifiedMonitor