#!/usr/bin/env python3
"""
Packets Per Second (PPS) Monitor for XDP VXLAN Pipeline
Provides real-time and post-test analysis of packet throughput
"""

import time
import json
import argparse
import subprocess
import threading
from datetime import datetime
from collections import deque, defaultdict
import psutil


class PPSMonitor:
    """Real-time packet per second monitor with advanced metrics"""
    
    def __init__(self, interface="lo", window_size=5):
        self.interface = interface
        self.window_size = window_size
        self.running = False
        self.data_points = deque(maxlen=1000)  # Store last 1000 measurements
        self.start_time = None
        self.end_time = None
        
        # Interface statistics paths
        self.rx_packets_path = f"/sys/class/net/{interface}/statistics/rx_packets"
        self.tx_packets_path = f"/sys/class/net/{interface}/statistics/tx_packets"
        self.rx_bytes_path = f"/sys/class/net/{interface}/statistics/rx_bytes"
        self.tx_bytes_path = f"/sys/class/net/{interface}/statistics/tx_bytes"
    
    def get_interface_stats(self):
        """Get current interface statistics"""
        try:
            with open(self.rx_packets_path) as f:
                rx_packets = int(f.read().strip())
            with open(self.tx_packets_path) as f:
                tx_packets = int(f.read().strip())
            with open(self.rx_bytes_path) as f:
                rx_bytes = int(f.read().strip())
            with open(self.tx_bytes_path) as f:
                tx_bytes = int(f.read().strip())
            
            return {
                'rx_packets': rx_packets,
                'tx_packets': tx_packets,
                'rx_bytes': rx_bytes,
                'tx_bytes': tx_bytes,
                'timestamp': time.time()
            }
        except (FileNotFoundError, ValueError) as e:
            return None
    
    def calculate_rates(self, current_stats, previous_stats):
        """Calculate packet and byte rates"""
        if not previous_stats:
            return {}
        
        time_delta = current_stats['timestamp'] - previous_stats['timestamp']
        if time_delta <= 0:
            return {}
        
        rx_pps = (current_stats['rx_packets'] - previous_stats['rx_packets']) / time_delta
        tx_pps = (current_stats['tx_packets'] - previous_stats['tx_packets']) / time_delta
        rx_bps = (current_stats['rx_bytes'] - previous_stats['rx_bytes']) / time_delta
        tx_bps = (current_stats['tx_bytes'] - previous_stats['tx_bytes']) / time_delta
        
        return {
            'rx_pps': max(0, rx_pps),
            'tx_pps': max(0, tx_pps),
            'rx_bps': max(0, rx_bps),
            'tx_bps': max(0, tx_bps),
            'total_pps': max(0, rx_pps + tx_pps),
            'timestamp': current_stats['timestamp']
        }
    
    def start_monitoring(self, duration=None, callback=None):
        """Start real-time monitoring"""
        self.running = True
        self.start_time = time.time()
        previous_stats = None
        
        print(f"Starting PPS monitoring on interface {self.interface}")
        print("Timestamp       RX PPS    TX PPS    Total PPS   RX Mbps   TX Mbps")
        print("-" * 75)
        
        try:
            while self.running:
                current_stats = self.get_interface_stats()
                if current_stats:
                    rates = self.calculate_rates(current_stats, previous_stats)
                    
                    if rates and previous_stats:
                        # Store data point
                        data_point = {
                            'timestamp': rates['timestamp'],
                            'rx_pps': rates['rx_pps'],
                            'tx_pps': rates['tx_pps'],
                            'total_pps': rates['total_pps'],
                            'rx_mbps': rates['rx_bps'] * 8 / 1_000_000,
                            'tx_mbps': rates['tx_bps'] * 8 / 1_000_000
                        }
                        self.data_points.append(data_point)
                        
                        # Display current rates
                        timestamp_str = datetime.fromtimestamp(rates['timestamp']).strftime("%H:%M:%S")
                        print(f"{timestamp_str}  {rates['rx_pps']:8.0f}  {rates['tx_pps']:8.0f}  "
                              f"{rates['total_pps']:9.0f}  {data_point['rx_mbps']:8.2f}  {data_point['tx_mbps']:8.2f}")
                        
                        # Call callback if provided
                        if callback:
                            callback(data_point)
                    
                    previous_stats = current_stats
                
                time.sleep(1.0)
                
                # Check duration limit
                if duration and (time.time() - self.start_time) >= duration:
                    break
                    
        except KeyboardInterrupt:
            print("\nMonitoring interrupted by user")
        finally:
            self.running = False
            self.end_time = time.time()
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.running = False
    
    def get_statistics(self):
        """Get comprehensive statistics from collected data"""
        if not self.data_points:
            return {}
        
        # Calculate statistics
        rx_pps_values = [dp['rx_pps'] for dp in self.data_points]
        tx_pps_values = [dp['tx_pps'] for dp in self.data_points]
        total_pps_values = [dp['total_pps'] for dp in self.data_points]
        
        stats = {
            'monitoring_duration': (self.end_time or time.time()) - (self.start_time or time.time()),
            'data_points_collected': len(self.data_points),
            'rx_pps': {
                'min': min(rx_pps_values) if rx_pps_values else 0,
                'max': max(rx_pps_values) if rx_pps_values else 0,
                'avg': sum(rx_pps_values) / len(rx_pps_values) if rx_pps_values else 0,
            },
            'tx_pps': {
                'min': min(tx_pps_values) if tx_pps_values else 0,
                'max': max(tx_pps_values) if tx_pps_values else 0,
                'avg': sum(tx_pps_values) / len(tx_pps_values) if tx_pps_values else 0,
            },
            'total_pps': {
                'min': min(total_pps_values) if total_pps_values else 0,
                'max': max(total_pps_values) if total_pps_values else 0,
                'avg': sum(total_pps_values) / len(total_pps_values) if total_pps_values else 0,
            },
            'peak_performance_window': self._find_peak_window(),
        }
        
        return stats
    
    def _find_peak_window(self):
        """Find the peak performance window"""
        if len(self.data_points) < self.window_size:
            return {}
        
        max_avg_pps = 0
        peak_window = {}
        
        for i in range(len(self.data_points) - self.window_size + 1):
            window_data = list(self.data_points)[i:i + self.window_size]
            avg_pps = sum(dp['total_pps'] for dp in window_data) / len(window_data)
            
            if avg_pps > max_avg_pps:
                max_avg_pps = avg_pps
                peak_window = {
                    'start_time': window_data[0]['timestamp'],
                    'end_time': window_data[-1]['timestamp'],
                    'avg_pps': avg_pps,
                    'max_pps': max(dp['total_pps'] for dp in window_data),
                    'duration': self.window_size
                }
        
        return peak_window
    
    def export_data(self, filename):
        """Export collected data to JSON file"""
        data = {
            'metadata': {
                'interface': self.interface,
                'start_time': self.start_time,
                'end_time': self.end_time,
                'duration': (self.end_time or time.time()) - (self.start_time or time.time()),
            },
            'statistics': self.get_statistics(),
            'data_points': list(self.data_points)
        }
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"Data exported to {filename}")
    
    def print_summary(self):
        """Print monitoring summary"""
        stats = self.get_statistics()
        
        if not stats:
            print("No data collected")
            return
        
        print("\n" + "="*60)
        print("PPS MONITORING SUMMARY")
        print("="*60)
        print(f"Interface: {self.interface}")
        print(f"Duration: {stats['monitoring_duration']:.1f} seconds")
        print(f"Data Points: {stats['data_points_collected']}")
        print()
        
        print("RX Performance:")
        print(f"  Min: {stats['rx_pps']['min']:,.0f} PPS")
        print(f"  Max: {stats['rx_pps']['max']:,.0f} PPS")
        print(f"  Avg: {stats['rx_pps']['avg']:,.0f} PPS")
        print()
        
        print("TX Performance:")
        print(f"  Min: {stats['tx_pps']['min']:,.0f} PPS")
        print(f"  Max: {stats['tx_pps']['max']:,.0f} PPS")  
        print(f"  Avg: {stats['tx_pps']['avg']:,.0f} PPS")
        print()
        
        print("Total Performance:")
        print(f"  Min: {stats['total_pps']['min']:,.0f} PPS")
        print(f"  Max: {stats['total_pps']['max']:,.0f} PPS")
        print(f"  Avg: {stats['total_pps']['avg']:,.0f} PPS")
        
        if stats['peak_performance_window']:
            peak = stats['peak_performance_window']
            print()
            print(f"Peak {self.window_size}s Window:")
            print(f"  Average: {peak['avg_pps']:,.0f} PPS")
            print(f"  Maximum: {peak['max_pps']:,.0f} PPS")
            print(f"  Start: {datetime.fromtimestamp(peak['start_time']).strftime('%H:%M:%S')}")
            print(f"  End: {datetime.fromtimestamp(peak['end_time']).strftime('%H:%M:%S')}")


def monitor_xdp_performance(interface, duration, output_file=None):
    """Monitor XDP pipeline performance"""
    monitor = PPSMonitor(interface)
    
    # Start monitoring in a separate thread
    monitor_thread = threading.Thread(
        target=monitor.start_monitoring,
        args=(duration,)
    )
    monitor_thread.start()
    
    # Wait for completion
    monitor_thread.join()
    
    # Print summary
    monitor.print_summary()
    
    # Export data if requested
    if output_file:
        monitor.export_data(output_file)
    
    return monitor.get_statistics()


def main():
    parser = argparse.ArgumentParser(description="PPS Monitor for XDP VXLAN Pipeline")
    parser.add_argument("-i", "--interface", default="lo", 
                       help="Network interface to monitor (default: lo)")
    parser.add_argument("-d", "--duration", type=int, default=30,
                       help="Monitoring duration in seconds (default: 30)")
    parser.add_argument("-o", "--output", 
                       help="Output file for detailed results (JSON format)")
    parser.add_argument("-w", "--window", type=int, default=5,
                       help="Peak performance window size in seconds (default: 5)")
    
    args = parser.parse_args()
    
    print(f"XDP VXLAN Pipeline PPS Monitor")
    print(f"Interface: {args.interface}")
    print(f"Duration: {args.duration} seconds")
    print(f"Peak window: {args.window} seconds")
    if args.output:
        print(f"Output file: {args.output}")
    print()
    
    monitor = PPSMonitor(args.interface, args.window)
    
    try:
        monitor.start_monitoring(args.duration)
        monitor.print_summary()
        
        if args.output:
            monitor.export_data(args.output)
            
    except Exception as e:
        print(f"Error during monitoring: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())