#!/usr/bin/env python3
"""
XDP VXLAN Pipeline - Real-time System Resource Monitor
Monitors CPU, memory, network, and XDP-specific metrics during performance tests
"""

import time
import psutil
import json
import argparse
import threading
from datetime import datetime
from pathlib import Path
from collections import deque
import subprocess
import os

class SystemResourceMonitor:
    """Comprehensive system resource monitoring for XDP performance testing"""
    
    def __init__(self, interval=1, interface="lo", output_dir="performance_results"):
        self.interval = interval
        self.interface = interface
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.running = False
        self.start_time = None
        self.metrics = deque(maxlen=3600)  # Store up to 1 hour of data
        
        # XDP statistics paths
        self.xdp_stats_file = None
        if interface != "lo":
            self.xdp_stats_file = f"/sys/class/net/{interface}/xdp/prog_id"
    
    def get_cpu_stats(self):
        """Get detailed CPU statistics"""
        cpu_percent = psutil.cpu_percent(interval=None, percpu=True)
        cpu_freq = psutil.cpu_freq()
        
        return {
            'cpu_percent_total': psutil.cpu_percent(interval=None),
            'cpu_percent_per_core': cpu_percent,
            'cpu_count': psutil.cpu_count(),
            'cpu_freq_current': cpu_freq.current if cpu_freq else None,
            'cpu_freq_min': cpu_freq.min if cpu_freq else None,
            'cpu_freq_max': cpu_freq.max if cpu_freq else None,
            'load_average': os.getloadavg()
        }
    
    def get_memory_stats(self):
        """Get memory usage statistics"""
        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()
        
        return {
            'memory_total': memory.total,
            'memory_available': memory.available,
            'memory_used': memory.used,
            'memory_percent': memory.percent,
            'memory_free': memory.free,
            'memory_buffers': getattr(memory, 'buffers', 0),
            'memory_cached': getattr(memory, 'cached', 0),
            'swap_total': swap.total,
            'swap_used': swap.used,
            'swap_percent': swap.percent
        }
    
    def get_network_stats(self):
        """Get network interface statistics"""
        try:
            net_io = psutil.net_io_counters(pernic=True)
            if self.interface in net_io:
                stats = net_io[self.interface]
                return {
                    'bytes_sent': stats.bytes_sent,
                    'bytes_recv': stats.bytes_recv,
                    'packets_sent': stats.packets_sent,
                    'packets_recv': stats.packets_recv,
                    'errin': stats.errin,
                    'errout': stats.errout,
                    'dropin': stats.dropin,
                    'dropout': stats.dropout
                }
        except Exception as e:
            pass
        
        return {
            'bytes_sent': 0,
            'bytes_recv': 0,
            'packets_sent': 0,
            'packets_recv': 0,
            'errin': 0,
            'errout': 0,
            'dropin': 0,
            'dropout': 0
        }
    
    def get_disk_stats(self):
        """Get disk I/O statistics"""
        disk_io = psutil.disk_io_counters()
        disk_usage = psutil.disk_usage('/')
        
        return {
            'disk_read_bytes': disk_io.read_bytes if disk_io else 0,
            'disk_write_bytes': disk_io.write_bytes if disk_io else 0,
            'disk_read_count': disk_io.read_count if disk_io else 0,
            'disk_write_count': disk_io.write_count if disk_io else 0,
            'disk_total': disk_usage.total,
            'disk_used': disk_usage.used,
            'disk_free': disk_usage.free,
            'disk_percent': disk_usage.percent
        }
    
    def get_xdp_stats(self):
        """Get XDP-specific statistics if available"""
        xdp_stats = {
            'xdp_prog_loaded': False,
            'xdp_prog_id': None,
            'xdp_processed': 0,
            'xdp_dropped': 0,
            'xdp_redirect': 0,
            'xdp_aborted': 0
        }
        
        # Check if XDP program is loaded
        try:
            if self.xdp_stats_file and os.path.exists(self.xdp_stats_file):
                with open(self.xdp_stats_file, 'r') as f:
                    prog_id = f.read().strip()
                    if prog_id and prog_id != "0":
                        xdp_stats['xdp_prog_loaded'] = True
                        xdp_stats['xdp_prog_id'] = int(prog_id)
        except Exception:
            pass
        
        # Try to get XDP statistics from bpftool if available
        try:
            if xdp_stats['xdp_prog_loaded']:
                result = subprocess.run(['bpftool', 'prog', 'show', 'id', str(xdp_stats['xdp_prog_id'])],
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    # Parse bpftool output for statistics (implementation specific)
                    pass
        except Exception:
            pass
        
        return xdp_stats
    
    def get_process_stats(self):
        """Get process-specific statistics"""
        processes = []
        
        # Find processes related to our XDP pipeline
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'cmdline']):
            try:
                info = proc.info
                cmdline = ' '.join(info['cmdline']) if info['cmdline'] else ''
                
                # Look for our processes
                if any(keyword in cmdline.lower() for keyword in ['vxlan', 'xdp', 'ebpf']):
                    processes.append({
                        'pid': info['pid'],
                        'name': info['name'],
                        'cpu_percent': info['cpu_percent'],
                        'memory_percent': info['memory_percent'],
                        'cmdline': cmdline
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        return processes
    
    def get_system_info(self):
        """Get static system information"""
        return {
            'hostname': os.uname().nodename,
            'platform': os.uname().sysname,
            'platform_release': os.uname().release,
            'platform_version': os.uname().version,
            'architecture': os.uname().machine,
            'processor': os.uname().machine,
            'python_version': f"{psutil.version_info}",
            'boot_time': psutil.boot_time()
        }
    
    def collect_metrics(self):
        """Collect all system metrics at once"""
        timestamp = datetime.now()
        
        metrics = {
            'timestamp': timestamp.isoformat(),
            'uptime_seconds': time.time() - self.start_time if self.start_time else 0,
            'cpu': self.get_cpu_stats(),
            'memory': self.get_memory_stats(),
            'network': self.get_network_stats(),
            'disk': self.get_disk_stats(),
            'xdp': self.get_xdp_stats(),
            'processes': self.get_process_stats()
        }
        
        return metrics
    
    def monitor_loop(self):
        """Main monitoring loop"""
        print(f"📊 Starting system monitoring (interval: {self.interval}s)")
        print(f"🖥️  Monitoring interface: {self.interface}")
        
        while self.running:
            try:
                metrics = self.collect_metrics()
                self.metrics.append(metrics)
                
                # Print real-time summary
                cpu_pct = metrics['cpu']['cpu_percent_total']
                mem_pct = metrics['memory']['memory_percent']
                net_rx_mb = metrics['network']['bytes_recv'] / 1_000_000
                net_tx_mb = metrics['network']['bytes_sent'] / 1_000_000
                
                print(f"\r⚡ CPU: {cpu_pct:5.1f}% | MEM: {mem_pct:5.1f}% | "
                     f"RX: {net_rx_mb:8.2f}MB | TX: {net_tx_mb:8.2f}MB | "
                     f"XDP: {'✓' if metrics['xdp']['xdp_prog_loaded'] else '✗'}", end='', flush=True)
                
                time.sleep(self.interval)
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"\n⚠️  Monitoring error: {e}")
                time.sleep(self.interval)
    
    def start_monitoring(self, test_name="system_monitor"):
        """Start monitoring in background thread"""
        if self.running:
            print("⚠️  Monitoring already running")
            return
        
        self.running = True
        self.start_time = time.time()
        self.test_name = test_name
        
        # Collect initial system info
        self.system_info = self.get_system_info()
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self.monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        print(f"✅ System monitoring started for test: {test_name}")
    
    def stop_monitoring(self):
        """Stop monitoring and save results"""
        if not self.running:
            print("⚠️  Monitoring not running")
            return
        
        self.running = False
        
        if hasattr(self, 'monitor_thread'):
            self.monitor_thread.join(timeout=5)
        
        print("\n🛑 Monitoring stopped")
        
        # Save results
        self.save_results()
    
    def save_results(self):
        """Save monitoring results to files"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        base_filename = f"{self.test_name}_{timestamp}"
        
        # Save raw JSON data
        json_file = self.output_dir / f"{base_filename}_metrics.json"
        results = {
            'test_name': self.test_name,
            'start_time': datetime.fromtimestamp(self.start_time).isoformat() if self.start_time else None,
            'end_time': datetime.now().isoformat(),
            'interface': self.interface,
            'interval': self.interval,
            'system_info': self.system_info if hasattr(self, 'system_info') else {},
            'metrics': list(self.metrics)
        }
        
        with open(json_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        # Save CSV summary
        csv_file = self.output_dir / f"{base_filename}_summary.csv"
        with open(csv_file, 'w') as f:
            f.write("timestamp,cpu_percent,memory_percent,network_rx_mbps,network_tx_mbps,"
                   "disk_read_mbps,disk_write_mbps,xdp_loaded\n")
            
            prev_net_rx = 0
            prev_net_tx = 0
            prev_disk_read = 0
            prev_disk_write = 0
            
            for i, metric in enumerate(self.metrics):
                if i == 0:
                    prev_net_rx = metric['network']['bytes_recv']
                    prev_net_tx = metric['network']['bytes_sent']
                    prev_disk_read = metric['disk']['disk_read_bytes']
                    prev_disk_write = metric['disk']['disk_write_bytes']
                    continue
                
                # Calculate rates
                net_rx_mbps = (metric['network']['bytes_recv'] - prev_net_rx) * 8 / (self.interval * 1_000_000)
                net_tx_mbps = (metric['network']['bytes_sent'] - prev_net_tx) * 8 / (self.interval * 1_000_000)
                disk_read_mbps = (metric['disk']['disk_read_bytes'] - prev_disk_read) / (self.interval * 1_000_000)
                disk_write_mbps = (metric['disk']['disk_write_bytes'] - prev_disk_write) / (self.interval * 1_000_000)
                
                f.write(f"{metric['timestamp']},{metric['cpu']['cpu_percent_total']:.2f},"
                       f"{metric['memory']['memory_percent']:.2f},{net_rx_mbps:.2f},"
                       f"{net_tx_mbps:.2f},{disk_read_mbps:.2f},{disk_write_mbps:.2f},"
                       f"{metric['xdp']['xdp_prog_loaded']}\n")
                
                prev_net_rx = metric['network']['bytes_recv']
                prev_net_tx = metric['network']['bytes_sent']
                prev_disk_read = metric['disk']['disk_read_bytes']
                prev_disk_write = metric['disk']['disk_write_bytes']
        
        print(f"💾 Results saved:")
        print(f"   📄 Raw data: {json_file}")
        print(f"   📊 Summary:  {csv_file}")
        
        # Generate performance summary
        self.generate_summary()
    
    def generate_summary(self):
        """Generate performance monitoring summary"""
        if not self.metrics:
            return
        
        # Calculate statistics
        cpu_values = [m['cpu']['cpu_percent_total'] for m in self.metrics]
        mem_values = [m['memory']['memory_percent'] for m in self.metrics]
        
        summary = {
            'duration_seconds': len(self.metrics) * self.interval,
            'cpu_avg': sum(cpu_values) / len(cpu_values),
            'cpu_max': max(cpu_values),
            'cpu_min': min(cpu_values),
            'memory_avg': sum(mem_values) / len(mem_values),
            'memory_max': max(mem_values),
            'memory_min': min(mem_values),
            'xdp_active_time': sum(1 for m in self.metrics if m['xdp']['xdp_prog_loaded']) * self.interval,
            'total_samples': len(self.metrics)
        }
        
        print(f"\n📈 Performance Summary:")
        print(f"   ⏱️  Duration: {summary['duration_seconds']} seconds")
        print(f"   🔥 CPU Usage: avg={summary['cpu_avg']:.1f}%, max={summary['cpu_max']:.1f}%")
        print(f"   🧠 Memory Usage: avg={summary['memory_avg']:.1f}%, max={summary['memory_max']:.1f}%")
        print(f"   ⚡ XDP Active Time: {summary['xdp_active_time']} seconds")

def main():
    parser = argparse.ArgumentParser(description="XDP VXLAN Pipeline System Resource Monitor")
    parser.add_argument('-i', '--interface', default='lo',
                       help='Network interface to monitor')
    parser.add_argument('-t', '--interval', type=float, default=1.0,
                       help='Monitoring interval in seconds')
    parser.add_argument('-o', '--output', default='performance_results',
                       help='Output directory for results')
    parser.add_argument('-n', '--name', default='system_monitor',
                       help='Test name for output files')
    parser.add_argument('-d', '--duration', type=int, default=0,
                       help='Monitoring duration in seconds (0 = run until interrupted)')
    
    args = parser.parse_args()
    
    # Create monitor
    monitor = SystemResourceMonitor(
        interval=args.interval,
        interface=args.interface,
        output_dir=args.output
    )
    
    try:
        # Start monitoring
        monitor.start_monitoring(args.name)
        
        if args.duration > 0:
            print(f"⏱️  Monitoring for {args.duration} seconds...")
            time.sleep(args.duration)
        else:
            print("⏱️  Monitoring until interrupted (Ctrl+C to stop)...")
            while monitor.running:
                time.sleep(1)
    
    except KeyboardInterrupt:
        print("\n🛑 Interrupted by user")
    
    finally:
        monitor.stop_monitoring()

if __name__ == "__main__":
    main()