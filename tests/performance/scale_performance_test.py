#!/usr/bin/env python3
"""
XDP VXLAN Pipeline - Scale and Performance Test Generator
Generates high-volume VXLAN traffic for performance testing and benchmarking
"""

import os
import sys
import argparse
import time
import json
import threading
import multiprocessing as mp
from datetime import datetime
from pathlib import Path

# Import scapy modules - using virtual environment
try:
    from scapy.all import *
    from scapy.layers.vxlan import VXLAN
    from scapy.layers.inet import IP, UDP, TCP, ICMP
    from scapy.layers.l2 import Ether, ARP
    import scapy.utils
except ImportError as e:
    print(f"ERROR: Failed to import scapy: {e}")
    print("Make sure you're running in the virtual environment:")
    print("  source .venv/bin/activate")
    sys.exit(1)

class ScaleTestConfig:
    """Configuration for scale and performance tests"""
    
    # Test scenarios
    SCENARIOS = {
        'baseline': {
            'duration': 30,
            'pps': 1000,
            'packet_size': 64,
            'vxlan_ratio': 0.8,
            'description': 'Baseline performance test'
        },
        'high_throughput': {
            'duration': 60,
            'pps': 100000,
            'packet_size': 1400,
            'vxlan_ratio': 1.0,
            'description': 'High throughput stress test'
        },
        'small_packets': {
            'duration': 45,
            'pps': 500000,
            'packet_size': 64,
            'vxlan_ratio': 0.9,
            'description': 'Small packet flood test'
        },
        'large_packets': {
            'duration': 45,
            'pps': 10000,
            'packet_size': 9000,
            'vxlan_ratio': 1.0,
            'description': 'Jumbo frame test'
        },
        'mixed_traffic': {
            'duration': 90,
            'pps': 50000,
            'packet_size': [64, 256, 1400, 1500],
            'vxlan_ratio': 0.7,
            'description': 'Mixed size traffic simulation'
        },
        'burst_test': {
            'duration': 120,
            'pps': [10000, 200000, 10000],  # burst pattern
            'packet_size': 1400,
            'vxlan_ratio': 1.0,
            'description': 'Burst traffic patterns'
        },
        'cpu_stress': {
            'duration': 300,
            'pps': 1000000,
            'packet_size': 64,
            'vxlan_ratio': 1.0,
            'description': 'CPU stress test - 1M PPS'
        }
    }

class PerformancePacketGenerator:
    """High-performance packet generator for scale testing"""
    
    def __init__(self, config):
        self.config = config
        self.packets_sent = 0
        self.bytes_sent = 0
        self.start_time = None
        self.stop_event = threading.Event()
        
    def create_vxlan_packet(self, size=64, vni=1, src_port=42844, dst_ip="10.2.41.17", dst_port=8081):
        """Create a VXLAN packet with specified parameters"""
        
        # Outer Ethernet header
        eth = Ether(src="11:22:33:44:55:66", dst="aa:bb:cc:dd:ee:ff")
        
        # Outer IP header  
        outer_ip = IP(src="192.168.1.100", dst="192.168.1.101", ttl=64)
        
        # VXLAN UDP header
        outer_udp = UDP(sport=src_port, dport=4789)
        
        # VXLAN header
        vxlan = VXLAN(vni=vni, flags=0x08)
        
        # Inner Ethernet header
        inner_eth = Ether(src="00:11:22:33:44:55", dst="00:aa:bb:cc:dd:ee")
        
        # Inner IP header
        inner_ip = IP(src="10.0.1.100", dst=dst_ip, ttl=63)
        
        # Inner UDP payload
        inner_udp = UDP(sport=12345, dport=dst_port)
        
        # Calculate payload size needed
        headers_size = len(eth/outer_ip/outer_udp/vxlan/inner_eth/inner_ip/inner_udp)
        payload_size = max(0, size - headers_size)
        
        # Create payload
        payload = Raw(b"X" * payload_size)
        
        # Assemble packet
        packet = eth / outer_ip / outer_udp / vxlan / inner_eth / inner_ip / inner_udp / payload
        
        return packet
    
    def create_non_vxlan_packet(self, size=64):
        """Create a non-VXLAN packet for mixed traffic"""
        
        eth = Ether(src="11:22:33:44:55:66", dst="aa:bb:cc:dd:ee:ff")
        ip = IP(src="192.168.1.200", dst="192.168.1.201", ttl=64)
        udp = UDP(sport=8080, dport=9090)
        
        headers_size = len(eth/ip/udp)
        payload_size = max(0, size - headers_size)
        payload = Raw(b"Y" * payload_size)
        
        return eth / ip / udp / payload
    
    def generate_packet_batch(self, batch_size=100, packet_size=64, vxlan_ratio=0.8):
        """Generate a batch of packets for efficient sending"""
        
        batch = []
        vxlan_count = int(batch_size * vxlan_ratio)
        
        # Generate VXLAN packets
        for i in range(vxlan_count):
            # Vary VNI and ports slightly for realism
            vni = 1 + (i % 10)
            src_port = 42844 + (i % 100)
            packet = self.create_vxlan_packet(packet_size, vni, src_port)
            batch.append(packet)
        
        # Generate non-VXLAN packets
        for i in range(batch_size - vxlan_count):
            packet = self.create_non_vxlan_packet(packet_size)
            batch.append(packet)
        
        return batch
    
    def calculate_send_interval(self, target_pps, batch_size):
        """Calculate interval between batch sends to achieve target PPS"""
        return batch_size / target_pps
    
    def send_worker(self, interface, packets, interval, worker_id, results_queue):
        """Worker process for sending packets"""
        
        worker_stats = {
            'worker_id': worker_id,
            'packets_sent': 0,
            'bytes_sent': 0,
            'errors': 0,
            'start_time': time.time()
        }
        
        try:
            socket_obj = conf.L2socket(iface=interface)
            
            while not self.stop_event.is_set():
                batch_start = time.time()
                
                for packet in packets:
                    try:
                        socket_obj.send(packet)
                        worker_stats['packets_sent'] += 1
                        worker_stats['bytes_sent'] += len(packet)
                    except Exception as e:
                        worker_stats['errors'] += 1
                
                # Calculate sleep time to maintain target rate
                elapsed = time.time() - batch_start
                sleep_time = max(0, interval - elapsed)
                if sleep_time > 0:
                    time.sleep(sleep_time)
        
        except Exception as e:
            worker_stats['error_msg'] = str(e)
        
        finally:
            worker_stats['end_time'] = time.time()
            results_queue.put(worker_stats)
    
    def run_performance_test(self, scenario_name, interface="lo", workers=4):
        """Run a performance test scenario"""
        
        scenario = ScaleTestConfig.SCENARIOS.get(scenario_name)
        if not scenario:
            raise ValueError(f"Unknown scenario: {scenario_name}")
        
        print(f"\n🚀 Starting Performance Test: {scenario_name}")
        print(f"📋 {scenario['description']}")
        print(f"⏱️  Duration: {scenario['duration']}s")
        print(f"📡 Interface: {interface}")
        print(f"👥 Workers: {workers}")
        
        # Handle variable parameters
        packet_sizes = scenario['packet_size']
        if not isinstance(packet_sizes, list):
            packet_sizes = [packet_sizes]
        
        target_pps = scenario['pps']
        if not isinstance(target_pps, list):
            target_pps = [target_pps] * (scenario['duration'] // 30 + 1)
        
        # Start monitoring
        results = {
            'scenario': scenario_name,
            'config': scenario,
            'start_time': datetime.now().isoformat(),
            'interface': interface,
            'workers': workers,
            'phases': []
        }
        
        self.start_time = time.time()
        phase_duration = scenario['duration'] // len(target_pps)
        
        try:
            for phase_idx, pps in enumerate(target_pps):
                phase_start = time.time()
                print(f"\n📊 Phase {phase_idx + 1}: Target {pps:,} PPS")
                
                # Select packet size for this phase
                packet_size = packet_sizes[phase_idx % len(packet_sizes)]
                
                # Generate packet batch
                batch_size = min(100, pps // workers)
                packets = self.generate_packet_batch(
                    batch_size=batch_size,
                    packet_size=packet_size,
                    vxlan_ratio=scenario['vxlan_ratio']
                )
                
                # Calculate send interval per worker
                per_worker_pps = pps // workers
                interval = self.calculate_send_interval(per_worker_pps, batch_size)
                
                # Start worker processes
                processes = []
                results_queue = mp.Queue()
                
                for worker_id in range(workers):
                    p = mp.Process(
                        target=self.send_worker,
                        args=(interface, packets, interval, worker_id, results_queue)
                    )
                    p.start()
                    processes.append(p)
                
                # Run for phase duration
                time.sleep(phase_duration)
                
                # Stop workers
                self.stop_event.set()
                for p in processes:
                    p.join(timeout=5)
                    if p.is_alive():
                        p.terminate()
                
                # Collect results
                phase_stats = []
                while not results_queue.empty():
                    phase_stats.append(results_queue.get())
                
                phase_results = {
                    'phase': phase_idx + 1,
                    'target_pps': pps,
                    'packet_size': packet_size,
                    'duration': time.time() - phase_start,
                    'worker_stats': phase_stats
                }
                
                results['phases'].append(phase_results)
                
                # Reset for next phase
                self.stop_event.clear()
                
                # Print phase summary
                total_packets = sum(w['packets_sent'] for w in phase_stats)
                total_bytes = sum(w['bytes_sent'] for w in phase_stats)
                actual_pps = total_packets / phase_duration
                throughput_mbps = (total_bytes * 8) / (phase_duration * 1_000_000)
                
                print(f"   Packets sent: {total_packets:,}")
                print(f"   Actual PPS: {actual_pps:,.0f}")
                print(f"   Throughput: {throughput_mbps:.2f} Mbps")
                print(f"   Efficiency: {(actual_pps/pps*100):.1f}%")
        
        except KeyboardInterrupt:
            print("\n⚠️  Test interrupted by user")
            self.stop_event.set()
        
        results['end_time'] = datetime.now().isoformat()
        results['total_duration'] = time.time() - self.start_time
        
        return results

class PerformanceAnalyzer:
    """Analyze and report performance test results"""
    
    def __init__(self):
        pass
    
    def calculate_metrics(self, results):
        """Calculate comprehensive performance metrics"""
        
        metrics = {
            'total_packets': 0,
            'total_bytes': 0,
            'average_pps': 0,
            'peak_pps': 0,
            'average_throughput_mbps': 0,
            'peak_throughput_mbps': 0,
            'efficiency_percent': 0,
            'error_rate': 0,
            'phases': []
        }
        
        for phase in results['phases']:
            phase_metrics = {
                'phase': phase['phase'],
                'target_pps': phase['target_pps'],
                'packet_size': phase['packet_size']
            }
            
            # Aggregate worker stats
            total_packets = sum(w['packets_sent'] for w in phase['worker_stats'])
            total_bytes = sum(w['bytes_sent'] for w in phase['worker_stats'])
            total_errors = sum(w['errors'] for w in phase['worker_stats'])
            
            # Calculate phase metrics
            actual_pps = total_packets / phase['duration']
            throughput_mbps = (total_bytes * 8) / (phase['duration'] * 1_000_000)
            efficiency = (actual_pps / phase['target_pps']) * 100
            error_rate = (total_errors / max(1, total_packets)) * 100
            
            phase_metrics.update({
                'packets_sent': total_packets,
                'bytes_sent': total_bytes,
                'actual_pps': actual_pps,
                'throughput_mbps': throughput_mbps,
                'efficiency_percent': efficiency,
                'error_rate': error_rate
            })
            
            metrics['phases'].append(phase_metrics)
            
            # Update overall metrics
            metrics['total_packets'] += total_packets
            metrics['total_bytes'] += total_bytes
            metrics['peak_pps'] = max(metrics['peak_pps'], actual_pps)
            metrics['peak_throughput_mbps'] = max(metrics['peak_throughput_mbps'], throughput_mbps)
        
        # Calculate averages
        if metrics['phases']:
            metrics['average_pps'] = sum(p['actual_pps'] for p in metrics['phases']) / len(metrics['phases'])
            metrics['average_throughput_mbps'] = sum(p['throughput_mbps'] for p in metrics['phases']) / len(metrics['phases'])
            metrics['efficiency_percent'] = sum(p['efficiency_percent'] for p in metrics['phases']) / len(metrics['phases'])
            metrics['error_rate'] = sum(p['error_rate'] for p in metrics['phases']) / len(metrics['phases'])
        
        return metrics
    
    def generate_report(self, results, output_dir):
        """Generate comprehensive performance report"""
        
        metrics = self.calculate_metrics(results)
        
        # Create output directory
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        # Save raw results
        results_file = Path(output_dir) / f"performance_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        # Generate text report
        report_file = Path(output_dir) / f"performance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        with open(report_file, 'w') as f:
            f.write("═══════════════════════════════════════════════════════════════\n")
            f.write("       XDP VXLAN PIPELINE - PERFORMANCE TEST REPORT\n")
            f.write("═══════════════════════════════════════════════════════════════\n\n")
            
            f.write(f"Test Scenario: {results['scenario']}\n")
            f.write(f"Description: {results['config']['description']}\n")
            f.write(f"Test Duration: {results['total_duration']:.1f} seconds\n")
            f.write(f"Interface: {results['interface']}\n")
            f.write(f"Workers: {results['workers']}\n")
            f.write(f"Start Time: {results['start_time']}\n")
            f.write(f"End Time: {results['end_time']}\n\n")
            
            f.write("OVERALL PERFORMANCE METRICS\n")
            f.write("─────────────────────────────────────────────────────────────\n")
            f.write(f"Total Packets Sent:     {metrics['total_packets']:,}\n")
            f.write(f"Total Data Transferred: {metrics['total_bytes']/1_000_000:.2f} MB\n")
            f.write(f"Average PPS:           {metrics['average_pps']:,.0f}\n")
            f.write(f"Peak PPS:              {metrics['peak_pps']:,.0f}\n")
            f.write(f"Average Throughput:    {metrics['average_throughput_mbps']:.2f} Mbps\n")
            f.write(f"Peak Throughput:       {metrics['peak_throughput_mbps']:.2f} Mbps\n")
            f.write(f"Average Efficiency:    {metrics['efficiency_percent']:.1f}%\n")
            f.write(f"Error Rate:            {metrics['error_rate']:.3f}%\n\n")
            
            f.write("PHASE-BY-PHASE BREAKDOWN\n")
            f.write("─────────────────────────────────────────────────────────────\n")
            
            for phase in metrics['phases']:
                f.write(f"Phase {phase['phase']}:\n")
                f.write(f"  Target PPS:      {phase['target_pps']:,}\n")
                f.write(f"  Actual PPS:      {phase['actual_pps']:,.0f}\n")
                f.write(f"  Packet Size:     {phase['packet_size']} bytes\n")
                f.write(f"  Packets Sent:    {phase['packets_sent']:,}\n")
                f.write(f"  Throughput:      {phase['throughput_mbps']:.2f} Mbps\n")
                f.write(f"  Efficiency:      {phase['efficiency_percent']:.1f}%\n")
                f.write(f"  Error Rate:      {phase['error_rate']:.3f}%\n\n")
        
        print(f"\n📊 Performance report saved:")
        print(f"   📄 Results: {results_file}")
        print(f"   📋 Report:  {report_file}")
        
        return report_file, results_file

def main():
    parser = argparse.ArgumentParser(description="XDP VXLAN Pipeline Scale & Performance Tester")
    parser.add_argument('scenario', choices=list(ScaleTestConfig.SCENARIOS.keys()) + ['all'],
                       help='Performance test scenario to run')
    parser.add_argument('-i', '--interface', default='lo',
                       help='Network interface to use for testing')
    parser.add_argument('-w', '--workers', type=int, default=4,
                       help='Number of worker processes')
    parser.add_argument('-o', '--output', default='tests/performance_results',
                       help='Output directory for results')
    parser.add_argument('--list', action='store_true',
                       help='List available test scenarios')
    
    args = parser.parse_args()
    
    if args.list:
        print("\nAvailable Performance Test Scenarios:")
        print("═══════════════════════════════════════")
        for name, config in ScaleTestConfig.SCENARIOS.items():
            print(f"{name:15} - {config['description']}")
        return
    
    generator = PerformancePacketGenerator(ScaleTestConfig.SCENARIOS)
    analyzer = PerformanceAnalyzer()
    
    if args.scenario == 'all':
        scenarios = list(ScaleTestConfig.SCENARIOS.keys())
    else:
        scenarios = [args.scenario]
    
    for scenario in scenarios:
        try:
            print(f"\n{'='*60}")
            results = generator.run_performance_test(scenario, args.interface, args.workers)
            analyzer.generate_report(results, args.output)
            
        except KeyboardInterrupt:
            print("\n⚠️  Test suite interrupted")
            break
        except Exception as e:
            print(f"❌ Error running scenario '{scenario}': {e}")
    
    print("\n🏁 Performance testing complete!")

if __name__ == "__main__":
    main()