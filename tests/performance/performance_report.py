#!/usr/bin/env python3
"""
XDP VXLAN Pipeline - Performance Report Generator
Generates comprehensive performance analysis reports from test results
"""

import json
import argparse
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
from datetime import datetime
import numpy as np
import sys

# Set matplotlib backend for headless systems
import matplotlib
matplotlib.use('Agg')

class PerformanceReportGenerator:
    """Generate comprehensive performance reports with charts and analysis"""
    
    def __init__(self, results_dir="performance_results"):
        self.results_dir = Path(results_dir)
        self.report_data = {}
        
        # Set style for plots
        plt.style.use('default')
        sns.set_palette("husl")
    
    def load_test_results(self):
        """Load all performance test results"""
        results_files = list(self.results_dir.glob("performance_results_*.json"))
        
        if not results_files:
            print(f"❌ No performance results found in {self.results_dir}")
            return False
        
        print(f"📁 Found {len(results_files)} performance result files")
        
        for result_file in results_files:
            try:
                with open(result_file, 'r') as f:
                    data = json.load(f)
                    scenario = data.get('scenario', 'unknown')
                    self.report_data[scenario] = data
                    print(f"   ✅ Loaded: {scenario}")
            except Exception as e:
                print(f"   ⚠️  Error loading {result_file}: {e}")
        
        return len(self.report_data) > 0
    
    def load_monitoring_data(self):
        """Load system monitoring data"""
        monitor_files = list(self.results_dir.glob("*_metrics.json"))
        monitoring_data = {}
        
        for monitor_file in monitor_files:
            try:
                with open(monitor_file, 'r') as f:
                    data = json.load(f)
                    test_name = data.get('test_name', 'unknown')
                    monitoring_data[test_name] = data
            except Exception as e:
                print(f"   ⚠️  Error loading monitoring data {monitor_file}: {e}")
        
        return monitoring_data
    
    def calculate_performance_metrics(self):
        """Calculate comprehensive performance metrics"""
        metrics_summary = {}
        
        for scenario, data in self.report_data.items():
            scenario_metrics = {
                'scenario': scenario,
                'description': data.get('config', {}).get('description', ''),
                'total_duration': data.get('total_duration', 0),
                'phases': len(data.get('phases', [])),
                'total_packets': 0,
                'total_bytes': 0,
                'avg_pps': 0,
                'max_pps': 0,
                'avg_throughput_mbps': 0,
                'max_throughput_mbps': 0,
                'avg_efficiency': 0,
                'error_rate': 0,
                'phase_details': []
            }
            
            for phase in data.get('phases', []):
                # Calculate phase metrics
                total_packets = sum(w.get('packets_sent', 0) for w in phase.get('worker_stats', []))
                total_bytes = sum(w.get('bytes_sent', 0) for w in phase.get('worker_stats', []))
                total_errors = sum(w.get('errors', 0) for w in phase.get('worker_stats', []))
                
                duration = phase.get('duration', 1)
                actual_pps = total_packets / duration
                throughput_mbps = (total_bytes * 8) / (duration * 1_000_000)
                target_pps = phase.get('target_pps', 1)
                efficiency = (actual_pps / target_pps) * 100 if target_pps > 0 else 0
                error_rate = (total_errors / max(1, total_packets)) * 100
                
                phase_detail = {
                    'phase': phase.get('phase', 0),
                    'target_pps': target_pps,
                    'actual_pps': actual_pps,
                    'packet_size': phase.get('packet_size', 0),
                    'packets_sent': total_packets,
                    'bytes_sent': total_bytes,
                    'throughput_mbps': throughput_mbps,
                    'efficiency': efficiency,
                    'error_rate': error_rate,
                    'duration': duration
                }
                
                scenario_metrics['phase_details'].append(phase_detail)
                
                # Update scenario totals
                scenario_metrics['total_packets'] += total_packets
                scenario_metrics['total_bytes'] += total_bytes
                scenario_metrics['max_pps'] = max(scenario_metrics['max_pps'], actual_pps)
                scenario_metrics['max_throughput_mbps'] = max(scenario_metrics['max_throughput_mbps'], throughput_mbps)
            
            # Calculate averages
            if scenario_metrics['phase_details']:
                num_phases = len(scenario_metrics['phase_details'])
                scenario_metrics['avg_pps'] = sum(p['actual_pps'] for p in scenario_metrics['phase_details']) / num_phases
                scenario_metrics['avg_throughput_mbps'] = sum(p['throughput_mbps'] for p in scenario_metrics['phase_details']) / num_phases
                scenario_metrics['avg_efficiency'] = sum(p['efficiency'] for p in scenario_metrics['phase_details']) / num_phases
                scenario_metrics['error_rate'] = sum(p['error_rate'] for p in scenario_metrics['phase_details']) / num_phases
            
            metrics_summary[scenario] = scenario_metrics
        
        return metrics_summary
    
    def create_performance_charts(self, metrics, output_dir):
        """Create performance visualization charts"""
        charts_dir = Path(output_dir) / "charts"
        charts_dir.mkdir(exist_ok=True)
        
        # Chart 1: PPS Comparison across scenarios
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
        
        scenarios = list(metrics.keys())
        avg_pps = [metrics[s]['avg_pps'] for s in scenarios]
        max_pps = [metrics[s]['max_pps'] for s in scenarios]
        
        x = np.arange(len(scenarios))
        width = 0.35
        
        ax1.bar(x - width/2, avg_pps, width, label='Average PPS', alpha=0.8)
        ax1.bar(x + width/2, max_pps, width, label='Peak PPS', alpha=0.8)
        ax1.set_xlabel('Test Scenarios')
        ax1.set_ylabel('Packets Per Second')
        ax1.set_title('PPS Performance Comparison')
        ax1.set_xticks(x)
        ax1.set_xticklabels(scenarios, rotation=45, ha='right')
        ax1.legend()
        ax1.grid(True, alpha=0.3)
        
        # Chart 2: Throughput Comparison
        avg_throughput = [metrics[s]['avg_throughput_mbps'] for s in scenarios]
        max_throughput = [metrics[s]['max_throughput_mbps'] for s in scenarios]
        
        ax2.bar(x - width/2, avg_throughput, width, label='Average Mbps', alpha=0.8)
        ax2.bar(x + width/2, max_throughput, width, label='Peak Mbps', alpha=0.8)
        ax2.set_xlabel('Test Scenarios')
        ax2.set_ylabel('Throughput (Mbps)')
        ax2.set_title('Throughput Performance Comparison')
        ax2.set_xticks(x)
        ax2.set_xticklabels(scenarios, rotation=45, ha='right')
        ax2.legend()
        ax2.grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(charts_dir / "performance_comparison.png", dpi=300, bbox_inches='tight')
        plt.close()
        
        # Chart 3: Efficiency and Error Rates
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
        
        efficiency = [metrics[s]['avg_efficiency'] for s in scenarios]
        error_rates = [metrics[s]['error_rate'] for s in scenarios]
        
        colors = sns.color_palette("husl", len(scenarios))
        
        ax1.bar(scenarios, efficiency, color=colors, alpha=0.8)
        ax1.set_xlabel('Test Scenarios')
        ax1.set_ylabel('Efficiency (%)')
        ax1.set_title('Average Efficiency by Scenario')
        ax1.set_xticklabels(scenarios, rotation=45, ha='right')
        ax1.grid(True, alpha=0.3)
        ax1.axhline(y=90, color='red', linestyle='--', alpha=0.7, label='90% Target')
        ax1.legend()
        
        ax2.bar(scenarios, error_rates, color=colors, alpha=0.8)
        ax2.set_xlabel('Test Scenarios')
        ax2.set_ylabel('Error Rate (%)')
        ax2.set_title('Error Rate by Scenario')
        ax2.set_xticklabels(scenarios, rotation=45, ha='right')
        ax2.grid(True, alpha=0.3)
        ax2.axhline(y=1.0, color='red', linestyle='--', alpha=0.7, label='1% Threshold')
        ax2.legend()
        
        plt.tight_layout()
        plt.savefig(charts_dir / "efficiency_errors.png", dpi=300, bbox_inches='tight')
        plt.close()
        
        # Chart 4: Phase-by-phase performance for multi-phase tests
        for scenario, metric_data in metrics.items():
            if len(metric_data['phase_details']) > 1:
                fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 10))
                
                phases = [p['phase'] for p in metric_data['phase_details']]
                target_pps = [p['target_pps'] for p in metric_data['phase_details']]
                actual_pps = [p['actual_pps'] for p in metric_data['phase_details']]
                throughput = [p['throughput_mbps'] for p in metric_data['phase_details']]
                efficiency = [p['efficiency'] for p in metric_data['phase_details']]
                
                # PPS comparison
                ax1.plot(phases, target_pps, 'o-', label='Target PPS', linewidth=2, markersize=6)
                ax1.plot(phases, actual_pps, 's-', label='Actual PPS', linewidth=2, markersize=6)
                ax1.set_xlabel('Phase')
                ax1.set_ylabel('Packets Per Second')
                ax1.set_title(f'{scenario} - PPS by Phase')
                ax1.legend()
                ax1.grid(True, alpha=0.3)
                
                # Throughput
                ax2.plot(phases, throughput, 'o-', color='green', linewidth=2, markersize=6)
                ax2.set_xlabel('Phase')
                ax2.set_ylabel('Throughput (Mbps)')
                ax2.set_title(f'{scenario} - Throughput by Phase')
                ax2.grid(True, alpha=0.3)
                
                # Efficiency
                ax3.plot(phases, efficiency, 'o-', color='orange', linewidth=2, markersize=6)
                ax3.set_xlabel('Phase')
                ax3.set_ylabel('Efficiency (%)')
                ax3.set_title(f'{scenario} - Efficiency by Phase')
                ax3.grid(True, alpha=0.3)
                ax3.axhline(y=90, color='red', linestyle='--', alpha=0.7)
                
                # Packet sizes
                packet_sizes = [p['packet_size'] for p in metric_data['phase_details']]
                ax4.bar(phases, packet_sizes, alpha=0.7, color='purple')
                ax4.set_xlabel('Phase')
                ax4.set_ylabel('Packet Size (bytes)')
                ax4.set_title(f'{scenario} - Packet Size by Phase')
                ax4.grid(True, alpha=0.3)
                
                plt.tight_layout()
                safe_filename = scenario.replace(' ', '_').replace('/', '_')
                plt.savefig(charts_dir / f"{safe_filename}_phases.png", dpi=300, bbox_inches='tight')
                plt.close()
        
        print(f"📊 Charts saved in: {charts_dir}")
        return charts_dir
    
    def generate_html_report(self, metrics, monitoring_data, output_file):
        """Generate comprehensive HTML report"""
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XDP VXLAN Pipeline - Performance Analysis Report</title>
    <style>
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0; padding: 20px; background: #f5f7fa; color: #2d3748;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        .header h1 {{ margin: 0; font-size: 2.5em; }}
        .header p {{ margin: 10px 0 0 0; opacity: 0.9; }}
        .section {{ 
            background: white; margin: 20px 0; padding: 25px; border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .metrics-grid {{ 
            display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px; margin: 20px 0;
        }}
        .metric-card {{ 
            background: #f8fafc; padding: 20px; border-radius: 8px; text-align: center;
            border-left: 4px solid #4299e1;
        }}
        .metric-value {{ font-size: 2em; font-weight: bold; color: #2b6cb0; }}
        .metric-label {{ color: #64748b; margin-top: 5px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #e2e8f0; }}
        th {{ background: #f7fafc; font-weight: 600; color: #2d3748; }}
        tr:hover {{ background: #f7fafc; }}
        .status-pass {{ color: #38a169; font-weight: bold; }}
        .status-warn {{ color: #d69e2e; font-weight: bold; }}
        .status-fail {{ color: #e53e3e; font-weight: bold; }}
        .chart {{ text-align: center; margin: 20px 0; }}
        .chart img {{ max-width: 100%; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .summary-stats {{ 
            display: flex; justify-content: space-around; flex-wrap: wrap;
            margin: 20px 0; padding: 20px; background: #edf2f7; border-radius: 8px;
        }}
        .summary-stat {{ text-align: center; margin: 10px; }}
        .summary-stat .value {{ font-size: 1.5em; font-weight: bold; color: #2b6cb0; }}
        .summary-stat .label {{ color: #64748b; margin-top: 5px; }}
        .performance-badge {{ 
            display: inline-block; padding: 4px 12px; border-radius: 20px;
            font-size: 0.85em; font-weight: bold; color: white;
        }}
        .badge-excellent {{ background: #38a169; }}
        .badge-good {{ background: #3182ce; }}
        .badge-fair {{ background: #d69e2e; }}
        .badge-poor {{ background: #e53e3e; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 XDP VXLAN Pipeline Performance Report</h1>
            <p>Comprehensive Performance Analysis and Benchmarking Results</p>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
"""

        # Executive Summary
        total_tests = len(metrics)
        total_packets = sum(m['total_packets'] for m in metrics.values())
        avg_efficiency = sum(m['avg_efficiency'] for m in metrics.values()) / total_tests if total_tests > 0 else 0
        max_pps_achieved = max((m['max_pps'] for m in metrics.values()), default=0)
        
        html_content += f"""
        <div class="section">
            <h2>📊 Executive Summary</h2>
            <div class="summary-stats">
                <div class="summary-stat">
                    <div class="value">{total_tests}</div>
                    <div class="label">Test Scenarios</div>
                </div>
                <div class="summary-stat">
                    <div class="value">{total_packets:,}</div>
                    <div class="label">Total Packets</div>
                </div>
                <div class="summary-stat">
                    <div class="value">{max_pps_achieved:,.0f}</div>
                    <div class="label">Peak PPS</div>
                </div>
                <div class="summary-stat">
                    <div class="value">{avg_efficiency:.1f}%</div>
                    <div class="label">Avg Efficiency</div>
                </div>
            </div>
        </div>
"""

        # Performance Metrics Table
        html_content += """
        <div class="section">
            <h2>🏁 Performance Results by Scenario</h2>
            <table>
                <tr>
                    <th>Scenario</th>
                    <th>Description</th>
                    <th>Avg PPS</th>
                    <th>Peak PPS</th>
                    <th>Avg Throughput</th>
                    <th>Efficiency</th>
                    <th>Error Rate</th>
                    <th>Status</th>
                </tr>
"""
        
        for scenario, metric_data in metrics.items():
            # Determine status badge
            efficiency = metric_data['avg_efficiency']
            if efficiency >= 95:
                badge = '<span class="performance-badge badge-excellent">Excellent</span>'
            elif efficiency >= 90:
                badge = '<span class="performance-badge badge-good">Good</span>'
            elif efficiency >= 75:
                badge = '<span class="performance-badge badge-fair">Fair</span>'
            else:
                badge = '<span class="performance-badge badge-poor">Poor</span>'
            
            html_content += f"""
                <tr>
                    <td><strong>{scenario}</strong></td>
                    <td>{metric_data['description']}</td>
                    <td>{metric_data['avg_pps']:,.0f}</td>
                    <td>{metric_data['max_pps']:,.0f}</td>
                    <td>{metric_data['avg_throughput_mbps']:.2f} Mbps</td>
                    <td>{metric_data['avg_efficiency']:.1f}%</td>
                    <td>{metric_data['error_rate']:.3f}%</td>
                    <td>{badge}</td>
                </tr>
"""
        
        html_content += """
            </table>
        </div>
"""

        # Performance Charts
        html_content += """
        <div class="section">
            <h2>📈 Performance Visualizations</h2>
            <div class="chart">
                <h3>Performance Comparison</h3>
                <img src="charts/performance_comparison.png" alt="Performance Comparison Chart">
            </div>
            <div class="chart">
                <h3>Efficiency and Error Analysis</h3>
                <img src="charts/efficiency_errors.png" alt="Efficiency and Error Chart">
            </div>
        </div>
"""

        # Add phase charts for multi-phase tests
        for scenario in metrics.keys():
            chart_file = f"charts/{scenario.replace(' ', '_').replace('/', '_')}_phases.png"
            if (Path(output_file).parent / chart_file).exists():
                html_content += f"""
        <div class="section">
            <h2>📊 {scenario} - Phase Analysis</h2>
            <div class="chart">
                <img src="{chart_file}" alt="{scenario} Phase Analysis">
            </div>
        </div>
"""

        # System Information (if monitoring data available)
        if monitoring_data:
            html_content += """
        <div class="section">
            <h2>🖥️ System Monitoring</h2>
            <p>System resource utilization during performance testing.</p>
"""
            
            # Add monitoring summary for each test
            for test_name, monitor_data in monitoring_data.items():
                if 'metrics' in monitor_data and monitor_data['metrics']:
                    metrics_data = monitor_data['metrics']
                    cpu_values = [m['cpu']['cpu_percent_total'] for m in metrics_data if 'cpu' in m]
                    mem_values = [m['memory']['memory_percent'] for m in metrics_data if 'memory' in m]
                    
                    if cpu_values and mem_values:
                        avg_cpu = sum(cpu_values) / len(cpu_values)
                        max_cpu = max(cpu_values)
                        avg_mem = sum(mem_values) / len(mem_values)
                        max_mem = max(mem_values)
                        
                        html_content += f"""
            <h3>{test_name}</h3>
            <div class="metrics-grid">
                <div class="metric-card">
                    <div class="metric-value">{avg_cpu:.1f}%</div>
                    <div class="metric-label">Average CPU</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">{max_cpu:.1f}%</div>
                    <div class="metric-label">Peak CPU</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">{avg_mem:.1f}%</div>
                    <div class="metric-label">Average Memory</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">{max_mem:.1f}%</div>
                    <div class="metric-label">Peak Memory</div>
                </div>
            </div>
"""
            
            html_content += """
        </div>
"""

        # Recommendations
        html_content += """
        <div class="section">
            <h2>🎯 Performance Analysis & Recommendations</h2>
"""
        
        # Generate recommendations based on results
        recommendations = []
        
        for scenario, metric_data in metrics.items():
            efficiency = metric_data['avg_efficiency']
            error_rate = metric_data['error_rate']
            
            if efficiency < 90:
                recommendations.append(f"⚠️ {scenario}: Efficiency ({efficiency:.1f}%) below target. Consider optimizing packet processing or reducing load.")
            
            if error_rate > 1.0:
                recommendations.append(f"❌ {scenario}: High error rate ({error_rate:.2f}%). Check system resources and network configuration.")
            
            if metric_data['max_pps'] > 100000:
                recommendations.append(f"🚀 {scenario}: Excellent high-throughput performance achieved ({metric_data['max_pps']:,.0f} PPS).")
        
        if not recommendations:
            recommendations.append("✅ All tests performed within acceptable parameters. System is well-tuned for VXLAN processing.")
        
        for rec in recommendations:
            html_content += f"<p>{rec}</p>"
        
        html_content += """
        </div>
        
        <div class="section">
            <h2>📋 Test Configuration</h2>
            <p><strong>Results Directory:</strong> """ + str(self.results_dir) + """</p>
            <p><strong>Generated Files:</strong> Performance results, monitoring data, and visualization charts</p>
        </div>
        
    </div>
</body>
</html>
"""
        
        with open(output_file, 'w') as f:
            f.write(html_content)
        
        print(f"📋 HTML report generated: {output_file}")
        return output_file
    
    def generate_report(self, output_dir=None):
        """Generate complete performance report"""
        
        if not output_dir:
            output_dir = self.results_dir / "reports"
        else:
            output_dir = Path(output_dir)
        
        output_dir.mkdir(parents=True, exist_ok=True)
        
        print("📊 Generating Performance Analysis Report...")
        
        # Load test results
        if not self.load_test_results():
            return False
        
        # Load monitoring data
        monitoring_data = self.load_monitoring_data()
        
        # Calculate metrics
        metrics = self.calculate_performance_metrics()
        
        # Create charts
        charts_dir = self.create_performance_charts(metrics, output_dir)
        
        # Generate HTML report
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        html_report = output_dir / f"performance_report_{timestamp}.html"
        self.generate_html_report(metrics, monitoring_data, html_report)
        
        # Save metrics as JSON
        metrics_file = output_dir / f"performance_metrics_{timestamp}.json"
        with open(metrics_file, 'w') as f:
            json.dump(metrics, f, indent=2)
        
        print(f"\n🎉 Report Generation Complete!")
        print(f"   📋 HTML Report: {html_report}")
        print(f"   📊 Charts: {charts_dir}")
        print(f"   📄 Metrics: {metrics_file}")
        
        return html_report

def main():
    parser = argparse.ArgumentParser(description="Generate XDP VXLAN Pipeline Performance Report")
    parser.add_argument('-r', '--results-dir', default='performance_results',
                       help='Directory containing performance test results')
    parser.add_argument('-o', '--output-dir', 
                       help='Output directory for generated reports')
    
    args = parser.parse_args()
    
    try:
        generator = PerformanceReportGenerator(args.results_dir)
        report_file = generator.generate_report(args.output_dir)
        
        if report_file:
            print(f"\n🌐 Open report: file://{report_file.absolute()}")
    
    except ImportError as e:
        print(f"❌ Missing required packages: {e}")
        print("Install with: pip install pandas matplotlib seaborn")
        sys.exit(1)
    
    except Exception as e:
        print(f"❌ Error generating report: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()