"""
Display management with Rich formatting and multiple output formats
"""

from typing import List, Dict, Optional, Any
from pathlib import Path
import json
from datetime import datetime
from .models import PipelineStatus, BPFMapInfo, AllowlistEntry, PipelineStats, NetworkInterface
from .utils import Logger

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.live import Live
    from rich.text import Text
    from rich.tree import Tree
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

class DisplayManager:
    """Enhanced display management with multiple output formats"""
    
    def __init__(self, logger: Optional[Logger] = None, use_color: bool = None):
        self.logger = logger or Logger("display")
        self.output_format = "table"  # Default format
        
        if use_color is None:
            use_color = RICH_AVAILABLE
            
        self.console = Console(force_terminal=use_color) if RICH_AVAILABLE and use_color else None
        self.use_color = use_color and RICH_AVAILABLE
    
    def set_format(self, format_type: str):
        """Set output format (json, yaml, table, plain)"""
        valid_formats = ['json', 'yaml', 'table', 'plain']
        if format_type in valid_formats:
            self.output_format = format_type
        else:
            self.logger.warning(f"Unknown format '{format_type}', using 'table'")
            self.output_format = "table"
    
    def print_status(self, message: str, level: str = "info"):
        """Print formatted status message"""
        if self.console:
            colors = {"info": "blue", "success": "green", "error": "red", "warning": "yellow"}
            self.console.print(f"[{colors.get(level, 'white')}]{message}[/]")
        else:
            prefixes = {"info": "[INFO]", "success": "[OK]", "error": "[ERROR]", "warning": "[WARN]"}
            print(f"{prefixes.get(level, '')} {message}")
    
    def show_pipeline_status(self, status: PipelineStatus, details: Dict[str, Any] = None):
        """Display comprehensive pipeline status"""
        if self.console:
            # Rich formatted display
            status_color = "green" if status == PipelineStatus.RUNNING else "red"
            
            panel = Panel.fit(
                f"[bold {status_color}]{status.value.upper()}[/bold {status_color}]",
                title="XDP Pipeline Status",
                border_style=status_color
            )
            self.console.print(panel)
            
            if details:
                table = Table(title="Pipeline Details", show_header=True)
                table.add_column("Component", style="cyan")
                table.add_column("Status", style="green")
                table.add_column("Details")
                
                for key, value in details.items():
                    table.add_row(key, str(value), "")
                
                self.console.print(table)
        else:
            # Plain text display
            print(f"Pipeline Status: {status.value}")
            if details:
                for key, value in details.items():
                    print(f"  {key}: {value}")
    
    def show_bpf_maps(self, maps: List[BPFMapInfo]):
        """Display BPF maps information"""
        if not maps:
            self.print_status("No BPF maps found", "warning")
            return
        
        if self.console:
            table = Table(title=f"BPF Maps ({len(maps)} total)", show_header=True)
            table.add_column("Name", style="cyan")
            table.add_column("Type", style="blue")
            table.add_column("Entries", justify="right", style="green")
            table.add_column("Max", justify="right", style="yellow")
            table.add_column("Usage %", justify="right", style="magenta")
            table.add_column("Memory", justify="right", style="white")
            
            for map_info in maps:
                usage_pct = map_info.usage_percentage
                usage_style = "green" if usage_pct < 70 else "yellow" if usage_pct < 90 else "red"
                
                # Estimate memory usage
                entry_size = map_info.key_size + map_info.value_size
                memory_kb = (entry_size * map_info.entries_count) // 1024
                
                table.add_row(
                    map_info.name,
                    map_info.type.replace("BPF_MAP_TYPE_", ""),
                    f"{map_info.entries_count:,}",
                    f"{map_info.max_entries:,}",
                    f"[{usage_style}]{usage_pct:.1f}%[/]",
                    f"{memory_kb}KB"
                )
            
            self.console.print(table)
        else:
            print(f"BPF Maps ({len(maps)} total):")
            for map_info in maps:
                usage_pct = map_info.usage_percentage
                print(f"  {map_info.name}: {map_info.entries_count:,}/{map_info.max_entries:,} ({usage_pct:.1f}%) - {map_info.type}")
    
    def show_allowlist(self, entries: List[AllowlistEntry]):
        """Display IP allowlist with categorization"""
        if not entries:
            self.print_status("No allowlist entries found", "warning")
            return
        
        individual_ips = [e for e in entries if not e.is_subnet]
        subnets = [e for e in entries if e.is_subnet]
        
        if self.console:
            # Summary panel
            summary = Panel(
                f"Total Entries: [bold]{len(entries)}[/bold]\n"
                f"Individual IPs: [blue]{len(individual_ips)}[/blue]\n"
                f"Subnets: [green]{len(subnets)}[/green]",
                title="IP Allowlist Summary",
                border_style="blue"
            )
            self.console.print(summary)
            
            # Detailed table
            table = Table(title="Allowlist Entries", show_header=True)
            table.add_column("Type", style="blue")
            table.add_column("Address", style="cyan")
            table.add_column("CIDR", style="green")
            table.add_column("Host Count", justify="right", style="yellow")
            table.add_column("Description", style="white")
            
            # Sort entries: subnets first, then IPs
            sorted_entries = sorted(entries, key=lambda x: (not x.is_subnet, x.address))
            
            for entry in sorted_entries:
                entry_type = "Subnet" if entry.is_subnet else "Individual IP"
                host_count = f"{entry.host_count:,}" if entry.is_subnet else "1"
                
                table.add_row(
                    entry_type,
                    entry.address,
                    entry.cidr_notation,
                    host_count,
                    entry.description or ""
                )
            
            self.console.print(table)
        else:
            print(f"IP Allowlist ({len(entries)} entries):")
            print(f"  Individual IPs: {len(individual_ips)}")
            print(f"  Subnets: {len(subnets)}")
            print()
            
            for entry in entries:
                entry_type = "Subnet" if entry.is_subnet else "IP"
                print(f"  {entry_type}: {entry.cidr_notation}")
    
    def show_network_interfaces(self, interfaces: List[NetworkInterface]):
        """Display network interfaces information"""
        if not interfaces:
            self.print_status("No network interfaces found", "warning")
            return
        
        if self.console:
            table = Table(title=f"Network Interfaces ({len(interfaces)} total)", show_header=True)
            table.add_column("Interface", style="cyan")
            table.add_column("State", style="green")
            table.add_column("MTU", justify="right", style="blue")
            table.add_column("XDP", style="yellow")
            table.add_column("IP Addresses", style="white")
            table.add_column("Driver", style="magenta")
            
            for iface in interfaces:
                state_style = "green" if iface.is_up else "red"
                xdp_status = "[green]Attached[/]" if iface.xdp_attached else "[red]None[/]"
                ip_list = ", ".join(iface.ip_addresses[:2])  # Show first 2 IPs
                if len(iface.ip_addresses) > 2:
                    ip_list += f" (+{len(iface.ip_addresses)-2} more)"
                
                table.add_row(
                    iface.name,
                    f"[{state_style}]{iface.state}[/]",
                    str(iface.mtu),
                    xdp_status,
                    ip_list,
                    iface.driver
                )
            
            self.console.print(table)
        else:
            print(f"Network Interfaces ({len(interfaces)} total):")
            for iface in interfaces:
                xdp_status = "XDP" if iface.xdp_attached else "None"
                print(f"  {iface.name}: {iface.state} MTU:{iface.mtu} XDP:{xdp_status}")
    
    def show_statistics(self, stats: PipelineStats):
        """Display pipeline statistics"""
        if self.console:
            # Create statistics table
            table = Table(title="Pipeline Statistics", show_header=True)
            table.add_column("Metric", style="cyan")
            table.add_column("Value", justify="right", style="green")
            table.add_column("Rate/Percentage", justify="right", style="yellow")
            
            # Add rows
            table.add_row("Packets Processed", f"{stats.packets_processed:,}", "")
            table.add_row("Packets Dropped", f"{stats.packets_dropped:,}", f"{stats.drop_rate:.2f}%")
            table.add_row("VXLAN Packets", f"{stats.vxlan_packets:,}", "")
            table.add_row("Allowlist Hits", f"{stats.allowlist_hits:,}", f"{stats.allowlist_hit_rate:.2f}%")
            table.add_row("Allowlist Misses", f"{stats.allowlist_misses:,}", "")
            table.add_row("Errors", f"{stats.errors:,}", "")
            
            if stats.uptime_seconds > 0:
                pps = stats.packets_processed / stats.uptime_seconds
                table.add_row("Processing Rate", f"{pps:,.0f} PPS", f"Uptime: {stats.uptime_seconds}s")
            
            self.console.print(table)
            
            # Add performance indicators
            if stats.packets_processed > 0:
                performance_panel = self._create_performance_panel(stats)
                self.console.print(performance_panel)
        else:
            print("Pipeline Statistics:")
            print(f"  Packets Processed: {stats.packets_processed:,}")
            print(f"  Packets Dropped: {stats.packets_dropped:,} ({stats.drop_rate:.2f}%)")
            print(f"  Allowlist Hits: {stats.allowlist_hits:,} ({stats.allowlist_hit_rate:.2f}%)")
            print(f"  Errors: {stats.errors:,}")
    
    def show_live_stats(self, stats_callback, update_interval: float = 1.0):
        """Display live updating statistics"""
        if not self.console:
            self.print_status("Live stats require Rich library", "error")
            return
        
        with Live(auto_refresh=False, refresh_per_second=1/update_interval) as live:
            try:
                while True:
                    stats = stats_callback()
                    table = self._create_stats_table(stats)
                    live.update(table)
                    live.refresh()
                    
                    import time
                    time.sleep(update_interval)
            except KeyboardInterrupt:
                self.print_status("Live monitoring stopped", "info")
    
    def export_data(self, data: Any, format: str = "json", file_path: Optional[str] = None) -> Optional[str]:
        """Export data in various formats"""
        try:
            if format == "json":
                output = json.dumps(data, indent=2, default=str)
            elif format == "csv":
                output = self._to_csv(data)
            elif format == "yaml":
                import yaml
                output = yaml.dump(data, default_flow_style=False)
            else:
                output = str(data)
            
            if file_path:
                Path(file_path).write_text(output)
                self.print_status(f"Data exported to {file_path}", "success")
            
            return output
            
        except Exception as e:
            self.print_status(f"Export failed: {e}", "error")
            return None
    
    def _create_performance_panel(self, stats: PipelineStats):
        """Create performance indicator panel"""
        if not RICH_AVAILABLE:
            return None
            
        # Determine performance level
        if stats.drop_rate > 5.0:
            perf_level = "[red]Poor[/red]"
            perf_color = "red"
        elif stats.drop_rate > 1.0:
            perf_level = "[yellow]Moderate[/yellow]"
            perf_color = "yellow"
        else:
            perf_level = "[green]Good[/green]"
            perf_color = "green"
        
        content = f"Performance Level: {perf_level}\n"
        content += f"Drop Rate: {stats.drop_rate:.2f}%\n"
        content += f"Allowlist Efficiency: {stats.allowlist_hit_rate:.2f}%"
        
        return Panel(content, title="Performance Indicators", border_style=perf_color)
    
    def _create_stats_table(self, stats: PipelineStats):
        """Create statistics table for live display"""
        if not RICH_AVAILABLE:
            return None
            
        table = Table(title=f"Live Statistics - {datetime.now().strftime('%H:%M:%S')}")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", justify="right", style="green")
        table.add_column("Rate", justify="right", style="yellow")
        
        table.add_row("Processed", f"{stats.packets_processed:,}", "")
        table.add_row("Dropped", f"{stats.packets_dropped:,}", f"{stats.drop_rate:.1f}%")
        table.add_row("Allowlist Hits", f"{stats.allowlist_hits:,}", f"{stats.allowlist_hit_rate:.1f}%")
        table.add_row("Errors", f"{stats.errors:,}", "")
        
        return table
    
    def _to_csv(self, data: Any) -> str:
        """Convert data to CSV format"""
        if isinstance(data, list) and data and isinstance(data[0], dict):
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=data[0].keys())
            writer.writeheader()
            writer.writerows(data)
            return output.getvalue()
        
        return str(data)
    
    def export_to_csv(self, data: Any, filepath: str, format_type: str = 'stats') -> bool:
        """
        Export data to CSV format
        """
        try:
            import csv
            from datetime import datetime
            
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                if format_type == 'stats':
                    self._export_stats_csv(writer, data)
                elif format_type == 'analytics':
                    self._export_analytics_csv(writer, data)
                elif format_type == 'diagnostics':
                    self._export_diagnostics_csv(writer, data)
                elif format_type == 'monitoring':
                    self._export_monitoring_csv(writer, data)
                else:
                    self.logger.error(f"Unknown CSV format type: {format_type}")
                    return False
            
            self.logger.info(f"Data exported to CSV: {filepath}")
            return True
            
        except Exception as e:
            self.logger.error(f"CSV export failed: {e}")
            return False
    
    def _export_stats_csv(self, writer, stats) -> None:
        """Export pipeline statistics to CSV"""
        # Write header
        writer.writerow([
            'timestamp', 'packets_processed', 'packets_dropped', 'drop_rate',
            'allowlist_hits', 'allowlist_misses', 'allowlist_hit_rate', 
            'errors', 'uptime_seconds'
        ])
        
        # Write data
        if hasattr(stats, '__dict__'):
            writer.writerow([
                datetime.now().isoformat(),
                stats.packets_processed,
                stats.packets_dropped, 
                f"{stats.drop_rate:.2f}%",
                stats.allowlist_hits,
                stats.allowlist_misses,
                f"{stats.allowlist_hit_rate:.2f}%",
                stats.errors,
                stats.uptime_seconds
            ])
    
    def _export_analytics_csv(self, writer, analytics) -> None:
        """Export analytics data to CSV"""
        writer.writerow(['metric', 'value', 'timestamp'])
        
        timestamp = analytics.get('timestamp', datetime.now().isoformat())
        
        # Performance metrics
        if 'performance_analysis' in analytics:
            perf = analytics['performance_analysis']
            for key, value in perf.items():
                writer.writerow([f"performance_{key}", value, timestamp])
        
        # Error analysis
        if 'error_analysis' in analytics:
            error = analytics['error_analysis']
            for key, value in error.items():
                writer.writerow([f"error_{key}", value, timestamp])
    
    def _export_diagnostics_csv(self, writer, diagnostics) -> None:
        """Export diagnostics data to CSV"""
        writer.writerow(['category', 'item', 'status', 'details', 'timestamp'])
        
        timestamp = diagnostics.get('timestamp', datetime.now().isoformat())
        
        # Network interfaces
        if 'network_interfaces' in diagnostics:
            for iface in diagnostics['network_interfaces']:
                writer.writerow([
                    'interface', iface['name'], iface['state'], 
                    f"MTU:{iface['mtu']}", timestamp
                ])
        
        # Connectivity tests
        if 'connectivity_tests' in diagnostics:
            for test, result in diagnostics['connectivity_tests'].items():
                status = 'PASS' if result.get('success') else 'FAIL'
                writer.writerow(['connectivity', test, status, '', timestamp])
    
    def _export_monitoring_csv(self, writer, samples) -> None:
        """Export monitoring samples to CSV"""
        if not samples:
            return
            
        # Get headers from first sample
        first_sample = samples[0]
        headers = ['timestamp']
        
        if 'metrics' in first_sample:
            headers.extend([f"metric_{k}" for k in first_sample['metrics'].keys()])
        if 'stats' in first_sample:
            headers.extend([f"stat_{k}" for k in first_sample['stats'].keys()])
        
        writer.writerow(headers)
        
        # Write data rows
        for sample in samples:
            row = [sample.get('timestamp', '')]
            
            if 'metrics' in sample:
                row.extend(sample['metrics'].values())
            if 'stats' in sample:
                row.extend(sample['stats'].values())
            
            writer.writerow(row)
    
    # Additional display methods for CLI compatibility
    def show_analytics(self, analysis: Dict[str, Any]) -> None:
        """Show comprehensive analytics"""
        self.print_status("Analytics Report", "info")
        if self.output_format == "json":
            print(json.dumps(analysis, indent=2, default=str))
        else:
            for key, value in analysis.items():
                print(f"{key}: {value}")
    
    def show_error_analysis(self, error_analysis: Dict[str, Any]) -> None:
        """Show error analysis"""
        self.print_status(f"Error Analysis - {error_analysis.get('total_errors', 0)} total errors", "warning")
        if self.output_format == "json":
            print(json.dumps(error_analysis, indent=2))
        else:
            for key, value in error_analysis.items():
                print(f"{key}: {value}")
    
    def show_performance_metrics(self, metrics: Dict[str, Any]) -> None:
        """Show performance metrics"""
        self.print_status("Performance Metrics", "info")
        if self.output_format == "json":
            print(json.dumps(metrics, indent=2))
        else:
            for key, value in metrics.items():
                if isinstance(value, float):
                    print(f"{key}: {value:.2f}")
                else:
                    print(f"{key}: {value}")
    
    def show_raw_stats(self, raw_stats: Dict[str, Any]) -> None:
        """Show raw statistics"""
        self.print_status("Raw BPF Statistics", "info")
        print(json.dumps(raw_stats, indent=2, default=str))
    
    def show_pipeline_stats(self, stats) -> None:
        """Show pipeline statistics"""
        self.show_statistics(stats)
    
    def show_comprehensive_analytics(self, analysis: Dict[str, Any]) -> None:
        """Show comprehensive analytics"""
        self.show_analytics(analysis)
    
    def show_diagnostics(self, diagnostics: Dict[str, Any]) -> None:
        """Show network diagnostics"""
        self.print_status("Network Diagnostics", "info")
        if self.output_format == "json":
            print(json.dumps(diagnostics, indent=2, default=str))
        else:
            for key, value in diagnostics.items():
                if isinstance(value, list) and value:
                    print(f"{key}: {len(value)} items")
                else:
                    print(f"{key}: {value}")
    
    def show_connectivity_results(self, results: Dict[str, Any]) -> None:
        """Show connectivity test results"""
        self.print_status("Connectivity Test Results", "info")
        if self.output_format == "json":
            print(json.dumps(results, indent=2, default=str))
        else:
            for target, result in results.get('connectivity_results', {}).items():
                status = "PASS" if result.get('success') else "FAIL"
                print(f"{target}: {status}")
    
    def show_packet_flow(self, flow_info: Dict[str, Any]) -> None:
        """Show packet flow information"""
        self.print_status(f"Packet Flow Analysis - {flow_info.get('interface', 'unknown')}", "info")
        print(json.dumps(flow_info, indent=2, default=str))
    
    def show_vxlan_analysis(self, vxlan_analysis: Dict[str, Any]) -> None:
        """Show VXLAN traffic analysis"""
        self.print_status("VXLAN Traffic Analysis", "info")
        print(json.dumps(vxlan_analysis, indent=2, default=str))
    
    def show_debug_info(self, debug_info: Dict[str, Any]) -> None:
        """Show debug information"""
        self.print_status("Debug Information", "info")
        print(json.dumps(debug_info, indent=2, default=str))
    
    def show_monitoring_results(self, samples: List[Dict[str, Any]]) -> None:
        """Show monitoring results"""
        self.print_status(f"Monitoring Results - {len(samples)} samples", "info")
        if self.output_format == "json":
            print(json.dumps(samples, indent=2, default=str))
        else:
            print(f"Collected {len(samples)} monitoring samples")
            if samples:
                print(f"Time range: {samples[0].get('timestamp')} to {samples[-1].get('timestamp')}")
    
    def show_config(self, config: Dict[str, Any]) -> None:
        """Show configuration"""
        self.print_status("Configuration", "info")
        if self.output_format == "json":
            print(json.dumps(config, indent=2, default=str))
        else:
            for key, value in config.items():
                print(f"{key}: {value}")
    
    def create_status_display(self, status) -> Any:
        """Create status display for live updates"""
        if self.console:
            from rich.panel import Panel
            return Panel(f"Status: {status}", title="XDP Pipeline")
        return f"Status: {status}"
    
    def create_top_display(self, stats_data: List[Dict], sort_by: str) -> Any:
        """Create top-like display"""
        if self.console:
            from rich.table import Table
            table = Table(title=f"XDP Top - Sorted by {sort_by}")
            table.add_column("Interface")
            table.add_column("RX PPS")
            table.add_column("TX PPS")
            table.add_column("Drops")
            table.add_column("XDP")
            
            for item in stats_data:
                table.add_row(
                    item['interface'],
                    str(item['rx_pps']),
                    str(item['tx_pps']),
                    str(item['rx_drops'] + item['tx_drops']),
                    item['xdp']
                )
            return table
    
    # Missing methods that the CLI expects
    def show_raw_stats(self, raw_stats: Dict[str, Any]) -> None:
        """Display raw BPF map statistics"""
        self.print_status("Raw Statistics", "info")
        if self.output_format == "json":
            print(json.dumps(raw_stats, indent=2))
        else:
            for map_name, data in raw_stats.items():
                print(f"Map: {map_name}")
                if isinstance(data, dict):
                    for key, value in data.items():
                        print(f"  {key}: {value}")

    def show_pipeline_stats(self, stats: PipelineStats) -> None:
        """Display pipeline statistics (alias for show_statistics)"""
        self.show_statistics(stats)

    def show_comprehensive_analytics(self, analysis: Dict[str, Any]) -> None:
        """Display comprehensive analytics (alias for show_analytics)"""
        self.show_analytics(analysis)

    def show_diagnostics(self, diagnostics: Dict[str, Any]) -> None:
        """Display network diagnostics"""
        self.print_status("Network Diagnostics", "info")
        if self.output_format == "json":
            print(json.dumps(diagnostics, indent=2))
        else:
            for section, data in diagnostics.items():
                print(f"\n{section.replace('_', ' ').title()}:")
                if isinstance(data, dict):
                    for key, value in data.items():
                        print(f"  {key}: {value}")
                elif isinstance(data, list):
                    for item in data:
                        print(f"  - {item}")
                else:
                    print(f"  {data}")

    def show_connectivity_results(self, results: Dict[str, Any]) -> None:
        """Display connectivity test results"""
        self.print_status("Connectivity Results", "info")
        if self.output_format == "json":
            print(json.dumps(results, indent=2))
        else:
            for target, result in results.items():
                status = "✓" if result.get('success', False) else "✗"
                print(f"  {status} {target}: {result.get('message', 'No details')}")

    def show_packet_flow(self, flow_info: Dict[str, Any]) -> None:
        """Display packet flow information"""
        self.print_status("Packet Flow Analysis", "info")
        if self.output_format == "json":
            print(json.dumps(flow_info, indent=2))
        else:
            print(f"  Interface: {flow_info.get('interface', 'Unknown')}")
            print(f"  Packets analyzed: {flow_info.get('packet_count', 0)}")
            print(f"  Duration: {flow_info.get('duration', 0)}s")

    def show_vxlan_analysis(self, vxlan_analysis: Dict[str, Any]) -> None:
        """Display VXLAN traffic analysis"""
        self.print_status("VXLAN Analysis", "info")
        if self.output_format == "json":
            print(json.dumps(vxlan_analysis, indent=2))
        else:
            print(f"  VXLAN packets: {vxlan_analysis.get('vxlan_packets', 0)}")
            print(f"  VNI distribution: {vxlan_analysis.get('vni_stats', {})}")

    def show_debug_info(self, flow_info: Dict[str, Any]) -> None:
        """Display debug information"""
        self.print_status("Debug Information", "info")
        if self.output_format == "json":
            print(json.dumps(flow_info, indent=2))
        else:
            print(f"  Timestamp: {flow_info.get('timestamp', 'Unknown')}")
            for key, value in flow_info.items():
                if key != 'timestamp':
                    print(f"  {key}: {value}")

    def show_monitoring_results(self, samples: List[Dict[str, Any]]) -> None:
        """Display monitoring results"""
        self.print_status("Monitoring Results", "info")
        if self.output_format == "json":
            print(json.dumps(samples, indent=2))
        else:
            print(f"  Total samples: {len(samples)}")
            if samples:
                latest = samples[-1]
                print(f"  Latest sample: {latest}")

    def show_config(self, config: Any) -> None:
        """Show configuration"""
        self.print_status("Configuration", "info")
        if hasattr(config, '__dict__'):
            config_dict = config.__dict__
        else:
            config_dict = config
        
        if self.output_format == "json":
            print(json.dumps(config_dict, indent=2, default=str))
        else:
            for key, value in config_dict.items():
                print(f"  {key}: {value}")

    def create_status_display(self, status: Any):
        """Create status display for live updates"""
        if self.console:
            return Panel(f"Status: {status}", title="XDP Pipeline Status")
        else:
            return f"Status: {status}"

    def create_top_display(self, stats_data: List[Dict[str, Any]], sort_by: str):
        """Create top-like display"""
        if self.console:
            table = Table(title=f"XDP Interface Statistics (sorted by {sort_by})")
            table.add_column("Interface")
            table.add_column("RX PPS")
            table.add_column("TX PPS") 
            table.add_column("XDP")
            
            for stat in stats_data[:10]:  # Show top 10
                table.add_row(
                    stat.get('interface', ''),
                    str(stat.get('rx_pps', 0)),
                    str(stat.get('tx_pps', 0)),
                    stat.get('xdp', '[NO]')
                )
            return table
        else:
            lines = ["Interface Statistics:"]
            for stat in stats_data[:10]:
                lines.append(f"  {stat.get('interface', '')}: RX={stat.get('rx_pps', 0)} TX={stat.get('tx_pps', 0)}")
            return "\n".join(lines)

    def create_debug_display(self, debug_info: Dict[str, Any]):
        """Create debug display"""
        if self.console:
            return Panel(str(debug_info), title="Debug Information")
        else:
            return f"Debug: {debug_info}"
        return f"XDP Top - {len(stats_data)} interfaces"
    
    def create_debug_display(self, debug_info: Dict[str, Any]) -> Any:
        """Create debug display"""
        if self.console:
            from rich.panel import Panel
            content = f"Interface: {debug_info.get('interface', 'unknown')}\n"
            content += f"Timestamp: {debug_info.get('timestamp', 'unknown')}"
            return Panel(content, title="Debug Information")
        return f"Debug: {debug_info.get('interface', 'unknown')}"