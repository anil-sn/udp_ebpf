#!/usr/bin/env python3
"""
Professional XDP Pipeline Management CLI
Advanced command-line interface for eBPF/XDP pipeline management with analytics and diagnostics
"""

import argparse
import sys
import json
from typing import Dict, Any, Optional
from pathlib import Path

# Rich imports for beautiful CLI
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.live import Live
    from rich.text import Text
    from rich import print as rich_print
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    rich_print = print

# Argcomplete for autocompletion
try:
    import argcomplete
    ARGCOMPLETE_AVAILABLE = True
except ImportError:
    ARGCOMPLETE_AVAILABLE = False

# XDP Manager imports
from xdp_manager import (
    XDPPipeline,
    AllowlistManager,
    BPFMapManager,
    NetworkManager,
    ConfigManager,
    DisplayManager,
    Logger
)
from xdp_manager.analytics import StatisticsAnalyzer
from xdp_manager.diagnostics import NetworkDiagnostics

class XDPManagerCLI:
    """Main CLI class for XDP pipeline management"""
    
    def __init__(self):
        self.console = Console() if RICH_AVAILABLE else None
        self.logger = Logger("xdp_cli")
        
        # Initialize managers
        self.config_manager = ConfigManager()
        self.network_manager = NetworkManager(self.logger)
        self.bpf_maps = BPFMapManager(logger=self.logger)
        self.allowlist_manager = AllowlistManager(logger=self.logger)
        self.display_manager = DisplayManager(logger=self.logger)
        self.pipeline = XDPPipeline(
            config_manager=self.config_manager
        )
        
        # Analytics and diagnostics
        self.analytics = StatisticsAnalyzer(self.bpf_maps, self.logger)
        self.diagnostics = NetworkDiagnostics(self.logger)
        
    def create_parser(self) -> argparse.ArgumentParser:
        """Create and configure argument parser with autocompletion"""
        parser = argparse.ArgumentParser(
            prog='xdp-manager',
            description='Professional XDP Pipeline Management CLI',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  xdp-manager start --interface eth0 --program vxlan_pipeline.bpf.o
  xdp-manager status --live
  xdp-manager allowlist add 192.168.1.0/24
  xdp-manager stats --analyze --export stats.json
  xdp-manager diagnostics --comprehensive --interface eth0
  xdp-manager monitor --interface eth0 --duration 300
            """
        )
        
        # Global options
        parser.add_argument('--config', '-c', type=str, help='Configuration file path')
        parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
        parser.add_argument('--quiet', '-q', action='store_true', help='Quiet mode - minimal output')
        parser.add_argument('--format', choices=['json', 'yaml', 'table', 'plain'], 
                           default='table', help='Output format')
        parser.add_argument('--no-color', action='store_true', help='Disable colored output')
        
        # Create subparsers
        subparsers = parser.add_subparsers(dest='command', help='Available commands')
        
        # Pipeline management commands
        self._add_pipeline_commands(subparsers)
        
        # Allowlist management commands
        self._add_allowlist_commands(subparsers)
        
        # Statistics and analytics commands
        self._add_statistics_commands(subparsers)
        
        # Diagnostics commands
        self._add_diagnostics_commands(subparsers)
        
        # Monitoring commands
        self._add_monitoring_commands(subparsers)
        
        # Configuration commands
        self._add_config_commands(subparsers)
        
        # Enable autocompletion if available
        if ARGCOMPLETE_AVAILABLE:
            argcomplete.autocomplete(parser)
        
        return parser
    
    def _add_pipeline_commands(self, subparsers):
        """Add pipeline management commands"""
        # Start command
        start_parser = subparsers.add_parser('start', help='Start XDP pipeline')
        start_parser.add_argument('--interface', '-i', help='Network interface (defaults to config)')
        start_parser.add_argument('--program', '-p', help='BPF program path (defaults to config)')
        start_parser.add_argument('--mode', choices=['xdp', 'xdpgeneric', 'xdpdrv', 'xdpoffload'], 
                                 default='xdp', help='XDP attachment mode')
        start_parser.add_argument('--force', action='store_true', help='Force attachment')
        start_parser.add_argument('--optimize', action='store_true', help='Apply performance optimizations')
        
        # Stop command
        stop_parser = subparsers.add_parser('stop', help='Stop XDP pipeline')
        stop_parser.add_argument('--interface', '-i', help='Network interface (all if not specified)')
        stop_parser.add_argument('--force', action='store_true', help='Force detachment')
        
        # Restart command
        restart_parser = subparsers.add_parser('restart', help='Restart XDP pipeline')
        restart_parser.add_argument('--interface', '-i', help='Network interface (defaults to config)')
        restart_parser.add_argument('--program', '-p', help='BPF program path')
        restart_parser.add_argument('--quick', action='store_true', help='Quick restart without validation')
        
        # Status command
        status_parser = subparsers.add_parser('status', help='Show pipeline status')
        status_parser.add_argument('--interface', '-i', help='Specific interface (all if not specified)')
        status_parser.add_argument('--live', action='store_true', help='Live status updates')
        status_parser.add_argument('--refresh', type=float, default=1.0, help='Refresh interval for live mode')
        
        # Reload command
        reload_parser = subparsers.add_parser('reload', help='Reload BPF program')
        reload_parser.add_argument('--interface', '-i', help='Network interface (defaults to config)')
        reload_parser.add_argument('--program', '-p', help='BPF program path (defaults to config)')
        
    def _add_allowlist_commands(self, subparsers):
        """Add allowlist management commands"""
        # Allowlist command group
        allowlist_parser = subparsers.add_parser('allowlist', help='Manage IP allowlist')
        allowlist_subparsers = allowlist_parser.add_subparsers(dest='allowlist_action')
        
        # Add IP/network
        add_parser = allowlist_subparsers.add_parser('add', help='Add IP or network to allowlist')
        add_parser.add_argument('ip_or_network', help='IP address or CIDR network')
        add_parser.add_argument('--comment', help='Optional comment')
        add_parser.add_argument('--sync', action='store_true', help='Sync to BPF map immediately')
        
        # Remove IP/network
        remove_parser = allowlist_subparsers.add_parser('remove', help='Remove IP or network from allowlist')
        remove_parser.add_argument('ip_or_network', help='IP address or CIDR network')
        remove_parser.add_argument('--sync', action='store_true', help='Sync to BPF map immediately')
        
        # List allowlist
        list_parser = allowlist_subparsers.add_parser('list', help='List allowlist entries')
        list_parser.add_argument('--source', choices=['file', 'bpf', 'both'], default='both',
                                help='Source to list from')
        
        # Sync allowlist
        sync_parser = allowlist_subparsers.add_parser('sync', help='Sync allowlist to BPF maps')
        sync_parser.add_argument('--validate', action='store_true', help='Validate entries before sync')
        
        # Clear allowlist
        clear_parser = allowlist_subparsers.add_parser('clear', help='Clear allowlist')
        clear_parser.add_argument('--target', choices=['file', 'bpf', 'both'], default='both',
                                 help='What to clear')
        clear_parser.add_argument('--confirm', action='store_true', help='Skip confirmation prompt')
        
        # Load allowlist from file
        load_parser = allowlist_subparsers.add_parser('load', help='Load allowlist from file')
        load_parser.add_argument('file', help='File path to load from')
        load_parser.add_argument('--replace', action='store_true', help='Replace existing entries')
        
        # Export allowlist
        export_parser = allowlist_subparsers.add_parser('export', help='Export allowlist to file')
        export_parser.add_argument('file', help='File path to export to')
        export_parser.add_argument('--source', choices=['file', 'bpf'], default='file',
                                  help='Source to export from')
        
    def _add_statistics_commands(self, subparsers):
        """Add statistics and analytics commands"""
        # Stats command
        stats_parser = subparsers.add_parser('stats', help='Show pipeline statistics')
        stats_parser.add_argument('--analyze', action='store_true', help='Perform comprehensive analysis')
        stats_parser.add_argument('--export', help='Export statistics to file')
        stats_parser.add_argument('--errors', action='store_true', help='Show error analysis')
        stats_parser.add_argument('--performance', action='store_true', help='Show performance metrics')
        stats_parser.add_argument('--raw', action='store_true', help='Show raw BPF map statistics')
        stats_parser.add_argument('--reset', action='store_true', help='Reset statistics counters')
        
        # Analytics command
        analytics_parser = subparsers.add_parser('analytics', help='Advanced analytics')
        analytics_parser.add_argument('--comprehensive', action='store_true', 
                                     help='Comprehensive analytics report')
        analytics_parser.add_argument('--errors', action='store_true', help='Error pattern analysis')
        analytics_parser.add_argument('--trends', action='store_true', help='Trend analysis')
        analytics_parser.add_argument('--export', help='Export analytics to file')
        
    def _add_diagnostics_commands(self, subparsers):
        """Add diagnostics commands"""
        # Diagnostics command
        diag_parser = subparsers.add_parser('diagnostics', help='Network diagnostics')
        diag_parser.add_argument('--comprehensive', action='store_true', 
                                help='Comprehensive network check')
        diag_parser.add_argument('--interface', '-i', help='Specific interface to check')
        diag_parser.add_argument('--connectivity', nargs='+', help='Test connectivity to targets')
        diag_parser.add_argument('--packet-flow', action='store_true', help='Debug packet flow')
        diag_parser.add_argument('--vxlan', action='store_true', help='Analyze VXLAN traffic')
        diag_parser.add_argument('--export', help='Export diagnostics to file')
        
        # Debug command
        debug_parser = subparsers.add_parser('debug', help='Debug XDP pipeline')
        debug_parser.add_argument('--interface', '-i', help='Network interface (defaults to config)')
        debug_parser.add_argument('--packet-count', type=int, default=100, help='Packets to analyze')
        debug_parser.add_argument('--duration', type=int, default=30, help='Analysis duration')
        debug_parser.add_argument('--live', action='store_true', help='Live debugging mode')
        
    def _add_monitoring_commands(self, subparsers):
        """Add monitoring commands"""
        # Monitor command
        monitor_parser = subparsers.add_parser('monitor', help='Real-time monitoring')
        monitor_parser.add_argument('--interface', '-i', help='Interface to monitor')
        monitor_parser.add_argument('--duration', type=int, default=60, help='Monitoring duration')
        monitor_parser.add_argument('--interval', type=float, default=1.0, help='Update interval')
        monitor_parser.add_argument('--export', help='Export monitoring data to file')
        monitor_parser.add_argument('--alerts', action='store_true', help='Enable performance alerts')
        
        # Top command (like top but for XDP)
        top_parser = subparsers.add_parser('top', help='Top-like interface for XDP monitoring')
        top_parser.add_argument('--sort-by', choices=['pps', 'bps', 'drops', 'errors'], 
                               default='pps', help='Sort criterion')
        top_parser.add_argument('--refresh', type=float, default=2.0, help='Refresh interval')
        
    def _add_config_commands(self, subparsers):
        """Add configuration commands"""
        # Config command
        config_parser = subparsers.add_parser('config', help='Configuration management')
        config_subparsers = config_parser.add_subparsers(dest='config_action')
        
        # Show config
        show_parser = config_subparsers.add_parser('show', help='Show current configuration')
        
        # Set config value
        set_parser = config_subparsers.add_parser('set', help='Set configuration value')
        set_parser.add_argument('key', help='Configuration key')
        set_parser.add_argument('value', help='Configuration value')
        
        # Reset config
        reset_parser = config_subparsers.add_parser('reset', help='Reset configuration to defaults')
        reset_parser.add_argument('--confirm', action='store_true', help='Skip confirmation')
        
        # Validate config
        validate_parser = config_subparsers.add_parser('validate', help='Validate configuration')
        
    def run(self):
        """Main CLI entry point"""
        parser = self.create_parser()
        args = parser.parse_args()
        
        # Configure logging based on verbosity
        if args.quiet:
            self.logger.set_level('ERROR')
        elif args.verbose:
            self.logger.set_level('DEBUG')
        else:
            self.logger.set_level('INFO')
        
        # Load configuration if specified
        if args.config:
            try:
                self.config_manager.load_config(args.config)
            except Exception as e:
                self._error(f"Failed to load configuration: {e}")
                return 1
        
        # Set output format
        if hasattr(args, 'format') and args.format:
            self.display_manager.set_format(args.format)
        
        # Disable colors if requested
        if args.no_color and self.console:
            self.console._color_system = None
        
        # Route to appropriate handler
        try:
            if not args.command:
                parser.print_help()
                return 1
            
            handler_name = f'_handle_{args.command}'
            handler = getattr(self, handler_name, None)
            
            if not handler:
                self._error(f"Unknown command: {args.command}")
                return 1
            
            return handler(args) or 0
            
        except KeyboardInterrupt:
            self._info("Operation interrupted by user")
            return 130
        except Exception as e:
            self._error(f"Unexpected error: {e}")
            if args.verbose:
                import traceback
                traceback.print_exc()
            return 1
    
    def _get_default_interface(self) -> Optional[str]:
        """Get default interface from configuration or auto-detect"""
        try:
            # Try to get from config first
            config = self.config_manager.get_config()
            if hasattr(config, 'pipeline_config') and config.pipeline_config.ingress_interface:
                return config.pipeline_config.ingress_interface
            
            # Auto-detect primary interface
            interfaces = self.network_manager.list_interfaces()
            for iface in interfaces:
                if iface.state == 'UP' and not iface.name.startswith(('lo', 'docker', 'br-')):
                    return iface.name
            
            return None
        except Exception:
            return None
    
    def _get_default_program(self) -> Optional[str]:
        """Get default BPF program path from configuration"""
        try:
            config = self.config_manager.get_config()
            if hasattr(config, 'pipeline_config') and config.pipeline_config.program_path:
                return config.pipeline_config.program_path
            
            # Check for common program names
            common_names = ['vxlan_pipeline.bpf.o', 'src/vxlan_pipeline.bpf.o']
            for name in common_names:
                from pathlib import Path
                if Path(name).exists():
                    return name
            return None
        except Exception:
            return None
    
    def _interface_completer(self, prefix, parsed_args, **kwargs):
        """Autocomplete network interfaces"""
        try:
            interfaces = self.network_manager.list_interfaces()
            return [iface.name for iface in interfaces if iface.name.startswith(prefix)]
        except Exception:
            # Load from configuration if available
            try:
                from .config import ConfigManager
                config_mgr = ConfigManager()
                if config_mgr.load_config():
                    interfaces = [
                        config_mgr.pipeline_config.ingress_interface,
                        config_mgr.pipeline_config.egress_interface
                    ]
                    return [iface for iface in interfaces if iface and iface.startswith(prefix)]
            except:
                pass
            return ['ens5', 'ens6']  # Configured defaults
    
    def _program_completer(self, prefix, parsed_args, **kwargs):
        """Autocomplete BPF program files"""
        try:
            from pathlib import Path
            import glob
            
            # Look for .bpf.o files
            bpf_files = []
            for pattern in ['*.bpf.o', 'src/*.bpf.o', '**/*.bpf.o']:
                bpf_files.extend(glob.glob(pattern, recursive=True))
            
            return [f for f in bpf_files if f.startswith(prefix)]
        except Exception:
            return ['vxlan_pipeline.bpf.o', 'src/vxlan_pipeline.bpf.o']  # Fallbacks
        # Command handlers
    def _handle_start(self, args) -> int:
        """Handle start command"""
        try:
            # Get interface from args or config
            interface = args.interface or self._get_default_interface()
            if not interface:
                self._error("No interface specified and no default available. Use --interface or configure default.")
                return 1
            
            # Get program from args or config  
            program = args.program or self._get_default_program()
            
            result = self.pipeline.start(
                interface=interface,
                program_path=program,
                mode=args.mode,
                force=args.force
            )
            
            if result:
                if args.optimize:
                    self.pipeline.optimize_performance()
                self._success(f"XDP pipeline started successfully on {interface}")
                return 0
            else:
                self._error(f"Failed to start XDP pipeline on {interface}")
                return 1
                
        except Exception as e:
            self._error(f"Start command failed: {e}")
            return 1
    
    def _handle_stop(self, args) -> int:
        """Handle stop command"""
        try:
            if args.interface:
                result = self.pipeline.stop(args.interface, force=args.force)
                if result:
                    self._success(f"XDP pipeline stopped on {args.interface}")
                    return 0
                else:
                    self._error(f"Failed to stop XDP pipeline on {args.interface}")
                    return 1
            else:
                # Stop on all interfaces
                interfaces = self.network_manager.list_interfaces()
                success_count = 0
                
                for iface in interfaces:
                    if self.pipeline.stop(iface.name, force=args.force):
                        success_count += 1
                
                self._success(f"XDP pipeline stopped on {success_count} interface(s)")
                return 0
                
        except Exception as e:
            self._error(f"Stop command failed: {e}")
            return 1
    
    def _handle_restart(self, args) -> int:
        """Handle restart command"""
        try:
            # Get interface from args or config
            interface = args.interface or self._get_default_interface()
            if not interface:
                self._error("No interface specified and no default available. Use --interface or configure default.")
                return 1
            
            # Get program from args or config
            program = args.program or self._get_default_program()
            
            result = self.pipeline.restart(
                interface=interface,
                program_path=program,
                quick=args.quick
            )
            
            if result:
                self._success(f"XDP pipeline restarted on {interface}")
                return 0
            else:
                self._error(f"Failed to restart XDP pipeline on {interface}")
                return 1
                
        except Exception as e:
            self._error(f"Restart command failed: {e}")
            return 1
    
    def _handle_status(self, args) -> int:
        """Handle status command"""
        try:
            if args.live:
                return self._show_live_status(args)
            else:
                status = self.pipeline.get_status()
                self.display_manager.show_pipeline_status(status)
                return 0
                
        except Exception as e:
            self._error(f"Status command failed: {e}")
            return 1
    
    def _handle_reload(self, args) -> int:
        """Handle reload command"""
        try:
            # Get interface from args or config
            interface = args.interface or self._get_default_interface()
            if not interface:
                self._error("No interface specified and no default available. Use --interface or configure default.")
                return 1
            
            # Get program from args or config
            program = args.program or self._get_default_program()
            if not program:
                self._error("No program specified and no default available. Use --program or configure default.")
                return 1
            
            result = self.pipeline.reload_program(interface, program)
            
            if result:
                self._success(f"BPF program reloaded on {interface}")
                return 0
            else:
                self._error(f"Failed to reload BPF program on {interface}")
                return 1
                
        except Exception as e:
            self._error(f"Reload command failed: {e}")
            return 1
    
    def _handle_allowlist(self, args) -> int:
        """Handle allowlist commands"""
        try:
            if not args.allowlist_action:
                self._error("Allowlist action required")
                return 1
            
            if args.allowlist_action == 'add':
                success = self.allowlist_manager.add_entry(args.ip_or_network, comment=args.comment)
                if success:
                    if args.sync:
                        self.allowlist_manager.sync_to_bpf()
                    self._success(f"Added {args.ip_or_network} to allowlist")
                    return 0
                else:
                    self._error(f"Failed to add {args.ip_or_network}")
                    return 1
            
            elif args.allowlist_action == 'remove':
                success = self.allowlist_manager.remove_entry(args.ip_or_network)
                if success:
                    if args.sync:
                        self.allowlist_manager.sync_to_bpf()
                    self._success(f"Removed {args.ip_or_network} from allowlist")
                    return 0
                else:
                    self._error(f"Failed to remove {args.ip_or_network}")
                    return 1
            
            elif args.allowlist_action == 'list':
                entries = self.allowlist_manager.list_entries()
                self.display_manager.show_allowlist(entries)
                return 0
            
            elif args.allowlist_action == 'sync':
                if args.validate:
                    self.allowlist_manager.validate_entries()
                success = self.allowlist_manager.sync_to_bpf()
                if success:
                    self._success("Allowlist synced to BPF maps")
                    return 0
                else:
                    self._error("Failed to sync allowlist")
                    return 1
            
            elif args.allowlist_action == 'clear':
                if not args.confirm:
                    if not self._confirm("Clear allowlist?"):
                        return 0
                
                success = self.allowlist_manager.clear_allowlist()
                if success:
                    self._success("Allowlist cleared")
                    return 0
                else:
                    self._error("Failed to clear allowlist")
                    return 1
            
            elif args.allowlist_action == 'load':
                success = self.allowlist_manager.load_from_file(args.file, replace=args.replace)
                if success:
                    self._success(f"Allowlist loaded from {args.file}")
                    return 0
                else:
                    self._error(f"Failed to load allowlist from {args.file}")
                    return 1
            
            elif args.allowlist_action == 'export':
                success = self.allowlist_manager.export_to_file(args.file)
                if success:
                    self._success(f"Allowlist exported to {args.file}")
                    return 0
                else:
                    self._error(f"Failed to export allowlist to {args.file}")
                    return 1
            
            else:
                self._error(f"Unknown allowlist action: {args.allowlist_action}")
                return 1
                
        except Exception as e:
            self._error(f"Allowlist command failed: {e}")
            return 1
    
    def _handle_stats(self, args) -> int:
        """Handle stats command"""
        try:
            if args.reset:
                success = self.bpf_maps.reset_statistics()
                if success:
                    self._success("Statistics reset")
                    return 0
                else:
                    self._error("Failed to reset statistics")
                    return 1
            
            if args.analyze:
                analysis = self.analytics.analyze_comprehensive_stats()
                self.display_manager.show_analytics(analysis)
            
            elif args.errors:
                error_analysis = self.analytics.analyze_error_markers()
                self.display_manager.show_error_analysis(error_analysis)
            
            elif args.performance:
                metrics = self.analytics.get_performance_metrics()
                self.display_manager.show_performance_metrics(metrics)
            
            elif args.raw:
                raw_stats = self.bpf_maps.get_all_map_entries()
                self.display_manager.show_raw_stats(raw_stats)
            
            else:
                # Default stats view
                stats = self.bpf_maps.get_pipeline_stats()
                self.display_manager.show_pipeline_stats(stats)
            
            # Export if requested
            if args.export:
                data = {
                    'comprehensive': self.analytics.analyze_comprehensive_stats() if args.analyze else None,
                    'errors': self.analytics.analyze_error_markers() if args.errors else None,
                    'performance': self.analytics.get_performance_metrics() if args.performance else None,
                    'pipeline_stats': self.bpf_maps.get_pipeline_stats()
                }
                
                # Determine export format
                if args.export.endswith('.csv'):
                    format_type = 'analytics' if args.analyze else 'stats'
                    success = self.display_manager.export_to_csv(data, args.export, format_type)
                else:
                    success = self._export_data(data, args.export)
                
                if not success:
                    return 1
            
            return 0
            
        except Exception as e:
            self._error(f"Stats command failed: {e}")
            return 1
    
    def _handle_analytics(self, args) -> int:
        """Handle analytics command"""
        try:
            if args.comprehensive:
                analysis = self.analytics.analyze_comprehensive_stats()
                self.display_manager.show_comprehensive_analytics(analysis)
            
            elif args.errors:
                error_analysis = self.analytics.analyze_error_markers()
                self.display_manager.show_error_analysis(error_analysis)
            
            elif args.trends:
                # This would need historical data
                self._info("Trend analysis requires historical data collection")
                return 0
            
            else:
                # Default analytics
                analysis = self.analytics.analyze_comprehensive_stats()
                self.display_manager.show_analytics(analysis)
            
            # Export if requested
            if args.export:
                if args.comprehensive:
                    data = self.analytics.analyze_comprehensive_stats()
                elif args.errors:
                    data = self.analytics.analyze_error_markers()
                else:
                    data = self.analytics.analyze_comprehensive_stats()
                
                self._export_data(data, args.export)
            
            return 0
            
        except Exception as e:
            self._error(f"Analytics command failed: {e}")
            return 1
    
    def _handle_diagnostics(self, args) -> int:
        """Handle diagnostics command"""
        try:
            if args.comprehensive:
                diagnostics = self.diagnostics.comprehensive_network_check()
                self.display_manager.show_diagnostics(diagnostics)
            
            elif args.connectivity:
                results = self.diagnostics.test_connectivity(args.connectivity, args.interface)
                self.display_manager.show_connectivity_results(results)
            
            elif args.packet_flow and args.interface:
                flow_info = self.diagnostics.debug_packet_flow(args.interface)
                self.display_manager.show_packet_flow(flow_info)
            
            elif args.vxlan and args.interface:
                vxlan_analysis = self.diagnostics.analyze_vxlan_traffic(args.interface)
                self.display_manager.show_vxlan_analysis(vxlan_analysis)
            
            else:
                # Default diagnostics
                diagnostics = self.diagnostics.comprehensive_network_check()
                self.display_manager.show_diagnostics(diagnostics)
            
            # Export if requested
            if args.export:
                if args.comprehensive:
                    data = self.diagnostics.comprehensive_network_check()
                elif args.connectivity:
                    data = self.diagnostics.test_connectivity(args.connectivity, args.interface)
                else:
                    data = self.diagnostics.comprehensive_network_check()
                
                self._export_data(data, args.export)
            
            return 0
            
        except Exception as e:
            self._error(f"Diagnostics command failed: {e}")
            return 1
    
    def _handle_debug(self, args) -> int:
        """Handle debug command"""
        try:
            if args.live:
                return self._live_debug(args)
            else:
                flow_info = self.diagnostics.debug_packet_flow(args.interface, args.packet_count)
                self.display_manager.show_debug_info(flow_info)
                return 0
                
        except Exception as e:
            self._error(f"Debug command failed: {e}")
            return 1
    
    def _handle_monitor(self, args) -> int:
        """Handle monitor command"""
        try:
            if args.interface:
                samples = self.diagnostics.monitor_interface_realtime(args.interface, args.duration)
            else:
                samples = self.analytics.monitor_realtime(args.duration, args.interval)
            
            self.display_manager.show_monitoring_results(samples)
            
            # Export if requested
            if args.export:
                self._export_data(samples, args.export)
            
            return 0
            
        except Exception as e:
            self._error(f"Monitor command failed: {e}")
            return 1
    
    def _handle_top(self, args) -> int:
        """Handle top command"""
        try:
            return self._show_top_interface(args)
        except Exception as e:
            self._error(f"Top command failed: {e}")
            return 1
    
    def _handle_config(self, args) -> int:
        """Handle config commands"""
        try:
            if not args.config_action:
                self._error("Config action required")
                return 1
            
            if args.config_action == 'show':
                config = self.config_manager.get_config()
                self.display_manager.show_config(config)
                return 0
            
            elif args.config_action == 'set':
                success = self.config_manager.set_value(args.key, args.value)
                if success:
                    self._success(f"Set {args.key} = {args.value}")
                    return 0
                else:
                    self._error(f"Failed to set {args.key}")
                    return 1
            
            elif args.config_action == 'reset':
                if not args.confirm:
                    if not self._confirm("Reset configuration to defaults?"):
                        return 0
                
                self.config_manager.reset_to_defaults()
                self._success("Configuration reset to defaults")
                return 0
            
            elif args.config_action == 'validate':
                is_valid, issues = self.config_manager.validate_config()
                if is_valid:
                    self._success("Configuration is valid")
                    return 0
                else:
                    self._error(f"Configuration validation failed: {', '.join(issues)}")
                    return 1
            
            else:
                self._error(f"Unknown config action: {args.config_action}")
                return 1
                
        except Exception as e:
            self._error(f"Config command failed: {e}")
            return 1
    
    # Helper methods
    def _show_live_status(self, args) -> int:
        """Show live status updates"""
        try:
            if not RICH_AVAILABLE:
                self._error("Live status requires 'rich' library")
                return 1
            
            with Live(console=self.console, refresh_per_second=1/args.refresh) as live:
                while True:
                    status = self.pipeline.get_status()
                    display = self.display_manager.create_status_display(status)
                    live.update(display)
                    
        except KeyboardInterrupt:
            return 0
    
    def _show_top_interface(self, args) -> int:
        """Show top-like interface"""
        try:
            if not RICH_AVAILABLE:
                self._error("Top interface requires 'rich' library")
                return 1
            
            with Live(console=self.console, refresh_per_second=1/args.refresh) as live:
                while True:
                    interfaces = self.network_manager.list_interfaces()
                    stats_data = []
                    
                    for iface in interfaces:
                        if iface.state == 'UP':
                            stats = self.diagnostics._get_interface_stats(iface.name)
                            xdp_attached = self.diagnostics._is_xdp_attached(iface.name)
                            
                            stats_data.append({
                                'interface': iface.name,
                                'rx_pps': stats.get('rx_packets', 0),
                                'tx_pps': stats.get('tx_packets', 0),
                                'rx_bps': stats.get('rx_bytes', 0),
                                'tx_bps': stats.get('tx_bytes', 0),
                                'rx_drops': stats.get('rx_dropped', 0),
                                'tx_drops': stats.get('tx_dropped', 0),
                                'rx_errors': stats.get('rx_errors', 0),
                                'tx_errors': stats.get('tx_errors', 0),
                                'xdp': '[OK]' if xdp_attached else '[NO]'
                            })
                    
                    # Sort by criteria
                    sort_key = {
                        'pps': lambda x: x['rx_pps'] + x['tx_pps'],
                        'bps': lambda x: x['rx_bps'] + x['tx_bps'],
                        'drops': lambda x: x['rx_drops'] + x['tx_drops'],
                        'errors': lambda x: x['rx_errors'] + x['tx_errors']
                    }
                    stats_data.sort(key=sort_key[args.sort_by], reverse=True)
                    
                    display = self.display_manager.create_top_display(stats_data, args.sort_by)
                    live.update(display)
                    
        except KeyboardInterrupt:
            return 0
    
    def _live_debug(self, args) -> int:
        """Live debugging mode"""
        try:
            if not RICH_AVAILABLE:
                self._error("Live debugging requires 'rich' library")
                return 1
            
            with Live(console=self.console, refresh_per_second=2) as live:
                while True:
                    # Get current statistics
                    stats = self.bpf_maps.get_pipeline_stats()
                    error_analysis = self.analytics.analyze_error_markers()
                    performance = self.analytics.get_performance_metrics()
                    
                    debug_info = {
                        'interface': args.interface,
                        'stats': stats,
                        'errors': error_analysis,
                        'performance': performance,
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    display = self.display_manager.create_debug_display(debug_info)
                    live.update(display)
                    
        except KeyboardInterrupt:
            return 0
    
    def _export_data(self, data: Any, filepath: str):
        """Export data to file"""
        try:
            path = Path(filepath)
            
            if path.suffix.lower() == '.json':
                with open(filepath, 'w') as f:
                    json.dump(data, f, indent=2, default=str)
            elif path.suffix.lower() in ['.yml', '.yaml']:
                try:
                    import yaml
                    with open(filepath, 'w') as f:
                        yaml.dump(data, f, default_flow_style=False)
                except ImportError:
                    self._error("YAML export requires 'pyyaml' package")
                    return
            else:
                # Default to JSON
                with open(filepath, 'w') as f:
                    json.dump(data, f, indent=2, default=str)
            
            self._success(f"Data exported to {filepath}")
            
        except Exception as e:
            self._error(f"Export failed: {e}")
    
    def _confirm(self, message: str) -> bool:
        """Ask for user confirmation"""
        try:
            response = input(f"{message} [y/N]: ").strip().lower()
            return response in ['y', 'yes']
        except EOFError:
            return False
    
    def _success(self, message: str):
        """Display success message"""
        if RICH_AVAILABLE and self.console:
            self.console.print(f"[SUCCESS] {message}", style="bold green")
        else:
            print(f"SUCCESS: {message}")
    
    def _error(self, message: str):
        """Display error message"""
        if RICH_AVAILABLE and self.console:
            self.console.print(f"[ERROR] {message}", style="bold red")
        else:
            print(f"ERROR: {message}", file=sys.stderr)
    
    def _warning(self, message: str):
        """Display warning message"""
        if RICH_AVAILABLE and self.console:
            self.console.print(f"[WARNING] {message}", style="bold yellow")
        else:
            print(f"WARNING: {message}")
    
    def _info(self, message: str):
        """Display info message"""
        if RICH_AVAILABLE and self.console:
            self.console.print(f"[INFO] {message}", style="bold blue")
        else:
            print(f"INFO: {message}")


def main():
    """Main entry point"""
    cli = XDPManagerCLI()
    return cli.run()


if __name__ == '__main__':
    sys.exit(main())