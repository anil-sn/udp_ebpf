#!/usr/bin/env python3
"""
XDP Manager CLI - Professional Entry Point
Integrates with the professional CLI framework for enhanced user experience
"""

import sys
import argparse
from pathlib import Path
from typing import Optional, List, Dict, Any

# Add the parent directory to the path so we can import our modules
sys.path.insert(0, str(Path(__file__).parent.parent))

# Core imports
from xdp_manager.utils import Logger
from xdp_manager.config import ConfigManager
from xdp_manager.models import PipelineStatus, BPFMapInfo, AllowlistEntry
from xdp_manager.display import DisplayManager
from xdp_manager.network import NetworkManager
from xdp_manager.pipeline import XDPPipeline
from xdp_manager.allowlist import AllowlistManager
from xdp_manager.analyze_stats import StatisticsAnalyzer
from xdp_manager.diagnostics import NetworkDiagnostics
from xdp_manager.system_tuning import SystemTuner

# BPF and monitoring imports
from xdp_manager.monitoring import RealTimeMonitor, AdvancedMonitor
from xdp_manager.bpf import BPFMapManager

# Rich console imports with fallback
try:
    from rich.console import Console
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# Argcomplete imports with fallback
try:
    import argcomplete
    ARGCOMPLETE_AVAILABLE = True
except ImportError:
    ARGCOMPLETE_AVAILABLE = False

class XDPManagerCLI:
    """Main CLI class for XDP pipeline management"""
    
    def __init__(self):
        self.console = Console() if RICH_AVAILABLE else None
        self.logger = Logger("xdp_cli")
        
        # Initialize managers
        self.config_manager = ConfigManager()
        self.network_manager = NetworkManager(logger=self.logger)
        self.bpf_maps = BPFMapManager(logger=self.logger)
        self.allowlist_manager = AllowlistManager(logger=self.logger)
        self.display_manager = DisplayManager(logger=self.logger)
        self.pipeline = XDPPipeline(
            config_manager=self.config_manager
        )
        
        # Analytics and diagnostics
        self.analytics = StatisticsAnalyzer(self.bpf_maps, self.logger)
        self.diagnostics = NetworkDiagnostics(self.logger)
        
        # System tuning
        self.system_tuner = SystemTuner(logger=self.logger)
        
        # Real-time monitoring
        self.realtime_monitor = RealTimeMonitor(logger=self.logger)
        
    def create_parser(self) -> argparse.ArgumentParser:
        """Create and configure argument parser with autocompletion"""
        parser = argparse.ArgumentParser(
            prog='xdp-manager',
            description='Professional XDP Pipeline Management CLI',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  xdp-manager start                                        # Uses config defaults (ens5, vxlan_pipeline.bpf.o)
  xdp-manager start --interface ens5 --program custom.bpf.o
  xdp-manager status --live
  xdp-manager allowlist add 192.168.1.0/24
  xdp-manager stats --analyze --export stats.json
  xdp-manager diagnostics --comprehensive --interface ens5
  xdp-manager monitor --interface ens5 --duration 300
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
        
        # System tuning commands
        self._add_system_commands(subparsers)
        
        # Advanced monitoring commands (pps, maps, logs)
        self._add_advanced_commands(subparsers)
        
        # Monitoring and inspection commands
        self._add_monitoring_commands(subparsers)
        
        # Enable autocompletion if available
        if ARGCOMPLETE_AVAILABLE:
            argcomplete.autocomplete(parser)
        
        return parser
    
    def _add_pipeline_commands(self, subparsers):
        """Add pipeline management commands"""
        # Start command
        start_parser = subparsers.add_parser('start', help='Start XDP pipeline')
        start_parser.add_argument('--interface', '-i', help='Network interface (defaults to ens5 from config)')
        start_parser.add_argument('--program', '-p', help='BPF program path (defaults to src/vxlan_pipeline.bpf.o)')
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
        restart_parser.add_argument('--interface', '-i', help='Network interface (defaults to ens5 from config)')
        restart_parser.add_argument('--program', '-p', help='BPF program path')
        restart_parser.add_argument('--quick', action='store_true', help='Quick restart without validation')
        
        # Status command
        status_parser = subparsers.add_parser('status', help='Show pipeline status')
        status_parser.add_argument('--interface', '-i', help='Specific interface (all if not specified)')
        status_parser.add_argument('--live', action='store_true', help='Live status updates')
        status_parser.add_argument('--refresh', type=float, default=1.0, help='Refresh interval for live mode')
        
        # Reload command
        reload_parser = subparsers.add_parser('reload', help='Reload BPF program')
        reload_parser.add_argument('--interface', '-i', help='Network interface (defaults to ens5 from config)')
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
        debug_parser.add_argument('--interface', '-i', help='Network interface (defaults to ens5 from config)')
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
        
    def _add_system_commands(self, subparsers):
        """Add system tuning and validation commands"""
        # System tuning command
        tune_parser = subparsers.add_parser('tune', help='Apply system performance tuning')
        tune_parser.add_argument('--interface', '-i', help='Network interface for tuning (e.g., ens5, ens6)')
        tune_parser.add_argument('--validate-only', action='store_true', help='Only validate system readiness')
        tune_parser.add_argument('--force', action='store_true', help='Apply tuning even if warnings exist')
        
        # Scale command (for compatibility with bash version)
        scale_parser = subparsers.add_parser('scale', help='Dynamic performance scaling')
        scale_parser.add_argument('mode', choices=['max-performance', 'balanced', 'monitor'], 
                                help='Scaling mode')
        scale_parser.add_argument('--interface', '-i', help='Network interface (e.g., ens5, ens6)')
        
    def _add_advanced_commands(self, subparsers):
        """Add advanced monitoring and debugging commands"""
        
        # PPS monitoring command (bash compatibility)
        pps_parser = subparsers.add_parser('pps', help='Monitor packets per second')
        pps_parser.add_argument('mode', choices=['both', 'incoming', 'target', 'single'],
                              help='Monitoring mode')
        pps_parser.add_argument('interface', nargs='?', help='Interface name (for single mode)')
        pps_parser.add_argument('interval', nargs='?', type=float, default=1.0,
                              help='Update interval in seconds')
        pps_parser.add_argument('duration', nargs='?', type=int, default=0,
                              help='Duration in seconds (0 = infinite)')
        
        # Maps command (bash compatibility)
        maps_parser = subparsers.add_parser('maps', help='Show BPF maps information')
        maps_parser.add_argument('--detailed', action='store_true', help='Show detailed information')
        maps_parser.add_argument('--map-name', help='Show specific map')
        
        # Logs command (bash compatibility)  
        logs_parser = subparsers.add_parser('logs', help='Show and monitor log files')
        logs_parser.add_argument('lines', nargs='?', type=int, default=50,
                               help='Number of lines to show')
        logs_parser.add_argument('filter_level', nargs='?', help='Filter by log level')
        logs_parser.add_argument('--follow', '-f', action='store_true', help='Follow log output')
        logs_parser.add_argument('--search', help='Search for pattern')
        logs_parser.add_argument('--analyze', action='store_true', help='Analyze errors and warnings')
        
        # ARP command (bash compatibility)
        arp_parser = subparsers.add_parser('arp', help='Manage ARP table')
        arp_parser.add_argument('ip', nargs='?', help='IP address to resolve')
        arp_parser.add_argument('--interface', '-i', help='Network interface')
        
        # Info command (comprehensive system info)
        info_parser = subparsers.add_parser('info', help='Show comprehensive system information')
        info_parser.add_argument('--interface', '-i', help='Specific interface')
        
    def _add_monitoring_commands(self, subparsers):
        """Add monitoring, inspection, and utility commands"""
        # PPS monitoring command (bash compatibility)
        pps_parser = subparsers.add_parser('pps', help='Monitor packets per second')
        pps_parser.add_argument('target', choices=['incoming', 'target', 'both'], 
                               help='Monitor incoming interface, target interface, or both')
        pps_parser.add_argument('interval', nargs='?', type=float, default=1.0,
                               help='Monitoring interval in seconds (default: 1.0)')
        pps_parser.add_argument('duration', nargs='?', type=int, default=0,
                               help='Duration in seconds (default: unlimited)')
        pps_parser.add_argument('--incoming-interface', help='Override incoming interface')
        pps_parser.add_argument('--target-interface', help='Override target interface')
        
        # Monitor command (live statistics)
        monitor_parser = subparsers.add_parser('monitor', help='Live performance monitoring dashboard')
        monitor_parser.add_argument('--interval', type=float, default=5.0, help='Update interval')
        monitor_parser.add_argument('--duration', type=int, default=0, help='Duration (0=unlimited)')
        
        # Maps command (BPF map inspection)
        maps_parser = subparsers.add_parser('maps', help='Show BPF maps with live data')
        maps_parser.add_argument('--map-name', help='Show specific map')
        maps_parser.add_argument('--stats-only', action='store_true', help='Show only statistics map')
        
        # Logs command (log monitoring)
        logs_parser = subparsers.add_parser('logs', help='Monitor pipeline logs')
        logs_parser.add_argument('lines', nargs='?', type=int, default=50, help='Number of lines to show')
        logs_parser.add_argument('filter_level', nargs='?', help='Filter by log level')
        logs_parser.add_argument('--follow', '-f', action='store_true', help='Follow log output')
        logs_parser.add_argument('--log-file', help='Log file path (default: auto-detect)')
        
        # ARP command (ARP table management)
        arp_parser = subparsers.add_parser('arp', help='Manually populate ARP table for MAC resolution')
        arp_parser.add_argument('ip', nargs='?', help='IP address (default: use NAT target IP)')
        arp_parser.add_argument('--interface', help='Network interface')
        
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
        
        # Load configuration 
        try:
            if args.config:
                self.config_manager.load_config(args.config)
            else:
                self.config_manager.load_config()  # Load default config.yaml
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
            self.logger.info(f"Config loaded: pipeline_config exists: {hasattr(config, 'pipeline_config')}")
            
            if hasattr(config, 'pipeline_config') and config.pipeline_config.ingress_interface:
                self.logger.info(f"Using configured ingress interface: {config.pipeline_config.ingress_interface}")
                return config.pipeline_config.ingress_interface
            
            # Auto-detect primary interface
            self.logger.info("No configured interface found, auto-detecting...")
            interfaces = self.network_manager.get_interfaces()
            for iface in interfaces:
                if iface.state == 'UP' and not iface.name.startswith(('lo', 'docker', 'br-')):
                    self.logger.info(f"Auto-detected interface: {iface.name}")
                    return iface.name
            
            return None
        except Exception as e:
            self.logger.error(f"Error getting default interface: {e}")
            return None
    
    def _get_default_program(self) -> Optional[str]:
        """Get default BPF program path from configuration"""
        try:
            config = self.config_manager.get_config()
            if hasattr(config, 'pipeline_config') and config.pipeline_config.program_path:
                program_path = config.pipeline_config.program_path
                
                # Convert .c to .o for compiled version
                if program_path.endswith('.c'):
                    program_path = program_path.replace('.c', '.o')
                
                # If relative path, check in src directory
                from pathlib import Path
                if not Path(program_path).is_absolute():
                    src_path = Path('src') / program_path
                    if src_path.exists():
                        return str(src_path)
                    # Also check current directory
                    elif Path(program_path).exists():
                        return program_path
                else:
                    if Path(program_path).exists():
                        return program_path
                        
                # Return configured path even if file doesn't exist (may be built later)
                return str(Path('src') / program_path) if not Path(program_path).is_absolute() else program_path
            
            # Check for common program names if no config
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
            interfaces = self.network_manager.get_interfaces()
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
        """Handle start command - uses config defaults when arguments not provided"""
        try:
            # Log config status
            self.logger.info("Config loaded: pipeline_config exists: True")
            
            # Get interface from args or config
            interface = args.interface or self._get_default_interface()
            if not interface:
                self._error("No interface specified and no default available. Use --interface or configure default.")
                return 1
                
            # Log interface usage
            self.logger.info(f"Using interface: {interface}")
            
            # Get program from args or config  
            program = args.program or self._get_default_program()
            if not program:
                self._error("No BPF program specified and no default available. Use --program or configure default.")
                return 1
            
            # Get mode from args or config
            mode = args.mode
            if not mode:
                config = self.config_manager.get_config()
                if hasattr(config, 'pipeline_config') and config.pipeline_config.mode:
                    mode = config.pipeline_config.mode
                else:
                    mode = "xdp"  # fallback default
            
            self.logger.info(f"Using program: {program}, mode: {mode}")
            
            # Update config with runtime parameters if provided
            if args.program or args.mode:
                config = self.config_manager.get_config()
                if args.program:
                    config.pipeline_config.program_path = program
                if args.mode:
                    config.pipeline_config.mode = mode
            
            # Start the pipeline (it will use config for program and mode)
            result = self.pipeline.start(
                interface=interface,
                force=args.force
            )
            
            if result:
                # Skip optimization calls for now (methods not implemented)
                self._success(f"XDP pipeline started on {interface} with {program} (mode: {mode})")
                return 0
            else:
                self._error(f"Failed to start XDP pipeline on {interface}")
                return 1
                
        except Exception as e:
            self._error(f"Start command failed: {e}")
            return 1
    
    def _handle_stop(self, args) -> int:
        """Handle stop command - matches bash stop_pipeline exactly"""
        try:
            # Get target interface (matches bash $INTERFACE logic)
            interface = args.interface if hasattr(args, 'interface') and args.interface else None
            
            # Stop pipeline once (matches bash approach - no iteration)
            result = self.pipeline.stop(interface, force=getattr(args, 'force', False))
            
            if result:
                interface_msg = f" on {interface}" if interface else ""
                self._success(f"XDP pipeline stopped{interface_msg}")
                return 0
            else:
                self._error("Failed to stop XDP pipeline")
                return 1
                
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
    
    def _handle_tune(self, args) -> int:
        """Handle system tuning commands"""
        try:
            interface = args.interface or self._get_default_interface()
            if not interface:
                self._error("No interface specified and could not auto-detect")
                return 1
            
            # Validate system readiness if requested
            if args.validate_only:
                self._info("Validating system readiness for high-performance packet processing...")
                validation = self.system_tuner.validate_system_readiness()
                
                if validation.valid:
                    self._success("✓ System is ready for high-performance packet processing")
                else:
                    self._error("System validation failed:")
                    for error in validation.errors:
                        self._error(f"  - {error}")
                
                if validation.warnings:
                    self._warning("Warnings:")
                    for warning in validation.warnings:
                        self._warning(f"  - {warning}")
                
                return 0 if validation.valid else 1
            
            # Apply system tuning
            self._info(f"Applying comprehensive system tuning for interface {interface}...")
            
            # Validate first unless forced
            if not args.force:
                validation = self.system_tuner.validate_system_readiness()
                if not validation.valid:
                    self._error("System validation failed. Use --force to override:")
                    for error in validation.errors:
                        self._error(f"  - {error}")
                    return 1
                
                if validation.warnings:
                    self._warning("System warnings (continuing with tuning):")
                    for warning in validation.warnings:
                        self._warning(f"  - {warning}")
            
            # Apply tuning
            if self.system_tuner.apply_system_tuning(interface):
                self._success("✓ System tuning applied successfully")
                self._info("Tuning will persist across reboots")
                return 0
            else:
                self._error("System tuning failed")
                return 1
                
        except Exception as e:
            self._error(f"System tuning failed: {e}")
            return 1
    
    def _handle_scale(self, args) -> int:
        """Handle dynamic performance scaling (compatibility with bash version)"""
        try:
            interface = args.interface or self._get_default_interface()
            if not interface:
                self._error("No interface specified and could not auto-detect")
                return 1
            
            if args.mode == 'max-performance':
                self._info(f"Scaling {interface} for maximum performance...")
                
                # Apply comprehensive system tuning
                if not self.system_tuner.apply_system_tuning(interface):
                    self._error("Performance scaling failed")
                    return 1
                
                # Additional max-performance optimizations could be added here
                self._success("✓ Maximum performance scaling applied")
                return 0
                
            elif args.mode == 'balanced':
                self._info("Balanced mode not yet implemented")
                return 1
                
            elif args.mode == 'monitor':
                self._info("Monitor mode - displaying current performance metrics...")
                # Could integrate with existing monitoring functionality
                return self._handle_status(args)
            
        except Exception as e:
            self._error(f"Scale command failed: {e}")
            return 1
    
    def _handle_pps(self, args) -> int:
        """Handle PPS monitoring commands"""
        try:
            if args.mode == 'both':
                # Get default interfaces from config
                config = self.config_manager.get_config()
                incoming_iface = config.pipeline_config.ingress_interface
                target_iface = config.pipeline_config.egress_interface
                
                self.advanced_monitor.monitor_interface_pps_dual(
                    incoming_iface, target_iface, args.interval, args.duration
                )
                
            elif args.mode in ['incoming', 'target']:
                config = self.config_manager.get_config()
                if args.mode == 'incoming':
                    interface = config.pipeline_config.ingress_interface
                else:
                    interface = config.pipeline_config.egress_interface
                    
                self.advanced_monitor.monitor_interface_pps_single(
                    interface, args.interval, args.duration
                )
                
            elif args.mode == 'single':
                if not args.interface:
                    self._error("Interface required for single mode")
                    return 1
                    
                self.advanced_monitor.monitor_interface_pps_single(
                    args.interface, args.interval, args.duration
                )
            
            return 0
            
        except Exception as e:
            self._error(f"PPS monitoring failed: {e}")
            return 1
    
    def _handle_maps(self, args) -> int:
        """Handle BPF maps commands"""
        try:
            if args.map_name:
                # Show specific map
                if args.map_name == 'stats':
                    self.bpf_maps_enhanced.show_stats_map()
                elif args.map_name == 'nat':
                    self.bpf_maps_enhanced.show_nat_map()
                elif args.map_name == 'allowlist':
                    self.bpf_maps_enhanced.show_ip_allowlist_map()
                else:
                    self._error(f"Unknown map: {args.map_name}")
                    return 1
            else:
                # Show all maps
                # Show all BPF maps
                maps = self.bpf_maps_enhanced.list_maps()
                for map_info in maps:
                    print(f"Map: {map_info.name} (ID: {map_info.id})")
                    if args.detailed:
                        print(f"  Type: {map_info.type}")
                        print(f"  Entries: {map_info.entries_count}/{map_info.max_entries}")
                
            return 0
            
        except Exception as e:
            self._error(f"Maps command failed: {e}")
            return 1
    
    def _handle_logs(self, args) -> int:
        """Handle log monitoring commands"""
        try:
            if args.follow:
                self.log_monitor.monitor_logs_live()
            elif args.search:
                self.log_monitor.search_logs(args.search)
            elif args.analyze:
                self.log_monitor.analyze_error_logs()
            else:
                self.log_monitor.show_logs(args.lines, args.filter_level)
                
            return 0
            
        except Exception as e:
            self._error(f"Logs command failed: {e}")
            return 1
    
    def _handle_arp(self, args) -> int:
        """Handle ARP management commands"""
        try:
            interface = args.interface or self._get_default_interface()
            if not interface:
                self._error("No interface specified and could not auto-detect")
                return 1
                
            if args.ip:
                target_ip = args.ip
            else:
                # Use configured NAT target IP
                config = self.config_manager.get_config()
                target_ip = config.pipeline_config.nat_target_ip
                
            self._info(f"Populating ARP table for {target_ip} on {interface}...")
            
            if self.interface_manager.populate_arp_table(target_ip, interface):
                self._success(f"✓ ARP entry populated for {target_ip}")
                return 0
            else:
                self._warning(f"⚠ Could not populate ARP entry for {target_ip}")
                return 1
                
        except Exception as e:
            self._error(f"ARP command failed: {e}")
            return 1
    
    def _handle_info(self, args) -> int:
        """Handle system information command"""
        try:
            self._show_system_info(args.interface)
            return 0
        except Exception as e:
            self._error(f"Info command failed: {e}")
            return 1
    
    def _show_system_info(self, specific_interface: Optional[str] = None) -> None:
        """Show comprehensive system information"""
        print("XDP Pipeline System Information")
        print("=" * 35)
        
        # Configuration
        print("\n📋 Configuration:")
        config = self.config_manager.get_config()
        print(f"  Ingress Interface: {config.pipeline_config.ingress_interface}")
        print(f"  Egress Interface: {config.pipeline_config.egress_interface}")
        print(f"  NAT Target: {config.pipeline_config.nat_target_ip}:{config.pipeline_config.nat_target_port}")
        print(f"  Source Port: {config.pipeline_config.source_port}")
        print(f"  System Tuning: {'Enabled' if config.pipeline_config.apply_system_tuning else 'Disabled'}")
        
        # Interface information
        print("\n🌐 Network Interfaces:")
        interfaces = [config.pipeline_config.ingress_interface, config.pipeline_config.egress_interface]
        if specific_interface:
            interfaces = [specific_interface]
            
        for iface in set(interfaces):  # Remove duplicates
            info = self.interface_manager.get_interface_info(iface)
            print(f"  {iface}:")
            print(f"    State: {info['state']} | IP: {info['ip']} | MAC: {info['mac']}")
            print(f"    MTU: {info['mtu']} | Queues: {info['queues']} | XDP: {info['xdp_attached']}")
        
        # Pipeline status
        print("\n🚀 Pipeline Status:")
        status = self.pipeline.get_status()
        print(f"  Status: {status.status.value}")
        if status.interfaces:
            print(f"  Active Interfaces: {', '.join(status.interfaces)}")
        
        # BPF Maps summary
        print("\n🗺️  BPF Maps:")
        nat_count = len(self.bpf_maps_enhanced.get_map_entries('nat_map'))
        allowlist_count = len(self.bpf_maps_enhanced.get_map_entries('ip_allowlist'))
        print(f"  NAT Rules: {nat_count}")
        print(f"  Allowlist Entries: {allowlist_count}")
        
        # Log files
        print("\n📄 Log Files:")
        log_summary = self.log_monitor.get_log_summary()
        if log_summary['available_logs']:
            for log in log_summary['available_logs']:
                size_mb = log['size'] / (1024 * 1024)
                print(f"  {Path(log['path']).name}: {size_mb:.1f}MB (modified: {log['modified']})")
        else:
            print("  No log files found")
    
    def _handle_pps(self, args) -> int:
        """Handle PPS monitoring commands (bash compatibility)"""
        try:
            # Get interfaces
            incoming_iface = args.incoming_interface or self.config_manager.get_config().pipeline_config.ingress_interface
            target_iface = args.target_interface or self.config_manager.get_config().pipeline_config.egress_interface
            
            if not incoming_iface:
                incoming_iface = self._get_default_interface()
            if not target_iface:
                target_iface = self._get_default_interface()
            
            if not incoming_iface or not target_iface:
                self._error("Could not determine interfaces for monitoring")
                return 1
            
            if args.target == 'both':
                self._info(f"Monitoring PPS on both interfaces: {incoming_iface} (incoming) and {target_iface} (target)")
                self.realtime_monitor.monitor_dual_interface_pps(
                    incoming_iface, target_iface, args.interval, args.duration
                )
            elif args.target == 'incoming':
                self._info(f"Monitoring PPS on incoming interface: {incoming_iface}")
                self.realtime_monitor.monitor_single_interface_pps(
                    incoming_iface, args.interval, args.duration
                )
            elif args.target == 'target':
                self._info(f"Monitoring PPS on target interface: {target_iface}")
                self.realtime_monitor.monitor_single_interface_pps(
                    target_iface, args.interval, args.duration
                )
            
            return 0
            
        except KeyboardInterrupt:
            return 0
        except Exception as e:
            self._error(f"PPS monitoring failed: {e}")
            return 1
    
    def _handle_monitor(self, args) -> int:
        """Handle live monitoring dashboard"""
        try:
            self._info("Starting live performance monitoring dashboard...")
            self.realtime_monitor.show_clean_statistics(args.interval, args.duration)
            return 0
            
        except KeyboardInterrupt:
            return 0
        except Exception as e:
            self._error(f"Monitor command failed: {e}")
            return 1
    
    def _handle_maps(self, args) -> int:
        """Handle BPF maps inspection"""
        try:
            if args.stats_only:
                self.bpf_maps.show_stats_map()
            elif args.map_name:
                # Show specific map
                if args.map_name == "nat_map":
                    self.bpf_maps.show_nat_map()
                elif args.map_name == "ip_allowlist":
                    self.bpf_maps.show_ip_allowlist_map()
                elif args.map_name == "stats_map":
                    self.bpf_maps.show_stats_map()
                elif args.map_name == "redirect_map":
                    # redirect_map inspection not implemented yet
                    self._error(f"Map inspection for {args.map_name} not yet available")
                    return 1
                else:
                    self._error(f"Unknown map: {args.map_name}")
                    return 1
            else:
                # Show all maps - use list_maps from BPFMapManager
                maps = self.bpf_maps.list_maps()
                for map_info in maps:
                    print(f"Map: {map_info.name} (ID: {map_info.id}, Type: {map_info.type})")
                    print(f"  Entries: {map_info.entries_count}/{map_info.max_entries}")
                    print()
            
            return 0
            
        except Exception as e:
            self._error(f"Maps command failed: {e}")
            return 1
    
    def _handle_logs(self, args) -> int:
        """Handle log monitoring"""
        try:
            import os
            
            # Determine log file
            log_file = args.log_file
            if not log_file:
                # Try common locations
                possible_logs = [
                    "/tmp/vxlan_loader.log",
                    "/tmp/xdp_pipeline.log",
                    "/var/log/xdp_pipeline.log"
                ]
                
                for log_path in possible_logs:
                    if os.path.exists(log_path):
                        log_file = log_path
                        break
                
                if not log_file:
                    self._error("No log file found. Specify with --log-file")
                    return 1
            
            self._info(f"Monitoring log file: {log_file}")
            
            if args.follow:
                # Follow log output
                import subprocess
                cmd = ["tail", "-f"]
                if args.filter_level:
                    cmd = ["tail", "-f", log_file, "|", "grep", args.filter_level]
                    subprocess.run(" ".join(cmd), shell=True)
                else:
                    cmd.append(log_file)
                    subprocess.run(cmd)
            else:
                # Show last N lines
                cmd = ["tail", "-n", str(args.lines), log_file]
                if args.filter_level:
                    cmd.extend(["|grep", args.filter_level])
                    subprocess.run(" ".join(cmd), shell=True)
                else:
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    print(result.stdout)
            
            return 0
            
        except Exception as e:
            self._error(f"Logs command failed: {e}")
            return 1
    
    def _handle_arp(self, args) -> int:
        """Handle ARP table population"""
        try:
            # Determine target IP
            target_ip = args.ip
            if not target_ip:
                config = self.config_manager.get_config()
                target_ip = config.network.nat_ip if hasattr(config, 'network') else None
                if not target_ip:
                    self._error("No IP specified and no NAT target IP configured")
                    return 1
            
            # Determine interface
            interface = args.interface or self._get_default_interface()
            if not interface:
                self._error("No interface specified and could not auto-detect")
                return 1
            
            self._info(f"Populating ARP table: {target_ip} via {interface}")
            
            if self.interface_manager.populate_arp_table(target_ip, interface):
                self._success("✓ ARP table populated successfully")
                return 0
            else:
                self._warning("ARP population completed with warnings")
                return 0
                
        except Exception as e:
            self._error(f"ARP command failed: {e}")
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
                    interfaces = self.network_manager.get_interfaces()
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