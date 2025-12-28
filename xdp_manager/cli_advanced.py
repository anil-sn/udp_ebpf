"""
Professional CLI framework with enhanced command handling and user experience
Provides enterprise-grade command-line interface with comprehensive features
"""

import argparse
import sys
import os
from typing import Dict, List, Any, Optional, Callable, Tuple
from pathlib import Path
import json
from datetime import datetime
import subprocess
from dataclasses import dataclass

# Rich imports for enhanced CLI experience
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.prompt import Prompt, Confirm
    from rich.syntax import Syntax
    from rich.tree import Tree
    from rich.columns import Columns
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("Warning: Rich library not available. Install with: pip install rich")

from .logging_manager import get_global_logger, initialize_logging
from .config import ProfessionalConfigManager, ConfigFormat
from .pipeline import XDPPipeline
from .monitoring import UnifiedMonitor
from .system_tuning import SystemTuning
from .interface_management import InterfaceManager
from .bpf import BPFMapManager
from .error_handler import ErrorHandler, ProfessionalValidator
from .monitoring import ProfessionalMonitor

@dataclass
class CommandResult:
    """Result from command execution"""
    success: bool
    message: str
    data: Optional[Any] = None
    exit_code: int = 0

class ProfessionalCLI:
    """Professional CLI framework with enhanced features"""
    
    def __init__(self):
        self.console = Console() if RICH_AVAILABLE else None
        self.logger = get_global_logger()
        self.config_manager = ProfessionalConfigManager(self.logger)
        self.error_handler = ErrorHandler(self.logger)
        self.validator = ProfessionalValidator()
        
        # Core components (initialized on demand)
        self.pipeline: Optional[XDPPipeline] = None
        self.monitor: Optional[UnifiedMonitor] = None
        self.system_tuning: Optional[SystemTuning] = None
        self.interface_manager: Optional[InterfaceManager] = None
        self.bpf_maps: Optional[BPFMapManager] = None
        self.professional_monitor: Optional[ProfessionalMonitor] = None
        
        # CLI state
        self.config: Dict[str, Any] = {}
        self.interactive_mode = False
        
    def create_parser(self) -> argparse.ArgumentParser:
        """Create comprehensive argument parser"""
        
        parser = argparse.ArgumentParser(
            description="XDP Manager - Professional eBPF/XDP Pipeline Management",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  %(prog)s setup --interface ens5 --egress ens6      # Setup XDP pipeline
  %(prog)s start --apply-tuning                      # Start with system tuning
  %(prog)s monitor --pps --continuous                # Monitor PPS continuously
  %(prog)s tune --network --cpu --persistent         # Apply system tuning
  %(prog)s maps --detailed --nat                     # Show detailed BPF maps
  %(prog)s logs --live --filter ERROR                # Live log monitoring
  %(prog)s scale --interface ens5 --queues 8        # Scale interface queues
  %(prog)s interactive                               # Interactive mode
  
For detailed help on any command: %(prog)s <command> --help
            """
        )
        
        # Global options
        parser.add_argument(
            '--config', '-c',
            type=str,
            default='config.yaml',
            help='Configuration file path (default: config.yaml)'
        )
        parser.add_argument(
            '--log-level',
            choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
            default='INFO',
            help='Logging level (default: INFO)'
        )
        parser.add_argument(
            '--no-color',
            action='store_true',
            help='Disable colored output'
        )
        parser.add_argument(
            '--json-output',
            action='store_true',
            help='Output results in JSON format'
        )
        parser.add_argument(
            '--quiet', '-q',
            action='store_true',
            help='Suppress non-essential output'
        )
        parser.add_argument(
            '--verbose', '-v',
            action='count',
            default=0,
            help='Increase verbosity (-v, -vv, -vvv)'
        )
        
        # Subcommands
        subparsers = parser.add_subparsers(
            dest='command',
            help='Available commands',
            metavar='COMMAND'
        )
        
        # Setup command
        setup_parser = subparsers.add_parser(
            'setup',
            help='Setup XDP pipeline',
            description='Configure and setup XDP pipeline with interfaces and BPF program'
        )
        setup_parser.add_argument('--interface', '-i', required=True, help='Ingress interface')
        setup_parser.add_argument('--egress', '-e', required=True, help='Egress interface')
        setup_parser.add_argument('--program', '-p', help='BPF program path')
        setup_parser.add_argument('--nat-ip', help='NAT target IP address')
        setup_parser.add_argument('--nat-port', type=int, help='NAT target port')
        setup_parser.add_argument('--source-port', type=int, help='Source port')
        setup_parser.add_argument('--validate', action='store_true', help='Validate setup only')
        
        # Start command
        start_parser = subparsers.add_parser(
            'start',
            help='Start XDP pipeline',
            description='Start the XDP pipeline with optional system tuning'
        )
        start_parser.add_argument('--apply-tuning', action='store_true', help='Apply system tuning')
        start_parser.add_argument('--monitor', action='store_true', help='Start with monitoring')
        start_parser.add_argument('--background', action='store_true', help='Run in background')
        
        # Stop command
        stop_parser = subparsers.add_parser(
            'stop',
            help='Stop XDP pipeline',
            description='Stop the running XDP pipeline'
        )
        stop_parser.add_argument('--cleanup', action='store_true', help='Clean up BPF maps')
        stop_parser.add_argument('--restore-tuning', action='store_true', help='Restore original system settings')
        
        # Monitor command
        monitor_parser = subparsers.add_parser(
            'monitor',
            help='Monitor XDP pipeline performance',
            description='Monitor pipeline performance with various display options'
        )
        monitor_parser.add_argument('--pps', action='store_true', help='Show packets per second')
        monitor_parser.add_argument('--stats', action='store_true', help='Show detailed statistics')
        monitor_parser.add_argument('--continuous', action='store_true', help='Continuous monitoring')
        monitor_parser.add_argument('--interval', type=int, default=5, help='Update interval in seconds')
        monitor_parser.add_argument('--dual', action='store_true', help='Dual interface monitoring')
        monitor_parser.add_argument('--format', choices=['table', 'json', 'compact'], default='table', help='Output format')
        
        # Tune command
        tune_parser = subparsers.add_parser(
            'tune',
            help='Apply system tuning optimizations',
            description='Apply various system performance optimizations'
        )
        tune_parser.add_argument('--network', action='store_true', help='Network buffer tuning')
        tune_parser.add_argument('--cpu', action='store_true', help='CPU optimization')
        tune_parser.add_argument('--irq', action='store_true', help='IRQ affinity tuning')
        tune_parser.add_argument('--all', action='store_true', help='Apply all tuning options')
        tune_parser.add_argument('--persistent', action='store_true', help='Make tuning persistent')
        tune_parser.add_argument('--restore', action='store_true', help='Restore original settings')
        
        # Maps command
        maps_parser = subparsers.add_parser(
            'maps',
            help='Manage and inspect BPF maps',
            description='Display and manage BPF maps with detailed information'
        )
        maps_parser.add_argument('--list', action='store_true', help='List all BPF maps')
        maps_parser.add_argument('--detailed', action='store_true', help='Show detailed map information')
        maps_parser.add_argument('--nat', action='store_true', help='Show NAT map contents')
        maps_parser.add_argument('--stats', action='store_true', help='Show statistics map')
        maps_parser.add_argument('--allowlist', action='store_true', help='Show IP allowlist map')
        maps_parser.add_argument('--clear', help='Clear specific map by name')
        
        # Logs command
        logs_parser = subparsers.add_parser(
            'logs',
            help='Monitor and analyze logs',
            description='Monitor application and system logs with filtering'
        )
        logs_parser.add_argument('--live', action='store_true', help='Live log monitoring')
        logs_parser.add_argument('--filter', help='Filter logs by pattern')
        logs_parser.add_argument('--level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], help='Filter by log level')
        logs_parser.add_argument('--lines', '-n', type=int, default=50, help='Number of lines to show')
        logs_parser.add_argument('--follow', '-f', action='store_true', help='Follow log file')
        logs_parser.add_argument('--analyze', action='store_true', help='Analyze log patterns')
        
        # Scale command
        scale_parser = subparsers.add_parser(
            'scale',
            help='Scale network interface configuration',
            description='Optimize network interface queues and settings for performance'
        )
        scale_parser.add_argument('--interface', '-i', required=True, help='Network interface to scale')
        scale_parser.add_argument('--queues', type=int, help='Number of queues to configure')
        scale_parser.add_argument('--optimize', action='store_true', help='Apply optimal settings')
        scale_parser.add_argument('--mtu', type=int, help='Set MTU size')
        
        # Info command
        info_parser = subparsers.add_parser(
            'info',
            help='Display system and pipeline information',
            description='Show comprehensive system and XDP pipeline information'
        )
        info_parser.add_argument('--system', action='store_true', help='Show system information')
        info_parser.add_argument('--network', action='store_true', help='Show network interfaces')
        info_parser.add_argument('--bpf', action='store_true', help='Show BPF environment')
        info_parser.add_argument('--config', action='store_true', help='Show current configuration')
        info_parser.add_argument('--all', action='store_true', help='Show all information')
        
        # Config command
        config_parser = subparsers.add_parser(
            'config',
            help='Configuration management',
            description='Manage configuration files and settings'
        )
        config_parser.add_argument('--generate-template', help='Generate config template to file')
        config_parser.add_argument('--validate', action='store_true', help='Validate current configuration')
        config_parser.add_argument('--show', action='store_true', help='Show current configuration')
        config_parser.add_argument('--set', nargs=2, metavar=('KEY', 'VALUE'), help='Set configuration value')
        config_parser.add_argument('--backup', action='store_true', help='Create configuration backup')
        
        # Interactive command
        interactive_parser = subparsers.add_parser(
            'interactive',
            help='Interactive mode',
            description='Start interactive command-line interface'
        )
        
        # Debug command  
        debug_parser = subparsers.add_parser(
            'debug',
            help='Debug and diagnostic tools',
            description='Advanced debugging and diagnostic functionality'
        )
        debug_parser.add_argument('--connectivity', action='store_true', help='Test network connectivity')
        debug_parser.add_argument('--performance', action='store_true', help='Performance diagnostics')
        debug_parser.add_argument('--bpf-maps', action='store_true', help='Debug BPF maps')
        debug_parser.add_argument('--system-health', action='store_true', help='System health check')
        
        # Status command
        status_parser = subparsers.add_parser(
            'status',
            help='Show XDP pipeline status',
            description='Display current status of XDP pipeline and components'
        )
        status_parser.add_argument('--detailed', action='store_true', help='Show detailed status')
        status_parser.add_argument('--json', action='store_true', help='JSON output format')
        
        return parser
    
    def run(self, args: Optional[List[str]] = None) -> int:
        """Main CLI entry point"""
        
        parser = self.create_parser()
        parsed_args = parser.parse_args(args)
        
        try:
            # Initialize logging
            self._setup_logging(parsed_args)
            
            # Load configuration
            self._load_configuration(parsed_args)
            
            # Setup console output
            self._setup_console(parsed_args)
            
            # Execute command
            if not parsed_args.command:
                parser.print_help()
                return 1
            
            result = self._execute_command(parsed_args)
            
            # Output result
            self._output_result(result, parsed_args)
            
            return result.exit_code
            
        except KeyboardInterrupt:
            self._print_info("🛑 Operation cancelled by user")
            return 130
        except Exception as e:
            self.error_handler.handle_error(e, context={"command": parsed_args.command})
            return 1
    
    def _setup_logging(self, args):
        """Setup logging configuration"""
        log_config = {
            "level": args.log_level,
            "console": {
                "enabled": True,
                "colors": not args.no_color,
                "level": args.log_level
            },
            "structured": {
                "enabled": args.json_output
            }
        }
        
        if args.verbose:
            if args.verbose >= 3:
                log_config["level"] = "DEBUG"
            elif args.verbose >= 2:
                log_config["console"]["level"] = "DEBUG"
        
        initialize_logging(log_config)
    
    def _load_configuration(self, args):
        """Load and validate configuration"""
        if Path(args.config).exists():
            self.config, validation_result = self.config_manager.load_config_with_validation(args.config)
            
            if not validation_result.valid:
                self._print_error("❌ Configuration validation failed:")
                for error in validation_result.errors:
                    self._print_error(f"  • {error}")
                
                if not Confirm.ask("Continue with invalid configuration?", console=self.console):
                    sys.exit(1)
            
            if validation_result.warnings:
                self._print_warning("⚠️  Configuration warnings:")
                for warning in validation_result.warnings:
                    self._print_warning(f"  • {warning}")
        else:
            self._print_warning(f"⚠️  Configuration file not found: {args.config}")
            self._print_info("Using default configuration")
            self.config = {}
    
    def _setup_console(self, args):
        """Setup console output configuration"""
        if not RICH_AVAILABLE:
            return
            
        self.console = Console(
            color_system="auto" if not args.no_color else None,
            quiet=args.quiet
        )
    
    def _execute_command(self, args) -> CommandResult:
        """Execute the specified command"""
        
        command_handlers = {
            'setup': self._cmd_setup,
            'start': self._cmd_start,
            'stop': self._cmd_stop,
            'monitor': self._cmd_monitor,
            'tune': self._cmd_tune,
            'maps': self._cmd_maps,
            'logs': self._cmd_logs,
            'scale': self._cmd_scale,
            'info': self._cmd_info,
            'config': self._cmd_config,
            'interactive': self._cmd_interactive,
            'debug': self._cmd_debug,
            'status': self._cmd_status
        }
        
        handler = command_handlers.get(args.command)
        if not handler:
            return CommandResult(
                success=False,
                message=f"Unknown command: {args.command}",
                exit_code=1
            )
        
        return handler(args)
    
    def _cmd_setup(self, args) -> CommandResult:
        """Handle setup command"""
        try:
            # Validate arguments
            validation_result = self.validator.validate_interface_exists(args.interface)
            if not validation_result.valid:
                return CommandResult(
                    success=False,
                    message=f"Invalid ingress interface: {validation_result.errors[0]}",
                    exit_code=1
                )
            
            validation_result = self.validator.validate_interface_exists(args.egress)
            if not validation_result.valid:
                return CommandResult(
                    success=False,
                    message=f"Invalid egress interface: {validation_result.errors[0]}",
                    exit_code=1
                )
            
            # Update configuration
            setup_config = {
                "pipeline": {
                    "ingress_interface": args.interface,
                    "egress_interface": args.egress
                }
            }
            
            if args.program:
                setup_config["pipeline"]["program_path"] = args.program
            if args.nat_ip:
                setup_config["pipeline"]["nat_target_ip"] = args.nat_ip
            if args.nat_port:
                setup_config["pipeline"]["nat_target_port"] = args.nat_port
            if args.source_port:
                setup_config["pipeline"]["source_port"] = args.source_port
            
            self.config.update(setup_config)
            
            if args.validate:
                return CommandResult(
                    success=True,
                    message="✅ Setup configuration is valid",
                    data=setup_config
                )
            
            # Initialize pipeline
            self.pipeline = XDPPipeline(self.config, self.logger)
            
            self._print_info("🚀 Setting up XDP pipeline...")
            success = self.pipeline.setup()
            
            if success:
                return CommandResult(
                    success=True,
                    message="✅ XDP pipeline setup completed successfully"
                )
            else:
                return CommandResult(
                    success=False,
                    message="❌ XDP pipeline setup failed",
                    exit_code=1
                )
                
        except Exception as e:
            return CommandResult(
                success=False,
                message=f"Setup failed: {e}",
                exit_code=1
            )
    
    def _cmd_start(self, args) -> CommandResult:
        """Handle start command"""
        try:
            if not self.pipeline:
                self.pipeline = XDPPipeline(self.config, self.logger)
            
            self._print_info("🏁 Starting XDP pipeline...")
            
            # Apply system tuning if requested
            if args.apply_tuning:
                if not self.system_tuning:
                    self.system_tuning = SystemTuning(self.logger)
                
                self._print_info("🔧 Applying system tuning...")
                self.system_tuning.apply_system_tuning()
            
            # Start pipeline
            success = self.pipeline.start()
            
            if not success:
                return CommandResult(
                    success=False,
                    message="❌ Failed to start XDP pipeline",
                    exit_code=1
                )
            
            # Start monitoring if requested
            if args.monitor:
                if not self.professional_monitor:
                    self.professional_monitor = ProfessionalMonitor(self.logger)
                
                self.professional_monitor.start_monitoring()
                self._print_info("📊 Professional monitoring started")
            
            return CommandResult(
                success=True,
                message="✅ XDP pipeline started successfully"
            )
            
        except Exception as e:
            return CommandResult(
                success=False,
                message=f"Start failed: {e}",
                exit_code=1
            )
    
    def _cmd_monitor(self, args) -> CommandResult:
        """Handle monitor command"""
        try:
            if not self.monitor:
                self.monitor = AdvancedMonitor(self.config, self.logger)
            
            if args.pps:
                if args.dual:
                    return self._monitor_pps_dual(args)
                else:
                    return self._monitor_pps_single(args)
            elif args.stats:
                return self._show_statistics(args)
            else:
                # Default monitoring
                return self._show_statistics(args)
                
        except Exception as e:
            return CommandResult(
                success=False,
                message=f"Monitoring failed: {e}",
                exit_code=1
            )
    
    def _output_result(self, result: CommandResult, args):
        """Output command result"""
        if args.json_output:
            output_data = {
                "success": result.success,
                "message": result.message,
                "data": result.data,
                "timestamp": datetime.now().isoformat()
            }
            print(json.dumps(output_data, indent=2, default=str))
        else:
            if result.success:
                self._print_success(result.message)
            else:
                self._print_error(result.message)
                
            if result.data and not args.quiet:
                self._print_data(result.data)
    
    def _print_info(self, message: str):
        """Print info message"""
        if RICH_AVAILABLE and self.console:
            self.console.print(message, style="blue")
        else:
            print(f"INFO: {message}")
    
    def _print_success(self, message: str):
        """Print success message"""
        if RICH_AVAILABLE and self.console:
            self.console.print(message, style="green")
        else:
            print(f"SUCCESS: {message}")
    
    def _print_error(self, message: str):
        """Print error message"""
        if RICH_AVAILABLE and self.console:
            self.console.print(message, style="red", file=sys.stderr)
        else:
            print(f"ERROR: {message}", file=sys.stderr)
    
    def _print_warning(self, message: str):
        """Print warning message"""
        if RICH_AVAILABLE and self.console:
            self.console.print(message, style="yellow")
        else:
            print(f"WARNING: {message}")
    
    def _print_data(self, data: Any):
        """Print data output"""
        if RICH_AVAILABLE and self.console:
            if isinstance(data, dict):
                self.console.print_json(json.dumps(data, default=str))
            else:
                self.console.print(str(data))
        else:
            if isinstance(data, dict):
                print(json.dumps(data, indent=2, default=str))
            else:
                print(str(data))

    # Additional command handlers would be implemented here...
    # (cmd_stop, cmd_tune, cmd_maps, cmd_logs, etc.)

def main():
    """Main entry point"""
    cli = ProfessionalCLI()
    return cli.run()

if __name__ == "__main__":
    sys.exit(main())