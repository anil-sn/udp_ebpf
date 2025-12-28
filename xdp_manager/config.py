"""
Configuration management for XDP pipeline
"""

import json
import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from .models import ValidationResult

@dataclass
class PipelineConfig:
    """Main pipeline configuration"""
    ingress_interface: str = "ens5"  # VXLAN ingress interface where XDP attaches
    egress_interface: str = "ens6"   # Packet egress interface for processed packets
    src_directory: str = "src"
    program_path: str = "vxlan_pipeline.bpf.c"  # BPF program file path
    mode: str = "xdp"  # XDP attachment mode: xdp, xdpgeneric, xdpdrv, xdpoffload
    allowlist_file: str = "ip_allowlist.json"
    max_entries: int = 10000
    log_level: str = "info"
    auto_reload: bool = False
    performance_mode: bool = True
    
@dataclass
class CompilerConfig:
    """BPF compiler configuration"""
    optimization_level: str = "O2"
    debug_info: bool = False
    warnings_as_errors: bool = False
    additional_flags: List[str] = None
    
    def __post_init__(self):
        if self.additional_flags is None:
            self.additional_flags = []

@dataclass
class MonitoringConfig:
    """Monitoring and statistics configuration"""
    stats_interval: int = 5
    enable_metrics: bool = True
    export_prometheus: bool = False
    prometheus_port: int = 9090
    log_file: str = "xdp_pipeline.log"

class ConfigManager:
    """Configuration management with validation and persistence"""
    
    DEFAULT_CONFIG_FILE = "config.yaml"
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = Path(config_file) if config_file else Path(self.DEFAULT_CONFIG_FILE)
        self.pipeline_config = PipelineConfig()
        self.compiler_config = CompilerConfig()
        self.monitoring_config = MonitoringConfig()
        
    def load_config(self, config_file: Optional[str] = None) -> bool:
        """Load configuration from file"""
        try:
            # Update config file path if provided
            if config_file:
                self.config_file = Path(config_file)
                
            if not self.config_file.exists():
                self.save_config()  # Create default config
                return True
                
            with open(self.config_file) as f:
                if self.config_file.suffix.lower() == '.json':
                    data = json.load(f)
                else:
                    data = yaml.safe_load(f)
            
            # Load pipeline config
            if 'pipeline' in data:
                pipeline_data = data['pipeline']
                for key, value in pipeline_data.items():
                    if hasattr(self.pipeline_config, key):
                        setattr(self.pipeline_config, key, value)
            
            # Load compiler config
            if 'compiler' in data:
                compiler_data = data['compiler']
                for key, value in compiler_data.items():
                    if hasattr(self.compiler_config, key):
                        setattr(self.compiler_config, key, value)
            
            # Load monitoring config
            if 'monitoring' in data:
                monitoring_data = data['monitoring']
                for key, value in monitoring_data.items():
                    if hasattr(self.monitoring_config, key):
                        setattr(self.monitoring_config, key, value)
            
            return True
            
        except Exception as e:
            print(f"Error loading config: {e}")
            return False
    
    def get_config(self):
        """Get the config manager instance (for compatibility)"""
        return self
    
    def save_config(self) -> bool:
        """Save configuration to file"""
        try:
            config_data = {
                'pipeline': asdict(self.pipeline_config),
                'compiler': asdict(self.compiler_config),
                'monitoring': asdict(self.monitoring_config)
            }
            
            with open(self.config_file, 'w') as f:
                if self.config_file.suffix.lower() == '.json':
                    json.dump(config_data, f, indent=2)
                else:
                    yaml.dump(config_data, f, default_flow_style=False)
            
            return True
            
        except Exception as e:
            print(f"Error saving config: {e}")
            return False
    
    def validate_config(self) -> ValidationResult:
        """Validate current configuration"""
        result = ValidationResult(valid=True)
        
        # Validate interface
        if not self.pipeline_config.ingress_interface:
            result.add_error("Ingress interface name cannot be empty")
        
        if not self.pipeline_config.egress_interface:
            result.add_error("Egress interface name cannot be empty")
        
        # Validate source directory
        src_path = Path(self.pipeline_config.src_directory)
        if not src_path.exists():
            result.add_error(f"Source directory does not exist: {src_path}")
        
        # Validate BPF program
        bpf_path = src_path / self.pipeline_config.program_path
        if not bpf_path.exists():
            result.add_error(f"BPF program not found: {bpf_path}")
        
        # Validate allowlist file
        allowlist_path = src_path / self.pipeline_config.allowlist_file
        if not allowlist_path.exists():
            result.add_warning(f"Allowlist file not found: {allowlist_path}")
        
        # Validate max entries
        if self.pipeline_config.max_entries <= 0:
            result.add_error("Max entries must be positive")
        elif self.pipeline_config.max_entries > 100000:
            result.add_warning("Max entries is very large, may impact performance")
        
        # Validate log level
        valid_levels = ['debug', 'info', 'warning', 'error', 'critical']
        if self.pipeline_config.log_level not in valid_levels:
            result.add_error(f"Invalid log level. Must be one of: {valid_levels}")
        
        # Validate compiler optimization
        valid_opts = ['O0', 'O1', 'O2', 'O3', 'Os']
        if self.compiler_config.optimization_level not in valid_opts:
            result.add_error(f"Invalid optimization level. Must be one of: {valid_opts}")
        
        # Validate monitoring ports
        if not (1024 <= self.monitoring_config.prometheus_port <= 65535):
            result.add_error("Prometheus port must be between 1024 and 65535")
        
        return result
    
    def get_src_path(self) -> Path:
        """Get source directory path"""
        return Path(self.pipeline_config.src_directory)
    
    def get_bpf_path(self) -> Path:
        """Get BPF program path"""
        return self.get_src_path() / self.pipeline_config.program_path
    
    def get_allowlist_path(self) -> Path:
        """Get allowlist file path"""
        return self.get_src_path() / self.pipeline_config.allowlist_file
    
    def get_log_path(self) -> Path:
        """Get log file path"""
        return Path(self.monitoring_config.log_file)
    
    def update_interface(self, interface: str) -> bool:
        """Update interface configuration"""
        self.pipeline_config.ingress_interface = interface
        return self.save_config()
    
    def enable_debug(self) -> bool:
        """Enable debug mode"""
        self.pipeline_config.log_level = "debug"
        self.compiler_config.debug_info = True
        return self.save_config()
    
    def enable_performance_mode(self) -> bool:
        """Enable performance optimizations"""
        self.pipeline_config.performance_mode = True
        self.compiler_config.optimization_level = "O3"
        return self.save_config()
    
    def get_compiler_flags(self) -> List[str]:
        """Get compiler flags based on configuration"""
        flags = []
        
        # Optimization
        flags.append(f"-{self.compiler_config.optimization_level}")
        
        # Debug info
        if self.compiler_config.debug_info:
            flags.extend(["-g", "-DDEBUG"])
        
        # Warnings
        if self.compiler_config.warnings_as_errors:
            flags.append("-Werror")
        
        # Performance mode
        if self.pipeline_config.performance_mode:
            flags.extend(["-DPERFORMANCE_MODE", "-march=native"])
        
        # Additional flags
        flags.extend(self.compiler_config.additional_flags)
        
        return flags
    
    def export_config(self) -> Dict[str, Any]:
        """Export configuration as dictionary"""
        return {
            'pipeline': asdict(self.pipeline_config),
            'compiler': asdict(self.compiler_config), 
            'monitoring': asdict(self.monitoring_config)
        }
    
    def import_config(self, config_data: Dict[str, Any]) -> bool:
        """Import configuration from dictionary"""
        try:
            if 'pipeline' in config_data:
                for key, value in config_data['pipeline'].items():
                    if hasattr(self.pipeline_config, key):
                        setattr(self.pipeline_config, key, value)
            
            if 'compiler' in config_data:
                for key, value in config_data['compiler'].items():
                    if hasattr(self.compiler_config, key):
                        setattr(self.compiler_config, key, value)
                        
            if 'monitoring' in config_data:
                for key, value in config_data['monitoring'].items():
                    if hasattr(self.monitoring_config, key):
                        setattr(self.monitoring_config, key, value)
            
            return self.save_config()
            
        except Exception as e:
            print(f"Error importing config: {e}")
            return False