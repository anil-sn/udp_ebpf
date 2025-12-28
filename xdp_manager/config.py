"""
Configuration management for XDP pipeline with professional validation and templating
Provides comprehensive configuration handling, validation, and environment management
"""

import os
import json
import yaml
from typing import Dict, List, Any, Optional, Tuple, Union
from pathlib import Path
from dataclasses import dataclass, field, asdict
from enum import Enum
import re
from .models import ValidationResult
from .utils import Logger

@dataclass
class PipelineConfig:
    """Main pipeline configuration - matches working solution defaults exactly"""
    ingress_interface: str = "ens5"  # VXLAN ingress interface where XDP attaches  
    egress_interface: str = "ens6"   # Packet egress interface for processed packets
    target_interface: str = "ens6"   # Target interface for forwarding (matches working solution)
    src_directory: str = "src"
    program_path: str = "vxlan_pipeline.bpf.c"  # BPF program file path
    mode: str = "xdp"  # XDP attachment mode: xdp, xdpgeneric, xdpdrv, xdpoffload
    allowlist_file: str = "ip_allowlist.json"
    max_entries: int = 10000
    log_level: str = "info"
    auto_reload: bool = False
    performance_mode: bool = True
    apply_system_tuning: bool = True  # Apply system tuning by default
    
    # NAT configuration (from working solution - exact defaults)
    nat_target_ip: str = "172.30.82.95"    # Working solution default
    nat_target_port: int = 8081             # Working solution default
    source_port: int = 31765                # Working solution default (nat_source_port)
    statistics_interval: int = 5            # Working solution default

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
    alert_thresholds: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if not self.alert_thresholds:
            self.alert_thresholds = {
                'min_pps': 50000,
                'max_error_rate': 5.0,
                'max_cpu_usage': 90.0,
                'max_memory_usage': 85.0
            }

class ConfigFormat(Enum):
    """Supported configuration formats"""
    YAML = "yaml"
    JSON = "json"
    ENV = "env"

@dataclass
class ConfigValidationRule:
    """Configuration validation rule"""
    field_path: str
    rule_type: str  # required, range, regex, custom
    parameters: Dict[str, Any] = field(default_factory=dict)
    error_message: str = ""

class ProfessionalConfigManager:
    """Professional configuration management with advanced features"""
    
    def __init__(self, logger: Optional[Logger] = None):
        self.logger = logger or Logger("config_manager")
        self.config_cache: Dict[str, Any] = {}
        self.validation_rules: List[ConfigValidationRule] = []
        self.config_watchers: Dict[str, callable] = {}
        
        # Initialize default validation rules
        self._setup_default_validation_rules()
    
    def load_config_with_validation(self, config_path: Optional[str] = None, 
                                  config_format: ConfigFormat = ConfigFormat.YAML) -> Tuple[Dict[str, Any], ValidationResult]:
        """Load configuration with comprehensive validation"""
        
        # Determine config file path
        if not config_path:
            config_path = self._find_default_config(config_format)
        
        if not config_path or not Path(config_path).exists():
            return {}, ValidationResult(
                valid=False,
                errors=[f"Configuration file not found: {config_path}"],
                warnings=[]
            )
        
        # Load configuration
        try:
            config_data = self._load_config_file(config_path, config_format)
        except Exception as e:
            return {}, ValidationResult(
                valid=False,
                errors=[f"Failed to load configuration: {e}"],
                warnings=[]
            )
        
        # Validate configuration
        validation_result = self.validate_config_comprehensive(config_data)
        
        # Apply environment variable overrides
        config_data = self._apply_env_overrides(config_data)
        
        # Cache configuration
        self.config_cache[config_path] = config_data
        
        self.logger.info(f"Configuration loaded from {config_path}")
        return config_data, validation_result
    
    def validate_config_comprehensive(self, config: Dict[str, Any]) -> ValidationResult:
        """Comprehensive configuration validation"""
        errors = []
        warnings = []
        
        # Apply validation rules
        for rule in self.validation_rules:
            try:
                field_value = self._get_nested_value(config, rule.field_path)
                rule_result = self._apply_validation_rule(field_value, rule)
                
                if not rule_result[0]:  # Validation failed
                    if rule.rule_type == "required":
                        errors.append(rule_result[1])
                    else:
                        warnings.append(rule_result[1])
                        
            except KeyError:
                if rule.rule_type == "required":
                    errors.append(f"Required field missing: {rule.field_path}")
        
        # Custom validation checks
        custom_errors, custom_warnings = self._custom_validation_checks(config)
        errors.extend(custom_errors)
        warnings.extend(custom_warnings)
        
        return ValidationResult(
            valid=len(errors) == 0,
            errors=errors,
            warnings=warnings
        )
    
    def generate_config_template(self, output_path: str, 
                                config_format: ConfigFormat = ConfigFormat.YAML,
                                include_examples: bool = True) -> bool:
        """Generate configuration template with documentation"""
        
        template_data = {
            "# XDP Manager Professional Configuration": None,
            "# Generated template with comprehensive options": None,
            "": None,
            "pipeline": {
                "# Network interface configuration": None,
                "ingress_interface": "ens5",  # "Interface where XDP attaches for VXLAN processing",
                "egress_interface": "ens6",   # "Interface for processed packet output",
                "": None,
                "# BPF program configuration": None,
                "program_path": "vxlan_pipeline.bpf.c",  # "Path to BPF program source",
                "mode": "xdp",  # "XDP attachment mode: xdp, xdpgeneric, xdpdrv, xdpoffload",
                "": None,
                "# Performance and system configuration": None,
                "apply_system_tuning": True,  # "Apply system performance tuning automatically",
                "performance_mode": True,     # "Enable high-performance optimizations",
                "": None,
                "# NAT configuration for packet processing": None,
                "nat_target_ip": "172.30.82.95",   # "Target IP for NAT translation",
                "nat_target_port": 8081,           # "Target port for NAT translation", 
                "source_port": 31765,              # "Source port matching (inner destination port)",
                "statistics_interval": 5           # "Statistics collection interval (seconds)"
            },
            "": None,
            "network": {
                "# Advanced network configuration": None,
                "connectivity_test_hosts": ["8.8.8.8", "1.1.1.1"],  # "Hosts for connectivity testing",
                "interface_optimization": {
                    "mtu_size": 3000,              # "Optimal MTU size for XDP",
                    "queue_count": 8,              # "Target number of network queues",
                    "ring_buffer_size": 4096       # "Network ring buffer size"
                },
                "": None,
                "arp_resolution": {
                    "enable_preload": True,        # "Pre-populate ARP table for performance",
                    "timeout_seconds": 10,         # "ARP resolution timeout",
                    "retry_count": 3               # "Number of ARP resolution retries"
                }
            },
            "": None,
            "performance": {
                "# Performance monitoring and thresholds": None,
                "target_pps": 85000,               # "Target packets per second",
                "threshold_pps": 60000,            # "Performance threshold for alerts",
                "stats_interval": 5,               # "Statistics collection interval",
                "": None,
                "monitoring": {
                    "enable_continuous": False,     # "Enable continuous performance monitoring",
                    "alert_thresholds": {
                        "min_pps": 50000,          # "Minimum PPS before alert",
                        "max_error_rate": 5.0,     # "Maximum error rate percentage",
                        "max_cpu_usage": 90.0,     # "Maximum CPU usage percentage",
                        "max_memory_usage": 85.0   # "Maximum memory usage percentage"
                    }
                }
            },
            "": None,
            "system": {
                "# System tuning configuration": None,
                "tuning": {
                    "network_buffers": {
                        "rmem_max": 134217728,      # "Maximum receive buffer size (128MB)",
                        "wmem_max": 134217728,      # "Maximum send buffer size (128MB)",
                        "netdev_budget": 600        # "Network device processing budget"
                    },
                    "cpu_optimization": {
                        "governor": "performance",   # "CPU frequency governor",
                        "irq_affinity": True,       # "Optimize IRQ affinity",
                        "disable_irqbalance": True  # "Disable irqbalance for manual tuning"
                    }
                },
                "": None,
                "validation": {
                    "min_kernel_version": "4.18",   # "Minimum kernel version for XDP support",
                    "required_tools": ["bpftool", "ethtool", "ip"],  # "Required system tools",
                    "min_memory_gb": 4              # "Minimum recommended memory (GB)"
                }
            },
            "": None,
            "logging": {
                "# Logging configuration": None,
                "level": "INFO",                    # "Log level: DEBUG, INFO, WARNING, ERROR",
                "file": "",                         # "Log file path (empty for console only)",
                "colors": True,                     # "Enable colored output",
                "structured": False,                # "Enable structured JSON logging",
                "": None,
                "rotation": {
                    "max_size_mb": 100,            # "Maximum log file size before rotation",
                    "backup_count": 5,             # "Number of backup log files to keep",
                    "rotate_on_startup": False     # "Rotate logs on application startup"
                }
            },
            "": None,
            "paths": {
                "# File and directory paths": None,
                "allowlist_file": "xdp_manager/config/ip_allowlist.json",
                "allowlist_prod_file": "xdp_manager/config/ip_allowlist_prod.json", 
                "bpf_programs_dir": "src",
                "temp_dir": "/tmp",
                "log_dir": "/var/log"
            }
        }
        
        try:
            if config_format == ConfigFormat.YAML:
                self._write_yaml_template(template_data, output_path)
            elif config_format == ConfigFormat.JSON:
                self._write_json_template(template_data, output_path)
            else:
                raise ValueError(f"Unsupported format for template: {config_format}")
            
            self.logger.info(f"Configuration template generated: {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to generate config template: {e}")
            return False
    
    def update_config_value(self, config_path: str, key_path: str, value: Any) -> bool:
        """Update configuration value with validation"""
        
        try:
            # Load current config
            if Path(config_path).suffix.lower() in ['.yml', '.yaml']:
                config_format = ConfigFormat.YAML
            else:
                config_format = ConfigFormat.JSON
            
            config_data = self._load_config_file(config_path, config_format)
            
            # Update value
            self._set_nested_value(config_data, key_path, value)
            
            # Validate updated config
            validation_result = self.validate_config_comprehensive(config_data)
            if not validation_result.valid:
                self.logger.error("Updated configuration is invalid:")
                for error in validation_result.errors:
                    self.logger.error(f"  - {error}")
                return False
            
            # Save updated config
            self._save_config_file(config_data, config_path, config_format)
            
            # Update cache
            self.config_cache[config_path] = config_data
            
            self.logger.info(f"Configuration updated: {key_path} = {value}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to update configuration: {e}")
            return False
    
    def backup_config(self, config_path: str) -> Optional[str]:
        """Create backup of configuration file"""
        try:
            import shutil
            from datetime import datetime
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = f"{config_path}.backup_{timestamp}"
            
            shutil.copy2(config_path, backup_path)
            self.logger.info(f"Configuration backup created: {backup_path}")
            
            return backup_path
            
        except Exception as e:
            self.logger.error(f"Failed to create config backup: {e}")
            return None
    
    def _setup_default_validation_rules(self):
        """Setup default validation rules"""
        self.validation_rules = [
            # Required fields
            ConfigValidationRule(
                "pipeline.ingress_interface",
                "required",
                error_message="Ingress interface is required"
            ),
            ConfigValidationRule(
                "pipeline.egress_interface", 
                "required",
                error_message="Egress interface is required"
            ),
            ConfigValidationRule(
                "pipeline.nat_target_ip",
                "required",
                error_message="NAT target IP is required"
            ),
            
            # Range validations
            ConfigValidationRule(
                "pipeline.nat_target_port",
                "range",
                {"min": 1, "max": 65535},
                "NAT target port must be between 1 and 65535"
            ),
            ConfigValidationRule(
                "pipeline.source_port",
                "range", 
                {"min": 1, "max": 65535},
                "Source port must be between 1 and 65535"
            ),
            ConfigValidationRule(
                "performance.target_pps",
                "range",
                {"min": 1000, "max": 1000000},
                "Target PPS must be between 1,000 and 1,000,000"
            ),
            
            # Format validations
            ConfigValidationRule(
                "pipeline.nat_target_ip",
                "regex",
                {"pattern": r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"},
                "NAT target IP must be a valid IPv4 address"
            ),
            
            # Custom validations would be handled in _custom_validation_checks
        ]
    
    def _find_default_config(self, config_format: ConfigFormat) -> Optional[str]:
        """Find default configuration file"""
        possible_paths = []
        
        if config_format == ConfigFormat.YAML:
            possible_paths = ["config.yaml", "config.yml", "xdp-manager.yaml"]
        elif config_format == ConfigFormat.JSON:
            possible_paths = ["config.json", "xdp-manager.json"]
        elif config_format == ConfigFormat.ENV:
            possible_paths = [".env", "xdp-manager.env"]
        
        for path in possible_paths:
            if Path(path).exists():
                return path
        
        return None
    
    def _load_config_file(self, config_path: str, config_format: ConfigFormat) -> Dict[str, Any]:
        """Load configuration file based on format"""
        with open(config_path, 'r') as f:
            if config_format == ConfigFormat.YAML:
                return yaml.safe_load(f) or {}
            elif config_format == ConfigFormat.JSON:
                return json.load(f)
            else:
                raise ValueError(f"Unsupported config format: {config_format}")
    
    def _save_config_file(self, config_data: Dict[str, Any], config_path: str, 
                         config_format: ConfigFormat):
        """Save configuration file"""
        with open(config_path, 'w') as f:
            if config_format == ConfigFormat.YAML:
                yaml.dump(config_data, f, default_flow_style=False, indent=2)
            elif config_format == ConfigFormat.JSON:
                json.dump(config_data, f, indent=2)
    
    def _apply_env_overrides(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Apply environment variable overrides"""
        
        # Define environment variable mappings
        env_mappings = {
            "XDP_INGRESS_INTERFACE": "pipeline.ingress_interface",
            "XDP_EGRESS_INTERFACE": "pipeline.egress_interface",
            "XDP_NAT_TARGET_IP": "pipeline.nat_target_ip",
            "XDP_NAT_TARGET_PORT": "pipeline.nat_target_port",
            "XDP_SOURCE_PORT": "pipeline.source_port",
            "XDP_LOG_LEVEL": "logging.level",
            "XDP_PERFORMANCE_MODE": "pipeline.performance_mode"
        }
        
        for env_var, config_path in env_mappings.items():
            env_value = os.getenv(env_var)
            if env_value is not None:
                # Convert string values to appropriate types
                converted_value = self._convert_env_value(env_value, config_path)
                self._set_nested_value(config, config_path, converted_value)
                self.logger.debug(f"Applied environment override: {env_var} -> {config_path}")
        
        return config
    
    def _convert_env_value(self, value: str, config_path: str) -> Any:
        """Convert environment variable string to appropriate type"""
        
        # Boolean conversions
        if value.lower() in ['true', '1', 'yes', 'on']:
            return True
        elif value.lower() in ['false', '0', 'no', 'off']:
            return False
        
        # Numeric conversions for known numeric fields
        numeric_fields = ['nat_target_port', 'source_port', 'target_pps', 'threshold_pps']
        if any(field in config_path for field in numeric_fields):
            try:
                return int(value)
            except ValueError:
                return value
        
        return value
    
    def _get_nested_value(self, config: Dict[str, Any], key_path: str) -> Any:
        """Get nested configuration value using dot notation"""
        keys = key_path.split('.')
        value = config
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                raise KeyError(f"Key not found: {key_path}")
        
        return value
    
    def _set_nested_value(self, config: Dict[str, Any], key_path: str, value: Any):
        """Set nested configuration value using dot notation"""
        keys = key_path.split('.')
        current = config
        
        # Navigate to parent of target key
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        
        # Set the final value
        current[keys[-1]] = value
    
    def _apply_validation_rule(self, value: Any, rule: ConfigValidationRule) -> Tuple[bool, str]:
        """Apply single validation rule"""
        
        if rule.rule_type == "required":
            if value is None or (isinstance(value, str) and value.strip() == ""):
                return False, rule.error_message or f"Required field is empty: {rule.field_path}"
        
        elif rule.rule_type == "range":
            if not isinstance(value, (int, float)):
                return False, f"Field {rule.field_path} must be numeric for range validation"
            
            min_val = rule.parameters.get("min")
            max_val = rule.parameters.get("max")
            
            if min_val is not None and value < min_val:
                return False, f"{rule.field_path} must be >= {min_val}"
            if max_val is not None and value > max_val:
                return False, f"{rule.field_path} must be <= {max_val}"
        
        elif rule.rule_type == "regex":
            pattern = rule.parameters.get("pattern")
            if pattern and isinstance(value, str):
                if not re.match(pattern, value):
                    return False, rule.error_message or f"Field {rule.field_path} does not match required format"
        
        return True, ""
    
    def _custom_validation_checks(self, config: Dict[str, Any]) -> Tuple[List[str], List[str]]:
        """Custom validation checks beyond standard rules"""
        errors = []
        warnings = []
        
        # Check interface consistency
        try:
            ingress = self._get_nested_value(config, "pipeline.ingress_interface")
            egress = self._get_nested_value(config, "pipeline.egress_interface")
            
            if ingress == egress:
                warnings.append("Ingress and egress interfaces are the same - ensure this is intentional")
        except KeyError:
            pass  # Will be caught by required field validation
        
        # Check port conflicts
        try:
            nat_port = self._get_nested_value(config, "pipeline.nat_target_port")
            source_port = self._get_nested_value(config, "pipeline.source_port")
            
            if nat_port == source_port:
                warnings.append("NAT target port and source port are the same - may cause conflicts")
        except KeyError:
            pass
        
        # Check performance settings consistency
        try:
            target_pps = self._get_nested_value(config, "performance.target_pps")
            threshold_pps = self._get_nested_value(config, "performance.threshold_pps")
            
            if threshold_pps >= target_pps:
                warnings.append("Performance threshold is >= target PPS - alerts may trigger frequently")
        except KeyError:
            pass
        
        return errors, warnings
    
    def _write_yaml_template(self, template_data: Dict[str, Any], output_path: str):
        """Write YAML template with comments preserved"""
        
        def represent_none(self, data):
            return self.represent_scalar('tag:yaml.org,2002:null', '')
        
        yaml.add_representer(type(None), represent_none)
        
        # Convert template to YAML string
        yaml_str = yaml.dump(template_data, default_flow_style=False, 
                           allow_unicode=True, indent=2)
        
        # Clean up the output to make it more readable
        lines = yaml_str.split('\n')
        cleaned_lines = []
        
        for line in lines:
            # Skip empty mapping values
            if ": null" in line and line.strip().startswith("#"):
                cleaned_lines.append(line.replace(": null", ""))
            elif ": null" not in line:
                cleaned_lines.append(line)
        
        # Write to file
        with open(output_path, 'w') as f:
            f.write('\n'.join(cleaned_lines))
    
    def _write_json_template(self, template_data: Dict[str, Any], output_path: str):
        """Write JSON template (comments will be lost)"""
        # Remove comment entries for JSON
        cleaned_data = self._remove_comment_keys(template_data)
        
        with open(output_path, 'w') as f:
            json.dump(cleaned_data, f, indent=2)
    
    def _remove_comment_keys(self, data: Any) -> Any:
        """Remove comment keys (starting with #) from data structure"""
        if isinstance(data, dict):
            return {k: self._remove_comment_keys(v) 
                   for k, v in data.items() 
                   if not k.startswith('#') and k != ""}
        elif isinstance(data, list):
            return [self._remove_comment_keys(item) for item in data]
        else:
            return data

class ConfigManager:
    """Basic configuration manager for backward compatibility"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or "config.yaml"
        self.pipeline_config = PipelineConfig()
        self.compiler_config = CompilerConfig()
        self.monitoring_config = MonitoringConfig()
        
    def load_config(self, config_path: Optional[str] = None) -> bool:
        """Load configuration from YAML file"""
        if config_path:
            self.config_path = config_path
            
        config_file = Path(self.config_path)
        if not config_file.exists():
            # Use defaults if config file doesn't exist
            return True
            
        try:
            with open(config_file, 'r') as f:
                data = yaml.safe_load(f)
            
            # Load pipeline config
            if 'pipeline' in data:
                pipeline_data = data['pipeline']
                for key, value in pipeline_data.items():
                    if hasattr(self.pipeline_config, key):
                        setattr(self.pipeline_config, key, value)
            
            return True
            
        except Exception as e:
            print(f"Error loading config: {e}")
            return False
    
    def get_allowlist_path(self) -> Path:
        """Get allowlist file path"""
        return Path(self.pipeline_config.src_directory) / self.pipeline_config.allowlist_file
    
    def get_config(self):
        """Get the config manager instance"""
        return self