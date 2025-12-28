"""
Professional logging system with structured output, rotation, and advanced features
Provides enterprise-grade logging capabilities for production XDP pipeline management
"""

import os
import sys
import json
import logging
import logging.handlers
from typing import Dict, Any, Optional, List, Union
from pathlib import Path
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
import traceback
import threading
from contextlib import contextmanager

class LogLevel(Enum):
    """Logging levels"""
    DEBUG = logging.DEBUG
    INFO = logging.INFO
    WARNING = logging.WARNING
    ERROR = logging.ERROR
    CRITICAL = logging.CRITICAL

class LogFormat(Enum):
    """Log output formats"""
    STANDARD = "standard"
    STRUCTURED = "structured" 
    JSON = "json"
    DETAILED = "detailed"

@dataclass
class LogEntry:
    """Structured log entry"""
    timestamp: str
    level: str
    logger_name: str
    message: str
    module: Optional[str] = None
    function: Optional[str] = None
    line_number: Optional[int] = None
    thread_id: Optional[int] = None
    process_id: Optional[int] = None
    extra_data: Optional[Dict[str, Any]] = None
    stack_trace: Optional[str] = None

class ColoredFormatter(logging.Formatter):
    """Colored console formatter"""
    
    # ANSI color codes
    COLORS = {
        'DEBUG': '\033[36m',     # Cyan
        'INFO': '\033[32m',      # Green
        'WARNING': '\033[33m',   # Yellow
        'ERROR': '\033[31m',     # Red
        'CRITICAL': '\033[35m',  # Magenta
    }
    RESET = '\033[0m'
    
    def format(self, record):
        # Add color to levelname
        if record.levelname in self.COLORS:
            record.levelname = f"{self.COLORS[record.levelname]}{record.levelname}{self.RESET}"
        
        return super().format(record)

class StructuredFormatter(logging.Formatter):
    """Structured JSON formatter"""
    
    def format(self, record):
        log_entry = LogEntry(
            timestamp=datetime.fromtimestamp(record.created).isoformat(),
            level=record.levelname,
            logger_name=record.name,
            message=record.getMessage(),
            module=getattr(record, 'module', record.module if hasattr(record, 'module') else None),
            function=getattr(record, 'funcName', None),
            line_number=getattr(record, 'lineno', None),
            thread_id=getattr(record, 'thread', None),
            process_id=getattr(record, 'process', None),
            extra_data=getattr(record, 'extra_data', None),
            stack_trace=self.formatException(record.exc_info) if record.exc_info else None
        )
        
        return json.dumps(asdict(log_entry), default=str, ensure_ascii=False)

class ProfessionalLogger:
    """Professional logging system with advanced features"""
    
    def __init__(self, name: str = "xdp_manager", config: Optional[Dict[str, Any]] = None):
        self.name = name
        self.config = config or self._get_default_config()
        self._loggers: Dict[str, logging.Logger] = {}
        self._handlers: List[logging.Handler] = []
        self._setup_logging()
        
        # Performance metrics
        self._log_counts = {"DEBUG": 0, "INFO": 0, "WARNING": 0, "ERROR": 0, "CRITICAL": 0}
        self._session_start = datetime.now()
        
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default logging configuration"""
        return {
            "level": "INFO",
            "format": LogFormat.STANDARD,
            "console": {
                "enabled": True,
                "colors": True,
                "level": "INFO"
            },
            "file": {
                "enabled": False,
                "path": "",
                "level": "INFO",
                "rotation": {
                    "max_size_mb": 100,
                    "backup_count": 5,
                    "rotate_on_startup": False
                }
            },
            "structured": {
                "enabled": False,
                "include_extra": True,
                "include_stack_trace": True
            },
            "filters": {
                "exclude_modules": [],
                "min_level_per_module": {}
            }
        }
    
    def _setup_logging(self):
        """Setup logging configuration"""
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(getattr(logging, self.config["level"].upper()))
        
        # Clear existing handlers
        root_logger.handlers = []
        
        # Setup console handler
        if self.config["console"]["enabled"]:
            self._setup_console_handler()
        
        # Setup file handler  
        if self.config["file"]["enabled"] and self.config["file"]["path"]:
            self._setup_file_handler()
        
        # Setup main logger
        self.logger = self.get_logger(self.name)
        
    def _setup_console_handler(self):
        """Setup console logging handler"""
        console_handler = logging.StreamHandler(sys.stdout)
        console_level = getattr(logging, self.config["console"]["level"].upper())
        console_handler.setLevel(console_level)
        
        # Choose formatter based on configuration
        if self.config.get("structured", {}).get("enabled"):
            formatter = StructuredFormatter()
        else:
            format_string = self._get_format_string()
            if self.config["console"].get("colors", True):
                formatter = ColoredFormatter(format_string)
            else:
                formatter = logging.Formatter(format_string)
        
        console_handler.setFormatter(formatter)
        self._handlers.append(console_handler)
        
        # Add to root logger
        logging.getLogger().addHandler(console_handler)
    
    def _setup_file_handler(self):
        """Setup file logging handler with rotation"""
        log_file = Path(self.config["file"]["path"])
        log_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Setup rotating file handler
        max_size = self.config["file"]["rotation"]["max_size_mb"] * 1024 * 1024
        backup_count = self.config["file"]["rotation"]["backup_count"]
        
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, 
            maxBytes=max_size,
            backupCount=backup_count
        )
        
        file_level = getattr(logging, self.config["file"]["level"].upper())
        file_handler.setLevel(file_level)
        
        # Use structured format for file logging
        if self.config.get("structured", {}).get("enabled"):
            formatter = StructuredFormatter()
        else:
            formatter = logging.Formatter(self._get_format_string(detailed=True))
        
        file_handler.setFormatter(formatter)
        self._handlers.append(file_handler)
        
        # Add to root logger
        logging.getLogger().addHandler(file_handler)
        
        # Rotate on startup if configured
        if self.config["file"]["rotation"].get("rotate_on_startup"):
            file_handler.doRollover()
    
    def _get_format_string(self, detailed: bool = False) -> str:
        """Get format string based on configuration"""
        
        if detailed:
            return (
                "%(asctime)s | %(levelname)-8s | %(name)s | "
                "%(module)s:%(funcName)s:%(lineno)d | "
                "PID:%(process)d TID:%(thread)d | %(message)s"
            )
        else:
            return "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    
    def get_logger(self, name: Optional[str] = None) -> logging.Logger:
        """Get or create logger instance"""
        logger_name = name or self.name
        
        if logger_name not in self._loggers:
            logger = logging.getLogger(logger_name)
            
            # Apply filters
            self._apply_logger_filters(logger)
            
            self._loggers[logger_name] = logger
        
        return self._loggers[logger_name]
    
    def _apply_logger_filters(self, logger: logging.Logger):
        """Apply configured filters to logger"""
        
        exclude_modules = self.config.get("filters", {}).get("exclude_modules", [])
        if logger.name in exclude_modules:
            logger.disabled = True
            return
        
        # Apply per-module level filters
        min_levels = self.config.get("filters", {}).get("min_level_per_module", {})
        if logger.name in min_levels:
            min_level = getattr(logging, min_levels[logger.name].upper())
            logger.setLevel(min_level)
    
    @contextmanager
    def performance_context(self, operation_name: str, **kwargs):
        """Context manager for performance logging"""
        start_time = datetime.now()
        logger = self.get_logger(f"{self.name}.performance")
        
        try:
            logger.info(f"Starting operation: {operation_name}", extra={
                "operation": operation_name,
                "start_time": start_time.isoformat(),
                **kwargs
            })
            yield
            
        except Exception as e:
            duration = (datetime.now() - start_time).total_seconds()
            logger.error(f"Operation failed: {operation_name} (duration: {duration:.3f}s)", extra={
                "operation": operation_name,
                "duration_seconds": duration,
                "error": str(e),
                "error_type": type(e).__name__,
                **kwargs
            })
            raise
            
        else:
            duration = (datetime.now() - start_time).total_seconds()
            logger.info(f"Operation completed: {operation_name} (duration: {duration:.3f}s)", extra={
                "operation": operation_name,
                "duration_seconds": duration,
                "success": True,
                **kwargs
            })
    
    def log_system_info(self):
        """Log system information for debugging"""
        import platform
        import psutil
        
        system_logger = self.get_logger(f"{self.name}.system")
        
        system_info = {
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "cpu_count": psutil.cpu_count(),
            "memory_total_gb": round(psutil.virtual_memory().total / (1024**3), 2),
            "disk_usage": {
                "total_gb": round(psutil.disk_usage('/').total / (1024**3), 2),
                "free_gb": round(psutil.disk_usage('/').free / (1024**3), 2)
            }
        }
        
        system_logger.info("System information", extra={"system_info": system_info})
    
    def log_network_interfaces(self):
        """Log available network interfaces"""
        try:
            import subprocess
            result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
            
            network_logger = self.get_logger(f"{self.name}.network")
            network_logger.debug("Network interfaces", extra={
                "interfaces_output": result.stdout,
                "command_exitcode": result.returncode
            })
            
        except Exception as e:
            self.get_logger().warning(f"Could not log network interfaces: {e}")
    
    def log_bpf_environment(self):
        """Log BPF environment information"""
        bpf_logger = self.get_logger(f"{self.name}.bpf")
        
        try:
            import subprocess
            
            # Check bpftool availability
            result = subprocess.run(['which', 'bpftool'], capture_output=True, text=True)
            bpftool_available = result.returncode == 0
            
            # Check kernel version
            result = subprocess.run(['uname', '-r'], capture_output=True, text=True)
            kernel_version = result.stdout.strip() if result.returncode == 0 else "unknown"
            
            bpf_info = {
                "bpftool_available": bpftool_available,
                "bpftool_path": result.stdout.strip() if bpftool_available else None,
                "kernel_version": kernel_version
            }
            
            bpf_logger.info("BPF environment information", extra={"bpf_info": bpf_info})
            
        except Exception as e:
            bpf_logger.warning(f"Could not log BPF environment: {e}")
    
    def get_session_statistics(self) -> Dict[str, Any]:
        """Get logging session statistics"""
        session_duration = datetime.now() - self._session_start
        
        return {
            "session_start": self._session_start.isoformat(),
            "session_duration_seconds": session_duration.total_seconds(),
            "log_counts": self._log_counts.copy(),
            "total_logs": sum(self._log_counts.values()),
            "loggers_created": len(self._loggers),
            "handlers_active": len(self._handlers)
        }
    
    def dump_configuration(self) -> Dict[str, Any]:
        """Dump current logging configuration"""
        return {
            "config": self.config,
            "loggers": list(self._loggers.keys()),
            "handlers": [
                {
                    "type": type(handler).__name__,
                    "level": handler.level,
                    "formatter": type(handler.formatter).__name__ if handler.formatter else None
                }
                for handler in self._handlers
            ],
            "root_level": logging.getLogger().level,
            "statistics": self.get_session_statistics()
        }
    
    def reconfigure(self, new_config: Dict[str, Any]):
        """Reconfigure logging with new settings"""
        self.config.update(new_config)
        
        # Remove existing handlers
        root_logger = logging.getLogger()
        for handler in self._handlers:
            root_logger.removeHandler(handler)
            handler.close()
        
        self._handlers.clear()
        
        # Setup with new configuration
        self._setup_logging()
        
        self.logger.info("Logging reconfigured", extra={"new_config": new_config})
    
    def emergency_log(self, message: str, data: Optional[Dict[str, Any]] = None):
        """Emergency logging that bypasses normal configuration"""
        
        timestamp = datetime.now().isoformat()
        emergency_entry = {
            "timestamp": timestamp,
            "level": "EMERGENCY",
            "message": message,
            "data": data,
            "stack_trace": traceback.format_stack()
        }
        
        # Try multiple output methods
        try:
            # Console output
            print(f"EMERGENCY | {timestamp} | {message}", file=sys.stderr)
            
            # File output (if configured)
            if self.config["file"]["enabled"] and self.config["file"]["path"]:
                try:
                    with open(self.config["file"]["path"], 'a') as f:
                        f.write(f"\nEMERGENCY | {timestamp} | {message}\n")
                        if data:
                            f.write(f"Data: {json.dumps(data, default=str, indent=2)}\n")
                except Exception:
                    pass
                    
        except Exception:
            # Ultimate fallback - write to /tmp
            try:
                emergency_file = f"/tmp/xdp_manager_emergency_{os.getpid()}.log"
                with open(emergency_file, 'a') as f:
                    f.write(f"{timestamp} | {message}\n")
                    if data:
                        f.write(f"Data: {json.dumps(data, default=str)}\n")
            except Exception:
                pass  # If we can't even write to /tmp, we're in serious trouble

# Global logger instance
_global_logger: Optional[ProfessionalLogger] = None

def get_global_logger() -> ProfessionalLogger:
    """Get global logger instance"""
    global _global_logger
    if _global_logger is None:
        _global_logger = ProfessionalLogger()
    return _global_logger

def initialize_logging(config: Optional[Dict[str, Any]] = None) -> ProfessionalLogger:
    """Initialize global logging with configuration"""
    global _global_logger
    _global_logger = ProfessionalLogger("xdp_manager", config)
    return _global_logger