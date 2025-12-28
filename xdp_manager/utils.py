"""
Common utilities and helper functions
"""

import subprocess
import sys
import os
import time
import logging
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime
from .models import LogLevel

class Logger:
    """Enhanced logging with multiple outputs"""
    
    def __init__(self, name: str = "xdp_manager", level: LogLevel = LogLevel.INFO):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, level.value.upper()))
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
        
    def debug(self, message: str, **kwargs):
        self.logger.debug(message, **kwargs)
        
    def info(self, message: str, **kwargs):
        self.logger.info(message, **kwargs)
        
    def warning(self, message: str, **kwargs):
        self.logger.warning(message, **kwargs)
        
    def error(self, message: str, **kwargs):
        self.logger.error(message, **kwargs)
        
    def critical(self, message: str, **kwargs):
        self.logger.critical(message, **kwargs)
        
    def add_file_handler(self, log_file: str):
        """Add file logging handler"""
        file_handler = logging.FileHandler(log_file)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
        )
        file_handler.setFormatter(file_formatter)
        self.logger.addHandler(file_handler)

class CommandRunner:
    """Execute shell commands with enhanced error handling"""
    
    def __init__(self, logger: Optional[Logger] = None):
        self.logger = logger or Logger("command_runner")
        
    def run(self, 
           cmd: List[str], 
           check: bool = True,
           capture: bool = True,
           timeout: Optional[int] = None,
           cwd: Optional[str] = None,
           env: Optional[Dict[str, str]] = None) -> subprocess.CompletedProcess:
        """Execute command with comprehensive error handling"""
        
        self.logger.debug(f"Executing command: {' '.join(cmd)}")
        start_time = time.time()
        
        try:
            # Prepare environment
            cmd_env = os.environ.copy()
            if env:
                cmd_env.update(env)
                
            result = subprocess.run(
                cmd,
                capture_output=capture,
                text=True,
                check=check,
                timeout=timeout,
                cwd=cwd,
                env=cmd_env
            )
            
            duration = time.time() - start_time
            self.logger.debug(f"Command completed in {duration:.2f}s")
            
            return result
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Command failed: {' '.join(cmd)}")
            self.logger.error(f"Return code: {e.returncode}")
            if e.stderr:
                self.logger.error(f"Error output: {e.stderr}")
            raise
            
        except subprocess.TimeoutExpired as e:
            self.logger.error(f"Command timed out after {timeout}s: {' '.join(cmd)}")
            raise
            
        except Exception as e:
            self.logger.error(f"Unexpected error executing command: {e}")
            raise
    
    def run_silent(self, cmd: List[str], **kwargs) -> bool:
        """Run command and return success/failure boolean"""
        try:
            self.run(cmd, check=True, capture=True, **kwargs)
            return True
        except subprocess.CalledProcessError:
            return False
        except Exception as e:
            self.logger.debug(f"Silent command failed: {e}")
            return False
    
    def get_output(self, cmd: List[str], **kwargs) -> Optional[str]:
        """Get command output, return None on failure"""
        try:
            result = self.run(cmd, check=True, capture=True, **kwargs)
            return result.stdout.strip()
        except:
            return None

class SystemInfo:
    """System information gathering"""
    
    def __init__(self, runner: Optional[CommandRunner] = None):
        self.runner = runner or CommandRunner()
        
    def get_kernel_version(self) -> str:
        """Get kernel version"""
        version = self.runner.get_output(['uname', '-r'])
        return version or "unknown"
    
    def is_bpf_jit_enabled(self) -> bool:
        """Check if BPF JIT is enabled"""
        try:
            with open('/proc/sys/net/core/bpf_jit_enable') as f:
                return f.read().strip() == '1'
        except:
            return False
    
    def get_cpu_count(self) -> int:
        """Get CPU core count"""
        try:
            return os.cpu_count() or 1
        except:
            return 1
    
    def get_memory_mb(self) -> int:
        """Get total system memory in MB"""
        try:
            with open('/proc/meminfo') as f:
                for line in f:
                    if line.startswith('MemTotal:'):
                        kb = int(line.split()[1])
                        return kb // 1024
        except:
            pass
        return 0
    
    def get_network_interfaces(self) -> List[str]:
        """Get list of network interfaces"""
        interfaces = []
        try:
            output = self.runner.get_output(['ip', 'link', 'show'])
            if output:
                for line in output.split('\n'):
                    if ': ' in line and 'state' in line.lower():
                        interface = line.split(': ')[1].split('@')[0]
                        if interface != 'lo':  # Skip loopback
                            interfaces.append(interface)
        except:
            # Fallback to /sys/class/net
            try:
                net_path = Path('/sys/class/net')
                if net_path.exists():
                    for iface_path in net_path.iterdir():
                        if iface_path.name != 'lo':
                            interfaces.append(iface_path.name)
            except:
                pass
        
        return interfaces
    
    def check_required_tools(self) -> Dict[str, bool]:
        """Check if required tools are available"""
        tools = {
            'bpftool': self.runner.run_silent(['which', 'bpftool']),
            'clang': self.runner.run_silent(['which', 'clang']),
            'llc': self.runner.run_silent(['which', 'llc']),
            'ip': self.runner.run_silent(['which', 'ip']),
            'make': self.runner.run_silent(['which', 'make']),
        }
        return tools
    
    def get_bpf_capabilities(self) -> Dict[str, Any]:
        """Get BPF system capabilities"""
        caps = {
            'jit_enabled': self.is_bpf_jit_enabled(),
            'kernel_version': self.get_kernel_version(),
            'tools_available': self.check_required_tools()
        }
        
        # Check BPF program types support
        try:
            result = self.runner.run(['sudo', 'bpftool', 'feature'], capture=True, check=False)
            if result.returncode == 0:
                caps['features'] = result.stdout
        except:
            caps['features'] = "unavailable"
        
        return caps

class FileOperations:
    """Safe file operations with backup and validation"""
    
    def __init__(self, logger: Optional[Logger] = None):
        self.logger = logger or Logger("file_ops")
        
    def backup_file(self, file_path: Path) -> Optional[Path]:
        """Create backup of file with timestamp"""
        if not file_path.exists():
            return None
            
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = file_path.with_suffix(f"{file_path.suffix}.backup_{timestamp}")
            
            import shutil
            shutil.copy2(file_path, backup_path)
            
            self.logger.debug(f"Created backup: {backup_path}")
            return backup_path
            
        except Exception as e:
            self.logger.error(f"Failed to create backup: {e}")
            return None
    
    def safe_write(self, file_path: Path, content: str, create_backup: bool = True) -> bool:
        """Safely write content to file with optional backup"""
        try:
            # Create backup if requested and file exists
            if create_backup and file_path.exists():
                self.backup_file(file_path)
            
            # Create parent directories if needed
            file_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Write to temporary file first
            temp_path = file_path.with_suffix(f"{file_path.suffix}.tmp")
            with open(temp_path, 'w') as f:
                f.write(content)
            
            # Atomic move to final location
            temp_path.replace(file_path)
            
            self.logger.debug(f"Successfully wrote to: {file_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to write file {file_path}: {e}")
            return False
    
    def validate_json(self, file_path: Path) -> Tuple[bool, Optional[str]]:
        """Validate JSON file format"""
        try:
            import json
            with open(file_path) as f:
                json.load(f)
            return True, None
        except json.JSONDecodeError as e:
            return False, str(e)
        except Exception as e:
            return False, str(e)

class PerformanceMonitor:
    """Simple performance monitoring"""
    
    def __init__(self):
        self.start_time = None
        self.measurements = {}
    
    def start_timer(self, name: str = "default"):
        """Start timing measurement"""
        self.measurements[name] = time.time()
    
    def end_timer(self, name: str = "default") -> float:
        """End timing measurement and return duration"""
        if name not in self.measurements:
            return 0.0
        
        duration = time.time() - self.measurements[name]
        del self.measurements[name]
        return duration
    
    def measure(self, name: str = "default"):
        """Context manager for timing measurements"""
        return TimerContext(self, name)

class TimerContext:
    """Context manager for performance measurements"""
    
    def __init__(self, monitor: PerformanceMonitor, name: str):
        self.monitor = monitor
        self.name = name
    
    def __enter__(self):
        self.monitor.start_timer(self.name)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        return self.monitor.end_timer(self.name)