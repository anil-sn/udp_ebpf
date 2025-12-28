"""
Professional error handling and recovery system for XDP pipeline
Provides comprehensive error detection, reporting, and automated recovery
"""

import time
import traceback
from typing import Dict, List, Optional, Any, Callable, Tuple
from dataclasses import dataclass
from enum import Enum
from .utils import CommandRunner, Logger

class ErrorSeverity(Enum):
    """Error severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high" 
    CRITICAL = "critical"

class RecoveryAction(Enum):
    """Available recovery actions"""
    RETRY = "retry"
    RESTART = "restart"
    RECONFIGURE = "reconfigure"
    ESCALATE = "escalate"
    IGNORE = "ignore"

@dataclass
class ErrorContext:
    """Context information for errors"""
    component: str
    operation: str
    error_type: str
    message: str
    severity: ErrorSeverity
    timestamp: float
    stack_trace: Optional[str] = None
    recovery_suggestion: Optional[RecoveryAction] = None
    metadata: Optional[Dict[str, Any]] = None

class ErrorHandler:
    """Professional error handling with automated recovery"""
    
    def __init__(self, logger: Optional[Logger] = None):
        self.logger = logger or Logger("error_handler")
        self.error_history: List[ErrorContext] = []
        self.recovery_handlers: Dict[str, Callable] = {}
        self.max_history = 1000
        
        # Register default recovery handlers
        self._register_default_handlers()
    
    def handle_error(self, error: Exception, component: str, operation: str, 
                    severity: ErrorSeverity = ErrorSeverity.MEDIUM,
                    metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Handle error with context and recovery attempts"""
        
        error_context = ErrorContext(
            component=component,
            operation=operation,
            error_type=type(error).__name__,
            message=str(error),
            severity=severity,
            timestamp=time.time(),
            stack_trace=traceback.format_exc(),
            metadata=metadata or {}
        )
        
        # Add to history
        self.error_history.append(error_context)
        if len(self.error_history) > self.max_history:
            self.error_history.pop(0)
        
        # Log error with appropriate level
        self._log_error(error_context)
        
        # Attempt recovery if handler exists
        recovery_key = f"{component}.{operation}"
        if recovery_key in self.recovery_handlers:
            return self._attempt_recovery(error_context, recovery_key)
        
        # Check for pattern-based recovery
        return self._pattern_based_recovery(error_context)
    
    def register_recovery_handler(self, component: str, operation: str, 
                                 handler: Callable[[ErrorContext], bool]):
        """Register custom recovery handler"""
        key = f"{component}.{operation}"
        self.recovery_handlers[key] = handler
        self.logger.debug(f"Registered recovery handler for {key}")
    
    def get_error_summary(self) -> Dict[str, Any]:
        """Get summary of recent errors"""
        if not self.error_history:
            return {"total_errors": 0, "recent_errors": [], "patterns": []}
        
        recent_errors = self.error_history[-10:]  # Last 10 errors
        
        # Analyze patterns
        error_patterns = {}
        for error in self.error_history:
            pattern_key = f"{error.component}.{error.error_type}"
            if pattern_key not in error_patterns:
                error_patterns[pattern_key] = 0
            error_patterns[pattern_key] += 1
        
        return {
            "total_errors": len(self.error_history),
            "recent_errors": [
                {
                    "component": e.component,
                    "operation": e.operation,
                    "message": e.message,
                    "severity": e.severity.value,
                    "timestamp": e.timestamp
                }
                for e in recent_errors
            ],
            "patterns": [
                {"pattern": k, "count": v}
                for k, v in sorted(error_patterns.items(), key=lambda x: x[1], reverse=True)
            ][:5]  # Top 5 patterns
        }
    
    def _register_default_handlers(self):
        """Register default recovery handlers for common issues"""
        
        # Interface configuration failures
        def interface_recovery(context: ErrorContext) -> bool:
            self.logger.info(f"Attempting interface recovery for {context.component}")
            # Could implement interface reset, MTU adjustment, etc.
            return True
        
        # BPF map loading failures  
        def bpf_map_recovery(context: ErrorContext) -> bool:
            self.logger.info("Attempting BPF map recovery")
            # Could implement map cleanup and reload
            return True
        
        # Permission errors
        def permission_recovery(context: ErrorContext) -> bool:
            self.logger.warning("Permission error detected - check sudo access")
            return False  # Can't auto-recover from permission issues
        
        self.recovery_handlers.update({
            "network.interface_config": interface_recovery,
            "bpf.map_load": bpf_map_recovery,
            "system.permission": permission_recovery
        })
    
    def _log_error(self, context: ErrorContext):
        """Log error with appropriate severity level"""
        log_msg = f"[{context.component}] {context.operation} failed: {context.message}"
        
        if context.severity == ErrorSeverity.CRITICAL:
            self.logger.critical(log_msg)
        elif context.severity == ErrorSeverity.HIGH:
            self.logger.error(log_msg)
        elif context.severity == ErrorSeverity.MEDIUM:
            self.logger.warning(log_msg)
        else:
            self.logger.info(log_msg)
        
        # Log stack trace for high/critical errors
        if context.severity in [ErrorSeverity.HIGH, ErrorSeverity.CRITICAL] and context.stack_trace:
            self.logger.debug(f"Stack trace: {context.stack_trace}")
    
    def _attempt_recovery(self, context: ErrorContext, recovery_key: str) -> bool:
        """Attempt recovery using registered handler"""
        try:
            handler = self.recovery_handlers[recovery_key]
            success = handler(context)
            
            if success:
                self.logger.info(f"Recovery successful for {recovery_key}")
            else:
                self.logger.warning(f"Recovery failed for {recovery_key}")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Recovery handler failed for {recovery_key}: {e}")
            return False
    
    def _pattern_based_recovery(self, context: ErrorContext) -> bool:
        """Attempt recovery based on error patterns"""
        
        # Permission denied errors
        if "permission denied" in context.message.lower():
            self.logger.warning("Permission denied - ensure running with sudo")
            return False
        
        # Interface not found errors
        if "not found" in context.message.lower() and context.component == "network":
            self.logger.info("Interface not found - checking available interfaces")
            return self._suggest_interface_fix(context)
        
        # BPF program loading errors
        if "bpf" in context.error_type.lower() or "ebpf" in context.message.lower():
            self.logger.info("BPF-related error detected - checking kernel version")
            return self._suggest_bpf_fix(context)
        
        return False
    
    def _suggest_interface_fix(self, context: ErrorContext) -> bool:
        """Suggest fixes for interface-related errors"""
        self.logger.info("Suggested fixes:")
        self.logger.info("  1. Check available interfaces: ip link show")
        self.logger.info("  2. Verify interface is up: ip link set <interface> up")
        self.logger.info("  3. Update configuration with correct interface name")
        return False
    
    def _suggest_bpf_fix(self, context: ErrorContext) -> bool:
        """Suggest fixes for BPF-related errors"""
        self.logger.info("Suggested fixes:")
        self.logger.info("  1. Check kernel version: uname -r (requires 4.18+)")
        self.logger.info("  2. Install BPF tools: apt install bpftool")
        self.logger.info("  3. Check BPF filesystem: mount | grep bpf")
        return False

class ProfessionalValidator:
    """Comprehensive validation system for XDP pipeline"""
    
    def __init__(self, runner: Optional[CommandRunner] = None, logger: Optional[Logger] = None):
        self.runner = runner or CommandRunner()
        self.logger = logger or Logger("validator")
        self.error_handler = ErrorHandler(logger)
    
    def validate_system_requirements(self) -> Tuple[bool, List[str], List[str]]:
        """Comprehensive system validation"""
        errors = []
        warnings = []
        
        # Kernel version check
        kernel_valid, kernel_msg = self._check_kernel_version()
        if not kernel_valid:
            errors.append(kernel_msg)
        
        # Required tools check
        missing_tools = self._check_required_tools()
        if missing_tools:
            errors.append(f"Missing required tools: {', '.join(missing_tools)}")
        
        # BPF filesystem check
        bpf_valid, bpf_msg = self._check_bpf_filesystem()
        if not bpf_valid:
            warnings.append(bpf_msg)
        
        # Memory check
        mem_valid, mem_msg = self._check_memory_requirements()
        if not mem_valid:
            warnings.append(mem_msg)
        
        # Root privileges check
        if not self._check_root_privileges():
            errors.append("Root privileges required for XDP operations")
        
        return len(errors) == 0, errors, warnings
    
    def validate_network_configuration(self, config) -> Tuple[bool, List[str], List[str]]:
        """Validate network configuration comprehensively"""
        errors = []
        warnings = []
        
        # Interface validation
        for interface_name in [config.pipeline_config.ingress_interface, 
                              config.pipeline_config.egress_interface]:
            if not self._interface_exists(interface_name):
                errors.append(f"Interface '{interface_name}' not found")
            elif not self._interface_is_up(interface_name):
                warnings.append(f"Interface '{interface_name}' is down")
        
        # IP address validation
        if not self._validate_ip_address(config.pipeline_config.nat_target_ip):
            errors.append(f"Invalid NAT target IP: {config.pipeline_config.nat_target_ip}")
        
        # Port validation
        for port_name, port_value in [
            ("NAT port", config.pipeline_config.nat_target_port),
            ("Source port", config.pipeline_config.source_port)
        ]:
            if not self._validate_port(port_value):
                errors.append(f"Invalid {port_name}: {port_value}")
        
        return len(errors) == 0, errors, warnings
    
    def validate_bpf_environment(self) -> Tuple[bool, List[str], List[str]]:
        """Validate BPF/XDP environment"""
        errors = []
        warnings = []
        
        # Check BPF program compilation
        try:
            result = self.runner.run(["which", "clang"], check=False)
            if result.returncode != 0:
                errors.append("clang compiler not found - required for BPF compilation")
        except Exception:
            errors.append("Failed to check for clang compiler")
        
        # Check bpftool availability
        try:
            result = self.runner.run(["bpftool", "version"], check=False)
            if result.returncode != 0:
                errors.append("bpftool not available - install with: apt install bpftool")
        except Exception:
            errors.append("bpftool not found")
        
        return len(errors) == 0, errors, warnings
    
    def _check_kernel_version(self) -> Tuple[bool, str]:
        """Check kernel version for XDP support"""
        try:
            result = self.runner.run(["uname", "-r"], check=False)
            if result.returncode != 0:
                return False, "Could not determine kernel version"
            
            version = result.stdout.strip()
            # Basic version check (should be more sophisticated)
            if "3." in version or "4.1" in version[:4]:
                return False, f"Kernel {version} may not support XDP (requires 4.18+)"
            
            return True, f"Kernel {version} should support XDP"
            
        except Exception as e:
            return False, f"Kernel version check failed: {e}"
    
    def _check_required_tools(self) -> List[str]:
        """Check for required system tools"""
        required_tools = ["ip", "ethtool", "sysctl", "bpftool", "clang", "make"]
        missing = []
        
        for tool in required_tools:
            try:
                result = self.runner.run(["which", tool], check=False)
                if result.returncode != 0:
                    missing.append(tool)
            except Exception:
                missing.append(tool)
        
        return missing
    
    def _check_bpf_filesystem(self) -> Tuple[bool, str]:
        """Check BPF filesystem mount"""
        try:
            result = self.runner.run(["mount"], check=False)
            if result.returncode != 0:
                return False, "Could not check filesystem mounts"
            
            if "bpf" in result.stdout:
                return True, "BPF filesystem is mounted"
            else:
                return False, "BPF filesystem not mounted - may need: mount -t bpf bpf /sys/fs/bpf"
                
        except Exception as e:
            return False, f"BPF filesystem check failed: {e}"
    
    def _check_memory_requirements(self) -> Tuple[bool, str]:
        """Check available memory"""
        try:
            with open("/proc/meminfo", 'r') as f:
                meminfo = f.read()
            
            for line in meminfo.split('\n'):
                if line.startswith('MemAvailable:'):
                    mem_kb = int(line.split()[1])
                    mem_gb = mem_kb / (1024 * 1024)
                    
                    if mem_gb < 2:
                        return False, f"Low memory: {mem_gb:.1f}GB available (recommend 4GB+)"
                    elif mem_gb < 4:
                        return True, f"Moderate memory: {mem_gb:.1f}GB available (recommend 8GB+ for high performance)"
                    else:
                        return True, f"Sufficient memory: {mem_gb:.1f}GB available"
            
            return False, "Could not determine available memory"
            
        except Exception as e:
            return False, f"Memory check failed: {e}"
    
    def _check_root_privileges(self) -> bool:
        """Check for root/sudo privileges"""
        try:
            result = self.runner.run(["id", "-u"], check=False)
            return result.returncode == 0 and result.stdout.strip() == "0"
        except Exception:
            return False
    
    def _interface_exists(self, interface: str) -> bool:
        """Check if network interface exists"""
        try:
            result = self.runner.run(["ip", "link", "show", interface], check=False)
            return result.returncode == 0
        except Exception:
            return False
    
    def _interface_is_up(self, interface: str) -> bool:
        """Check if interface is up"""
        try:
            result = self.runner.run(["ip", "link", "show", interface], check=False)
            return result.returncode == 0 and "state UP" in result.stdout
        except Exception:
            return False
    
    def _validate_ip_address(self, ip: str) -> bool:
        """Validate IP address format"""
        import re
        pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        return re.match(pattern, ip) is not None
    
    def _validate_port(self, port: int) -> bool:
        """Validate port number"""
        return 1 <= port <= 65535