"""
Core data models and enums for XDP pipeline management
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any
from datetime import datetime

class PipelineStatus(Enum):
    """Pipeline operational status"""
    STOPPED = "stopped"
    STARTING = "starting" 
    RUNNING = "running"
    ERROR = "error"
    UNKNOWN = "unknown"

class BPFMapType(Enum):
    """BPF map types"""
    HASH = "BPF_MAP_TYPE_HASH"
    ARRAY = "BPF_MAP_TYPE_ARRAY"
    LPM_TRIE = "BPF_MAP_TYPE_LPM_TRIE"
    PERCPU_ARRAY = "BPF_MAP_TYPE_PERCPU_ARRAY"
    RINGBUF = "BPF_MAP_TYPE_RINGBUF"
    PROG_ARRAY = "BPF_MAP_TYPE_PROG_ARRAY"

class LogLevel(Enum):
    """Logging levels"""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

@dataclass
class BPFMapInfo:
    """BPF map information"""
    id: int
    name: str
    type: str
    key_size: int
    value_size: int
    max_entries: int
    entries_count: int = 0
    flags: int = 0
    
    @property
    def usage_percentage(self) -> float:
        """Calculate usage percentage"""
        if self.max_entries == 0:
            return 0.0
        return (self.entries_count / self.max_entries) * 100

@dataclass
class AllowlistEntry:
    """IP allowlist entry"""
    address: str
    prefix_len: int
    is_subnet: bool
    description: str = ""
    added_at: datetime = field(default_factory=datetime.now)
    
    @property
    def cidr_notation(self) -> str:
        """Get CIDR notation"""
        return f"{self.address}/{self.prefix_len}"
    
    @property
    def host_count(self) -> int:
        """Calculate number of hosts in subnet"""
        if not self.is_subnet:
            return 1
        return 2 ** (32 - self.prefix_len)

@dataclass
class NetworkInterface:
    """Network interface information"""
    name: str
    state: str
    mtu: int
    mac_address: str
    ip_addresses: List[str] = field(default_factory=list)
    xdp_attached: bool = False
    driver: str = ""
    
    @property
    def is_up(self) -> bool:
        """Check if interface is up"""
        return self.state.upper() == "UP"

@dataclass
class PipelineStats:
    """Pipeline performance statistics"""
    packets_processed: int = 0
    packets_dropped: int = 0
    allowlist_hits: int = 0
    allowlist_misses: int = 0
    vxlan_packets: int = 0
    errors: int = 0
    uptime_seconds: int = 0
    last_updated: datetime = field(default_factory=datetime.now)
    
    @property
    def drop_rate(self) -> float:
        """Calculate packet drop rate"""
        if self.packets_processed == 0:
            return 0.0
        return (self.packets_dropped / self.packets_processed) * 100
    
    @property
    def allowlist_hit_rate(self) -> float:
        """Calculate allowlist hit rate"""
        total_checks = self.allowlist_hits + self.allowlist_misses
        if total_checks == 0:
            return 0.0
        return (self.allowlist_hits / total_checks) * 100

@dataclass
class SystemInfo:
    """System information"""
    kernel_version: str
    bpf_jit_enabled: bool
    available_interfaces: List[str] = field(default_factory=list)
    cpu_count: int = 0
    memory_mb: int = 0
    
@dataclass 
class CompilationResult:
    """BPF compilation result"""
    success: bool
    output_file: str = ""
    error_message: str = ""
    warnings: List[str] = field(default_factory=list)
    compilation_time: float = 0.0

@dataclass
class ValidationResult:
    """Configuration validation result"""
    valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    
    def add_error(self, message: str):
        """Add validation error"""
        self.errors.append(message)
        self.valid = False
    
    def add_warning(self, message: str):
        """Add validation warning"""
        self.warnings.append(message)

@dataclass
class SyncResult:
    """Allowlist sync result"""
    success: bool
    entries_added: int = 0
    entries_removed: int = 0
    entries_updated: int = 0
    total_entries: int = 0
    duration_seconds: float = 0.0
    errors: List[str] = field(default_factory=list)