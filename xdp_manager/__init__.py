"""
XDP VXLAN Pipeline Management Package
Professional-grade eBPF pipeline management toolkit with advanced analytics and diagnostics
"""

__version__ = "2.0.0"
__author__ = "Anilkumar Srirangapatna Nagesh"
__description__ = "High-performance VXLAN processing with eBPF/XDP"

# Core pipeline components
from .pipeline import XDPPipeline
from .allowlist import AllowlistManager
from .bpf_maps import BPFMapManager
from .network import NetworkManager
from .config import ConfigManager, PipelineConfig
from .display import DisplayManager
from .utils import Logger, CommandRunner, SystemInfo

# Analytics and diagnostics
from .analytics import StatisticsAnalyzer
from .diagnostics import NetworkDiagnostics

# Data models
from .models import (
    PipelineStatus,
    BPFMapInfo, 
    AllowlistEntry,
    NetworkInterface,
    PipelineStats
)

__all__ = [
    # Core classes
    'XDPPipeline',
    'AllowlistManager', 
    'BPFMapManager',
    'NetworkManager',
    'ConfigManager',
    'DisplayManager',
    'Logger',
    'CommandRunner',
    'SystemInfo',
    
    # Analytics and diagnostics
    'StatisticsAnalyzer',
    'NetworkDiagnostics',
    
    # Configuration
    'PipelineConfig',
    
    # Data models
    'PipelineStatus',
    'BPFMapInfo',
    'AllowlistEntry', 
    'NetworkInterface',
    'PipelineStats',
]