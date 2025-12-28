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
from .bpf import BPFMapManager
from .network import NetworkManager
from .config import ConfigManager, PipelineConfig
from .display import DisplayManager
from .utils import Logger, CommandRunner
from .system_tuning import SystemTuner
from .monitoring import UnifiedMonitor
from .interface_management import InterfaceManager

# Analytics and diagnostics
from .analyze_stats import StatisticsAnalyzer
from .diagnostics import NetworkDiagnostics

# Monitoring and inspection
from .monitoring import RealTimeMonitor
# BPFMapInspector functionality is now part of BPFMapManager in bpf.py
from .interface_management import InterfaceManager

# Data models
from .models import (
    PipelineStatus,
    BPFMapInfo, 
    AllowlistEntry,
    NetworkInterface,
    PipelineStats,
    SystemInfo
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
    'SystemTuner',
    'AdvancedMonitor',
    # 'EnhancedBPFMapManager',  # Now part of BPFMapManager
    'InterfaceManager', 
    'LogMonitor',
    'SystemInfo',
    
    # Analytics and diagnostics
    'StatisticsAnalyzer',
    'NetworkDiagnostics',
    
    # Monitoring and inspection
    'RealTimeMonitor',
    # 'BPFMapInspector',  # Now part of BPFMapManager
    'InterfaceManager',
    
    # Configuration
    'PipelineConfig',
    
    # Data models
    'PipelineStatus',
    'BPFMapInfo',
    'AllowlistEntry', 
    'NetworkInterface',
    'PipelineStats',
]