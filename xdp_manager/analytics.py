"""
Advanced analytics and statistics analysis for XDP pipeline
"""

import json
import struct
from typing import Dict, List, Tuple, Optional, Any
from datetime import datetime, timedelta
from .models import PipelineStats
from .utils import CommandRunner, Logger
from .bpf_maps import BPFMapManager

class StatisticsAnalyzer:
    """Advanced statistics analysis with error pattern detection"""
    
    # Statistics map indices from eBPF code
    STATS_MAP = {
        0x00: "TOTAL_PACKETS",
        0x01: "VXLAN_PACKETS", 
        0x02: "INNER_PACKETS",
        0x03: "NAT_APPLIED",
        0x04: "DF_CLEARED",
        0x05: "FORWARDED",
        0x06: "REDIRECTED",
        0x07: "ERRORS",
        0x08: "BYTES_PROCESSED",
        0x09: "IP_LEN_UPDATED",
        0x0a: "UDP_LEN_UPDATED",
        0x0b: "IP_CHECKSUM_UPDATED",
        0x0c: "BOUNDS_CHECK_FAILED",
        0x0d: "RINGBUF_SUBMITTED",
        0x0e: "PACKET_SIZE_DEBUG",
        0x0f: "LENGTH_CORRECTIONS",
        0x10: "IP_ALLOWLIST_HITS",
        0x11: "IP_ALLOWLIST_MISSES"
    }
    
    # Error marker definitions (professional error codes)
    ERROR_MARKERS = {
        # Processing Failures (0xE002001X)
        0xE0020010: "VXLAN parsing failure",
        0xE0020011: "Inner Ethernet bounds validation failure", 
        0xE0020012: "Inner IP header bounds validation failure",
        0xE0020013: "Inner UDP header bounds validation failure",
        0xE0020014: "VXLAN decapsulation failure",
        0xE0020015: "Packet header update failure (non-fatal)",
        
        # Stage Failures (0xE002002X-0xE002006X)
        0xE0020020: "Pipeline stage validation failure",
        0xE0020030: "Pipeline context initialization failure in classifier",
        0xE0020031: "VXLAN processor context initialization failure",
        0xE0020032: "VXLAN processor stage validation failure",
        0xE0020050: "NAT engine context initialization failure",
        0xE0020051: "NAT engine processing stage failure",
        0xE0020060: "Forwarding stage context initialization failure",
        
        # Ring Buffer Failures (0xE002004X)
        0xE0020040: "Buffer length validation error",
        0xE0020041: "Insufficient packet data error",
        0xE0020042: "Ring buffer copy operation failure",
        0xE0020043: "Forward packet Ethernet bounds validation failure",
        
        # Length Validation (0xE002009X)
        0xE0020099: "Zero packet length received",
        
        # IP Header Validation Failures (0xE002010X)
        0xE0020100: "IP header length validation failure",
        0xE0020101: "NAT engine IP header length validation failure", 
        0xE0020102: "NAT application failure marker",
        
        # Update Packet Headers Failures (0xE002020X)
        0xE0020200: "IP header bounds validation after decapsulation",
        0xE0020201: "IP header length validation after decapsulation",
        0xE0020202: "IP header options bounds validation after decapsulation",
        
        # Decapsulation Failures (0xE002030X)
        0xE0020300: "Decapsulation bounds validation failure",
        
        # Parse Outer Headers Failures (0xE002040X)
        0xE0020400: "Outer Ethernet header bounds validation failure",
        0xE0020401: "Outer IP header bounds validation failure",
        0xE0020402: "Outer IP header length validation failure",
        0xE0020403: "Outer UDP bounds validation failure",
        
        # Pipeline Stage Bounds Failures (0xE002050X)
        0xE0020500: "VXLAN classifier context initialization failure"
    }
    
    def __init__(self, bpf_maps: Optional[BPFMapManager] = None, logger: Optional[Logger] = None):
        self.bpf_maps = bpf_maps or BPFMapManager()
        self.logger = logger or Logger("stats_analyzer")
        self.runner = CommandRunner(self.logger)
        
    def analyze_comprehensive_stats(self) -> Dict[str, Any]:
        """Comprehensive statistics analysis with error pattern detection"""
        try:
            # Get raw statistics
            raw_stats = self._get_raw_statistics()
            pipeline_stats = self.bpf_maps.get_pipeline_stats()
            
            # Analyze error patterns
            error_analysis = self._analyze_error_patterns(raw_stats)
            
            # Performance analysis
            performance_analysis = self._analyze_performance(pipeline_stats, raw_stats)
            
            # Trend analysis
            trend_analysis = self._analyze_trends(raw_stats)
            
            return {
                'timestamp': datetime.now().isoformat(),
                'raw_statistics': raw_stats,
                'pipeline_stats': pipeline_stats,
                'error_analysis': error_analysis,
                'performance_analysis': performance_analysis,
                'trend_analysis': trend_analysis,
                'recommendations': self._generate_recommendations(error_analysis, performance_analysis)
            }
            
        except Exception as e:
            self.logger.error(f"Statistics analysis failed: {e}")
            return {}
    
    def analyze_error_markers(self) -> Dict[str, Any]:
        """Analyze error markers for systematic error detection"""
        try:
            error_entries = self.bpf_maps.get_map_entries('error_map')
            
            error_summary = {
                'total_errors': len(error_entries),
                'error_breakdown': {},
                'critical_errors': [],
                'error_patterns': {}
            }
            
            for entry in error_entries:
                if entry['raw_key'] and len(entry['raw_key']) >= 4:
                    # Extract error code
                    error_code = struct.unpack('<I', bytes(entry['raw_key'][:4]))[0]
                    
                    # Get error count
                    error_count = 1
                    if entry['raw_value'] and len(entry['raw_value']) >= 8:
                        error_count = struct.unpack('<Q', bytes(entry['raw_value'][:8]))[0]
                    
                    # Categorize error
                    error_description = self.ERROR_MARKERS.get(error_code, f"Unknown error: 0x{error_code:08x}")
                    error_category = self._categorize_error(error_code)
                    
                    error_summary['error_breakdown'][error_description] = {
                        'code': f"0x{error_code:08x}",
                        'count': error_count,
                        'category': error_category,
                        'severity': self._get_error_severity(error_code)
                    }
                    
                    # Track critical errors
                    if self._is_critical_error(error_code):
                        error_summary['critical_errors'].append({
                            'code': error_code,
                            'description': error_description,
                            'count': error_count
                        })
            
            return error_summary
            
        except Exception as e:
            self.logger.error(f"Error marker analysis failed: {e}")
            return {}
    
    def get_performance_metrics(self) -> Dict[str, float]:
        """Calculate key performance metrics"""
        try:
            stats = self.bpf_maps.get_pipeline_stats()
            raw_stats = self._get_raw_statistics()
            
            metrics = {
                'packets_per_second': 0.0,
                'bytes_per_second': 0.0,
                'drop_rate_percent': stats.drop_rate,
                'error_rate_percent': 0.0,
                'allowlist_hit_rate_percent': stats.allowlist_hit_rate,
                'vxlan_processing_efficiency': 0.0,
                'nat_application_rate': 0.0,
                'forwarding_success_rate': 0.0
            }
            
            # Calculate rates based on uptime
            if stats.uptime_seconds > 0:
                metrics['packets_per_second'] = stats.packets_processed / stats.uptime_seconds
                
                bytes_processed = raw_stats.get('BYTES_PROCESSED', 0)
                metrics['bytes_per_second'] = bytes_processed / stats.uptime_seconds
            
            # Calculate efficiency metrics
            total_packets = stats.packets_processed
            if total_packets > 0:
                vxlan_packets = raw_stats.get('VXLAN_PACKETS', 0)
                metrics['vxlan_processing_efficiency'] = (vxlan_packets / total_packets) * 100
                
                nat_applied = raw_stats.get('NAT_APPLIED', 0)
                metrics['nat_application_rate'] = (nat_applied / total_packets) * 100
                
                forwarded = raw_stats.get('FORWARDED', 0)
                metrics['forwarding_success_rate'] = (forwarded / total_packets) * 100
                
                errors = stats.errors
                metrics['error_rate_percent'] = (errors / total_packets) * 100
            
            return metrics
            
        except Exception as e:
            self.logger.error(f"Performance metrics calculation failed: {e}")
            return {}
    
    def monitor_realtime(self, duration_seconds: int = 60, interval_seconds: float = 1.0) -> List[Dict[str, Any]]:
        """Monitor statistics in real-time"""
        import time
        
        samples = []
        start_time = time.time()
        
        try:
            while time.time() - start_time < duration_seconds:
                timestamp = datetime.now()
                
                # Collect current metrics
                metrics = self.get_performance_metrics()
                pipeline_stats = self.bpf_maps.get_pipeline_stats()
                
                sample = {
                    'timestamp': timestamp.isoformat(),
                    'metrics': metrics,
                    'stats': {
                        'packets_processed': pipeline_stats.packets_processed,
                        'packets_dropped': pipeline_stats.packets_dropped,
                        'allowlist_hits': pipeline_stats.allowlist_hits,
                        'allowlist_misses': pipeline_stats.allowlist_misses,
                        'errors': pipeline_stats.errors
                    }
                }
                
                samples.append(sample)
                
                # Sleep for interval
                time.sleep(interval_seconds)
                
        except KeyboardInterrupt:
            self.logger.info("Real-time monitoring stopped by user")
        
        return samples
    
    def _get_raw_statistics(self) -> Dict[str, int]:
        """Get raw statistics from BPF maps"""
        stats = {}
        
        try:
            entries = self.bpf_maps.get_map_entries('stats_map')
            
            for entry in entries:
                if entry['raw_key'] and len(entry['raw_key']) >= 4:
                    # Extract key
                    key = struct.unpack('<I', bytes(entry['raw_key'][:4]))[0]
                    
                    # Extract value (handle percpu arrays)
                    value = 0
                    if entry['raw_value']:
                        if len(entry['raw_value']) >= 8:
                            # Sum percpu values
                            for i in range(0, len(entry['raw_value']), 8):
                                if i + 8 <= len(entry['raw_value']):
                                    cpu_val = struct.unpack('<Q', bytes(entry['raw_value'][i:i+8]))[0]
                                    value += cpu_val
                        else:
                            value = struct.unpack('<Q', bytes(entry['raw_value'][:8]))[0]
                    
                    # Map to human-readable name
                    stat_name = self.STATS_MAP.get(key, f"UNKNOWN_{key:02x}")
                    stats[stat_name] = value
                    
        except Exception as e:
            self.logger.error(f"Error getting raw statistics: {e}")
        
        return stats
    
    def _analyze_error_patterns(self, raw_stats: Dict[str, int]) -> Dict[str, Any]:
        """Analyze error patterns and trends"""
        error_analysis = {
            'total_errors': raw_stats.get('ERRORS', 0),
            'bounds_check_failures': raw_stats.get('BOUNDS_CHECK_FAILED', 0),
            'error_rate': 0.0,
            'critical_issues': [],
            'recommendations': []
        }
        
        total_packets = raw_stats.get('TOTAL_PACKETS', 0)
        if total_packets > 0:
            error_analysis['error_rate'] = (error_analysis['total_errors'] / total_packets) * 100
        
        # Identify critical issues
        if error_analysis['error_rate'] > 5.0:
            error_analysis['critical_issues'].append("High error rate detected")
        
        if error_analysis['bounds_check_failures'] > 0:
            error_analysis['critical_issues'].append("Bounds check failures indicate potential buffer overruns")
        
        return error_analysis
    
    def _analyze_performance(self, stats: PipelineStats, raw_stats: Dict[str, int]) -> Dict[str, Any]:
        """Analyze performance characteristics"""
        performance = {
            'throughput_pps': 0.0,
            'drop_rate': stats.drop_rate,
            'processing_efficiency': 0.0,
            'bottlenecks': [],
            'performance_grade': 'Unknown'
        }
        
        # Calculate throughput
        if stats.uptime_seconds > 0:
            performance['throughput_pps'] = stats.packets_processed / stats.uptime_seconds
        
        # Processing efficiency
        vxlan_packets = raw_stats.get('VXLAN_PACKETS', 0)
        if stats.packets_processed > 0:
            performance['processing_efficiency'] = (vxlan_packets / stats.packets_processed) * 100
        
        # Performance grading
        pps = performance['throughput_pps']
        if pps >= 85000:
            performance['performance_grade'] = 'Excellent'
        elif pps >= 50000:
            performance['performance_grade'] = 'Good'
        elif pps >= 25000:
            performance['performance_grade'] = 'Fair'
        else:
            performance['performance_grade'] = 'Poor'
        
        # Identify bottlenecks
        if performance['drop_rate'] > 1.0:
            performance['bottlenecks'].append('High packet drop rate')
        
        if performance['processing_efficiency'] < 80.0:
            performance['bottlenecks'].append('Low VXLAN processing efficiency')
        
        return performance
    
    def _analyze_trends(self, raw_stats: Dict[str, int]) -> Dict[str, Any]:
        """Analyze statistical trends"""
        # This would ideally compare with historical data
        trends = {
            'packet_processing_trend': 'stable',
            'error_trend': 'stable',
            'performance_trend': 'stable'
        }
        
        # Basic trend analysis based on current ratios
        total_packets = raw_stats.get('TOTAL_PACKETS', 0)
        errors = raw_stats.get('ERRORS', 0)
        
        if total_packets > 0:
            error_ratio = errors / total_packets
            if error_ratio > 0.05:
                trends['error_trend'] = 'increasing'
            elif error_ratio < 0.001:
                trends['error_trend'] = 'decreasing'
        
        return trends
    
    def _generate_recommendations(self, error_analysis: Dict[str, Any], performance_analysis: Dict[str, Any]) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        # Error-based recommendations
        if error_analysis.get('error_rate', 0) > 5.0:
            recommendations.append("High error rate detected - check packet format and network configuration")
        
        if error_analysis.get('bounds_check_failures', 0) > 0:
            recommendations.append("Bounds check failures detected - verify packet sizes and BPF program logic")
        
        # Performance-based recommendations
        throughput = performance_analysis.get('throughput_pps', 0)
        if throughput < 50000:
            recommendations.append("Low throughput detected - consider performance tuning")
        
        if performance_analysis.get('drop_rate', 0) > 1.0:
            recommendations.append("High drop rate - check system resources and network capacity")
        
        return recommendations
    
    def _categorize_error(self, error_code: int) -> str:
        """Categorize error by code range"""
        if 0xE0020010 <= error_code <= 0xE002001F:
            return "Processing Failure"
        elif 0xE0020020 <= error_code <= 0xE002006F:
            return "Stage Failure"
        elif 0xE0020040 <= error_code <= 0xE002004F:
            return "Buffer Failure"
        elif 0xE0020100 <= error_code <= 0xE002010F:
            return "IP Header Validation"
        else:
            return "Unknown"
    
    def _get_error_severity(self, error_code: int) -> str:
        """Determine error severity"""
        critical_errors = [
            0xE0020010,  # VXLAN parsing failure
            0xE0020040,  # Buffer length zero
            0xE0020099,  # Zero packet length
        ]
        
        if error_code in critical_errors:
            return "Critical"
        elif error_code & 0xE0020000 == 0xE0020000:
            return "Warning"
        else:
            return "Info"
    
    def _is_critical_error(self, error_code: int) -> bool:
        """Check if error is critical"""
        return self._get_error_severity(error_code) == "Critical"