#!/usr/bin/env python3
"""
eBPF VXLAN Pipeline Statistics Analysis Tool
Provides clean, actionable performance metrics and issue detection.
"""

import json
import subprocess
import sys
import argparse
from typing import Dict, List, Tuple

# Statistics map indices
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
    0x0f: "LENGTH_CORRECTIONS"
}

def get_active_interfaces() -> List[str]:
    """Get list of active network interfaces dynamically."""
    try:
        with open('/proc/net/dev', 'r') as f:
            lines = f.readlines()[2:]  # Skip headers
        
        active_interfaces = []
        for line in lines:
            if line.strip():
                iface = line.split(':')[0].strip()
                # Skip loopback and virtual interfaces that typically don't need monitoring
                if not iface.startswith(('lo', 'docker', 'br-', 'veth')):
                    active_interfaces.append(iface)
        
        return active_interfaces
    except Exception as e:
        print(f"Error getting interfaces: {e}")
        return []

# Debug markers for error analysis
DEBUG_MARKERS = {
    # Ring Buffer Failures (0xDEAD004X)
    0xDEAD0040: "temp_len zero error",
    0xDEAD0041: "Insufficient data error",
    0xDEAD0042: "Ring buffer copy failure",
    0xDEAD0043: "Forward packet eth header bounds failure",

    # Length Validation (0xDEAD009X)
    0xDEAD0099: "ZERO packet_len received",

    # IP Header Validation Failures (0xDEAD010X)
    0xDEAD0100: "IP header length validation failure",
    0xDEAD0101: "NAT engine IP header length validation failure",
    0xDEAD0102: "NAT apply failure marker",

    # Update Packet Headers Failures (0xDEAD020X)
    0xDEAD0200: "IP header bounds after decapsulation",
    0xDEAD0201: "IP header length validation after decapsulation",
    0xDEAD0202: "IP header options bounds after decapsulation",

    # Decapsulation Failures (0xDEAD030X)
    0xDEAD0300: "Decapsulation bounds validation failure",

    # Parse Outer Headers Failures (0xDEAD040X)
    0xDEAD0400: "Outer ethernet header bounds failure",
    0xDEAD0401: "Outer IP header bounds failure",
    0xDEAD0402: "Outer IP header length validation failure",
    0xDEAD0403: "Outer UDP header bounds failure",

    # Pipeline Stage Bounds Failures (0xDEAD050X)
    0xDEAD0500: "vxlan_classifier context failure",
    0xDEAD0501: "vxlan_processor eth bounds failure",
    0xDEAD0502: "vxlan_processor IP bounds failure",
    0xDEAD0503: "vxlan_processor UDP bounds failure",
    0xDEAD0504: "vxlan_processor VXLAN header bounds failure",
    0xDEAD0505: "nat_engine UDP bounds after validation failure",
    0xDEAD0506: "nat_engine post-decaps IP bounds failure",
    0xDEAD0507: "forwarding_stage post-decaps bounds failure",

    # Tail Call Failures (0xDEAD060X)
    0xDEAD0600: "Invalid stage number",
    0xDEAD0601: "Tail call failure",

    # Configuration Failures (0xBAD0000X)
    0xBAD00001: "Interface config failure",
    0xBAD00002: "NAT config failure",
    0xBAD00003: "Target ifindex failure",

    # VXLAN Parse Specific (0xDEAD0002)
    0xDEAD0002: "VNI validation failure in parse_vxlan"
}

class VXLANStatsAnalyzer:
    def __init__(self, compact=False):
        self.compact = compact
        self.stats = {}
    
    def get_bpf_stats(self) -> Dict[str, int]:
        """Get statistics from BPF maps"""
        try:
            result = subprocess.run(
                ["sudo", "bpftool", "map", "dump", "name", "stats_map", "--json"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                print("❌ Failed to retrieve BPF statistics")
                return {}
            
            data = json.loads(result.stdout)
            stats = {}
            
            for entry in data:
                if "formatted" in entry:
                    key = entry["formatted"]["key"]
                    if key in STATS_MAP:
                        values = entry["formatted"]["values"]
                        total = sum(v["value"] for v in values if isinstance(v, dict) and "value" in v)
                        stats[STATS_MAP[key]] = total
            
            return stats
        except Exception as e:
            print(f"❌ Error retrieving statistics: {e}")
            return {}
    
    def analyze_performance(self) -> Dict[str, str]:
        """Analyze performance and return actionable insights"""
        total = self.stats.get("TOTAL_PACKETS", 0)
        vxlan = self.stats.get("VXLAN_PACKETS", 0)
        errors = self.stats.get("ERRORS", 0)
        nat_applied = self.stats.get("NAT_APPLIED", 0)
        forwarded = self.stats.get("FORWARDED", 0)
        
        issues = []
        
        # Performance checks
        if total == 0:
            issues.append("🔴 No packets processed - check if pipeline is active")
        elif errors / total > 0.01:  # > 1% error rate
            issues.append(f"🔴 High error rate: {errors/total*100:.1f}%")
        
        if vxlan > 0:
            vxlan_pct = vxlan / total * 100
            if vxlan_pct < 80:
                issues.append(f"🟡 Low VXLAN detection: {vxlan_pct:.1f}%")
        
        if nat_applied > 0:
            nat_efficiency = nat_applied / vxlan * 100 if vxlan > 0 else 0
            if nat_efficiency < 5:
                issues.append(f"🟡 Low NAT efficiency: {nat_efficiency:.1f}%")
        
        if not issues:
            issues.append("✅ Pipeline performance looks good")
        
        return {
            "vxlan_detection": f"{vxlan/total*100:.1f}%" if total > 0 else "0%",
            "error_rate": f"{errors/total*100:.2f}%" if total > 0 else "0%", 
            "nat_efficiency": f"{nat_applied/vxlan*100:.1f}%" if vxlan > 0 else "0%",
            "issues": issues
        }
    
    def format_number(self, num):
        """Format large numbers with appropriate units"""
        if num >= 1_000_000_000:
            return f"{num/1_000_000_000:.1f}B"
        elif num >= 1_000_000:
            return f"{num/1_000_000:.1f}M"
        elif num >= 1_000:
            return f"{num/1_000:.1f}K"
        return str(num)
    
    def print_compact_stats(self):
        """Print compact one-line statistics"""
        total = self.stats.get("TOTAL_PACKETS", 0)
        vxlan = self.stats.get("VXLAN_PACKETS", 0)
        errors = self.stats.get("ERRORS", 0)
        nat = self.stats.get("NAT_APPLIED", 0)
        
        print(f"📊 Pipeline Stats: {self.format_number(total)} total, "
              f"{self.format_number(vxlan)} VXLAN ({vxlan/total*100:.1f}%), "
              f"{errors} errors, {self.format_number(nat)} NAT applied")
    
    def print_detailed_stats(self):
        """Print detailed statistics analysis"""
        print("📊 VXLAN Pipeline Performance Analysis")
        print("=" * 50)
        
        # Core metrics
        total = self.stats.get("TOTAL_PACKETS", 0)
        vxlan = self.stats.get("VXLAN_PACKETS", 0)
        inner = self.stats.get("INNER_PACKETS", 0)
        nat_applied = self.stats.get("NAT_APPLIED", 0)
        forwarded = self.stats.get("FORWARDED", 0)
        errors = self.stats.get("ERRORS", 0)
        
        print(f"📈 Packet Counters:")
        print(f"  Total Packets:     {self.format_number(total)}")
        print(f"  VXLAN Packets:     {self.format_number(vxlan)} ({vxlan/total*100:.1f}%)" if total > 0 else "  VXLAN Packets:     0")
        print(f"  Inner Extracted:   {self.format_number(inner)}")
        print(f"  NAT Applied:       {self.format_number(nat_applied)}")
        print(f"  Forwarded:         {self.format_number(forwarded)}")
        if errors > 0:
            print(f"  ❌ Errors:        {self.format_number(errors)} ({errors/total*100:.2f}%)" if total > 0 else f"  ❌ Errors:        {errors}")
        
        # Performance analysis
        analysis = self.analyze_performance()
        print(f"\n🔍 Performance Analysis:")
        print(f"  VXLAN Detection:   {analysis['vxlan_detection']}")
        print(f"  Error Rate:        {analysis['error_rate']}")
        print(f"  NAT Efficiency:    {analysis['nat_efficiency']}")
        
        print(f"\n💡 Status:")
        for issue in analysis['issues']:
            print(f"  {issue}")
        
        # Network interface analysis
        active_interfaces = get_active_interfaces()
        if active_interfaces:
            print(f"\n🔌 Active Network Interfaces:")
            for iface in active_interfaces[:5]:  # Show first 5 interfaces
                print(f"  {iface}")
            if len(active_interfaces) > 5:
                print(f"  ... and {len(active_interfaces) - 5} more")
    
    def run(self):
        """Main analysis function"""
        self.stats = self.get_bpf_stats()
        
        if not self.stats:
            print("❌ No statistics available")
            return 1
        
        if self.compact:
            self.print_compact_stats()
        else:
            self.print_detailed_stats()
        
        return 0

def main():
    parser = argparse.ArgumentParser(description='Analyze VXLAN pipeline statistics')
    parser.add_argument('--compact', '-c', action='store_true', 
                       help='Show compact one-line output')
    parser.add_argument('--detailed', '-d', action='store_true',
                       help='Show detailed analysis (default)')
    
    args = parser.parse_args()
    
    # Use compact mode if --compact is specified, otherwise detailed
    compact = args.compact
    
    analyzer = VXLANStatsAnalyzer(compact=compact)
    return analyzer.run()

if __name__ == "__main__":
    sys.exit(main())