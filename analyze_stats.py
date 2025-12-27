#!/usr/bin/env python3
"""
eBPF VXLAN Pipeline Statistics Analysis Tool
Analyzes BPF statistics to identify systematic error sources and performance metrics.
"""

import json
import subprocess
import sys
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
    0x09: "IP_LEN_UPDATED",
    0x0a: "UDP_LEN_UPDATED", 
    0x0b: "IP_CHECKSUM_UPDATED",
    0x0c: "BOUNDS_CHECK_FAILED",
    0x0d: "RINGBUF_SUBMITTED",
    0x0e: "PACKET_SIZE_DEBUG",
    0x0f: "LENGTH_CORRECTIONS"
}

# Debug marker mappings for systematic error analysis
DEBUG_MARKERS = {
    # Processing Failures (0xDEAD001X)
    0xDEAD0010: "parse_vxlan failure",
    0xDEAD0011: "Inner ethernet bounds failure", 
    0xDEAD0012: "Inner IP bounds failure",
    0xDEAD0013: "Inner UDP bounds failure",
    0xDEAD0014: "Decapsulation failure",
    0xDEAD0015: "Header update failure (non-fatal)",
    
    # Stage Failures (0xDEAD002X-0xDEAD006X)
    0xDEAD0020: "Forwarding stage validation failure",
    0xDEAD0030: "init_pipeline_ctx failure in classifier",
    0xDEAD0031: "vxlan_processor context failure", 
    0xDEAD0032: "vxlan_processor stage validation failure",
    0xDEAD0050: "nat_engine context failure",
    0xDEAD0051: "nat_engine stage validation failure",
    0xDEAD0060: "forwarding_stage context failure",
    
    # Ring Buffer Failures (0xDEAD004X)
    0xDEAD0040: "temp_len zero error",
    0xDEAD0041: "Insufficient data error", 
    0xDEAD0042: "Ring buffer copy failure",
    0xDEAD0043: "Forward packet eth header bounds failure",
    
    # Configuration Failures (0xBAD0000X)
    0xBAD00001: "Interface config failure",
    0xBAD00002: "NAT config failure",
    0xBAD00003: "Target ifindex failure",
    
    # VXLAN Parse Specific (0xDEAD0002)
    0xDEAD0002: "VNI validation failure in parse_vxlan"
}

def get_bpf_stats() -> Dict[int, int]:
    """Get BPF statistics from kernel via bpftool."""
    try:
        result = subprocess.run(
            ['sudo', 'bpftool', 'map', 'dump', 'name', 'stats_map', '--json'],
            capture_output=True, text=True, check=True
        )
        data = json.loads(result.stdout)
        
        stats = {}
        for item in data:
            key = int(item['key'][0], 16)
            total = sum(cpu['value'] for cpu in item['formatted']['values'])
            stats[key] = total
            
        return stats
        
    except subprocess.CalledProcessError as e:
        print(f"Error running bpftool: {e}")
        print(f"Make sure you have sudo privileges and the stats_map exists")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error parsing bpftool JSON output: {e}")
        sys.exit(1)

def analyze_debug_markers(stats: Dict[int, int]) -> List[Tuple[str, int]]:
    """Analyze debug markers in PACKET_SIZE_DEBUG counter."""
    debug_values = []
    
    # Get debug counter values per CPU
    try:
        result = subprocess.run(
            ['sudo', 'bpftool', 'map', 'dump', 'name', 'stats_map', '--json'],
            capture_output=True, text=True, check=True
        )
        data = json.loads(result.stdout)
        
        for item in data:
            if int(item['key'][0], 16) == 0x0e:  # PACKET_SIZE_DEBUG
                debug_values = [cpu['value'] for cpu in item['formatted']['values']]
                break
                
    except Exception as e:
        print(f"Error getting debug values: {e}")
        return []
    
    found_markers = []
    
    for i, val in enumerate(debug_values[:4]):  # Check first 4 CPUs
        if val in DEBUG_MARKERS:
            found_markers.append((DEBUG_MARKERS[val], val))
        elif val > 0:
            # Check if it's packed debug data or unknown marker
            if val > 0xFFFFFFFF:
                high_16 = (val >> 16) & 0xFFFF
                low_16 = val & 0xFFFF
                found_markers.append((f"Packed debug data: high={high_16}, low={low_16}", val))
            else:
                # Check if it's a known debug pattern
                found_markers.append((f"Unknown debug marker: 0x{val:x}", val))
    
    return found_markers

def print_performance_summary(stats: Dict[int, int]):
    """Print high-level performance metrics."""
    total = stats.get(0x00, 0)
    vxlan = stats.get(0x01, 0) 
    errors = stats.get(0x07, 0)
    ringbuf = stats.get(0x0d, 0)
    bounds = stats.get(0x0c, 0)
    
    print("=" * 60)
    print("VXLAN PIPELINE PERFORMANCE SUMMARY")
    print("=" * 60)
    
    print(f"📊 PACKET COUNTERS:")
    print(f"   Total Packets:      {total:,}")
    print(f"   VXLAN Packets:      {vxlan:,}")
    print(f"   Errors:             {errors:,}")
    print(f"   Successful Submits: {ringbuf:,}")
    print(f"   Bounds Failures:    {bounds:,}")
    
    print(f"\n📈 SUCCESS METRICS:")
    if total > 0:
        print(f"   Error Rate:         {(errors/total*100):.1f}%")
        print(f"   VXLAN Detection:    {(vxlan/total*100):.1f}%")
    
    if vxlan > 0:
        ratio = errors / vxlan if vxlan > 0 else 0
        success_rate = (ringbuf / vxlan * 100) if vxlan > 0 else 0
        print(f"   Error-to-VXLAN Ratio: {ratio:.6f}")
        print(f"   Success Rate:       {success_rate:.1f}%")
        
        # Systematic error detection
        if 0.99 <= ratio <= 1.01:
            print(f"   🚨 SYSTEMATIC ERROR DETECTED: ~1:1 error ratio indicates")
            print(f"      one error per VXLAN packet regardless of success rate!")
    
    print(f"\n💾 PROCESSING METRICS:")
    bytes_processed = stats.get(0x08, 0)
    nat_applied = stats.get(0x03, 0)
    df_cleared = stats.get(0x04, 0)
    
    print(f"   Bytes Processed:    {bytes_processed:,}")
    print(f"   NAT Applied:        {nat_applied:,}")
    print(f"   DF Bit Cleared:     {df_cleared:,}")

def print_detailed_stats(stats: Dict[int, int]):
    """Print detailed statistics breakdown."""
    print("\n" + "=" * 60)
    print("DETAILED STATISTICS BREAKDOWN")
    print("=" * 60)
    
    for key, value in sorted(stats.items()):
        stat_name = STATS_MAP.get(key, f"UNKNOWN_0x{key:02x}")
        if value > 0:  # Only show non-zero stats
            print(f"   {stat_name:20s}: {value:,}")

def print_debug_analysis(debug_markers: List[Tuple[str, int]]):
    """Print debug marker analysis."""
    print("\n" + "=" * 60) 
    print("DEBUG MARKER ANALYSIS - SYSTEMATIC ERROR SOURCE")
    print("=" * 60)
    
    if not debug_markers:
        print("✅ No debug markers detected - all error paths are clean!")
        return
        
    print("🔍 DETECTED ERROR SOURCES:")
    
    systematic_errors = []
    other_markers = []
    
    for description, value in debug_markers:
        if any(marker in hex(value) for marker in ['dead', 'bad']) or value in DEBUG_MARKERS:
            systematic_errors.append((description, value))
        else:
            other_markers.append((description, value))
    
    # Show systematic errors first (most important)
    if systematic_errors:
        print("\n   🚨 SYSTEMATIC ERROR MARKERS:")
        for desc, val in systematic_errors:
            print(f"      ▶ {desc}")
            print(f"        Marker: 0x{val:x}")
            if val in DEBUG_MARKERS:
                print(f"        Impact: Counts toward STAT_ERRORS for every occurrence")
    
    # Show other debug data
    if other_markers:
        print("\n   📊 OTHER DEBUG DATA:")
        for desc, val in other_markers:
            print(f"      ▶ {desc}")

def print_recommendations(stats: Dict[int, int], debug_markers: List[Tuple[str, int]]):
    """Print actionable recommendations."""
    print("\n" + "=" * 60)
    print("RECOMMENDATIONS")
    print("=" * 60)
    
    vxlan = stats.get(0x01, 0)
    errors = stats.get(0x07, 0) 
    ringbuf = stats.get(0x0d, 0)
    
    ratio = errors / vxlan if vxlan > 0 else 0
    
    if 0.99 <= ratio <= 1.01:
        print("🎯 SYSTEMATIC ERROR ELIMINATION:")
        print("   The 1:1 error ratio indicates a systematic issue where")
        print("   exactly one error is counted per VXLAN packet.")
        
        if debug_markers:
            print("\n   Based on debug markers, focus on:")
            for desc, val in debug_markers[:3]:  # Top 3 most frequent
                if val in DEBUG_MARKERS:
                    print(f"   ▶ Fix: {desc}")
        else:
            print("\n   ✅ All instrumented error paths are clean!")
            print("   🔍 Check uninstrumented code paths or")
            print("       review statistics increment logic.")
    
    success_rate = (ringbuf / vxlan * 100) if vxlan > 0 else 0
    if success_rate > 80:
        print(f"\n✅ PERFORMANCE: {success_rate:.1f}% success rate is excellent!")
    elif success_rate > 60:
        print(f"\n⚠️  PERFORMANCE: {success_rate:.1f}% success rate is good but can improve")
    else:
        print(f"\n🚨 PERFORMANCE: {success_rate:.1f}% success rate needs attention!")

def main():
    """Main analysis function."""
    print("Analyzing eBPF VXLAN Pipeline Statistics...")
    
    # Get statistics
    stats = get_bpf_stats()
    
    if not stats:
        print("No statistics found. Make sure the eBPF program is loaded.")
        return
        
    # Analyze debug markers
    debug_markers = analyze_debug_markers(stats)
    
    # Print analysis
    print_performance_summary(stats)
    print_detailed_stats(stats)
    print_debug_analysis(debug_markers)
    print_recommendations(stats, debug_markers)
    
    print("\n" + "=" * 60)
    print("Analysis complete! Use this data to optimize your pipeline.")
    print("=" * 60)

if __name__ == "__main__":
    main()