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
    
    # IP Header Validation Failures (0xDEAD010X)
    0xDEAD0100: "IP header length validation failure - SYSTEMATIC ERROR SOURCE",
    0xDEAD0101: "NAT engine IP header length validation failure",
    0xDEAD0102: "NAT apply failure marker",
    
    # Update Packet Headers Failures (0xDEAD020X) - MOST LIKELY SYSTEMATIC ERROR SOURCE
    0xDEAD0200: "IP header bounds after decapsulation - SYSTEMATIC ERROR SOURCE",
    0xDEAD0201: "IP header length validation after decapsulation - SYSTEMATIC ERROR SOURCE", 
    0xDEAD0202: "IP header options bounds after decapsulation - SYSTEMATIC ERROR SOURCE",
    
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
    
    # Tail Call Failures (0xDEAD060X) - LIKELY SYSTEMATIC ERROR SOURCE  
    0xDEAD0600: "Invalid stage number - SYSTEMATIC ERROR SOURCE",
    0xDEAD0601: "Tail call failure - SYSTEMATIC ERROR SOURCE",
    
    # Configuration Failures (0xBAD0000X)
    0xBAD00001: "Interface config failure",
    0xBAD00002: "NAT config failure",
    0xBAD00003: "Target ifindex failure",
    
    # VXLAN Parse Specific (0xDEAD0002)
    0xDEAD0002: "VNI validation failure in parse_vxlan"
}

def get_comprehensive_stats() -> Dict[str, any]:
    """Get comprehensive statistics from all BPF maps."""
    try:
        result = subprocess.run(
            ['sudo', 'bpftool', 'map', 'dump', 'name', 'stats_map', '--json'],
            capture_output=True, text=True, check=True
        )
        data = json.loads(result.stdout)
        
        comprehensive_stats = {
            'counters': {},
            'per_cpu_data': {},
            'debug_markers': [],
            'raw_data': data
        }
        
        for item in data:
            key = int(item['key'][0], 16)
            
            # Handle different data structures (formatted vs direct values)
            if 'formatted' in item and 'values' in item['formatted']:
                # New format with formatted values
                total = sum(cpu['value'] for cpu in item['formatted']['values'])
                per_cpu_values = [cpu['value'] for cpu in item['formatted']['values']]
            elif 'value' in item:
                # Direct format - could be array or single value
                if isinstance(item['value'], list):
                    total = sum(item['value'])
                    per_cpu_values = item['value']
                else:
                    total = item['value']
                    per_cpu_values = [item['value']]
            else:
                # Fallback - skip malformed entries
                continue
                
            comprehensive_stats['counters'][key] = total
            comprehensive_stats['per_cpu_data'][key] = per_cpu_values
            
            # Special handling for debug markers
            if key == 0x0e:  # PACKET_SIZE_DEBUG
                for cpu_idx, cpu_data in enumerate(item['formatted']['values']):
                    val = cpu_data['value']
                    if val > 0 and val in DEBUG_MARKERS:
                        comprehensive_stats['debug_markers'].append({
                            'cpu': cpu_idx,
                            'value': val,
                            'description': DEBUG_MARKERS[val],
                            'hex': f"0x{val:x}"
                        })
        
        return comprehensive_stats
        
    except subprocess.CalledProcessError as e:
        print(f"Error running bpftool: {e}")
        return {}
    except json.JSONDecodeError as e:
        print(f"Error parsing bpftool JSON output: {e}")
        return {}

def get_bpf_stats() -> Dict[int, int]:
    """Get BPF statistics from kernel via bpftool."""
    comprehensive = get_comprehensive_stats()
    return comprehensive.get('counters', {})

def analyze_debug_markers(stats: Dict[int, int]) -> List[Tuple[str, int]]:
    """Analyze debug markers in PACKET_SIZE_DEBUG counter."""
    debug_values = []
    debug_per_cpu = []
    
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
                debug_per_cpu = item['formatted']['values']
                break
                
    except Exception as e:
        print(f"Error getting debug values: {e}")
        return []
    
    found_markers = []
    systematic_error_markers = []
    
    # Check all CPUs for debug markers
    for i, val in enumerate(debug_values):
        if val == 0:
            continue
            
        # Check for exact debug marker matches
        if val in DEBUG_MARKERS:
            marker_info = (DEBUG_MARKERS[val], val)
            found_markers.append(marker_info)
            
            # Track systematic error markers separately
            if "SYSTEMATIC ERROR SOURCE" in DEBUG_MARKERS[val]:
                systematic_error_markers.append(marker_info)
            
        elif val > 0:
            # Enhanced packed data analysis for large values
            if val > 0xFFFFFFFF:
                # Try different unpacking strategies
                
                # Strategy 1: High/Low 32-bit words
                high_32 = (val >> 32) & 0xFFFFFFFF
                low_32 = val & 0xFFFFFFFF
                
                # Strategy 2: High/Low 16-bit words  
                high_16 = (val >> 16) & 0xFFFF
                low_16 = val & 0xFFFF
                
                # Strategy 3: Extract potential DEAD markers from the full value
                hex_str = hex(val).lower()
                
                marker_found = False
                
                # Check if any of our debug markers are embedded
                for marker_val, marker_desc in DEBUG_MARKERS.items():
                    marker_hex = hex(marker_val)[2:]  # Remove '0x'
                    if marker_hex in hex_str:
                        found_markers.append((f"Embedded marker: {marker_desc}", marker_val))
                        if "SYSTEMATIC ERROR SOURCE" in marker_desc:
                            systematic_error_markers.append((f"Embedded: {marker_desc}", marker_val))
                        marker_found = True
                        break
                
                # If no embedded markers found, check the unpacked values
                if not marker_found:
                    if high_32 in DEBUG_MARKERS:
                        found_markers.append((f"High 32-bit: {DEBUG_MARKERS[high_32]}", high_32))
                        if "SYSTEMATIC ERROR SOURCE" in DEBUG_MARKERS[high_32]:
                            systematic_error_markers.append((f"High 32-bit: {DEBUG_MARKERS[high_32]}", high_32))
                        marker_found = True
                    elif low_32 in DEBUG_MARKERS:
                        found_markers.append((f"Low 32-bit: {DEBUG_MARKERS[low_32]}", low_32))
                        if "SYSTEMATIC ERROR SOURCE" in DEBUG_MARKERS[low_32]:
                            systematic_error_markers.append((f"Low 32-bit: {DEBUG_MARKERS[low_32]}", low_32))
                        marker_found = True
                    elif high_16 in DEBUG_MARKERS:
                        found_markers.append((f"High 16-bit: {DEBUG_MARKERS[high_16]}", high_16))
                        if "SYSTEMATIC ERROR SOURCE" in DEBUG_MARKERS[high_16]:
                            systematic_error_markers.append((f"High 16-bit: {DEBUG_MARKERS[high_16]}", high_16))
                        marker_found = True
                    elif low_16 in DEBUG_MARKERS:
                        found_markers.append((f"Low 16-bit: {DEBUG_MARKERS[low_16]}", low_16))
                        if "SYSTEMATIC ERROR SOURCE" in DEBUG_MARKERS[low_16]:
                            systematic_error_markers.append((f"Low 16-bit: {DEBUG_MARKERS[low_16]}", low_16))
                        marker_found = True
                
                # If still no marker found, show the packed data with detailed hex analysis
                if not marker_found:
                    found_markers.append((f"Packed data 0x{val:x}: high32=0x{high_32:x}, low32=0x{low_32:x}, high16=0x{high_16:x}, low16=0x{low_16:x}", val))
            else:
                # Check for partial marker matches or unknown patterns
                hex_val = hex(val)
                if 'dead' in hex_val.lower():
                    found_markers.append((f"Potential DEAD marker: 0x{val:x}", val))
                elif 'bad' in hex_val.lower():
                    found_markers.append((f"Configuration error marker: 0x{val:x}", val))
                else:
                    found_markers.append((f"Unknown debug value: {val} (0x{val:x})", val))
    
    return found_markers

def check_specific_debug_markers():
    """Check for specific debug markers that might indicate systematic errors."""
    try:
        result = subprocess.run(
            ['sudo', 'bpftool', 'map', 'dump', 'name', 'stats_map', '--json'],
            capture_output=True, text=True, check=True
        )
        data = json.loads(result.stdout)
        
        print("\n" + "=" * 60)
        print("SPECIFIC DEBUG MARKER DETECTION")
        print("=" * 60)
        
        # Target markers that are likely systematic error sources
        target_markers = {
            0xDEAD0040: "temp_len zero error marker - SYSTEMATIC ERROR SOURCE",
            0xDEAD0041: "Insufficient data error marker - SYSTEMATIC ERROR SOURCE",
            0xDEAD0042: "Ring buffer copy failure marker - SYSTEMATIC ERROR SOURCE",
            0xDEAD0100: "IP header length validation failure - SYSTEMATIC ERROR SOURCE",
            0xDEAD0200: "IP header bounds after decapsulation - SYSTEMATIC ERROR SOURCE", 
            0xDEAD0201: "IP header length validation after decapsulation - SYSTEMATIC ERROR SOURCE",
            0xDEAD0600: "Invalid stage number - SYSTEMATIC ERROR SOURCE",
            0xDEAD0601: "Tail call failure - SYSTEMATIC ERROR SOURCE",
            0xBAD00001: "Interface config failure - SYSTEMATIC ERROR SOURCE",
            0xBAD00002: "NAT config failure - SYSTEMATIC ERROR SOURCE", 
            0xBAD00003: "Target ifindex failure - SYSTEMATIC ERROR SOURCE"
        }
        
        found_any = False
        
        for item in data:
            if int(item['key'][0], 16) == 0x0e:  # PACKET_SIZE_DEBUG
                print("Checking PACKET_SIZE_DEBUG values per CPU:")
                
                for cpu_idx, cpu_data in enumerate(item['formatted']['values']):
                    val = cpu_data['value']
                    if val == 0:
                        continue
                        
                    print(f"\nCPU{cpu_idx}: {val} (0x{val:x})")
                    
                    # Check for exact matches first
                    for marker_val, marker_desc in target_markers.items():
                        if val == marker_val:
                            print(f"  *** EXACT MATCH: {marker_desc} ***")
                            found_any = True
                    
                    # Check if this large value contains our target markers
                    if val > 0xFFFFFFFF:
                        hex_str = hex(val).lower()
                        for marker_val, marker_desc in target_markers.items():
                            marker_hex = hex(marker_val)[2:]  # Remove '0x'
                            if marker_hex in hex_str:
                                print(f"  *** EMBEDDED: {marker_desc} ***")
                                found_any = True
                    
                    # Check for any DEAD markers
                    hex_str = hex(val).lower()
                    if 'dead' in hex_str:
                        print(f"  Contains DEAD marker pattern")
                        found_any = True
                
                break
        
        if not found_any:
            print("No target systematic error markers detected.")
            print("This suggests the systematic error is in an uninstrumented code path.")
        
        return found_any
        
    except Exception as e:
        print(f"Error checking specific markers: {e}")
        return False

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
    
    print(f"PACKET COUNTERS:")
    print(f"   Total Packets:      {total:,}")
    print(f"   VXLAN Packets:      {vxlan:,}")
    print(f"   Errors:             {errors:,}")
    print(f"   Successful Submits: {ringbuf:,}")
    print(f"   Bounds Failures:    {bounds:,}")
    
    print(f"\nSUCCESS METRICS:")
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
            print(f"   SYSTEMATIC ERROR DETECTED: ~1:1 error ratio indicates")
            print(f"      one error per VXLAN packet regardless of success rate!")
    
    print(f"\nPROCESSING METRICS:")
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
    
    # Get comprehensive data for per-CPU analysis
    comprehensive = get_comprehensive_stats()
    per_cpu_data = comprehensive.get('per_cpu_data', {})
    
    for key, value in sorted(stats.items()):
        stat_name = STATS_MAP.get(key, f"UNKNOWN_0x{key:02x}")
        if value > 0:  # Only show non-zero stats
            print(f"   {stat_name:25s}: {value:,}")
            
            # Show per-CPU breakdown for key statistics
            if key in [0x00, 0x01, 0x07, 0x0d, 0x0e] and key in per_cpu_data:
                cpu_values = per_cpu_data[key]
                non_zero_cpus = [(i, v) for i, v in enumerate(cpu_values) if v > 0]
                if len(non_zero_cpus) > 1:
                    print(f"     Per-CPU breakdown: ", end="")
                    for i, (cpu, val) in enumerate(non_zero_cpus[:4]):  # Show first 4 CPUs
                        print(f"CPU{cpu}={val:,}", end="")
                        if i < len(non_zero_cpus) - 1 and i < 3:
                            print(", ", end="")
                    if len(non_zero_cpus) > 4:
                        print(f", +{len(non_zero_cpus) - 4} more")
                    else:
                        print()

def print_debug_analysis(debug_markers: List[Tuple[str, int]]):
    """Print debug marker analysis."""
    print("\n" + "=" * 60) 
    print("DEBUG MARKER ANALYSIS - SYSTEMATIC ERROR SOURCE")
    print("=" * 60)
    
    if not debug_markers:
        print("No debug markers detected - all error paths are clean!")
        print("   This suggests the systematic error is in an uninstrumented path.")
        return
        
    print("DETECTED ERROR SOURCES:")
    
    systematic_errors = []
    config_errors = []
    bounds_errors = []
    other_markers = []
    
    # Categorize markers for better analysis
    for description, value in debug_markers:
        hex_str = hex(value).lower()
        
        if "systematic error source" in description.lower():
            systematic_errors.append((description, value))
        elif any(marker in hex_str for marker in ['0xbad', 'config', 'interface']):
            config_errors.append((description, value))
        elif "bounds" in description.lower():
            bounds_errors.append((description, value))
        elif any(marker in hex_str for marker in ['0xdead']):
            other_markers.append((description, value))
        else:
            other_markers.append((description, value))
    
    # Show systematic errors first (highest priority)
    if systematic_errors:
        print("\n   SYSTEMATIC ERROR MARKERS (CRITICAL):")
        for desc, val in systematic_errors:
            print(f"      - {desc}")
            print(f"        Marker: 0x{val:x}")
            print(f"        Impact: This is likely the 1:1 error source!")
            
    # Show configuration errors
    if config_errors:
        print("\n   CONFIGURATION ERROR MARKERS:")
        for desc, val in config_errors:
            print(f"      - {desc}")
            print(f"        Marker: 0x{val:x}")
            print(f"        Impact: Configuration issue affecting all packets")
    
    # Show bounds check errors
    if bounds_errors:
        print("\n   BOUNDS CHECK ERROR MARKERS:")
        for desc, val in bounds_errors:
            print(f"      - {desc}")
            print(f"        Marker: 0x{val:x}")
            print(f"        Impact: Packet validation failure")
    
    # Show other debug data
    if other_markers:
        print("\n   OTHER DEBUG MARKERS:")
        for desc, val in other_markers[:5]:  # Limit to first 5 to avoid spam
            print(f"      - {desc}")
            if val < 0xFFFFFFFF:
                print(f"        Marker: 0x{val:x}")
        
        if len(other_markers) > 5:
            print(f"      ... and {len(other_markers) - 5} more debug markers")
    
    # Provide specific guidance based on detected markers
    if systematic_errors:
        print("\n   SYSTEMATIC ERROR ANALYSIS:")
        print("     The detected systematic error markers indicate the exact")
        print("     code path causing the 1:1 error pattern. Focus debugging")
        print("     efforts on these specific functions.")
    elif config_errors:
        print("\n   CONFIGURATION ERROR ANALYSIS:")
        print("     Configuration errors suggest setup issues that affect")
        print("     every packet. Check map configurations and initialization.")
    elif bounds_errors:
        print("\n   BOUNDS CHECK ANALYSIS:")
        print("     Bounds check failures suggest packet parsing issues.")
        print("     Check packet structure assumptions and validation logic.")

def print_recommendations(stats: Dict[int, int], debug_markers: List[Tuple[str, int]]):
    """Print actionable recommendations based on comprehensive analysis."""
    print("\n" + "=" * 60)
    print("RECOMMENDATIONS & ANALYSIS")
    print("=" * 60)
    
    # Get comprehensive analysis data
    comprehensive = get_comprehensive_stats()
    per_cpu_data = comprehensive.get('per_cpu_data', {})
    
    # Correct mapping: 0x00=RX, 0x01=ERRORS, 0x07=VXLAN, 0x0d=RINGBUF
    rx_packets = stats.get(0x00, 0)
    error_count = stats.get(0x01, 0)  
    vxlan_packets = stats.get(0x07, 0)
    ringbuf_success = stats.get(0x0d, 0)
    
    if rx_packets > 0 and vxlan_packets > 0:
        error_to_vxlan_ratio = error_count / vxlan_packets if vxlan_packets > 0 else 0
        success_rate = (rx_packets - error_count) / rx_packets if rx_packets > 0 else 0
        processing_efficiency = (vxlan_packets / rx_packets) if rx_packets > 0 else 0
        
        print(f"KEY METRICS:")
        print(f"   Success Rate: {success_rate:.1%}")
        print(f"   Error-to-VXLAN Ratio: {error_to_vxlan_ratio:.6f}")
        print(f"   Processing Efficiency: {processing_efficiency:.1%}")
        print(f"   Ringbuf Success Rate: {(ringbuf_success/vxlan_packets):.1%}" if vxlan_packets > 0 else "   Ringbuf Success Rate: N/A")
        
        if 0.99 <= error_to_vxlan_ratio <= 1.01:  # Close to 1:1 ratio
            print("\nCRITICAL: Systematic 1:1 error pattern detected!")
            print("   Every VXLAN packet appears to generate exactly one error.")
            print("   This indicates a fundamental issue in error counting logic.")
            
            # Analyze debug markers to identify source
            if debug_markers:
                print("\nDEBUG MARKER ANALYSIS:")
                for desc, val in debug_markers[:5]:  # Show top 5 markers
                    if val in DEBUG_MARKERS:
                        marker_info = DEBUG_MARKERS[val]
                        print(f"   0x{val:x}: {desc}")
                        print(f"      Description: {marker_info}")
                        
                        # Show per-CPU distribution if available
                        if 0x0e in per_cpu_data:
                            cpu_values = per_cpu_data[0x0e]
                            active_cpus = [i for i, v in enumerate(cpu_values) if v > 0]
                            if len(active_cpus) > 1:
                                print(f"      CPU Distribution: {len(active_cpus)} CPUs active")
                
                print("\nSYSTEMATIC ERROR ELIMINATION PLAN:")
                print("   1. IMMEDIATE: Focus on the debug marker(s) with highest counts above")
                print("   2. ANALYZE: Review the specific code paths in vxlan_pipeline.bpf.c")
                print("   3. FIX: Remove or correct the double-counting error logic")
                print("   4. VERIFY: Recompile and test to confirm ratio approaches 0")
            else:
                print("\nRECOMMENDED ACTIONS:")
                print("   1. All instrumented error paths are clean!")
                print("   2. Check uninstrumented code paths or")
                print("   3. Review statistics increment logic for systematic issues")
                print("   4. Add debug markers to any remaining untracked error paths")
        else:
            print(f"\nError pattern appears normal (ratio: {error_to_vxlan_ratio:.3f})")
    
    # Performance analysis
    if rx_packets > 0:
        if success_rate > 0.80:
            print(f"\nPERFORMANCE: {success_rate:.1%} success rate is excellent!")
        elif success_rate > 0.60:
            print(f"\nPERFORMANCE: {success_rate:.1%} success rate is good but can improve")
        else:
            print(f"\nPERFORMANCE: {success_rate:.1%} success rate needs attention!")
    
    # Additional error analysis
    error_types = []
    if stats.get(0x02, 0) > 0:
        error_types.append("Memory allocation failures")
    if stats.get(0x03, 0) > 0:
        error_types.append("Packet parsing errors")
    if stats.get(0x0c, 0) > 0:
        error_types.append("Processing pipeline errors")
    
    if error_types:
        print(f"\nADDITIONAL ISSUES DETECTED:")
        for error_type in error_types:
            print(f"   - {error_type}")
        print("   Review corresponding code paths for these specific error types")

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
    
    # Check for specific systematic error markers
    check_specific_debug_markers()
    
    print_recommendations(stats, debug_markers)
    
    print("\n" + "=" * 60)
    print("Analysis complete! Use this data to optimize your pipeline.")
    print("=" * 60)

if __name__ == "__main__":
    main()