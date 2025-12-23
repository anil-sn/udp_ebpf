// SPDX-License-Identifier: GPL-2.0
/*
 * Production eBPF/XDP UDP DF Modifier
 * 
 * ARCHITECTURE:
 * This XDP program operates at the network driver level, intercepting packets
 * before they enter the kernel network stack. It specifically targets UDP packets
 * to port 31765 that exceed 1400 bytes and clears their DF (Don't Fragment) bit
 * to prevent fragmentation issues in high-throughput scenarios.
 *
 * PERFORMANCE DESIGN:
 * - Zero-copy packet processing at driver level
 * - Per-CPU statistics maps for scalable monitoring
 * - Minimal branching for optimal CPU cache utilization
 * - Comprehensive bounds checking for security
 * - Always passes packets (XDP_PASS) - never drops
 *
 * SAFETY FEATURES:
 * - Extensive packet boundary validation
 * - Size limits to prevent processing malformed packets
 * - Conservative modification approach
 * - Statistics-only monitoring (no performance-affecting logs)
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* IP header flags */
#define IP_DF 0x4000  /* Don't fragment flag */

/* Configuration Constants */
// Target UDP destination port for DF bit modification
#define TARGET_PORT 31765

// Packet size thresholds for processing
#define MIN_PACKET_SIZE 1400  // Only process packets likely to fragment
#define MAX_PACKET_SIZE 9000  // Reject oversized packets (jumbo frame limit)

/*
 * Per-CPU Statistics Map
 * 
 * Uses BPF_MAP_TYPE_PERCPU_ARRAY for optimal performance:
 * - Each CPU maintains independent counters (no locking)
 * - Userspace sums values across all CPUs for totals
 * - Minimal overhead for high-frequency updates
 * - Shared with userspace for real-time monitoring
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4);
} stats_map SEC(".maps");

/* Statistics Counter Indices */
enum stats_index {
    STAT_TOTAL_PACKETS = 0,    /* All packets examined by XDP hook */
    STAT_UDP_PACKETS = 1,      /* UDP packets that passed initial filtering */
    STAT_MODIFIED_PACKETS = 2, /* Packets where DF bit was actually cleared */
    STAT_BYTES_PROCESSED = 3,  /* Total bytes of processed traffic */
};

/*
 * Optimized IP Header Checksum Calculation
 * 
 * PERFORMANCE OPTIMIZATIONS:
 * - Always inlined to avoid function call overhead
 * - Loop unrolling for predictable execution time
 * - 16-bit word processing for CPU efficiency
 * - Minimal branching in carry calculation
 * 
 * ALGORITHM: RFC 791 Internet Checksum
 * 1. Zero the checksum field
 * 2. Sum all 16-bit words in header
 * 3. Add carry bits until none remain
 * 4. Return one's complement of result
 */
static __always_inline __u16 ip_checksum(struct iphdr *iph)
{
    __u32 sum = 0;
    __u16 *ptr = (__u16 *)iph;
    
    /* Clear existing checksum field */
    iph->check = 0;
    
    /* Sum all 16-bit words in IP header (unrolled for performance) */
    #pragma unroll
    for (unsigned int i = 0; i < (sizeof(struct iphdr) / 2); i++) {
        sum += ptr[i];
    }
    
    /* Fold 32-bit sum to 16-bit by adding carry bits */
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    /* Return one's complement */
    return ~sum;
}

/*
 * Atomic Statistics Update
 * 
 * PERFORMANCE NOTES:
 * - Always inlined to eliminate function call overhead
 * - Per-CPU map ensures no cross-CPU synchronization needed
 * - Null check prevents kernel panic if map lookup fails
 * - Direct pointer arithmetic for minimal CPU cycles
 */
static __always_inline void update_stat(__u32 index, __u64 value)
{
    __u64 *stat = bpf_map_lookup_elem(&stats_map, &index);
    if (stat) {
        *stat += value;  /* Atomic on per-CPU maps */
    }
    /* Note: No error logging here to maintain performance */
}

// Main XDP program entry point
SEC("xdp")
int udp_df_modifier(struct xdp_md *ctx)
{
    // Get packet data boundaries
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Basic packet size validation - ensure minimum Ethernet frame
    if (data + sizeof(struct ethhdr) > data_end) {
        return XDP_PASS; // Too small for valid Ethernet frame
    }
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    
    // Boundary check: ensure we can read Ethernet header
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS; // Malformed packet, let kernel handle it
    }
    
    // Only process IPv4 packets
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }
    
    // Parse IP header
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    
    // Boundary check: ensure we can read IP header
    if ((void *)(iph + 1) > data_end) {
        return XDP_PASS;
    }
    
    // Update total packets counter
    update_stat(STAT_TOTAL_PACKETS, 1);
    
    // Only process UDP packets
    if (iph->protocol != IPPROTO_UDP) {
        return XDP_PASS;
    }
    
    // Validate IP header length (IHL field * 4 bytes)
    int ip_hdr_len = iph->ihl * 4;
    if (ip_hdr_len < (int)sizeof(struct iphdr) || ip_hdr_len > 60) {
        return XDP_PASS; // Invalid IP header length
    }
    
    // Parse UDP header with proper bounds checking
    struct udphdr *udph = (struct udphdr *)((char *)iph + ip_hdr_len);
    
    // Boundary check: ensure we can read UDP header
    if ((void *)(udph + 1) > data_end) {
        return XDP_PASS;
    }
    
    // Update UDP packets counter
    update_stat(STAT_UDP_PACKETS, 1);
    
    // Check if this is our target port (31765)
    if (bpf_ntohs(udph->dest) != TARGET_PORT) {
        return XDP_PASS;
    }
    
    // Check packet size - only modify large packets that might fragment
    __u16 total_len = bpf_ntohs(iph->tot_len);
    if (total_len <= MIN_PACKET_SIZE || total_len > 9000) {
        return XDP_PASS; // Too small or suspiciously large (> jumbo frame)
    }
    
    // Additional validation: ensure total_len matches actual packet size
    if ((char*)data + sizeof(struct ethhdr) + total_len > (char*)data_end) {
        return XDP_PASS; // Packet size mismatch
    }
    
    // Update bytes processed counter
    update_stat(STAT_BYTES_PROCESSED, total_len);
    
    // Check if DF (Don't Fragment) bit is set
    if (iph->frag_off & bpf_htons(IP_DF)) {
        // Clear the DF bit
        iph->frag_off &= ~bpf_htons(IP_DF);
        
        // Recalculate IP checksum
        iph->check = ip_checksum(iph);
        
        // For UDP over IPv4, we can zero the UDP checksum (RFC allows this)
        // This avoids expensive UDP checksum recalculation
        udph->check = 0;
        
        // Update modified packets counter
        update_stat(STAT_MODIFIED_PACKETS, 1);
    }
    
    // Pass packet to network stack for normal processing
    return XDP_PASS;
}

// License required by eBPF verifier
char _license[] SEC("license") = "GPL";