/*
 * VXLAN Pipeline XDP Program - Userspace Control Plane
 * 
 * ARCHITECTURE OVERVIEW:
 * =====================
 * This userspace program serves as the control plane for the high-performance
 * XDP VXLAN processing pipeline. It manages the complete lifecycle of the
 * eBPF program and provides real-time monitoring and configuration capabilities.
 * 
 * CORE RESPONSIBILITIES:
 * =====================
 * 1. eBPF Program Management:
 *    - Load and verify eBPF bytecode from compiled .o file
 *    - Attach XDP program to network interface with optimal mode selection
 *    - Configure eBPF maps with runtime parameters (NAT rules, redirect targets)
 *    - Handle graceful program detachment and cleanup on exit/signals
 * 
 * 2. Configuration Management:
 *    - Parse command-line arguments for flexible deployment options
 *    - Configure NAT (Network Address Translation) rules via eBPF hash maps
 *    - Set up packet forwarding targets via redirect interface maps
 *    - Validate all configuration parameters before application
 * 
 * 3. Real-time Performance Monitoring:
 *    - Collect per-CPU statistics from eBPF maps with configurable intervals
 *    - Aggregate counters across all CPU cores for system-wide metrics
 *    - Calculate real-time packet rates, throughput, and error percentages
 *    - Display comprehensive performance dashboard with rate calculations
 * 
 * 4. System Integration:
 *    - Comprehensive command-line interface for operational flexibility
 *    - Signal handling (SIGINT, SIGTERM) for graceful shutdown
 *    - Automatic resource cleanup on all exit paths
 *    - Error recovery and diagnostic information
 * 
 * TARGET WORKLOAD:
 * ===============
 * Designed for sustained processing of 85,000+ packets per second from
 * AWS Traffic Mirror VXLAN streams with comprehensive monitoring and
 * sub-microsecond per-packet processing latency.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <time.h>
#include <termios.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <getopt.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/if_link.h>

#include "vxlan_pipeline.h"

/* Statistics indices - must match eBPF program */
enum stats_index {
    STAT_TOTAL_PACKETS = 0,
    STAT_VXLAN_PACKETS = 1,
    STAT_INNER_PACKETS = 2,
    STAT_NAT_APPLIED = 3,
    STAT_DF_CLEARED = 4,
    STAT_FORWARDED = 5,
    STAT_REDIRECTED = 6,      /* New: packets redirected via XDP_REDIRECT */
    STAT_ERRORS = 7,
    STAT_BYTES_PROCESSED = 8,
    STAT_MAX_ENTRIES = 9,
};

/* NAT Entry Structure - must match eBPF program */
struct nat_entry {
    __u32 target_ip;
    __u16 target_port;
    __u16 flags;
} __attribute__((packed, aligned(4)));

/* NAT Key Structure - Source port based */
struct nat_key {
    __u16 src_port;
} __attribute__((packed));

/* Interface Configuration Structure - must match eBPF program */
struct interface_config {
    __u8 mac_addr[6];       /* Target interface MAC address */
    __u32 ifindex;          /* Interface index for validation */
} __attribute__((packed));

/* NAT Target Configuration Structure - must match eBPF program */
struct nat_target_config {
    __u8 mac_addr[6];       /* NAT target IP's MAC address */
    __u32 ip_addr;          /* NAT target IP for validation */
} __attribute__((packed));

/* Global variables for cleanup */
static struct bpf_object *bpf_obj = NULL;
static int prog_fd = -1;
static int stats_map_fd = -1;
static int nat_map_fd = -1;
static int redirect_map_fd = -1;
static int interface_map_fd = -1;  /* New: interface configuration map */
static int nat_target_map_fd = -1; /* New: NAT target configuration map */
static int ifindex = -1;
static volatile sig_atomic_t running = 1;

/* Configuration */
struct config {
    char interface[IF_NAMESIZE];
    char target_interface[IF_NAMESIZE];
    char nat_target_ip[INET_ADDRSTRLEN];
    __u8 nat_target_mac[6];         /* Pre-resolved NAT target MAC address */
    int nat_target_port;
    int nat_source_port;
    int stats_interval;
    int verbose;
};

static struct config cfg = {
    .interface = "ens5",
    .target_interface = "ens6", 
    .nat_target_ip = "172.30.82.95",
    .nat_target_mac = {0},              /* Will be resolved at startup */
    .nat_target_port = 8081,
    .nat_source_port = 31765,
    .stats_interval = 5,
    .verbose = 0,
};

/* Signal handler for graceful shutdown */
static void signal_handler(int sig)
{
    /* Restore terminal immediately */
    fflush(stdout);
    fflush(stderr);
    printf("\nReceived signal %d, shutting down gracefully...\n", sig);
    running = 0;
}

/* Cleanup function */
static void cleanup()
{
    /* Flush output streams */
    fflush(stdout);
    fflush(stderr);
    
    if (ifindex > 0 && prog_fd >= 0) {
        if (bpf_set_link_xdp_fd(ifindex, -1, 0) < 0) {
            fprintf(stderr, "Warning: Failed to detach XDP program\n");
        } else if (cfg.verbose) {
            printf("XDP program detached from interface %s\n", cfg.interface);
        }
    }
    
    if (bpf_obj) {
        bpf_object__close(bpf_obj);
        bpf_obj = NULL; /* Prevent double free */
    }
    
    /* Final flush */
    fflush(stdout);
    fflush(stderr);
}

/*
 * GET AGGREGATED STATISTICS FROM PER-CPU MAP
 * ==========================================
 * 
 * eBPF programs use per-CPU maps to avoid contention during high-frequency
 * counter updates. Each CPU core maintains its own copy of statistics counters,
 * which eliminates atomic operations and cache line bouncing that would occur
 * with shared counters.
 * 
 * PERFORMANCE BENEFITS:
 * - Zero contention: Each CPU updates only its local counters
 * - Cache efficiency: Counters stay in local CPU cache
 * - Atomic-free: No expensive atomic increment operations
 * - Scalability: Performance scales linearly with CPU cores
 * 
 * AGGREGATION PROCESS:
 * 1. Read per-CPU array containing all CPU-specific counter values
 * 2. Sum values across all active CPU cores for total system count
 * 3. Handle variable CPU counts gracefully (containers, NUMA systems)
 * 4. Protect against reading uninitialized memory locations
 * 
 * This function is called frequently (every stats_interval seconds) so
 * efficiency is important for maintaining low overhead monitoring.
 */
static __u64 get_stat_value(int map_fd, __u32 key)
{
    __u64 values[MAX_CPU_CORES]; /* Per-CPU counter array - one entry per CPU core */
    __u64 total = 0;
    int num_cpus;
    
    /* Initialize array to prevent reading garbage values from unused entries */
    memset(values, 0, sizeof(values));
    
    if (bpf_map_lookup_elem(map_fd, &key, values) != 0) {
        return 0;
    }
    
    /* Get actual CPU count to avoid reading uninitialized memory */
    num_cpus = libbpf_num_possible_cpus();
    if (num_cpus < 0 || num_cpus > MAX_CPU_CORES) {
        num_cpus = MAX_CPU_CORES;
    }
    
    /* Sum across actual CPUs only */
    for (int i = 0; i < num_cpus; i++) {
        total += values[i];
    }
    
    return total;
}

/* Initialize statistics to zero for clean startup */
static void init_stats()
{
    __u64 zero_values[MAX_CPU_CORES];
    int num_cpus;
    
    /* Get actual CPU count */
    num_cpus = libbpf_num_possible_cpus();
    if (num_cpus < 0 || num_cpus > MAX_CPU_CORES) {
        num_cpus = MAX_CPU_CORES;
    }
    
    /* Initialize array to zeros */
    memset(zero_values, 0, sizeof(zero_values));
    
    /* Initialize all statistics counters to zero */
    for (int stat = 0; stat < STAT_MAX_ENTRIES; stat++) {
        __u32 key = stat;
        /* Note: For per-CPU maps, we initialize with zero array */
        bpf_map_update_elem(stats_map_fd, &key, zero_values, BPF_ANY);
    }
    
    if (cfg.verbose) {
        printf("Statistics counters initialized (%d CPUs)\n", num_cpus);
    }
}

/*
 * CONFIGURE NAT RULES IN EBPF MAP
 * ===============================
 * 
 * This function sets up Network Address Translation (NAT) rules that the XDP program
 * uses to rewrite packet destinations. The NAT implementation is optimized for the
 * specific use case of redirecting AWS Traffic Mirror VXLAN traffic.
 * 
 * NAT DESIGN PHILOSOPHY:
 * =====================
 * - Source port matching: Identify packets by their destination port (e.g., 31765)
 * - Selective translation: Only packets matching the configured port get NAT'd
 * - Preserve source: Keep original source IP/port for connection tracking
 * - Fast lookup: Hash map provides O(1) lookup performance in XDP context
 * 
 * PACKET TRANSFORMATION:
 * =====================
 * Input:  [Inner Src IP]:[Inner Src Port] → [Inner Dst IP]:31765
 * Output: [Inner Src IP]:[Inner Src Port] → [NAT_IP]:[NAT_PORT]
 * 
 * RATIONALE FOR SOURCE PORT AS KEY:
 * ================================
 * - Deterministic matching: Specific port identification (31765)
 * - Performance: Single hash lookup vs multiple field comparisons
 * - Flexibility: Easy to add multiple NAT rules for different ports
 * - AWS Integration: Traffic Mirror often uses specific destination ports
 * 
 * MAP STRUCTURE:
 * =============
 * Key: Source port in network byte order (uint16_t)
 * Value: NAT entry containing target IP, port, and flags
 */
static int configure_nat_rules()
{
    struct nat_entry entry = {0};
    struct nat_key key = {
        .src_port = htons(cfg.nat_source_port)  /* Network byte order for eBPF map consistency */
    };
    
    /*
     * PARSE AND VALIDATE TARGET IP ADDRESS
     * ===================================
     * Convert dotted decimal notation to binary format for eBPF program.
     * inet_pton() handles IPv4 validation and ensures proper byte ordering.
     */
    if (inet_pton(AF_INET, cfg.nat_target_ip, &entry.target_ip) != 1) {
        fprintf(stderr, "Invalid target IP address: %s\n", cfg.nat_target_ip);
        return -1;
    }
    
    entry.target_port = cfg.nat_target_port;  /* Store in host byte order, will be converted in eBPF */
    entry.flags = 0;
    
    /* Add NAT rule using source port as key (user's design) */
    if (bpf_map_update_elem(nat_map_fd, &key, &entry, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to add NAT rule: %s\n", strerror(errno));
        return -1;
    }
    
    printf("[OK] NAT rule configured: dest_port %d -> %s:%d\n", 
           cfg.nat_source_port, cfg.nat_target_ip, cfg.nat_target_port);
    printf("     (Matches packets TO destination port %d)\n", cfg.nat_source_port);
    
    return 0;
}

/*
 * RESOLVE MAC ADDRESS FROM IP ADDRESS
 * ===================================
 * 
 * This function resolves the MAC address for a given IP address using the
 * system's ARP table. This is critical for proper L2 forwarding to ensure
 * packets reach the correct destination.
 * 
 * RESOLUTION METHODS:
 * 1. Check /proc/net/arp for existing ARP entries
 * 2. If not found, attempt to ping the IP to populate ARP table
 * 3. Re-check ARP table after ping attempt
 * 
 * PERFORMANCE CONSIDERATIONS:
 * - ARP lookup is done once at startup, not per-packet
 * - Cached result avoids runtime network queries
 * - Essential for proper packet delivery in switched networks
 */
static int resolve_ip_to_mac(const char* ip_str, __u8 mac_addr[6])
{
    FILE *arp_table;
    char line[256];
    char arp_ip[16], arp_mac[18];
    int found = 0;
    
    /* First, try to find the IP in the ARP table */
    arp_table = fopen("/proc/net/arp", "r");
    if (!arp_table) {
        perror("Failed to open /proc/net/arp");
        return -1;
    }
    
    /* Skip the header line */
    if (fgets(line, sizeof(line), arp_table) == NULL) {
        fclose(arp_table);
        return -1;
    }
    
    /* Search for the target IP in ARP table */
    while (fgets(line, sizeof(line), arp_table)) {
        if (sscanf(line, "%15s %*s %*s %17s", arp_ip, arp_mac) == 2) {
            if (strcmp(arp_ip, ip_str) == 0 && strlen(arp_mac) == 17) {
                /* Found the IP, parse MAC address */
                if (sscanf(arp_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                          &mac_addr[0], &mac_addr[1], &mac_addr[2],
                          &mac_addr[3], &mac_addr[4], &mac_addr[5]) == 6) {
                    found = 1;
                    break;
                }
            }
        }
    }
    fclose(arp_table);
    
    if (!found) {
        /* IP not in ARP table, try to populate it with ARP probe */
        printf("MAC address for %s not found in ARP table, attempting to resolve via ARP probe...\n", ip_str);
        
        /* Use ip neigh to add a probe entry which triggers ARP resolution */
        char arp_cmd[256];
        snprintf(arp_cmd, sizeof(arp_cmd), "ip neigh add %s dev %s proxy >/dev/null 2>&1 || ip neigh replace %s dev %s nud probe >/dev/null 2>&1", 
                ip_str, cfg.target_interface, ip_str, cfg.target_interface);
        
        int arp_result = system(arp_cmd);
        if (arp_result != 0) {
            printf("Warning: ARP probe for %s failed (exit code: %d)\n", ip_str, arp_result);
            /* Continue anyway, maybe ARP entry exists from other sources */
        }
        
        /* Wait briefly for ARP resolution */
        usleep(500000); /* 500ms delay for ARP resolution */
        
        /* Try ARP table lookup again after ping */
        arp_table = fopen("/proc/net/arp", "r");
        if (!arp_table) {
            perror("Failed to re-open /proc/net/arp");
            return -1;
        }
        
        /* Skip header */
        if (fgets(line, sizeof(line), arp_table) == NULL) {
            fclose(arp_table);
            return -1;
        }
        
        /* Search again */
        while (fgets(line, sizeof(line), arp_table)) {
            if (sscanf(line, "%15s %*s %*s %17s", arp_ip, arp_mac) == 2) {
                if (strcmp(arp_ip, ip_str) == 0 && strlen(arp_mac) == 17) {
                    if (sscanf(arp_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                              &mac_addr[0], &mac_addr[1], &mac_addr[2],
                              &mac_addr[3], &mac_addr[4], &mac_addr[5]) == 6) {
                        found = 1;
                        break;
                    }
                }
            }
        }
        fclose(arp_table);
    }
    
    if (!found) {
        printf("Error: Could not resolve MAC address for IP %s\n", ip_str);
        printf("Please ensure:\n");
        printf("  1. The IP %s is reachable from this host\n", ip_str);
        printf("  2. The target host responds to ping\n");
        printf("  3. No firewall is blocking ICMP\n");
        return -1;
    }
    
    printf("Resolved MAC address for %s: %02x:%02x:%02x:%02x:%02x:%02x\n",
           ip_str, mac_addr[0], mac_addr[1], mac_addr[2],
           mac_addr[3], mac_addr[4], mac_addr[5]);
    
    return 0;
}

/*
 * CONFIGURE TARGET INTERFACE FOR PACKET FORWARDING
 * ================================================
 * 
 * This function sets up the redirect interface configuration that enables
 * the XDP program to forward processed packets to a specific network interface
 * using the high-performance XDP_REDIRECT action.
 * 
 * REDIRECT MECHANISM:
 * ==================
 * - XDP_REDIRECT: Fastest packet forwarding method in XDP
 * - Bypass kernel stack: Direct interface-to-interface forwarding
 * - Zero-copy: Packet buffers passed directly between interfaces
 * - Wire speed: Minimal CPU overhead for packet forwarding
 * 
 * INTERFACE CONFIGURATION REQUIREMENTS:
 * ====================================
 * 1. Interface index: Kernel identifier for target interface
 * 2. MAC address: Layer 2 destination for Ethernet frame construction
 * 3. Validation: Ensure interface exists and is accessible
 * 4. Map population: Store configuration in eBPF maps for XDP access
 * 
 * PERFORMANCE CONSIDERATIONS:
 * ==========================
 * - Interface lookup is done once at startup, not per-packet
 * - MAC address is pre-resolved to avoid ARP lookups in XDP
 * - Configuration is stored in eBPF maps for fast XDP access
 * - Error handling prevents runtime failures in packet processing
 */
static int configure_redirect_interface()
{
    if (strlen(cfg.target_interface) == 0) {
        return 0; /* No redirect configured - packets will be passed to kernel */
    }
    
    /*
     * RESOLVE INTERFACE NAME TO KERNEL INDEX
     * ======================================
     * Convert human-readable interface name (e.g., "ens6") to kernel's
     * internal interface index required by XDP_REDIRECT action.
     */
    int target_ifindex = if_nametoindex(cfg.target_interface);
    if (target_ifindex == 0) {
        fprintf(stderr, "Target interface '%s' not found\n", cfg.target_interface);
        return -1;
    }
    
    /* Configure redirect map */
    __u32 key = 0;
    __u32 value = target_ifindex;
    
    if (bpf_map_update_elem(redirect_map_fd, &key, &value, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to configure redirect interface: %s\n", strerror(errno));
        return -1;
    }
    
    /* Get and configure interface MAC address */
    char mac_file[256];
    snprintf(mac_file, sizeof(mac_file), "/sys/class/net/%s/address", cfg.target_interface);
    
    FILE *f = fopen(mac_file, "r");
    if (!f) {
        fprintf(stderr, "Failed to read MAC address for %s\n", cfg.target_interface);
        return -1;
    }
    
    char mac_str[18];
    if (fgets(mac_str, sizeof(mac_str), f) == NULL) {
        fclose(f);
        fprintf(stderr, "Failed to read MAC address\n");
        return -1;
    }
    fclose(f);
    
    /* Parse MAC address */
    struct interface_config if_config = {0};
    if (sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &if_config.mac_addr[0], &if_config.mac_addr[1], &if_config.mac_addr[2],
               &if_config.mac_addr[3], &if_config.mac_addr[4], &if_config.mac_addr[5]) != 6) {
        fprintf(stderr, "Failed to parse MAC address: %s\n", mac_str);
        return -1;
    }
    
    if_config.ifindex = target_ifindex;
    
    /* Update interface map */
    if (bpf_map_update_elem(interface_map_fd, &key, &if_config, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to configure interface map: %s\n", strerror(errno));
        return -1;
    }
    
    printf("Redirect interface configured: %s (ifindex %d)\n", 
           cfg.target_interface, target_ifindex);
    printf("Target MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
           if_config.mac_addr[0], if_config.mac_addr[1], if_config.mac_addr[2],
           if_config.mac_addr[3], if_config.mac_addr[4], if_config.mac_addr[5]);
    
    return 0;
}

/*
 * CONFIGURE NAT TARGET MAC ADDRESS
 * ================================
 * 
 * This function configures the MAC address for the NAT target IP using
 * the pre-resolved MAC address from the config structure. The MAC address
 * should have been resolved during program initialization.
 * 
 * PROCESS:
 * 1. Use pre-resolved MAC address from config
 * 2. Store MAC address and IP in nat_target_map
 * 3. Validate configuration for proper packet forwarding
 */
static int configure_nat_target_mac()
{
    struct nat_target_config nat_config = {0};
    __u32 key = 0;
    
    /* Use pre-resolved MAC address from config */
    memcpy(nat_config.mac_addr, cfg.nat_target_mac, 6);
    
    /* Double-check MAC address validity (should have been validated earlier) */
    int mac_valid = 0;
    for (int i = 0; i < 6; i++) {
        if (nat_config.mac_addr[i] != 0) {
            mac_valid = 1;
            break;
        }
    }
    if (!mac_valid) {
        fprintf(stderr, "Error: Cannot configure NAT target with invalid MAC address\n");
        return -1;
    }
    
    /* Store NAT target IP for validation */
    if (inet_pton(AF_INET, cfg.nat_target_ip, &nat_config.ip_addr) != 1) {
        fprintf(stderr, "Invalid NAT target IP address: %s\n", cfg.nat_target_ip);
        return -1;
    }
    
    /* Update NAT target map */
    if (bpf_map_update_elem(nat_target_map_fd, &key, &nat_config, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to update NAT target map: %s\n", strerror(errno));
        return -1;
    }
    
    printf("NAT target MAC configured: %s -> %02x:%02x:%02x:%02x:%02x:%02x\n",
           cfg.nat_target_ip,
           nat_config.mac_addr[0], nat_config.mac_addr[1], nat_config.mac_addr[2],
           nat_config.mac_addr[3], nat_config.mac_addr[4], nat_config.mac_addr[5]);
    
    return 0;
}

/*
 * DISPLAY REAL-TIME STATISTICS WITH PERFORMANCE ANALYSIS
 * ======================================================
 * 
 * This function provides comprehensive real-time monitoring of the VXLAN
 * pipeline performance, including throughput analysis, error tracking,
 * and performance assessment against the 85K+ PPS target.
 * 
 * MONITORING METHODOLOGY:
 * ======================
 * 1. Delta calculation: Compare current vs. previous statistics snapshots
 * 2. Rate computation: Calculate per-second rates for key metrics
 * 3. Performance assessment: Evaluate against throughput targets
 * 4. Efficiency analysis: Compute processing ratios and success rates
 * 
 * KEY PERFORMANCE INDICATORS (KPIs):
 * =================================
 * - Packets Per Second (PPS): Primary performance metric
 * - VXLAN Processing Rate: Specialized packet handling efficiency
 * - NAT Application Rate: Network address translation effectiveness
 * - Throughput (Mbps): Bandwidth utilization measurement
 * - Error Rate: System reliability and stability indicator
 * 
 * PERFORMANCE THRESHOLDS:
 * ======================
 * - TARGET: 85,000+ PPS (production requirement)
 * - GOOD: 60,000+ PPS (acceptable performance)
 * - WARNING: <60,000 PPS (performance investigation needed)
 * 
 * STATISTICAL ACCURACY:
 * ====================
 * - Uses previous snapshot baseline for accurate delta calculations
 * - Handles counter wraparound scenarios gracefully
 * - Provides meaningful rates even during startup phase
 * - Aggregates multi-CPU statistics for system-wide view
 */
static void display_stats()
{
    static __u64 prev_stats[STAT_MAX_ENTRIES] = {0}; /* Previous snapshot for delta calculation */
    static time_t last_time = 0;                     /* Previous timestamp for rate calculation */
    
    time_t current_time = time(NULL);
    double interval = current_time - last_time;
    if (last_time == 0) interval = 1.0; /* Handle first call gracefully */
    
    __u64 current_stats[STAT_MAX_ENTRIES];
    
    /*
     * COLLECT CURRENT STATISTICS FROM ALL CPU CORES
     * =============================================
     * Aggregate per-CPU counters to get system-wide statistics.
     * This is performed atomically to ensure consistency across
     * all metrics for accurate rate calculations.
     */
    for (int i = 0; i < STAT_MAX_ENTRIES; i++) {
        current_stats[i] = get_stat_value(stats_map_fd, i);
    }
    
    /* Calculate rates */
    __u64 packets_delta = current_stats[STAT_TOTAL_PACKETS] - prev_stats[STAT_TOTAL_PACKETS];
    __u64 bytes_delta = current_stats[STAT_BYTES_PROCESSED] - prev_stats[STAT_BYTES_PROCESSED];
    __u64 vxlan_delta = current_stats[STAT_VXLAN_PACKETS] - prev_stats[STAT_VXLAN_PACKETS];
    __u64 nat_delta = current_stats[STAT_NAT_APPLIED] - prev_stats[STAT_NAT_APPLIED];
    
    double pps = packets_delta / interval;
    double vxlan_pps = vxlan_delta / interval;
    double mbps = (bytes_delta * 8.0) / (interval * 1024 * 1024);
    
    /* Performance status indicators */
    const char* perf_status = "[!]";
    if (pps >= 85000) perf_status = "[OK]";
    else if (pps >= 60000) perf_status = "[--]";
    
    /* Display comprehensive statistics */
    printf("\n%s === VXLAN Pipeline Statistics [%ds interval] ===\n", perf_status, cfg.stats_interval);
    printf("[P] Total Packets:    %10llu (%8.0f pps)\n", current_stats[STAT_TOTAL_PACKETS], pps);
    printf("[V] VXLAN Packets:    %10llu (%8.0f pps, %5.1f%%)\n",
           current_stats[STAT_VXLAN_PACKETS], vxlan_pps,
           current_stats[STAT_TOTAL_PACKETS] > 0 ? 
               (double)current_stats[STAT_VXLAN_PACKETS] * 100.0 / current_stats[STAT_TOTAL_PACKETS] : 0.0);
    printf("[I] Inner Packets:    %10llu\n", current_stats[STAT_INNER_PACKETS]);
    printf("[N] NAT Applied:      %10llu (%8.0f/s)\n", current_stats[STAT_NAT_APPLIED], nat_delta / interval);
    printf("[D] DF Bits Cleared:  %10llu (for >1400B pkts)\n", current_stats[STAT_DF_CLEARED]);
    printf("[F] Forwarded:        %10llu\n", current_stats[STAT_FORWARDED]);
    printf("[R] Redirected:       %10llu (XDP_REDIRECT)\n", current_stats[STAT_REDIRECTED]);
    printf("[E] Errors:           %10llu\n", current_stats[STAT_ERRORS]);
    printf("[T] Throughput:       %10.2f Mbps\n", mbps);
    
    /* Performance analysis */
    if (pps >= 85000) {
        printf("[!] PERFORMANCE TARGET ACHIEVED! (%0.f PPS)\n", pps);
    } else if (current_stats[STAT_TOTAL_PACKETS] > 1000) {
        printf("[+] Performance: %.0f PPS (target: 85K+)\n", pps);
    }
    
    /* NAT efficiency analysis */
    if (current_stats[STAT_VXLAN_PACKETS] > 0) {
        double nat_ratio = (current_stats[STAT_NAT_APPLIED] * 100.0) / current_stats[STAT_VXLAN_PACKETS];
        printf("[*] NAT Efficiency:   %.1f%% (src_port matching)\n", nat_ratio);
    }
    
    printf("========================================\n");
    
    /* Update previous stats */
    memcpy(prev_stats, current_stats, sizeof(prev_stats));
    last_time = current_time;
    
    /* Flush output to prevent corruption */
    fflush(stdout);
}

/* Load and attach eBPF program */
static int load_bpf_program()
{
    struct bpf_program *prog;
    int err;
    
    /* Load eBPF object file */
    bpf_obj = bpf_object__open("vxlan_pipeline.bpf.o");
    if (libbpf_get_error(bpf_obj)) {
        fprintf(stderr, "Failed to open eBPF object file\n");
        return -1;
    }
    
    /* Load program into kernel */
    err = bpf_object__load(bpf_obj);
    if (err) {
        fprintf(stderr, "Failed to load eBPF program: %s\n", strerror(-err));
        bpf_object__close(bpf_obj);
        bpf_obj = NULL;
        return -1;
    }
    
    /* Find main program */
    prog = bpf_object__find_program_by_name(bpf_obj, "vxlan_pipeline_main");
    if (!prog) {
        /* Try alternative section name */
        prog = bpf_program__next(NULL, bpf_obj);
        if (!prog) {
            fprintf(stderr, "Failed to find XDP program\n");
            bpf_object__close(bpf_obj);
            bpf_obj = NULL;
            return -1;
        }
    }
    
    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to get program fd\n");
        bpf_object__close(bpf_obj);
        bpf_obj = NULL;
        return -1;
    }
    
    /* Get map file descriptors */
    stats_map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "stats_map");
    nat_map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "nat_map");
    redirect_map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "redirect_map");
    interface_map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "interface_map");
    nat_target_map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "nat_target_map");
    
    if (stats_map_fd < 0 || nat_map_fd < 0 || redirect_map_fd < 0 || interface_map_fd < 0 || nat_target_map_fd < 0) {
        fprintf(stderr, "Failed to find required maps\n");
        bpf_object__close(bpf_obj);
        bpf_obj = NULL;
        return -1;
    }
    
    /*
     * PIN MAPS FOR INTER-PROGRAM COMMUNICATION
     * ========================================
     * 
     * BPF map pinning enables communication between different programs
     * by persisting maps in the filesystem. This is essential for the
     * architecture where vxlan_loader manages XDP and packet_injector
     * accesses the maps for userspace packet processing.
     * 
     * PINNING ARCHITECTURE:
     * ====================
     * 1. vxlan_loader: Creates and pins maps during XDP program loading
     * 2. packet_injector: Accesses pinned maps for ring buffer processing
     * 3. Filesystem persistence: Maps survive program restarts
     * 4. Atomic updates: Multiple programs can safely access shared maps
     * 
     * PINNED MAP FUNCTIONS:
     * ====================
     * - stats_map: Real-time performance statistics sharing
     * - nat_map: NAT configuration for both XDP and userspace
     * - redirect_map: Interface configuration for packet forwarding
     * - interface_map: MAC address and interface metadata
     * - ip_allowlist: IP filtering configuration
     * - packet_ringbuf: High-performance kernel-userspace communication
     * 
     * FILESYSTEM LOCATION:
     * ===================
     * All maps pinned to /sys/fs/bpf/ for standardized access
     * and compatibility with BPF filesystem conventions.
     */
    struct bpf_map *stats_map = bpf_object__find_map_by_name(bpf_obj, "stats_map");
    struct bpf_map *nat_map = bpf_object__find_map_by_name(bpf_obj, "nat_map");
    struct bpf_map *redirect_map = bpf_object__find_map_by_name(bpf_obj, "redirect_map");
    struct bpf_map *interface_map = bpf_object__find_map_by_name(bpf_obj, "interface_map");
    struct bpf_map *nat_target_map = bpf_object__find_map_by_name(bpf_obj, "nat_target_map");
    struct bpf_map *ip_allowlist_map = bpf_object__find_map_by_name(bpf_obj, "ip_allowlist");
    struct bpf_map *ringbuf_map = bpf_object__find_map_by_name(bpf_obj, "packet_ringbuf");
    
    /* Create pinning directory if it doesn't exist */
    if (system("mkdir -p /sys/fs/bpf") != 0) {
        fprintf(stderr, "Warning: Failed to create /sys/fs/bpf directory\n");
    }
    
    /* Pin all maps */
    if (stats_map && bpf_map__pin(stats_map, "/sys/fs/bpf/vxlan_stats_map")) {
        fprintf(stderr, "Warning: Failed to pin stats_map\n");
    }
    if (nat_map && bpf_map__pin(nat_map, "/sys/fs/bpf/vxlan_nat_map")) {
        fprintf(stderr, "Warning: Failed to pin nat_map\n");
    }
    if (redirect_map && bpf_map__pin(redirect_map, "/sys/fs/bpf/vxlan_redirect_map")) {
        fprintf(stderr, "Warning: Failed to pin redirect_map\n");
    }
    if (interface_map && bpf_map__pin(interface_map, "/sys/fs/bpf/vxlan_interface_map")) {
        fprintf(stderr, "Warning: Failed to pin interface_map\n");
    }
    if (nat_target_map && bpf_map__pin(nat_target_map, "/sys/fs/bpf/vxlan_nat_target_map")) {
        fprintf(stderr, "Warning: Failed to pin nat_target_map\n");
    }
    if (ip_allowlist_map && bpf_map__pin(ip_allowlist_map, "/sys/fs/bpf/vxlan_ip_allowlist")) {
        fprintf(stderr, "Warning: Failed to pin ip_allowlist\n");
    }
    if (ringbuf_map && bpf_map__pin(ringbuf_map, "/sys/fs/bpf/vxlan_packet_ringbuf")) {
        fprintf(stderr, "Warning: Failed to pin packet_ringbuf\n");
    }
    
    printf("Maps pinned to /sys/fs/bpf/ for packet_injector access\n");
    
    printf("eBPF program loaded successfully\n");
    return 0;
}

/*
 * ATTACH XDP PROGRAM TO NETWORK INTERFACE
 * =======================================
 * 
 * This function attaches the compiled eBPF program to a network interface
 * using XDP (eXpress Data Path) for high-performance packet processing.
 * XDP operates at the earliest point in the kernel's packet reception path,
 * providing maximum performance and minimum latency.
 * 
 * XDP ATTACHMENT MODES:
 * ====================
 * 
 * 1. DRIVER MODE (XDP_FLAGS_DRV_MODE) - HIGHEST PERFORMANCE:
 *    - Native driver support required
 *    - Packets processed before sk_buff allocation
 *    - Maximum performance: 10M+ PPS on modern hardware
 *    - Zero memory allocations for dropped/redirected packets
 *    - Preferred mode for production high-throughput scenarios
 * 
 * 2. GENERIC MODE (XDP_FLAGS_SKB_MODE) - COMPATIBILITY FALLBACK:
 *    - Works with any network driver
 *    - Packets processed after sk_buff allocation
 *    - Lower performance but broader compatibility
 *    - Used when driver mode is not available
 *    - Still significantly faster than traditional kernel path
 * 
 * ATTACHMENT STRATEGY:
 * ===================
 * 1. Try driver mode first for maximum performance
 * 2. Fallback to generic mode if driver doesn't support XDP
 * 3. Provide clear feedback on which mode was successfully attached
 * 4. Fail completely only if both modes fail (rare on modern systems)
 * 
 * PERFORMANCE IMPACT:
 * ==================
 * - Driver mode: 85K+ PPS target easily achievable
 * - Generic mode: Still handles high packet rates but with higher CPU usage
 * - Mode selection is automatic and transparent to the application
 */
static int attach_xdp_program()
{
    /*
     * RESOLVE INTERFACE NAME TO KERNEL INDEX
     * ======================================
     * Convert interface name to the numeric index used by kernel APIs.
     * This index is used for all subsequent XDP operations.
     */
    ifindex = if_nametoindex(cfg.interface);
    if (ifindex == 0) {
        fprintf(stderr, "Interface '%s' not found\n", cfg.interface);
        return -1;
    }
    
    /*
     * ATTEMPT DRIVER MODE ATTACHMENT (OPTIMAL PERFORMANCE)
     * ===================================================
     * Driver mode provides the highest performance by processing packets
     * before the kernel allocates sk_buff structures. This is the preferred
     * mode for production deployments targeting 85K+ PPS throughput.
     */
    int flags = XDP_FLAGS_DRV_MODE;
    int err = bpf_set_link_xdp_fd(ifindex, prog_fd, flags);
    
    if (err) {
        /* Fallback to generic mode if driver mode fails */
        printf("Driver mode attachment failed, trying generic mode...\n");
        flags = XDP_FLAGS_SKB_MODE;
        err = bpf_set_link_xdp_fd(ifindex, prog_fd, flags);
    }
    
    if (err) {
        fprintf(stderr, "Failed to attach XDP program to %s: %s\n", 
                cfg.interface, strerror(-err));
        return -1;
    }
    
    printf("XDP program attached to interface %s (%s mode)\n", 
           cfg.interface, (flags & XDP_FLAGS_DRV_MODE) ? "driver" : "generic");
    
    return 0;
}

/* Print usage information */
static void print_usage(const char *prog_name)
{
    printf("Usage: %s [OPTIONS]\n\n", prog_name);
    printf("High-Performance VXLAN Pipeline Controller\n\n");
    printf("Options:\n");
    printf("  -i, --interface=NAME      Interface to attach XDP program (default: ens5)\n");
    printf("  -t, --target=NAME         Target interface for forwarding (default: ens6)\n");
    printf("  -a, --nat-target=IP       NAT target IP address (default: 127.0.0.1)\n");
    printf("  -p, --nat-port=PORT       NAT target port (default: 8080)\n");
    printf("  -s, --source-port=PORT    NAT source port to match (default: 31765)\n");
    printf("  -I, --interval=SECONDS    Statistics display interval (default: 5)\n");
    printf("  -v, --verbose             Enable verbose output\n");
    printf("  -h, --help               Show this help message\n");
    printf("\nExample:\n");
    printf("  %s -i ens5 -t ens6 -a 10.0.0.100 -p 8080 -s 31765\n", prog_name);
}

/* Parse command line arguments */
static int parse_args(int argc, char **argv)
{
    static struct option long_options[] = {
        {"interface",    required_argument, 0, 'i'},
        {"target",       required_argument, 0, 't'},
        {"nat-target",   required_argument, 0, 'a'},
        {"nat-port",     required_argument, 0, 'p'},
        {"source-port",  required_argument, 0, 's'},
        {"interval",     required_argument, 0, 'I'},
        {"verbose",      no_argument,       0, 'v'},
        {"help",         no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    
    int c;
    while ((c = getopt_long(argc, argv, "i:t:a:p:s:I:vh", long_options, NULL)) != -1) {
        switch (c) {
        case 'i':
            strncpy(cfg.interface, optarg, IF_NAMESIZE - 1);
            break;
        case 't':
            strncpy(cfg.target_interface, optarg, IF_NAMESIZE - 1);
            break;
        case 'a':
            strncpy(cfg.nat_target_ip, optarg, INET_ADDRSTRLEN - 1);
            break;
        case 'p':
            cfg.nat_target_port = atoi(optarg);
            break;
        case 's':
            cfg.nat_source_port = atoi(optarg);
            break;
        case 'I':
            cfg.stats_interval = atoi(optarg);
            break;
        case 'v':
            cfg.verbose = 1;
            break;
        case 'h':
            print_usage(argv[0]);
            return 1;
        default:
            print_usage(argv[0]);
            return -1;
        }
    }
    
    return 0;
}

int main(int argc, char **argv)
{
    int ret;
    
    /* Parse command line arguments */
    ret = parse_args(argc, argv);
    if (ret != 0) {
        return ret == 1 ? 0 : 1; /* 1 means help was shown */
    }
    
    /* Resolve NAT target MAC address early for fast startup validation */
    printf("Resolving NAT target MAC address for %s...\n", cfg.nat_target_ip);
    if (resolve_ip_to_mac(cfg.nat_target_ip, cfg.nat_target_mac) != 0) {
        fprintf(stderr, "Failed to resolve MAC address for NAT target IP %s\n", cfg.nat_target_ip);
        fprintf(stderr, "This is required for proper L2 forwarding. Please ensure:\n");
        fprintf(stderr, "  1. NAT target IP %s is reachable\n", cfg.nat_target_ip);
        fprintf(stderr, "  2. Target interface %s exists and is up\n", cfg.target_interface);
        return 1;
    }
    
    /* Validate resolved MAC address is not all zeros */
    int mac_is_valid = 0;
    for (int i = 0; i < 6; i++) {
        if (cfg.nat_target_mac[i] != 0) {
            mac_is_valid = 1;
            break;
        }
    }
    if (!mac_is_valid) {
        fprintf(stderr, "Error: Resolved NAT target MAC address is invalid (all zeros)\n");
        fprintf(stderr, "This indicates ARP resolution failed. Please check:\n");
        fprintf(stderr, "  1. NAT target IP %s is on the same network segment\n", cfg.nat_target_ip);
        fprintf(stderr, "  2. Target host is responding to ARP requests\n");
        fprintf(stderr, "  3. No firewall is blocking ARP traffic\n");
        return 1;
    }
    
    printf("NAT target MAC resolved: %02x:%02x:%02x:%02x:%02x:%02x\n",
           cfg.nat_target_mac[0], cfg.nat_target_mac[1], cfg.nat_target_mac[2],
           cfg.nat_target_mac[3], cfg.nat_target_mac[4], cfg.nat_target_mac[5]);
    
    /* Setup signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    /* Register cleanup function */
    atexit(cleanup);
    
    printf("Starting VXLAN Pipeline Controller...\n");
    printf("Interface: %s -> %s\n", cfg.interface, cfg.target_interface);
    printf("NAT Rule: port %d -> %s:%d\n", 
           cfg.nat_source_port, cfg.nat_target_ip, cfg.nat_target_port);
    
    /* Load eBPF program */
    if (load_bpf_program() != 0) {
        return 1;
    }
    
    /* Configure NAT rules */
    if (configure_nat_rules() != 0) {
        return 1;
    }
    
    /* Configure redirect interface */
    if (configure_redirect_interface() != 0) {
        return 1;
    }
    
    /* Configure NAT target MAC address */
    if (configure_nat_target_mac() != 0) {
        return 1;
    }
    
    /* Attach XDP program */
    if (attach_xdp_program() != 0) {
        return 1;
    }
    
    /* Initialize statistics counters for clean startup */
    init_stats();
    
    printf("VXLAN pipeline is active. Press Ctrl+C to stop.\n");
    
    /* Main statistics loop */
    while (running) {
        sleep(cfg.stats_interval);
        if (running) {
            display_stats();
        }
    }
    
    printf("Shutting down...\n");
    return 0;
}