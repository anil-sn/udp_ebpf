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

/* Global variables for cleanup */
static struct bpf_object *bpf_obj = NULL;
static int prog_fd = -1;
static int stats_map_fd = -1;
static int nat_map_fd = -1;
static int redirect_map_fd = -1;
static int interface_map_fd = -1;  /* New: interface configuration map */
static int ifindex = -1;
static volatile sig_atomic_t running = 1;

/* Configuration */
struct config {
    char interface[IF_NAMESIZE];
    char target_interface[IF_NAMESIZE];
    char nat_target_ip[INET_ADDRSTRLEN];
    int nat_target_port;
    int nat_source_port;
    int stats_interval;
    int verbose;
};

static struct config cfg = {
    .interface = "ens4",
    .target_interface = "ens5", 
    .nat_target_ip = "10.2.41.17",
    .nat_target_port = 8081,
    .nat_source_port = 42844,
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
    }
    
    /* Final flush */
    fflush(stdout);
    fflush(stderr);
}

/* Get aggregated statistics from per-CPU map */
static __u64 get_stat_value(int map_fd, __u32 key)
{
    __u64 values[MAX_CPU_CORES]; /* Support up to MAX_CPU_CORES CPUs */
    __u64 total = 0;
    int num_cpus;
    
    /* Initialize array to avoid reading garbage values */
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

/* Configure NAT rules in eBPF map - Destination Port Based (Fixed) */
static int configure_nat_rules()
{
    struct nat_entry entry = {0};
    struct nat_key key = {
        .src_port = htons(cfg.nat_source_port)  /* NOTE: Despite name, this matches destination port in packets */
    };
    
    /* Parse target IP address */
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

/* Configure target interface for packet forwarding */
static int configure_redirect_interface()
{
    if (strlen(cfg.target_interface) == 0) {
        return 0; /* No target interface configured */
    }
    
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

/* Display real-time statistics with 85K+ PPS performance tracking */
static void display_stats()
{
    static __u64 prev_stats[STAT_MAX_ENTRIES] = {0};
    static time_t last_time = 0;
    
    time_t current_time = time(NULL);
    double interval = current_time - last_time;
    if (last_time == 0) interval = 1.0;
    
    __u64 current_stats[STAT_MAX_ENTRIES];
    
    /* Collect current statistics */
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
            return -1;
        }
    }
    
    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to get program fd\n");
        bpf_object__close(bpf_obj);
        return -1;
    }
    
    /* Get map file descriptors */
    stats_map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "stats_map");
    nat_map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "nat_map");
    redirect_map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "redirect_map");
    interface_map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "interface_map");
    
    if (stats_map_fd < 0 || nat_map_fd < 0 || redirect_map_fd < 0 || interface_map_fd < 0) {
        fprintf(stderr, "Failed to find required maps\n");
        bpf_object__close(bpf_obj);
        return -1;
    }
    
    printf("eBPF program loaded successfully\n");
    return 0;
}

/* Attach XDP program to interface */
static int attach_xdp_program()
{
    ifindex = if_nametoindex(cfg.interface);
    if (ifindex == 0) {
        fprintf(stderr, "Interface '%s' not found\n", cfg.interface);
        return -1;
    }
    
    /* Attach in XDP_FLAGS_DRV_MODE for best performance */
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