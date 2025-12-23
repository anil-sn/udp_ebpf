/*
 * Production eBPF/XDP UDP DF Modifier - Userspace Control Plane
 * 
 * ARCHITECTURE:
 * This userspace program manages the complete lifecycle of the XDP program:
 * - eBPF program loading and verification
 * - Safe XDP attachment with validation
 * - Real-time statistics collection and display
 * - Graceful cleanup and resource management
 *
 * PERFORMANCE DESIGN:
 * - Statistics collection via efficient per-CPU maps
 * - Minimal logging (errors only) to avoid performance impact
 * - Signal-based graceful shutdown
 * - Resource cleanup on all exit paths
 *
 * SAFETY FEATURES:
 * - Interface validation before attachment
 * - Automatic XDP program detachment on exit
 * - Comprehensive error handling
 * - Production-ready deployment checks
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <time.h>
#include <net/if.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/if_link.h>

/* Statistics indices - must match eBPF program */
enum stats_index {
    STAT_TOTAL_PACKETS = 0,    /* All packets examined by XDP */
    STAT_UDP_PACKETS = 1,      /* UDP packets processed */
    STAT_MODIFIED_PACKETS = 2, /* DF bits actually cleared */
    STAT_BYTES_PROCESSED = 3,  /* Total bytes processed */
    STAT_MAX_ENTRIES = 4,
};

// Global variables for cleanup
static struct bpf_object *bpf_obj = NULL;
static int prog_fd = -1;
static int ifindex = -1;
static int stats_map_fd = -1;
static volatile sig_atomic_t running = 1;

// Signal handler for graceful shutdown
static void signal_handler(int sig)
{
    printf("\nReceived signal %d, shutting down gracefully...\n", sig);
    running = 0;
}

/*
 * Resource Cleanup Function
 * 
 * Ensures proper cleanup of all resources on program exit:
 * - Detaches XDP program from network interface
 * - Closes eBPF object and file descriptors
 * - Prevents resource leaks and interface lock-up
 * 
 * Called automatically on signal or normal exit
 */
static void cleanup()
{
    if (ifindex > 0 && prog_fd >= 0) {
        /* Detach XDP program to restore normal interface operation */
        if (bpf_set_link_xdp_fd(ifindex, -1, 0) < 0) {
            fprintf(stderr, "Warning: Failed to detach XDP program\n");
        }
    }
    
    if (bpf_obj) {
        bpf_object__close(bpf_obj);
    }
}

/*
 * Per-CPU Statistics Aggregation
 * 
 * Efficiently collects and sums statistics from all CPU cores:
 * - Queries per-CPU map values
 * - Aggregates across all available CPUs
 * - Returns total value for monitoring
 */
static __u64 get_stat_value(int map_fd, __u32 key)
{
    __u64 values[128]; /* Support up to 128 CPUs */
    __u64 total = 0;
    
    if (bpf_map_lookup_elem(map_fd, &key, values) != 0) {
        return 0;
    }
    
    int num_cpus = libbpf_num_possible_cpus();
    for (int i = 0; i < num_cpus && i < 128; i++) {
        total += values[i];
    }
    
    return total;
}

/*
 * Real-time Statistics Display
 * 
 * Provides efficient monitoring with rate calculations:
 * - Shows current counters and rates
 * - Calculates packets/second and bandwidth
 * - Minimal output for production monitoring
 */
static void print_stats(int map_fd)
{
    static __u64 prev_total = 0, prev_udp = 0, prev_modified = 0, prev_bytes = 0;
    static time_t prev_time = 0;
    
    time_t current_time = time(NULL);
    __u64 total = get_stat_value(map_fd, STAT_TOTAL_PACKETS);
    __u64 udp = get_stat_value(map_fd, STAT_UDP_PACKETS);
    __u64 modified = get_stat_value(map_fd, STAT_MODIFIED_PACKETS);
    __u64 bytes = get_stat_value(map_fd, STAT_BYTES_PROCESSED);
    
    /* Calculate rates for performance monitoring */
    if (prev_time > 0) {
        time_t time_diff = current_time - prev_time;
        if (time_diff > 0) {
            __u64 pps = (total - prev_total) / time_diff;
            __u64 bps = (bytes - prev_bytes) / time_diff;
            __u64 mod_rate = (modified - prev_modified) / time_diff;
            __u64 udp_rate = (udp - prev_udp) / time_diff;
            
            printf("\r[*] Total: %llu (+%llu/s) | UDP: %llu (+%llu/s) | Modified: %llu (+%llu/s) | %.2f Mbps",
                   (unsigned long long)total, (unsigned long long)pps, 
                   (unsigned long long)udp, (unsigned long long)udp_rate,
                   (unsigned long long)modified, (unsigned long long)mod_rate, 
                   (bps * 8.0) / 1000000.0);
            fflush(stdout);
        }
    } else {
        /* First run - show initial counters */
        printf("XDP UDP DF Modifier - Monitoring Interface\n");
        printf("Counters: Total: %llu | UDP: %llu | Modified: %llu | Bytes: %llu\n",
               (unsigned long long)total, (unsigned long long)udp, 
               (unsigned long long)modified, (unsigned long long)bytes);
    }
    
    /* Update previous values for rate calculation */
    prev_total = total;
    prev_udp = udp;
    prev_modified = modified;
    prev_bytes = bytes;
    prev_time = current_time;
}

/* Display usage information */
static void usage(const char *prog_name)
{
    printf("Usage: %s <interface_name>\n", prog_name);
    printf("\nHigh-performance UDP DF modifier using XDP/eBPF\n");
    printf("\nOptions:\n");
    printf("  interface_name    Network interface to attach XDP program (e.g., eth0)\n");
    printf("\nExample:\n");
    printf("  sudo %s eth0\n", prog_name);
    printf("\nThe program will:\n");
    printf("- Load XDP eBPF program for packet processing\n");
    printf("- Attach to specified network interface\n");
    printf("- Display real-time statistics every 5 seconds\n");
    printf("- Handle UDP packets on port 31765 > 1400 bytes\n");
    printf("- Clear DF bit to prevent fragmentation issues\n");
}

int main(int argc, char *argv[])
{
    const char *interface_name;
    struct bpf_program *prog;
    int err;
    
    // Parse command line arguments
    if (argc != 2) {
        usage(argv[0]);
        return 1;
    }
    
    interface_name = argv[1];
    
    // Get interface index
    ifindex = if_nametoindex(interface_name);
    if (ifindex == 0) {
        fprintf(stderr, "Error: Interface '%s' not found\n", interface_name);
        return 1;
    }
    
    printf("Starting XDP UDP DF modifier on interface %s (index: %d)\n", 
           interface_name, ifindex);
    
    // Setup signal handlers for graceful shutdown
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Increase memory limit for eBPF
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        fprintf(stderr, "Warning: Failed to increase memory limit: %s\n", strerror(errno));
    }
    
    // Load eBPF program from object file
    bpf_obj = bpf_object__open_file("udp_df_modifier.bpf.o", NULL);
    if (libbpf_get_error(bpf_obj)) {
        fprintf(stderr, "Error: Failed to open eBPF object file: %s\n", 
                strerror(-libbpf_get_error(bpf_obj)));
        return 1;
    }
    
    // Load program into kernel
    err = bpf_object__load(bpf_obj);
    if (err) {
        fprintf(stderr, "Error: Failed to load eBPF program: %s\n", strerror(-err));
        goto cleanup;
    }
    
    // Find the XDP program
    prog = bpf_object__find_program_by_name(bpf_obj, "udp_df_modifier");
    if (!prog) {
        fprintf(stderr, "Error: XDP program 'udp_df_modifier' not found\n");
        err = 1;
        goto cleanup;
    }
    
    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Error: Failed to get program file descriptor\n");
        err = 1;
        goto cleanup;
    }
    
    // Get statistics map file descriptor
    struct bpf_map *stats_map = bpf_object__find_map_by_name(bpf_obj, "stats_map");
    if (!stats_map) {
        fprintf(stderr, "Error: Statistics map not found\n");
        err = 1;
        goto cleanup;
    }
    
    stats_map_fd = bpf_map__fd(stats_map);
    if (stats_map_fd < 0) {
        fprintf(stderr, "Error: Failed to get statistics map file descriptor\n");
        err = 1;
        goto cleanup;
    }
    
    // Validate interface exists and is up before attempting attachment
    printf("Validating interface %s...\n", interface_name);
    
    // Check if interface exists and get its status
    char path[256];
    snprintf(path, sizeof(path), "/sys/class/net/%s/operstate", interface_name);
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "Error: Network interface '%s' not found\n", interface_name);
        err = 1;
        goto cleanup;
    }
    
    char state[16];
    if (fgets(state, sizeof(state), f)) {
        // Remove newline
        state[strcspn(state, "\n")] = 0;
        printf("Interface %s state: %s\n", interface_name, state);
        
        if (strcmp(state, "down") == 0) {
            fprintf(stderr, "Warning: Interface %s is DOWN. XDP may still attach but won't process packets.\n", interface_name);
            printf("Continue anyway? (y/N): ");
            char response = getchar();
            if (response != 'y' && response != 'Y') {
                fclose(f);
                err = 1;
                goto cleanup;
            }
        }
    }
    fclose(f);
    
    // Attach XDP program to interface
    printf("Attaching XDP program to interface %s...\n", interface_name);
    err = bpf_set_link_xdp_fd(ifindex, prog_fd, 0);
    if (err < 0) {
        fprintf(stderr, "Error: Failed to attach XDP program: %s\n", strerror(-err));
        goto cleanup;
    }
    
    printf("XDP program successfully attached!\n");
    printf("Processing UDP packets on port 31765 > 1400 bytes\n");
    printf("Press Ctrl+C to stop...\n\n");
    
    // Main statistics loop
    while (running) {
        sleep(5);  // Update statistics every 5 seconds
        if (running) {  // Check again in case we were interrupted
            print_stats(stats_map_fd);
        }
    }
    
    err = 0;

cleanup:
    cleanup();
    return err;
}