/*
 * High-Performance Multithreaded Packet Injector - Header File
 *
 * This header contains all constants, structures, and type definitions
 * for the packet injection system.
 */

#ifndef PACKET_INJECTOR_H
#define PACKET_INJECTOR_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sched.h>
#include <sys/time.h>
#include <time.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <signal.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

/*
 * PERFORMANCE CONFIGURATION CONSTANTS
 * ===================================
 */
#define MAX_WORKER_THREADS 8           /* Maximum worker threads (match CPU cores for cache locality) */
#define DEFAULT_WORKER_THREADS 4       /* Default number of worker threads */
#define PACKET_QUEUE_SIZE 4096         /* Per-worker queue size (power of 2 for efficient modulo) */
#define BATCH_SIZE 64                  /* Packets per sendto() batch (balanced latency vs efficiency) */
#define MAX_PACKET_SIZE 3000           /* Maximum packet size to match ens5 MTU and support VXLAN decapsulation */

/*
 * MEMORY AND ALIGNMENT CONSTANTS
 * ==============================
 */
#define CACHE_LINE_SIZE 64             /* CPU cache line size for alignment */
#define MEMORY_POOL_MULTIPLIER 2       /* Pool size = queue_size * workers * multiplier */

/*
 * TIMING CONSTANTS (in microseconds unless noted)
 * ===============================================
 */
#define WORKER_YIELD_TIME_US 100       /* Worker thread yield time when no packets available */
#define RING_BUFFER_TIMEOUT_MS 1       /* Ring buffer polling timeout in milliseconds */
#define MONITOR_INTERVAL_SEC 1         /* Performance monitoring interval in seconds */

/*
 * PERFORMANCE OPTIMIZATION CONSTANTS
 * ==================================
 */
#define PREFETCH_DISTANCE 2            /* Cache prefetch distance for packet processing */

/*
 * BPF MAP CONSTANTS
 * =================
 */
#define BPF_MAP_PATH "/sys/fs/bpf/vxlan_packet_ringbuf"  /* Pinned ring buffer map path */

/*
 * NETWORK SOCKET CONSTANTS
 * ========================
 */
#define SOCKET_SEND_BUFFER_SIZE (2 * 1024 * 1024)  /* 2MB send buffer for burst handling */
#define SOCKET_REUSE_ENABLE 1          /* Enable SO_REUSEADDR */

/*
 * PERFORMANCE MONITORING CONSTANTS
 * ================================
 */
#define BYTES_PER_KB 1024              /* Bytes in a kilobyte */
#define BYTES_PER_MB (1024 * 1024)     /* Bytes in a megabyte */
#define NANOSEC_PER_SEC 1000000000L    /* Nanoseconds per second */
#define MICROSEC_PER_SEC 1000000L      /* Microseconds per second */
#define BITS_PER_BYTE 8                /* Bits per byte for bandwidth calculations */

/*
 * SYSTEM CONSTANTS
 * ================
 */
#define INTERFACE_INVALID 0            /* Invalid interface index */
#define SUCCESS_RATE_TARGET 85000      /* Target PPS for performance assessment */
#define GOOD_PERFORMANCE_THRESHOLD 50000  /* Good performance PPS threshold */
#define INIT_VALUE_ZERO 0              /* Initial value for counters */
#define INIT_VALUE_ONE 1               /* Initial value for flags */

/*
 * BUSY WAIT AND YIELD CONSTANTS
 * ==============================
 */
#define BUSY_WAIT_ITERATIONS 1000      /* Iterations for busy-wait loop */
#define PROGRESS_REPORT_INTERVAL 100   /* Report progress every N operations */
#define BATCH_PROGRESS_INTERVAL 25     /* Progress reporting for batch operations */

/*
 * ERROR HANDLING CONSTANTS
 * ========================
 */
#define MAX_ERROR_DISPLAY 10           /* Maximum errors to display in reports */

/*
 * LOCK-FREE PACKET QUEUE STRUCTURE
 * =================================
 */
struct packet_queue {
    /* Producer side (ring buffer reader) - own cache line */
    volatile uint32_t head __attribute__((aligned(CACHE_LINE_SIZE)));

    /* Consumer side (worker threads) - separate cache line */
    volatile uint32_t tail __attribute__((aligned(CACHE_LINE_SIZE)));

    /* Packet pointer array - shared read-only after initialization */
    struct packet_buffer *packets[PACKET_QUEUE_SIZE];
} __attribute__((aligned(CACHE_LINE_SIZE)));

/*
 * PACKET BUFFER STRUCTURE
 * =======================
 */
struct packet_buffer {
    uint16_t len;                                    /* Packet length in bytes */
    uint8_t data[MAX_PACKET_SIZE];                  /* Raw packet data from ring buffer */
    struct timespec timestamp;                       /* Packet arrival time for latency tracking */
} __attribute__((aligned(CACHE_LINE_SIZE)));

/*
 * WORKER THREAD CONTEXT STRUCTURE
 * ===============================
 */
struct worker_context {
    /* Thread identification and CPU binding */
    int thread_id;                                   /* Worker identifier */
    int cpu_id;                                      /* CPU core this worker is bound to */

    /* Network resources per worker */
    int raw_socket;                                  /* Dedicated AF_PACKET socket */
    struct sockaddr_ll target_addr;                  /* Pre-filled target interface address */

    /* Work queue and thread handle */
    struct packet_queue *queue;                      /* Pointer to this worker's packet queue */
    pthread_t thread;                                /* POSIX thread handle */

    /* Performance statistics (updated atomically) */
    volatile uint64_t packets_sent;                  /* Successfully transmitted packets */
    volatile uint64_t bytes_sent;                    /* Total bytes transmitted */
    volatile uint64_t errors;                        /* Network errors */
} __attribute__((aligned(CACHE_LINE_SIZE)));

/*
 * PERFORMANCE STATISTICS STRUCTURE
 * ================================
 */
struct perf_stats {
    uint64_t total_packets;                          /* Total packets processed */
    uint64_t total_bytes;                            /* Total bytes processed */
    uint64_t ring_buffer_polls;                      /* Ring buffer poll operations */
    uint64_t queue_full_drops;                       /* Packets dropped due to queue full */
    uint64_t allocation_failures;                    /* Memory allocation failures */
    struct timespec start_time;                      /* System start timestamp */
};

/*
 * PACKET EVENT STRUCTURE (from BPF)
 * =================================
 */
struct packet_event {
    uint32_t ifindex;                                /* Target interface index */
    uint16_t len;                                    /* Packet length in bytes */
    uint8_t data[];                                  /* Variable-length packet data */
};

#endif /* PACKET_INJECTOR_H */