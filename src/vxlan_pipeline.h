#ifndef __VXLAN_PIPELINE_H__
#define __VXLAN_PIPELINE_H__

/*
 * VXLAN Pipeline Configuration Header
 * 
 * This header file contains all configuration constants, magic numbers,
 * and compile-time parameters for the high-performance VXLAN XDP pipeline.
 * 
 * Centralizing constants here improves maintainability and makes it easier
 * to tune the pipeline for different environments.
 */

/* =================================================================== */
/* PROTOCOL CONSTANTS                                                   */
/* =================================================================== */

/* VXLAN Protocol (RFC 7348) */
#define VXLAN_PORT                      4789        /* Standard VXLAN UDP port */
#define TARGET_VNI                      1           /* AWS Traffic Mirror VNI (always 1) */
#define VXLAN_VNI_FLAG                  0x08        /* VNI flag in VXLAN header */
#define VXLAN_HEADER_SIZE               8           /* VXLAN header size in bytes */

/* IP Protocol Constants */
#define IP_DF                          0x4000       /* Don't Fragment flag (network byte order) */
#define IP_HEADER_MIN_SIZE             20           /* Minimum IP header size */
#define IP_HEADER_MAX_SIZE             60           /* Maximum IP header size with options */
#define IP_CHECKSUM_WORDS              10           /* Number of 16-bit words in standard IP header */

/* Ethernet Protocol */
#define ETH_HEADER_SIZE                14           /* Ethernet header size */

/* UDP Protocol */
#define UDP_HEADER_SIZE                8            /* UDP header size */

/* =================================================================== */
/* PACKET PROCESSING LIMITS                                            */
/* =================================================================== */

/* Size Limits */
#define MIN_FRAGMENT_SIZE              1400         /* Only clear DF bit on packets > this size */
#define MAX_PACKET_SIZE                9000         /* Reject packets larger than jumbo frame */
#define MAX_OUTER_HEADERS_SIZE         200          /* Maximum reasonable VXLAN overhead */
#define MIN_PACKET_SIZE                64           /* Minimum valid packet size */

/* Performance Limits */
#define TARGET_PPS                     85000        /* Target packet processing rate */
#define MAX_CPU_CORES                  128          /* Maximum CPU cores for per-CPU stats */

/* =================================================================== */
/* EBPF MAP CONFIGURATION                                              */
/* =================================================================== */

/* Statistics Map */
#define STATS_MAP_MAX_ENTRIES          9            /* Number of statistics counters */
#define STATS_MAP_TYPE                 BPF_MAP_TYPE_PERCPU_ARRAY

/* NAT Map */
#define NAT_MAP_MAX_ENTRIES            1024         /* Maximum NAT translation rules */
#define NAT_MAP_TYPE                   BPF_MAP_TYPE_HASH

/* Redirect Map */
#define REDIRECT_MAP_MAX_ENTRIES       1           /* Single redirect target interface */
#define REDIRECT_MAP_TYPE              BPF_MAP_TYPE_ARRAY

/* =================================================================== */
/* DEFAULT CONFIGURATION VALUES                                        */
/* =================================================================== */

/* NAT Configuration */
#define DEFAULT_NAT_SOURCE_PORT        31765        /* Default port for NAT matching */
#define DEFAULT_NAT_TARGET_IP          "10.2.41.17" /* Default target IP (example) */
#define DEFAULT_NAT_TARGET_PORT        8081         /* Default target port (example) */

/* Interface Configuration */
#define DEFAULT_INGRESS_INTERFACE      "ens4"       /* Default input interface */
#define DEFAULT_EGRESS_INTERFACE       "ens5"       /* Default output interface */

/* Monitoring Configuration */
#define DEFAULT_STATS_INTERVAL         5            /* Default statistics reporting interval (seconds) */

/* =================================================================== */
/* PERFORMANCE TUNING CONSTANTS                                        */
/* =================================================================== */

/* CPU Performance */
#define CHECKSUM_CPU_CYCLES_MIN        50           /* Minimum CPU cycles for checksum */
#define CHECKSUM_CPU_CYCLES_MAX        100          /* Maximum CPU cycles for checksum */

/* Memory Performance */
#define CACHE_LINE_SIZE                64           /* CPU cache line size */
#define PREFETCH_DISTANCE              3            /* Prefetch locality (0-3) */

/* Network Performance */
#define RING_BUFFER_SIZE               4096         /* Optimal ring buffer size */
#define INTERRUPT_COALESCING_USECS     1            /* Interrupt coalescing microseconds */
#define INTERRUPT_COALESCING_FRAMES    1            /* Interrupt coalescing frame count */

/* =================================================================== */
/* ERROR AND VALIDATION CONSTANTS                                      */
/* =================================================================== */

/* Validation Limits */
#define MAX_LOOP_ITERATIONS            32           /* Maximum loop iterations for eBPF verifier */
#define BOUNDS_CHECK_MARGIN            16           /* Safety margin for bounds checking */

/* Error Codes */
#define ERROR_INVALID_PACKET           -1           /* Invalid packet structure */
#define ERROR_BOUNDS_CHECK             -2           /* Bounds check failure */
#define ERROR_MAP_LOOKUP               -3           /* eBPF map lookup failure */
#define ERROR_CHECKSUM                 -4           /* Checksum calculation error */

/* =================================================================== */
/* DEBUGGING AND MONITORING                                            */
/* =================================================================== */

/* Debug Levels */
#define DEBUG_LEVEL_NONE               0            /* No debug output */
#define DEBUG_LEVEL_ERROR              1            /* Error messages only */
#define DEBUG_LEVEL_INFO               2            /* Informational messages */
#define DEBUG_LEVEL_DEBUG              3            /* Detailed debug output */

/* Global debug level (set at compile time or runtime) */
extern int current_debug_level;

/* Debug logging macros */
#define LOG_ERROR(fmt, ...) \
    do { if (current_debug_level >= DEBUG_LEVEL_ERROR) \
        printf("[ERROR] " fmt "\n", ##__VA_ARGS__); } while(0)

#define LOG_INFO(fmt, ...) \
    do { if (current_debug_level >= DEBUG_LEVEL_INFO) \
        printf("[INFO] " fmt "\n", ##__VA_ARGS__); } while(0)

#define LOG_DEBUG(fmt, ...) \
    do { if (current_debug_level >= DEBUG_LEVEL_DEBUG) \
        printf("[DEBUG] " fmt "\n", ##__VA_ARGS__); } while(0)

/* Packet tracing macros */
#define TRACE_PACKET(fmt, ...) \
    do { if (current_debug_level >= DEBUG_LEVEL_DEBUG) \
        printf("[TRACE] " fmt "\n", ##__VA_ARGS__); } while(0)

#define TRACE_VXLAN(fmt, ...) \
    do { if (current_debug_level >= DEBUG_LEVEL_INFO) \
        printf("[VXLAN] " fmt "\n", ##__VA_ARGS__); } while(0)

#define TRACE_NAT(fmt, ...) \
    do { if (current_debug_level >= DEBUG_LEVEL_INFO) \
        printf("[NAT] " fmt "\n", ##__VA_ARGS__); } while(0)

/* Statistics Intervals */
#define FAST_STATS_INTERVAL            1            /* Fast statistics (seconds) */
#define NORMAL_STATS_INTERVAL          5            /* Normal statistics (seconds) */
#define SLOW_STATS_INTERVAL            60           /* Slow statistics (seconds) */

/* =================================================================== */
/* AWS TRAFFIC MIRROR SPECIFIC                                         */
/* =================================================================== */

/* AWS Constants */
#define AWS_MIRROR_VNI                 1            /* AWS Traffic Mirror always uses VNI 1 */
#define AWS_NLB_MTU                    9000         /* AWS NLB maximum MTU */
#define AWS_VPC_MTU                    1500         /* AWS VPC standard MTU */

/* Example Values from User Analysis */
#define EXAMPLE_SOURCE_IP              "10.2.41.20"   /* Example source from hex dump */
#define EXAMPLE_SOURCE_PORT            42844           /* Example port from hex dump */
#define EXAMPLE_TARGET_IP              "10.2.41.17"    /* Example NAT target from analysis */
#define EXAMPLE_TARGET_PORT            8081            /* Example NAT target port */
#define EXAMPLE_LARGE_PACKET_SIZE      2852            /* Example jumbo frame size */

/* =================================================================== */
/* COMPILER AND OPTIMIZATION HINTS                                     */
/* =================================================================== */

/* Function Attributes */
#define ALWAYS_INLINE                  static __always_inline
#define LIKELY(x)                      __builtin_expect(!!(x), 1)
#define UNLIKELY(x)                    __builtin_expect(!!(x), 0)

/* Alignment */
#define CACHE_ALIGN                    __attribute__((aligned(CACHE_LINE_SIZE)))
#define PACK_STRUCT                    __attribute__((packed))
#define ALIGN_4                        __attribute__((aligned(4)))

/* =================================================================== */
/* UTILITY MACROS                                                      */
/* =================================================================== */

/* Byte Order Conversion */
#define HTONS(x)                       bpf_htons(x)
#define NTOHS(x)                       bpf_ntohs(x)
#define HTONL(x)                       bpf_htonl(x)
#define NTOHL(x)                       bpf_ntohl(x)

/* Size Calculations */
#define ARRAY_SIZE(arr)                (sizeof(arr) / sizeof((arr)[0]))
#define MIN(a, b)                      ((a) < (b) ? (a) : (b))
#define MAX(a, b)                      ((a) > (b) ? (a) : (b))

/* Bit Operations */
#define SET_BIT(val, bit)              ((val) |= (1U << (bit)))
#define CLEAR_BIT(val, bit)            ((val) &= ~(1U << (bit)))
#define TEST_BIT(val, bit)             ((val) & (1U << (bit)))

/* Validation Macros */
#define BOUNDS_CHECK(ptr, size, end)   ((void *)(ptr) + (size) <= (void *)(end))
#define IS_VALID_IP_HDR_LEN(ihl)       ((ihl) >= 5 && (ihl) <= 15)
#define IS_JUMBO_FRAME(size)           ((size) > AWS_VPC_MTU)

#endif /* __VXLAN_PIPELINE_H__ */