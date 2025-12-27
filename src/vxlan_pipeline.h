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

/* BPF System Constants */
#ifndef BPF_MAP_TYPE_ARRAY
#define BPF_MAP_TYPE_ARRAY              2
#endif
#ifndef BPF_MAP_TYPE_HASH
#define BPF_MAP_TYPE_HASH               1
#endif
#ifndef BPF_MAP_TYPE_PERCPU_ARRAY
#define BPF_MAP_TYPE_PERCPU_ARRAY       6
#endif
#ifndef BPF_MAP_TYPE_RINGBUF
#define BPF_MAP_TYPE_RINGBUF            27
#endif
#ifndef BPF_MAP_TYPE_PROG_ARRAY
#define BPF_MAP_TYPE_PROG_ARRAY         3
#endif
#ifndef BPF_F_NO_PREALLOC
#define BPF_F_NO_PREALLOC              0x01UL
#endif

/* XDP Action Codes */
#ifndef XDP_ABORTED
#define XDP_ABORTED                     0
#endif
#ifndef XDP_DROP
#define XDP_DROP                        1
#endif
#ifndef XDP_PASS
#define XDP_PASS                        2
#endif
#ifndef XDP_TX
#define XDP_TX                          3
#endif
#ifndef XDP_REDIRECT
#define XDP_REDIRECT                    4
#endif

/* Network Protocol Definitions */
#ifndef ETH_P_IP
#define ETH_P_IP                        0x0800
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP                     17
#endif
#ifndef ETH_HLEN
#define ETH_HLEN                        14
#endif

/* VXLAN Protocol (RFC 7348) */
#define VXLAN_PORT                      4789        /* Standard VXLAN UDP port */
#define VXLAN_UDP_PORT                  4789        /* Standard VXLAN UDP port (alternative name) */
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

/* Network Address Constants */
#define MAC_ADDR_LEN                   6            /* MAC address length in bytes */
#define IPV4_ADDR_LEN                  4            /* IPv4 address length in bytes */

/* Checksum and Processing Constants */
#define CHECKSUM_CARRY_MASK            0xFFFF       /* Mask for checksum carry handling */

/* Network MTU and Size Constants */
#define STANDARD_MTU                   1500         /* Standard Ethernet MTU */
#define JUMBO_FRAME_THRESHOLD          9000         /* Jumbo frame size threshold */

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
#define MAX_CPU_CORES                  16           /* Maximum CPU cores for per-CPU stats */

/* =================================================================== */
/* EBPF MAP CONFIGURATION                                              */
/* =================================================================== */

/* Statistics Map */
#define STATS_MAP_MAX_ENTRIES          16           /* Number of statistics counters (0-15) */
#define STATS_MAP_TYPE                 BPF_MAP_TYPE_PERCPU_ARRAY

/* NAT Map */
#define NAT_MAP_MAX_ENTRIES            1024         /* Maximum NAT translation rules */
#define NAT_MAP_TYPE                   BPF_MAP_TYPE_HASH

/* Redirect Map */
#define REDIRECT_MAP_MAX_ENTRIES       1           /* Single redirect target interface */
#define REDIRECT_MAP_TYPE              BPF_MAP_TYPE_ARRAY

/* Memory and Buffer Size Constants */
#define RINGBUF_SIZE_BYTES             (512 * 1024 * 1024) /* 256MB ring buffer - BTF-compatible high performance */
#define PACKET_DATA_MAX_SIZE           3000         /* Maximum packet data for large VXLAN packets */
#define RINGBUF_RESERVE_SIZE           3006         /* Full reservation size (3000 bytes + 6 metadata) */
#define IP_ALLOWLIST_MAX_ENTRIES       10000        /* Support up to 10K allowed IPs */

/* =================================================================== */
/* PROTOCOL CONSTANTS ONLY - NO HARDCODED CONFIG                     */
/* All configuration values passed via command line from xdp.sh       */
/* =================================================================== */

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
/* PROCESSING AND VALIDATION CONSTANTS                                  */
/* =================================================================== */

/* VNI Array Indices (for VXLAN VNI validation) */
#define VNI_BYTE_0_INDEX               0            /* First byte of VNI array */
#define VNI_BYTE_1_INDEX               1            /* Second byte of VNI array */
#define VNI_BYTE_2_INDEX               2            /* Third byte of VNI array */

/* Key Constants for Map Lookups */
#define MAP_KEY_SINGLE_ENTRY           0            /* Key for single-entry maps */

/* Boolean and Validation Constants */
#define IP_ALLOWED                     1            /* IP allowlist allowed value */
#define IP_BLOCKED                     0            /* IP allowlist blocked value */
#define INTERFACE_INVALID              0            /* Invalid interface index */
#define BPF_SUBMIT_FLAGS_NONE          0            /* No flags for bpf_ringbuf_submit */

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

/* AWS Constants (Protocol Requirements) */
#define AWS_MIRROR_VNI                 1            /* AWS Traffic Mirror always uses VNI 1 */
#define AWS_NLB_MTU                    9000         /* AWS NLB maximum MTU */
#define AWS_VPC_MTU                    1500         /* AWS VPC standard MTU */

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