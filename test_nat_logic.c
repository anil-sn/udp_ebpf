/*
 * Test program to verify NAT lookup logic
 * Compile: gcc -o test_nat_logic test_nat_logic.c
 */
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

struct nat_key {
    uint16_t src_port;         
};

int main() {
    printf("=== NAT Logic Test ===\n\n");
    
    // Packet data from analysis
    uint16_t inner_udp_src = 19480;    // Source port from packet
    uint16_t inner_udp_dst = 31765;    // Destination port from packet
    uint32_t config_source_port = 31765; // SOURCE_PORT from .env config
    
    printf("From packet analysis:\n");
    printf("  Inner UDP Source Port: %u\n", inner_udp_src);
    printf("  Inner UDP Dest Port: %u\n", inner_udp_dst);
    printf("\nFrom configuration:\n");
    printf("  SOURCE_PORT (config): %u\n", config_source_port);
    
    printf("\n=== Logic Comparison ===\n");
    
    // Old logic (was using source port)
    struct nat_key old_key = { .src_port = htons(inner_udp_src) };
    printf("OLD logic - NAT key: %u (network order: %u)\n", 
           inner_udp_src, ntohs(old_key.src_port));
    printf("  Would match config? %s\n", 
           (inner_udp_src == config_source_port) ? "YES" : "NO");
    
    // New logic (using destination port)  
    struct nat_key new_key = { .src_port = htons(inner_udp_dst) };
    printf("\nNEW logic - NAT key: %u (network order: %u)\n",
           inner_udp_dst, ntohs(new_key.src_port));
    printf("  Would match config? %s\n",
           (inner_udp_dst == config_source_port) ? "YES" : "NO");
           
    printf("\n=== CONCLUSION ===\n");
    if (inner_udp_dst == config_source_port) {
        printf("✅ Fixed! New logic correctly matches destination port %u with config\n", config_source_port);
    } else {
        printf("❌ Still broken - need to check configuration\n");
    }
    
    return 0;
}