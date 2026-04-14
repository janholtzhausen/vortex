// SPDX-License-Identifier: GPL-2.0
/*
 * vortex-tc-egress-simple.bpf.c — Simple TC egress program for vortex tarpitting
 * 
 * Clamps TCP window to 1 byte in egress packets to blocked IPs.
 *
 * Compiled with: clang -O2 -g -target bpf -D__BPF__ -D__TARGET_ARCH_x86
 */

#define __BPF__
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "maps.h"

/* MAX_PROTECTED_PORTS, port_config and port_config_map are defined in maps.h */

#define ETH_P_IP    0x0800
#define ETH_P_IPV6  0x86DD
#define IPPROTO_TCP 6

// BPF maps for blocklist (same as vortex)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key,   __be32);
    __type(value, __u8);
} blocklist_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key,   struct ip6_addr);
    __type(value, __u8);
} blocklist_map_v6 SEC(".maps");

/* Port configuration map - which ports vortex protects */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, struct port_config);
} port_config_map SEC(".maps");

// Helper to clamp TCP window to 1 byte
static __always_inline void clamp_tcp_window(struct tcphdr *tcp)
{
    // Set window size to 1 byte (in network byte order)
    tcp->window = bpf_htons(1);
}

/* Check if a port is in the protected ports list */
static __always_inline int is_protected_port(__be16 port)
{
    __u32 key = 0;
    struct port_config *config = bpf_map_lookup_elem(&port_config_map, &key);
    
    if (!config || config->count == 0) {
        // Default to protecting ports 80 and 443 if no config
        __u16 port_host = bpf_ntohs(port);
        return (port_host == 80 || port_host == 443);
    }
    
    // Check if port is in the configured list
    __u16 port_host = bpf_ntohs(port);
    for (int i = 0; i < config->count && i < MAX_PROTECTED_PORTS; i++) {
        if (bpf_ntohs(config->ports[i]) == port_host) {
            return 1;
        }
    }
    
    return 0;
}

SEC("tc")
int tc_egress_tarpit(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0;  // TC_ACT_OK
    
    __u16 eth_proto = bpf_ntohs(eth->h_proto);
    
    // Handle IPv4 egress
    if (eth_proto == ETH_P_IP) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return 0;
        
        __u32 ip_hlen = ip->ihl * 4;
        if (ip_hlen < 20 || (void *)ip + ip_hlen > data_end)
            return 0;
        
        // Only process TCP packets
        if (ip->protocol != IPPROTO_TCP)
            return 0;
        
        struct tcphdr *tcp = (void *)ip + ip_hlen;
        if ((void *)(tcp + 1) > data_end)
            return 0;
        
        // Validate TCP header
        if (tcp->doff < 5 || (void *)tcp + tcp->doff * 4 > data_end)
            return 0;
        
        // Check if destination IP is in blocklist
        __u8 *blocked = bpf_map_lookup_elem(&blocklist_map, &ip->daddr);
        if (blocked && *blocked) {
            // Only tarpit egress to protected ports
            if (is_protected_port(tcp->dest)) {
                // TARPIT: Clamp TCP window to 1 byte in egress packets
                clamp_tcp_window(tcp);
            }
        }
        return 0;
    }
    
    // Handle IPv6 egress
    if (eth_proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end)
            return 0;
        
        // Only process TCP packets
        if (ip6->nexthdr != IPPROTO_TCP)
            return 0;
        
        struct tcphdr *tcp6 = (void *)(ip6 + 1);
        if ((void *)(tcp6 + 1) > data_end)
            return 0;
        
        // Validate TCP header
        if (tcp6->doff < 5 || (void *)tcp6 + tcp6->doff * 4 > data_end)
            return 0;
        
        struct ip6_addr dst_ip6 = {0};
        __builtin_memcpy(dst_ip6.addr, &ip6->daddr, sizeof(dst_ip6.addr));
        
        // Check if destination IP is in blocklist
        __u8 *blocked = bpf_map_lookup_elem(&blocklist_map_v6, &dst_ip6);
        if (blocked && *blocked) {
            // Only tarpit egress to protected ports
            if (is_protected_port(tcp6->dest)) {
                // TARPIT: Clamp TCP window to 1 byte in egress packets
                clamp_tcp_window(tcp6);
            }
        }
        return 0;
    }
    
    return 0;
}

char _license[] SEC("license") = "GPL";