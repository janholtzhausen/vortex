// SPDX-License-Identifier: GPL-2.0
/*
 * vortex_xdp.bpf.c — XDP program for vortex reverse proxy
 *
 * Compiled with: clang -O2 -g -target bpf -D__BPF__ -D__TARGET_ARCH_x86
 *
 * Processing pipeline (per ingress TCP packet):
 *   1. Parse Ethernet / IPv4 or IPv6 / TCP headers with bounds checks
 *   2. IP blocklist enforcement   — XDP_DROP if source IP is blocked
 *   3. Stateful L4 conntrack      — XDP_DROP if no matching TCP state
 *      • RST  : tear down CT entry, always pass
 *      • SYN  : rate-limit new connections, create CT_SYN_SENT entry
 *      • other: require valid CT entry; advance state machine; drop stale
 *   4. Per-CPU metrics counters
 */

#define __BPF__
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include "maps.h"
#include "vortex_xdp.h"

#define ETH_P_IP    0x0800
#define ETH_P_IPV6  0x86DD

#define IPPROTO_TCP 6

#define TCP_FLAG_FIN  0x01
#define TCP_FLAG_SYN  0x02
#define TCP_FLAG_RST  0x04
#define TCP_FLAG_ACK  0x10

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key,   __be32);
    __type(value, struct rate_limit_entry);
} rate_limit_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key,   struct ip6_addr);
    __type(value, struct rate_limit_entry);
} rate_limit_map_v6 SEC(".maps");

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

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, struct vortex_metrics);
} metrics_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, struct rate_config);
} rate_config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, CT_MAP_MAX_ENTRIES);
    __type(key,   struct conn_tuple);
    __type(value, struct conn_state);
} conn_track_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, CT_MAP_MAX_ENTRIES);
    __type(key,   struct conn_tuple_v6);
    __type(value, struct conn_state);
} conn_track_map_v6 SEC(".maps");

static __always_inline struct vortex_metrics *get_metrics(void)
{
    __u32 key = 0;
    return bpf_map_lookup_elem(&metrics_map, &key);
}

static __always_inline int apply_rate_limit_v4(struct vortex_metrics *m, __be32 src_ip,
                                               __u64 now)
{
    __u32 rckey = 0;
    struct rate_config *rcfg = bpf_map_lookup_elem(&rate_config_map, &rckey);
    __u64 tps = (rcfg && rcfg->tokens_per_sec) ? rcfg->tokens_per_sec : DEFAULT_TOKENS_PER_SEC;
    __u64 burst = (rcfg && rcfg->burst) ? rcfg->burst : DEFAULT_BURST_TOKENS;

    struct rate_limit_entry *rle = bpf_map_lookup_elem(&rate_limit_map, &src_ip);
    if (!rle) {
        struct rate_limit_entry new_rle = {
            .tokens = burst * RATE_SCALE,
            .last_refill_ns = now,
        };
        bpf_map_update_elem(&rate_limit_map, &src_ip, &new_rle, BPF_ANY);
        return XDP_PASS;
    }

    __u64 elapsed = now - rle->last_refill_ns;
    __u64 add = (elapsed * tps * RATE_SCALE) / 1000000000ULL;
    __u64 max_tok = burst * RATE_SCALE;
    rle->tokens += add;
    if (rle->tokens > max_tok)
        rle->tokens = max_tok;
    rle->last_refill_ns = now;

    if (rle->tokens < RATE_SCALE) {
        if (m) m->dropped_ratelimit++;
        return XDP_DROP;
    }
    rle->tokens -= RATE_SCALE;
    return XDP_PASS;
}

static __always_inline int apply_rate_limit_v6(struct vortex_metrics *m,
                                               const struct ip6_addr *src_ip,
                                               __u64 now)
{
    __u32 rckey = 0;
    struct rate_config *rcfg = bpf_map_lookup_elem(&rate_config_map, &rckey);
    __u64 tps = (rcfg && rcfg->tokens_per_sec) ? rcfg->tokens_per_sec : DEFAULT_TOKENS_PER_SEC;
    __u64 burst = (rcfg && rcfg->burst) ? rcfg->burst : DEFAULT_BURST_TOKENS;

    struct rate_limit_entry *rle = bpf_map_lookup_elem(&rate_limit_map_v6, src_ip);
    if (!rle) {
        struct rate_limit_entry new_rle = {
            .tokens = burst * RATE_SCALE,
            .last_refill_ns = now,
        };
        bpf_map_update_elem(&rate_limit_map_v6, src_ip, &new_rle, BPF_ANY);
        return XDP_PASS;
    }

    __u64 elapsed = now - rle->last_refill_ns;
    __u64 add = (elapsed * tps * RATE_SCALE) / 1000000000ULL;
    __u64 max_tok = burst * RATE_SCALE;
    rle->tokens += add;
    if (rle->tokens > max_tok)
        rle->tokens = max_tok;
    rle->last_refill_ns = now;

    if (rle->tokens < RATE_SCALE) {
        if (m) m->dropped_ratelimit++;
        return XDP_DROP;
    }
    rle->tokens -= RATE_SCALE;
    return XDP_PASS;
}

static __always_inline int conntrack_tcp_v4(struct vortex_metrics *m,
                                            __be32 src_ip, __be32 dst_ip,
                                            struct tcphdr *tcp)
{
    __u8 *blocked = bpf_map_lookup_elem(&blocklist_map, &src_ip);
    if (blocked && *blocked) {
        if (m) m->dropped_blocklist++;
        return XDP_DROP;
    }

    __u8 tcp_flags = ((__u8 *)tcp)[13];
    int f_syn = (tcp_flags & TCP_FLAG_SYN) && !(tcp_flags & TCP_FLAG_ACK);
    int f_rst = (tcp_flags & TCP_FLAG_RST) != 0;
    int f_fin = (tcp_flags & TCP_FLAG_FIN) != 0;
    int f_ack = (tcp_flags & TCP_FLAG_ACK) != 0;

    struct conn_tuple key = {0};
    key.src_ip = src_ip;
    key.dst_ip = dst_ip;
    key.src_port = tcp->source;
    key.dst_port = tcp->dest;
    key.proto = IPPROTO_TCP;

    __u64 now = bpf_ktime_get_ns();
    if (f_rst) {
        bpf_map_delete_elem(&conn_track_map, &key);
        return XDP_PASS;
    }

    if (f_syn) {
        if (apply_rate_limit_v4(m, src_ip, now) == XDP_DROP)
            return XDP_DROP;

        struct conn_state new_state = {0};
        new_state.tcp_state = CT_SYN_SENT;
        new_state.last_seen_ns = now;
        bpf_map_update_elem(&conn_track_map, &key, &new_state, BPF_ANY);
        return XDP_PASS;
    }

    struct conn_state *cs = bpf_map_lookup_elem(&conn_track_map, &key);
    if (!cs) {
        if (m) m->dropped_conntrack++;
        return XDP_DROP;
    }

    __u64 timeout = (cs->tcp_state == CT_ESTABLISHED) ? CT_TIMEOUT_EST_NS : CT_TIMEOUT_SYN_NS;
    if (now - cs->last_seen_ns > timeout) {
        bpf_map_delete_elem(&conn_track_map, &key);
        if (m) m->dropped_conntrack++;
        return XDP_DROP;
    }

    if (f_fin)
        cs->tcp_state = (cs->tcp_state == CT_FIN_WAIT) ? CT_CLOSING : CT_FIN_WAIT;
    else if (f_ack && cs->tcp_state == CT_SYN_SENT)
        cs->tcp_state = CT_ESTABLISHED;
    cs->last_seen_ns = now;
    return XDP_PASS;
}

static __always_inline int conntrack_tcp_v6(struct vortex_metrics *m,
                                            const struct ip6_addr *src_ip,
                                            const struct ip6_addr *dst_ip,
                                            struct tcphdr *tcp)
{
    __u8 *blocked = bpf_map_lookup_elem(&blocklist_map_v6, src_ip);
    if (blocked && *blocked) {
        if (m) m->dropped_blocklist++;
        return XDP_DROP;
    }

    __u8 tcp_flags = ((__u8 *)tcp)[13];
    int f_syn = (tcp_flags & TCP_FLAG_SYN) && !(tcp_flags & TCP_FLAG_ACK);
    int f_rst = (tcp_flags & TCP_FLAG_RST) != 0;
    int f_fin = (tcp_flags & TCP_FLAG_FIN) != 0;
    int f_ack = (tcp_flags & TCP_FLAG_ACK) != 0;

    struct conn_tuple_v6 key = {0};
    __builtin_memcpy(&key.src_ip, src_ip, sizeof(*src_ip));
    __builtin_memcpy(&key.dst_ip, dst_ip, sizeof(*dst_ip));
    key.src_port = tcp->source;
    key.dst_port = tcp->dest;
    key.proto = IPPROTO_TCP;

    __u64 now = bpf_ktime_get_ns();
    if (f_rst) {
        bpf_map_delete_elem(&conn_track_map_v6, &key);
        return XDP_PASS;
    }

    if (f_syn) {
        if (apply_rate_limit_v6(m, src_ip, now) == XDP_DROP)
            return XDP_DROP;

        struct conn_state new_state = {0};
        new_state.tcp_state = CT_SYN_SENT;
        new_state.last_seen_ns = now;
        bpf_map_update_elem(&conn_track_map_v6, &key, &new_state, BPF_ANY);
        return XDP_PASS;
    }

    struct conn_state *cs = bpf_map_lookup_elem(&conn_track_map_v6, &key);
    if (!cs) {
        if (m) m->dropped_conntrack++;
        return XDP_DROP;
    }

    __u64 timeout = (cs->tcp_state == CT_ESTABLISHED) ? CT_TIMEOUT_EST_NS : CT_TIMEOUT_SYN_NS;
    if (now - cs->last_seen_ns > timeout) {
        bpf_map_delete_elem(&conn_track_map_v6, &key);
        if (m) m->dropped_conntrack++;
        return XDP_DROP;
    }

    if (f_fin)
        cs->tcp_state = (cs->tcp_state == CT_FIN_WAIT) ? CT_CLOSING : CT_FIN_WAIT;
    else if (f_ack && cs->tcp_state == CT_SYN_SENT)
        cs->tcp_state = CT_ESTABLISHED;
    cs->last_seen_ns = now;
    return XDP_PASS;
}

SEC("xdp")
int vortex_xdp_main(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct vortex_metrics *m = get_metrics();

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        goto pass_invalid;

    __u16 eth_proto = bpf_ntohs(eth->h_proto);
    if (eth_proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end)
            goto pass_invalid;

        __u8 nexthdr = ip6->nexthdr;
        __u32 off = sizeof(*ip6);

#pragma unroll
        for (int i = 0; i < 6; i++) {
            if (nexthdr == IPPROTO_TCP)
                break;
            if (nexthdr == 0 || nexthdr == 43 || nexthdr == 60) {
                struct ipv6_opt_hdr *opt = (void *)ip6 + off;
                if ((void *)(opt + 1) > data_end)
                    goto pass_invalid;
                nexthdr = opt->nexthdr;
                off += ((__u32)opt->hdrlen + 1) * 8;
                if ((void *)ip6 + off > data_end)
                    goto pass_invalid;
                continue;
            }
            if (nexthdr == 44) {
                struct frag_hdr *frag = (void *)ip6 + off;
                if ((void *)(frag + 1) > data_end)
                    goto pass_invalid;
                nexthdr = frag->nexthdr;
                off += sizeof(*frag);
                if ((bpf_ntohs(frag->frag_off) & 0xfff8) != 0)
                    goto pass;
                continue;
            }
            goto pass;
        }

        if (nexthdr != IPPROTO_TCP)
            goto pass;

        struct tcphdr *tcp6 = (void *)ip6 + off;
        if ((void *)(tcp6 + 1) > data_end)
            goto pass_invalid;

        struct ip6_addr src_ip6 = {0}, dst_ip6 = {0};
        __builtin_memcpy(src_ip6.addr, &ip6->saddr, sizeof(src_ip6.addr));
        __builtin_memcpy(dst_ip6.addr, &ip6->daddr, sizeof(dst_ip6.addr));
        if (conntrack_tcp_v6(m, &src_ip6, &dst_ip6, tcp6) == XDP_DROP)
            return XDP_DROP;
        goto pass;
    }

    if (eth_proto != ETH_P_IP)
        goto pass;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        goto pass_invalid;

    __u32 ip_hlen = ip->ihl * 4;
    if (ip_hlen < 20 || (void *)ip + ip_hlen > data_end)
        goto pass_invalid;
    if (ip->protocol != IPPROTO_TCP)
        goto pass;

    struct tcphdr *tcp = (void *)ip + ip_hlen;
    if ((void *)(tcp + 1) > data_end)
        goto pass_invalid;

    if (conntrack_tcp_v4(m, ip->saddr, ip->daddr, tcp) == XDP_DROP)
        return XDP_DROP;

pass:
    if (m) {
        m->rx_packets++;
        m->rx_bytes += (data_end - data);
        m->passed++;
    }
    return XDP_PASS;

pass_invalid:
    if (m) m->dropped_invalid++;
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
