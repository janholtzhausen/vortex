// SPDX-License-Identifier: GPL-2.0
/*
 * vortex_xdp.bpf.c — XDP program for vortex reverse proxy
 *
 * Compiled with: clang -O2 -g -target bpf -D__BPF__ -D__TARGET_ARCH_x86
 *
 * Processing pipeline (per ingress TCP/IPv4 packet):
 *   1. Parse Ethernet / IPv4 / TCP headers with bounds checks
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

/* Ethernet protocol numbers */
#define ETH_P_IP    0x0800
#define ETH_P_IPV6  0x86DD

/* IP protocol numbers */
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

/* TCP flags (byte 13 of the TCP header, 0-indexed) */
#define TCP_FLAG_FIN  0x01
#define TCP_FLAG_SYN  0x02
#define TCP_FLAG_RST  0x04
#define TCP_FLAG_PSH  0x08
#define TCP_FLAG_ACK  0x10
#define TCP_FLAG_URG  0x20

/* ------------------------------------------------------------------ */
/* BPF Maps                                                            */
/* ------------------------------------------------------------------ */

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key,   __be32);
    __type(value, struct rate_limit_entry);
} rate_limit_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key,   __be32);
    __type(value, __u8);
} blocklist_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, struct vortex_metrics);
} metrics_map SEC(".maps");

/* Global rate limit config — userspace writes tokens_per_sec and burst */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, struct rate_config);
} rate_config_map SEC(".maps");

/*
 * Stateful L4 connection tracking map.
 * Key:   5-tuple (src_ip, dst_ip, src_port, dst_port, proto)
 * Value: TCP state + last-seen timestamp
 * LRU eviction handles connections that close without RST/FIN.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, CT_MAP_MAX_ENTRIES);
    __type(key,   struct conn_tuple);
    __type(value, struct conn_state);
} conn_track_map SEC(".maps");

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static __always_inline struct vortex_metrics *get_metrics(void)
{
    __u32 key = 0;
    return bpf_map_lookup_elem(&metrics_map, &key);
}

/* ------------------------------------------------------------------ */
/* XDP Main Program                                                    */
/* ------------------------------------------------------------------ */

SEC("xdp")
int vortex_xdp_main(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct vortex_metrics *m = get_metrics();

    /* Step 1: Parse Ethernet header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        goto pass_invalid;

    __u16 eth_proto = bpf_ntohs(eth->h_proto);
    if (eth_proto != ETH_P_IP) {
        /* Pass IPv6, ARP, etc. — conntrack is IPv4/TCP only */
        goto pass;
    }

    /* Step 2: Parse IPv4 header */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        goto pass_invalid;

    __u32 ip_hlen = ip->ihl * 4;
    if (ip_hlen < 20)
        goto pass_invalid;

    if ((void *)ip + ip_hlen > data_end)
        goto pass_invalid;

    __be32 src_ip = ip->saddr;

    /* Step 3: Only handle TCP — pass UDP, ICMP, etc. without conntrack */
    if (ip->protocol != IPPROTO_TCP)
        goto pass;

    /* Step 4: Parse TCP header (sizeof(tcphdr) == 20, flags at byte 13) */
    struct tcphdr *tcp = (void *)ip + ip_hlen;
    if ((void *)(tcp + 1) > data_end)
        goto pass_invalid;

    /* Read the TCP control flags byte directly from offset 13 of the header.
     * The bounds check above ((void *)(tcp+1) > data_end, sizeof(tcphdr)=20)
     * guarantees bytes 0..19 are accessible; byte 13 is within that range. */
    __u8 tcp_flags = ((__u8 *)tcp)[13];

    int f_syn = (tcp_flags & TCP_FLAG_SYN) && !(tcp_flags & TCP_FLAG_ACK);
    int f_rst = (tcp_flags & TCP_FLAG_RST) != 0;
    int f_fin = (tcp_flags & TCP_FLAG_FIN) != 0;
    int f_ack = (tcp_flags & TCP_FLAG_ACK) != 0;

    /* Step 5: Blocklist check */
    __u8 *blocked = bpf_map_lookup_elem(&blocklist_map, &src_ip);
    if (blocked && *blocked) {
        if (m) m->dropped_blocklist++;
        return XDP_DROP;
    }

    /* Step 6: Stateful L4 connection tracking
     *
     * Policy:
     *   RST        → delete CT entry; pass (connection is being torn down)
     *   SYN (!ACK) → rate-limit new connection attempts; create CT_SYN_SENT
     *   everything else → require a valid, non-stale CT entry; advance state
     *
     * Rate limiting is applied only to SYNs (new connection requests).
     * Established-connection packets are not individually rate-limited.
     */
    {
        /* Build 5-tuple key — all padding bytes must be zero */
        struct conn_tuple ct_key;
        __builtin_memset(&ct_key, 0, sizeof(ct_key));
        ct_key.src_ip   = ip->saddr;
        ct_key.dst_ip   = ip->daddr;
        ct_key.src_port = tcp->source;
        ct_key.dst_port = tcp->dest;
        ct_key.proto    = IPPROTO_TCP;

        __u64 now = bpf_ktime_get_ns();

        /* ---- RST: tear down ---- */
        if (f_rst) {
            bpf_map_delete_elem(&conn_track_map, &ct_key);
            goto pass;
        }

        /* ---- SYN: new connection attempt ---- */
        if (f_syn) {
            /* Rate-limit new connection attempts per source IP */
            __u32 rckey = 0;
            struct rate_config *rcfg =
                bpf_map_lookup_elem(&rate_config_map, &rckey);
            __u64 tps   = (rcfg && rcfg->tokens_per_sec)
                          ? rcfg->tokens_per_sec : DEFAULT_TOKENS_PER_SEC;
            __u64 burst = (rcfg && rcfg->burst)
                          ? rcfg->burst : DEFAULT_BURST_TOKENS;

            struct rate_limit_entry *rle =
                bpf_map_lookup_elem(&rate_limit_map, &src_ip);
            if (!rle) {
                /* First SYN from this IP — seed the bucket and allow */
                struct rate_limit_entry new_rle;
                __builtin_memset(&new_rle, 0, sizeof(new_rle));
                new_rle.tokens         = burst * RATE_SCALE;
                new_rle.last_refill_ns = now;
                bpf_map_update_elem(&rate_limit_map, &src_ip,
                                    &new_rle, BPF_ANY);
            } else {
                /* Refill tokens for elapsed time, then consume one */
                __u64 elapsed  = now - rle->last_refill_ns;
                __u64 add      = (elapsed / 1000) * tps / 1000000 * RATE_SCALE;
                __u64 max_tok  = burst * RATE_SCALE;

                rle->tokens += add;
                if (rle->tokens > max_tok)
                    rle->tokens = max_tok;
                rle->last_refill_ns = now;

                if (rle->tokens < RATE_SCALE) {
                    if (m) m->dropped_ratelimit++;
                    return XDP_DROP;
                }
                rle->tokens -= RATE_SCALE;
            }

            /* Create CT entry in SYN_SENT state */
            struct conn_state new_cs;
            __builtin_memset(&new_cs, 0, sizeof(new_cs));
            new_cs.tcp_state    = CT_SYN_SENT;
            new_cs.last_seen_ns = now;
            bpf_map_update_elem(&conn_track_map, &ct_key, &new_cs, BPF_ANY);
            goto pass;
        }

        /* ---- Non-SYN, non-RST: validate existing connection ---- */
        struct conn_state *cs =
            bpf_map_lookup_elem(&conn_track_map, &ct_key);

        if (!cs) {
            /* No CT entry — packet has no matching connection; drop it.
             * This catches ACK scans, spoofed mid-stream packets, etc. */
            if (m) m->dropped_conntrack++;
            return XDP_DROP;
        }

        /* Idle timeout check */
        __u64 timeout = (cs->tcp_state == CT_ESTABLISHED)
                        ? CT_TIMEOUT_EST_NS : CT_TIMEOUT_SYN_NS;
        if (now - cs->last_seen_ns > timeout) {
            /* Stale entry — connection has been idle too long */
            bpf_map_delete_elem(&conn_track_map, &ct_key);
            if (m) m->dropped_conntrack++;
            return XDP_DROP;
        }

        /* Advance state machine (in-place update via the map value pointer) */
        if (f_fin) {
            /* First FIN → FIN_WAIT; second FIN → CLOSING */
            cs->tcp_state = (cs->tcp_state == CT_FIN_WAIT)
                            ? CT_CLOSING : CT_FIN_WAIT;
        } else if (f_ack && cs->tcp_state == CT_SYN_SENT) {
            /* Client ACK completing the three-way handshake */
            cs->tcp_state = CT_ESTABLISHED;
        }
        cs->last_seen_ns = now;
    }

    /* Step 7: Update pass metrics */
pass:
    if (m) {
        m->rx_packets++;
        m->rx_bytes += (data_end - data);
        m->passed++;
    }
    return XDP_PASS;

pass_invalid:
    if (m) m->dropped_invalid++;
    return XDP_PASS; /* Pass malformed frames to the kernel stack */
}

char _license[] SEC("license") = "GPL";
