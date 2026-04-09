#pragma once

/*
 * BPF map definitions shared between XDP program and userspace.
 * This header is included by both bpf/vortex_xdp.bpf.c and src/bpf_loader.c
 */

#ifdef __BPF__
/* BPF-side includes */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#else
/* Userspace-side includes — use kernel types directly */
#include <stdint.h>
#include <linux/types.h>
#endif

/* Per-IP rate limiting entry — token bucket */
struct rate_limit_entry {
    __u64 tokens;           /* Current token count (scaled by RATE_SCALE) */
    __u64 last_refill_ns;   /* ktime_get_ns() at last refill */
};

struct ip6_addr {
    __u8 addr[16];
};

/* Aggregate metrics — fetched by userspace from per-CPU array */
struct vortex_metrics {
    __u64 rx_packets;
    __u64 rx_bytes;
    __u64 dropped_ratelimit;
    __u64 dropped_blocklist;
    __u64 dropped_invalid;
    __u64 passed;
    __u64 dropped_conntrack;   /* packets dropped due to invalid TCP connection state */
};

/* Rate limit scale factor: tokens stored as (real_tokens * RATE_SCALE) */
#define RATE_SCALE          1000000ULL
/* Default tokens per second per IP (used when rate_config_map not yet set) */
#define DEFAULT_TOKENS_PER_SEC  1000ULL
/* Default burst (initial bucket fill) */
#define DEFAULT_BURST_TOKENS    2000ULL

/* Global rate limit configuration — written by userspace, read by XDP */
struct rate_config {
    __u64 tokens_per_sec;   /* New connections allowed per second per IP (0 = default) */
    __u64 burst;            /* Max burst size in connections (0 = use default) */
};

/* ------------------------------------------------------------------ */
/* Stateful L4 connection tracking                                     */
/* ------------------------------------------------------------------ */

/* TCP connection states tracked in XDP */
#define CT_SYN_SENT    1   /* SYN seen, awaiting ACK to complete handshake */
#define CT_ESTABLISHED 2   /* Three-way handshake complete, data flowing */
#define CT_FIN_WAIT    3   /* FIN seen from one side, waiting for close */
#define CT_CLOSING     4   /* Both sides have sent FIN */

/* Idle timeouts — connections not updated within these limits are expired */
#define CT_TIMEOUT_SYN_NS  (30ULL  * 1000000000ULL)  /* 30 s: incomplete handshake */
#define CT_TIMEOUT_EST_NS  (120ULL * 1000000000ULL)  /* 120 s: idle established    */
#define CT_TIMEOUT_FIN_NS  (30ULL  * 1000000000ULL)  /* 30 s: half-closed          */

/* Maximum number of simultaneously tracked connections */
#define CT_MAP_MAX_ENTRIES 524288

/* 5-tuple connection key (all fields in network byte order) */
struct conn_tuple {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8   proto;
    __u8   _pad[3];   /* must be zero — part of the map key */
};

struct conn_tuple_v6 {
    struct ip6_addr src_ip;
    struct ip6_addr dst_ip;
    __be16          src_port;
    __be16          dst_port;
    __u8            proto;
    __u8            _pad[3];
};

/* Per-connection tracking state */
struct conn_state {
    __u8  tcp_state;     /* CT_SYN_SENT / CT_ESTABLISHED / CT_FIN_WAIT / CT_CLOSING */
    __u8  _pad[7];
    __u64 last_seen_ns;  /* bpf_ktime_get_ns() at last matching ingress packet */
};
