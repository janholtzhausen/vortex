#pragma once

#include "config.h"
#include "conn.h"
#include "uring.h"
#include "router.h"
#include "tls.h"
#include "tls_pool.h"
#include "compress_pool.h"
#include "cache.h"
#include "bpf_loader.h"
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#define WORKER_MAX_CONNS   4096  /* hard cap — actual capacity set at runtime */
#define WORKER_BUF_SIZE    16384 /* per-connection buffer (16 KB); recv_window starts at WORKER_BUF_INIT */
#define WORKER_BUF_INIT    4096  /* initial dynamic recv window (4 KB); doubles on full read up to BUF_SIZE */
#define WORKER_URING_DEPTH 4096
#define WORKER_TARPIT_MAX  512


/* How long evicted tarpit IPs stay in the XDP blocklist */
#define WORKER_BLOCK_TTL_SECS  3600
/* Ring capacity for tracking in-flight blocklist expiries */
#define WORKER_BLOCKED_MAX     4096

struct blocked_entry {
    struct vortex_ip_addr ip;
    time_t   expire_at;
};

struct worker {
    int              worker_id;
    int              listen_fd;       /* Shared listening socket */
    pthread_t        thread;

    struct uring_ctx uring;
    struct conn_pool pool;
    struct router    router;

#ifdef VORTEX_PHASE_TLS
    struct tls_ctx  *tls;             /* Shared TLS context (NULL = plain HTTP) */
    SSL_CTX         *backend_tls_client_ctx; /* Per-worker client SSL_CTX for HTTPS origins */
    SSL_SESSION     *backend_tls_sessions[VORTEX_MAX_ROUTES][VORTEX_MAX_BACKENDS];
#endif

    struct vortex_config *cfg;        /* Shared, atomic ptr swap for reload */

    /* Stats */
    uint64_t         accepted;
    uint64_t         completed;
    uint64_t         errors;
    uint64_t         pool_exhausted;
    uint64_t         tls12_count;   /* TLS 1.2 handshakes */
    uint64_t         tls13_count;   /* TLS 1.3 handshakes */
    uint64_t         ktls_count;    /* connections using kTLS */

    struct cache    *cache;

    /* Tarpit: unrecognised-SNI connections held with window=1 */
    int              tarpit_fds[WORKER_TARPIT_MAX];
    struct vortex_ip_addr tarpit_ips[WORKER_TARPIT_MAX];
    uint32_t         tarpit_head;   /* FIFO: head is the eviction index (oldest fd), wraps via %WORKER_TARPIT_MAX */
    uint32_t         tarpit_count;  /* number of live tarpit fds */
    uint64_t         tarpit_total;  /* cumulative tarpit count */

    int              urandom_fd;    /* /dev/urandom for tarpit noise */
    FILE            *tarpit_log;    /* /var/log/vortex/tarpit.log */

    /* Pipe for receiving completed TLS handshake results from tls_pool */
    int              tls_done_pipe_rd; /* read end — polled by io_uring */
    int              tls_done_pipe_wr; /* write end — passed to pool threads */
    /* Buffer for a single read from the result pipe (one result at a time) */
    uint8_t          tls_pipe_buf[sizeof(struct tls_handshake_result)];
    int              compress_done_pipe_rd; /* read end — polled by io_uring */
    int              compress_done_pipe_wr; /* write end — passed to pool threads */
    uint8_t          compress_pipe_buf[sizeof(struct compress_result)];

    /* XDP blocklist expiry ring — FIFO, oldest at head */
    struct blocked_entry blocked_list[WORKER_BLOCKED_MAX];
    uint32_t             blocked_head;
    uint32_t             blocked_tail;
    uint32_t             blocked_count;

    /* Circuit breaker per (route, backend). fail_count resets to 0 on first success.
     * open_until_ns=0 means closed. Half-open: when timeout expires, ONE probe request
     * is let through; if it succeeds, open_until_ns is cleared. */
    struct {
        uint32_t fail_count;
        uint64_t open_until_ns;
    } backend_cb[VORTEX_MAX_ROUTES][VORTEX_MAX_BACKENDS];

    /* Token bucket rate limiter. tokens is in integer requests (not millirequests).
     * last_ns is CLOCK_MONOTONIC_COARSE timestamp of last replenishment. */
    struct {
        uint32_t tokens;
        uint64_t last_ns;
    } route_rl[VORTEX_MAX_ROUTES];

    volatile int     stop;
};

/* Create listening socket bound to addr:port.
 * ipv4_only=true  → AF_INET socket, addr is a dotted-quad (or "" for INADDR_ANY).
 * ipv4_only=false → AF_INET6 socket with IPV6_V6ONLY=0; accepts both IPv4-mapped
 *                   and native IPv6.  addr should be "::" for all-interfaces.
 * XDP/tarpit blocklist and rate limiting apply to both IPv4 and IPv6. */
int worker_create_listener(const char *addr, uint16_t port, int backlog, bool ipv4_only);

/* Initialize worker (call before starting thread).
 * capacity = connection pool size (use worker_pool_capacity() to auto-size).
 * tls may be NULL for plain HTTP mode. */
int worker_init(struct worker *w, int id, int listen_fd, uint32_t capacity,
                struct vortex_config *cfg, struct tls_ctx *tls,
                struct cache *shared_cache);

/* Compute connection pool capacity for one worker from available system memory.
 * budget_pct: fraction of MemAvailable to use across all workers (e.g. 0.5).
 * Result is clamped to [1, WORKER_MAX_CONNS]. */
uint32_t worker_pool_capacity(int num_workers, double budget_pct);

/* Start worker thread */
int worker_start(struct worker *w);

/* Signal worker to stop */
void worker_stop(struct worker *w);

/* Wait for worker thread to exit */
void worker_join(struct worker *w);

void worker_destroy(struct worker *w);
