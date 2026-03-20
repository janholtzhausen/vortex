#pragma once

#include "config.h"
#include "conn.h"
#include "uring.h"
#include "router.h"
#include "tls.h"
#include "cache.h"
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#define WORKER_MAX_CONNS   4096  /* hard cap — actual capacity set at runtime */
#define WORKER_BUF_SIZE    65536
#define WORKER_URING_DEPTH 4096
#define WORKER_TARPIT_MAX  512

/* Maximum idle backend fds held per (route, backend) pair */
#define BACKEND_POOL_SLOTS 16

/*
 * Per-(route, backend) idle connection pool.
 * Stored per-worker to avoid cross-thread locking.
 * Connections are returned here after a complete HTTP response when the
 * backend has keep-alive semantics (pool_size > 0 in config).
 */
struct backend_fd_pool {
    int      fds[BACKEND_POOL_SLOTS];
    uint32_t count;
};

/* How long evicted tarpit IPs stay in the XDP blocklist */
#define WORKER_BLOCK_TTL_SECS  3600
/* Ring capacity for tracking in-flight blocklist expiries */
#define WORKER_BLOCKED_MAX     4096

struct blocked_entry {
    uint32_t ip_host;     /* host byte order, IPv4 only */
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
#endif

    struct vortex_config *cfg;        /* Shared, atomic ptr swap for reload */

    /* Stats */
    uint64_t         accepted;
    uint64_t         completed;
    uint64_t         errors;
    uint64_t         tls12_count;   /* TLS 1.2 handshakes */
    uint64_t         tls13_count;   /* TLS 1.3 handshakes */
    uint64_t         ktls_count;    /* connections using kTLS */

    struct cache     cache;

    /* Tarpit: unrecognised-SNI connections held with window=1 */
    int              tarpit_fds[WORKER_TARPIT_MAX];
    uint32_t         tarpit_head;   /* FIFO head index */
    uint32_t         tarpit_count;  /* number of live tarpit fds */
    uint64_t         tarpit_total;  /* cumulative tarpit count */

    int              urandom_fd;    /* /dev/urandom for tarpit noise */
    FILE            *tarpit_log;    /* /var/log/vortex/tarpit.log */

    /* XDP blocklist expiry ring — FIFO, oldest at head */
    struct blocked_entry blocked_list[WORKER_BLOCKED_MAX];
    uint32_t             blocked_head;
    uint32_t             blocked_tail;
    uint32_t             blocked_count;

    /* Per-(route, backend) idle connection pools */
    struct backend_fd_pool backend_pool[VORTEX_MAX_ROUTES][VORTEX_MAX_BACKENDS];

    volatile int     stop;
};

/* Create listening socket bound to addr:port */
int worker_create_listener(const char *addr, uint16_t port, int backlog);

/* Initialize worker (call before starting thread).
 * capacity = connection pool size (use worker_pool_capacity() to auto-size).
 * tls may be NULL for plain HTTP mode. */
int worker_init(struct worker *w, int id, int listen_fd, uint32_t capacity,
                struct vortex_config *cfg, struct tls_ctx *tls);

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
