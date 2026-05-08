#ifndef VORTEX_POOL_H
#define VORTEX_POOL_H

#include <pthread.h>
#include <unistd.h>
#include <stdbool.h>
#ifdef VORTEX_PHASE_TLS
#include <picotls.h>
#endif
#include "config.h"

/*
 * Global backend connection pool — shared across all worker threads.
 *
 * One pool per (route_idx, backend_idx) pair.  Workers borrow an idle fd by
 * calling global_pool_get(), use it for exactly one HTTP request cycle, then
 * return it via global_pool_put().
 *
 * The fd is still installed into the borrowing worker's io_uring fixed-file
 * table (uring_install_fd / uring_remove_fd) on each borrow/return, so zero-
 * copy SQE dispatch works exactly as before.  The only new cost is the
 * spinlock acquire/release (~10 ns uncontended).
 *
 * Sharing the pool across workers eliminates per-worker pool starvation under
 * uneven load and ensures the configured pool_size is the actual global cap
 * rather than being siloed per worker.
 */

/* Upper bound on pooled fds per (route, backend).
 * Real cap is min(pool_size_from_config, GLOBAL_POOL_SLOTS). */
#define GLOBAL_POOL_SLOTS 256

struct global_backend_conn {
    int fd;
    void *ssl;
    uint32_t pooled_at_s; /* coarse CLOCK_MONOTONIC seconds at put time */
};

struct global_fd_pool {
    pthread_spinlock_t spin;
    uint32_t count;
    struct global_backend_conn conns[GLOBAL_POOL_SLOTS];
};

extern struct global_fd_pool g_backend_pools[VORTEX_MAX_ROUTES][VORTEX_MAX_BACKENDS];

void global_pool_init(void);
void global_pool_destroy(void);

/* Default idle TTL: 55 s (just under nginx's 60 s keepalive_timeout default). */
#define POOL_IDLE_TTL_S 55

static inline uint32_t pool_coarse_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);
    return (uint32_t)ts.tv_sec;
}

/* Returns a fresh pooled backend connection or false if pool is empty/stale. */
static inline bool global_pool_get(int ri, int bi, struct global_backend_conn *out)
{
    struct global_fd_pool *p = &g_backend_pools[ri][bi];
    uint32_t now_s = pool_coarse_s();
    pthread_spin_lock(&p->spin);
    while (p->count > 0) {
        struct global_backend_conn c = p->conns[--p->count];
        p->conns[p->count] = (struct global_backend_conn){.fd = -1};
        pthread_spin_unlock(&p->spin);
        if (now_s - c.pooled_at_s <= POOL_IDLE_TTL_S) {
            if (out) *out = c;
            return true;
        }
        /* Stale — discard */
        close(c.fd);
#ifdef VORTEX_PHASE_TLS
        if (c.ssl) ptls_free((ptls_t *)c.ssl);
#endif
        pthread_spin_lock(&p->spin);
    }
    pthread_spin_unlock(&p->spin);
    return false;
}

/* Returns a backend connection to the pool, stamping idle timestamp. */
static inline void global_pool_put(int ri, int bi, struct global_backend_conn conn, int cap)
{
    conn.pooled_at_s = pool_coarse_s();
    struct global_fd_pool *p = &g_backend_pools[ri][bi];
    int slots = (cap < GLOBAL_POOL_SLOTS) ? cap : GLOBAL_POOL_SLOTS;
    pthread_spin_lock(&p->spin);
    if ((int)p->count < slots) {
        p->conns[p->count++] = conn;
        pthread_spin_unlock(&p->spin);
    } else {
        pthread_spin_unlock(&p->spin);
        close(conn.fd);
#ifdef VORTEX_PHASE_TLS
        if (conn.ssl) ptls_free((ptls_t *)conn.ssl);
#endif
    }
}

#endif /* VORTEX_POOL_H */
