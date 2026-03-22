#ifndef VORTEX_POOL_H
#define VORTEX_POOL_H

#include <pthread.h>
#include <unistd.h>
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

struct global_fd_pool {
    pthread_spinlock_t spin;
    uint32_t           count;
    int                fds[GLOBAL_POOL_SLOTS];
};

extern struct global_fd_pool g_backend_pools[VORTEX_MAX_ROUTES][VORTEX_MAX_BACKENDS];

void global_pool_init(void);
void global_pool_destroy(void);

/* Returns a pooled fd or -1 if the pool is empty. */
static inline int global_pool_get(int ri, int bi)
{
    struct global_fd_pool *p = &g_backend_pools[ri][bi];
    pthread_spin_lock(&p->spin);
    int fd = (p->count > 0) ? p->fds[--p->count] : -1;
    pthread_spin_unlock(&p->spin);
    return fd;
}

/* Returns fd to the pool.  Closes it if the pool is already at cap. */
static inline void global_pool_put(int ri, int bi, int fd, int cap)
{
    struct global_fd_pool *p = &g_backend_pools[ri][bi];
    int slots = (cap < GLOBAL_POOL_SLOTS) ? cap : GLOBAL_POOL_SLOTS;
    pthread_spin_lock(&p->spin);
    if ((int)p->count < slots) {
        p->fds[p->count++] = fd;
        pthread_spin_unlock(&p->spin);
    } else {
        pthread_spin_unlock(&p->spin);
        close(fd);
    }
}

#endif /* VORTEX_POOL_H */
