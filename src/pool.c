#include "pool.h"

struct global_fd_pool g_backend_pools[VORTEX_MAX_ROUTES][VORTEX_MAX_BACKENDS];

void global_pool_init(void)
{
    for (int ri = 0; ri < VORTEX_MAX_ROUTES; ri++) {
        for (int bi = 0; bi < VORTEX_MAX_BACKENDS; bi++) {
            struct global_fd_pool *p = &g_backend_pools[ri][bi];
            pthread_spin_init(&p->spin, PTHREAD_PROCESS_PRIVATE);
            p->count = 0;
            for (int i = 0; i < GLOBAL_POOL_SLOTS; i++)
                p->fds[i] = -1;
        }
    }
}

void global_pool_destroy(void)
{
    for (int ri = 0; ri < VORTEX_MAX_ROUTES; ri++) {
        for (int bi = 0; bi < VORTEX_MAX_BACKENDS; bi++) {
            struct global_fd_pool *p = &g_backend_pools[ri][bi];
            pthread_spin_lock(&p->spin);
            for (uint32_t i = 0; i < p->count; i++) {
                if (p->fds[i] >= 0) { close(p->fds[i]); p->fds[i] = -1; }
            }
            p->count = 0;
            pthread_spin_unlock(&p->spin);
            pthread_spin_destroy(&p->spin);
        }
    }
}
