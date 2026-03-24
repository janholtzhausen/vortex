#pragma once

#include "worker.h"
#include "cache.h"
#include "config.h"
#include <pthread.h>
#include <stdint.h>

struct dashboard_server {
    int            listen_fd;
    volatile int   running;
    pthread_t      thread;

    struct worker       **workers;
    int                   num_workers;
    struct cache         *cache;
    struct vortex_config *cfg;
    uint64_t              start_time;
};

int  dashboard_init(struct dashboard_server *ds,
                    const char *bind_addr, uint16_t port,
                    struct worker **workers, int num_workers,
                    struct cache *cache, struct vortex_config *cfg);
int  dashboard_start(struct dashboard_server *ds);
void dashboard_stop(struct dashboard_server *ds);
void dashboard_join(struct dashboard_server *ds);
