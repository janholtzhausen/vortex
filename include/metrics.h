#pragma once

#include "worker.h"
#include "../bpf/maps.h"
#include <stdint.h>

/* Per-route cert expiry info exposed to metrics */
struct metrics_cert_info {
    char   hostname[256];
    time_t not_after;   /* 0 = unknown */
};

struct metrics_server {
    int          listen_fd;
    int          running;
    pthread_t    thread;

    /* Pointers to live data */
    struct worker        **workers;
    int                   num_workers;
    uint64_t               start_time;

    /* TLS cert expiry (optional) */
    struct metrics_cert_info *cert_info;
    int                       cert_info_count;
};

int  metrics_init(struct metrics_server *ms,
                  const char *bind_addr, uint16_t port,
                  struct worker **workers, int num_workers);
int  metrics_start(struct metrics_server *ms);
void metrics_stop(struct metrics_server *ms);
void metrics_join(struct metrics_server *ms);
