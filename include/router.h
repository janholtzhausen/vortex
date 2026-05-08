#pragma once

#include "config.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <time.h>

struct router {
    struct vortex_config *cfg; /* Live config pointer — may be swapped */
    uint32_t rr_counters[VORTEX_MAX_ROUTES]; /* Round-robin state */
};

int router_init(struct router *r, struct vortex_config *cfg);
void router_destroy(struct router *r);

/* Find route index for given SNI hostname.
 * Returns route index, or -1 if no match. */
int router_lookup(struct router *r, const char *sni, size_t sni_len);

/* Select backend index within a route (applies LB algorithm).
 * Returns backend index. */
int router_select_backend(struct router *r, int route_idx, uint32_t client_ip);

/* Get backend address string for connection */
const char *router_backend_addr(struct router *r, int route_idx, int backend_idx);

/* Shared backend active-connection counters used by least_conn selection. */
void router_backend_active_inc(int route_idx, int backend_idx);
void router_backend_active_dec(int route_idx, int backend_idx);

/* ---- Global rate limiter (replaces per-worker route_rl) ---- */
typedef struct {
    _Atomic uint32_t tokens;
    _Atomic uint64_t last_ns;
} global_rate_bucket_t;

extern global_rate_bucket_t g_route_rl[VORTEX_MAX_ROUTES];

/* Returns true if the request is allowed, false if rate-limited. */
bool global_rate_limit_check(int ri, const struct route_rate_limit_config *rl);

/* ---- Global circuit breaker (replaces per-worker backend_cb) ---- */
typedef struct {
    _Atomic uint32_t fail_count;
    _Atomic uint64_t open_until_ns;
} global_cb_t;

extern global_cb_t g_backend_cb[VORTEX_MAX_ROUTES][VORTEX_MAX_BACKENDS];

bool cb_is_open_global(int ri, int bi, uint64_t now_ns);
void cb_record_failure_global(int ri, int bi, uint64_t now_ns, uint32_t threshold,
                              uint32_t open_ms);
void cb_record_success_global(int ri, int bi);
