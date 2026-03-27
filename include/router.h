#pragma once

#include "config.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

struct router {
    struct vortex_config *cfg;    /* Live config pointer — may be swapped */
    uint32_t              rr_counters[VORTEX_MAX_ROUTES]; /* Round-robin state */
};

int  router_init(struct router *r, struct vortex_config *cfg);
void router_destroy(struct router *r);

/* Find route index for given SNI hostname.
 * Returns route index, or -1 if no match. */
int router_lookup(struct router *r, const char *sni, size_t sni_len);

/* Select backend index within a route (applies LB algorithm).
 * Returns backend index. */
int router_select_backend(struct router *r, int route_idx,
                          uint32_t client_ip);

/* Get backend address string for connection */
const char *router_backend_addr(struct router *r, int route_idx, int backend_idx);

/* Shared backend active-connection counters used by least_conn selection. */
void router_backend_active_inc(int route_idx, int backend_idx);
void router_backend_active_dec(int route_idx, int backend_idx);
