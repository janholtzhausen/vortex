#include "router.h"
#include "log.h"
#include "util.h"

#include <string.h>
#include <stdlib.h>
#define _GNU_SOURCE
#include <fnmatch.h>

int router_init(struct router *r, struct vortex_config *cfg)
{
    memset(r, 0, sizeof(*r));
    r->cfg = cfg;
    log_info("router_init", "routes=%d", cfg->route_count);
    return 0;
}

void router_destroy(struct router *r)
{
    (void)r;
}

int router_lookup(struct router *r, const char *sni, size_t sni_len)
{
    if (!sni || sni_len == 0) {
        /* No SNI — return first route with empty/wildcard hostname, or -1 */
        for (int i = 0; i < r->cfg->route_count; i++) {
            if (r->cfg->routes[i].hostname[0] == '\0' ||
                r->cfg->routes[i].hostname[0] == '*') {
                return i;
            }
        }
        return -1;
    }

    /* Exact match first */
    for (int i = 0; i < r->cfg->route_count; i++) {
        const char *h = r->cfg->routes[i].hostname;
        if (h[0] == '*') continue; /* wildcard — try later */
        if (strncmp(h, sni, sni_len) == 0 && h[sni_len] == '\0') {
            return i;
        }
    }

    /* Wildcard match: *.example.com matches foo.example.com */
    for (int i = 0; i < r->cfg->route_count; i++) {
        const char *h = r->cfg->routes[i].hostname;
        if (h[0] != '*') continue;
        /* Use fnmatch for wildcard matching */
        char sni_buf[VORTEX_MAX_HOSTNAME];
        size_t copy_len = sni_len < sizeof(sni_buf) - 1 ? sni_len : sizeof(sni_buf) - 1;
        memcpy(sni_buf, sni, copy_len);
        sni_buf[copy_len] = '\0';
        if (fnmatch(h, sni_buf, FNM_CASEFOLD) == 0) {
            return i;
        }
    }

    return -1; /* No match */
}

int router_select_backend(struct router *r, int route_idx, uint32_t client_ip)
{
    if (route_idx < 0 || route_idx >= r->cfg->route_count) return 0;

    const struct route_config *route = &r->cfg->routes[route_idx];
    if (route->backend_count == 0) return 0;
    if (route->backend_count == 1) return 0;

    switch (route->lb_algo) {
    case LB_ROUND_ROBIN:
    case LB_WEIGHTED_ROUND_ROBIN: {
        /* Simple round-robin for now; weighted version: accumulate weights */
        uint32_t idx = __atomic_fetch_add(&r->rr_counters[route_idx], 1,
                                          __ATOMIC_RELAXED);
        return (int)(idx % route->backend_count);
    }

    case LB_IP_HASH: {
        uint64_t h = xxhash64(&client_ip, sizeof(client_ip));
        return (int)(h % (uint64_t)route->backend_count);
    }

    case LB_LEAST_CONN:
        /* TODO Phase 6: track active connections per backend */
        /* Fall through to round-robin for now */
    default: {
        uint32_t idx = __atomic_fetch_add(&r->rr_counters[route_idx], 1,
                                          __ATOMIC_RELAXED);
        return (int)(idx % route->backend_count);
    }
    }
}

const char *router_backend_addr(struct router *r, int route_idx, int backend_idx)
{
    if (route_idx < 0 || route_idx >= r->cfg->route_count) return NULL;
    const struct route_config *route = &r->cfg->routes[route_idx];
    if (backend_idx < 0 || backend_idx >= route->backend_count) return NULL;
    return route->backends[backend_idx].address;
}
