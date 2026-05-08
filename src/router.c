#define _GNU_SOURCE
#include "router.h"
#include "log.h"
#include "util.h"

#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <fnmatch.h>

static uint32_t g_backend_active[VORTEX_MAX_ROUTES][VORTEX_MAX_BACKENDS];

/* ---- Global rate limiter ---- */
global_rate_bucket_t g_route_rl[VORTEX_MAX_ROUTES];

bool global_rate_limit_check(int ri, const struct route_rate_limit_config *rl)
{
    if (!rl->enabled || rl->rps == 0) return true;
    uint32_t max_tokens = rl->burst ? rl->burst : rl->rps;

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);
    uint64_t now_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;

    uint64_t old_ns = atomic_load_explicit(&g_route_rl[ri].last_ns, memory_order_relaxed);
    if (now_ns > old_ns) {
        uint64_t elapsed = now_ns - old_ns;
        uint32_t add = (uint32_t)(elapsed / (1000000000ULL / rl->rps));
        if (add > 0) {
            uint32_t cur = atomic_load_explicit(&g_route_rl[ri].tokens, memory_order_relaxed);
            uint32_t next = cur + add > max_tokens ? max_tokens : cur + add;
            atomic_store_explicit(&g_route_rl[ri].tokens, next, memory_order_relaxed);
            atomic_store_explicit(&g_route_rl[ri].last_ns, now_ns, memory_order_relaxed);
        }
    }

    uint32_t cur;
    do {
        cur = atomic_load_explicit(&g_route_rl[ri].tokens, memory_order_relaxed);
        if (cur == 0) return false;
    } while (!atomic_compare_exchange_weak_explicit(&g_route_rl[ri].tokens, &cur, cur - 1,
                                                    memory_order_relaxed, memory_order_relaxed));
    return true;
}

/* ---- Global circuit breaker ---- */
global_cb_t g_backend_cb[VORTEX_MAX_ROUTES][VORTEX_MAX_BACKENDS];

bool cb_is_open_global(int ri, int bi, uint64_t now_ns)
{
    uint64_t until =
        atomic_load_explicit(&g_backend_cb[ri][bi].open_until_ns, memory_order_relaxed);
    return until != 0 && now_ns < until;
}

void cb_record_failure_global(int ri, int bi, uint64_t now_ns, uint32_t threshold, uint32_t open_ms)
{
    if (!threshold) threshold = 3;
    if (!open_ms) open_ms = 10000;
    uint32_t count =
        atomic_fetch_add_explicit(&g_backend_cb[ri][bi].fail_count, 1, memory_order_relaxed) + 1;
    if (count >= threshold) {
        atomic_store_explicit(&g_backend_cb[ri][bi].open_until_ns,
                              now_ns + (uint64_t)open_ms * 1000000ULL, memory_order_release);
        log_warn("circuit_breaker", "route=%d backend=%d OPEN after %u failures", ri, bi, count);
    }
}

void cb_record_success_global(int ri, int bi)
{
    if (atomic_load_explicit(&g_backend_cb[ri][bi].fail_count, memory_order_relaxed) > 0 ||
        atomic_load_explicit(&g_backend_cb[ri][bi].open_until_ns, memory_order_relaxed) != 0)
        log_info("circuit_breaker", "route=%d backend=%d CLOSED", ri, bi);
    atomic_store_explicit(&g_backend_cb[ri][bi].fail_count, 0, memory_order_relaxed);
    atomic_store_explicit(&g_backend_cb[ri][bi].open_until_ns, 0, memory_order_relaxed);
}

static uint32_t backend_effective_weight(const struct backend_config *backend)
{
    return backend->weight > 0 ? (uint32_t)backend->weight : 1u;
}

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
            if (r->cfg->routes[i].hostname[0] == '\0' || r->cfg->routes[i].hostname[0] == '*') {
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
    case LB_ROUND_ROBIN: {
        uint32_t idx = __atomic_fetch_add(&r->rr_counters[route_idx], 1, __ATOMIC_RELAXED);
        return (int)(idx % route->backend_count);
    }

    case LB_WEIGHTED_ROUND_ROBIN: {
        uint32_t total_weight = 0;
        for (int bi = 0; bi < route->backend_count; bi++)
            total_weight += backend_effective_weight(&route->backends[bi]);

        if (total_weight == 0) {
            uint32_t idx = __atomic_fetch_add(&r->rr_counters[route_idx], 1, __ATOMIC_RELAXED);
            return (int)(idx % route->backend_count);
        }

        uint32_t idx = __atomic_fetch_add(&r->rr_counters[route_idx], 1, __ATOMIC_RELAXED);
        uint32_t slot = idx % total_weight;
        uint32_t acc = 0;
        for (int bi = 0; bi < route->backend_count; bi++) {
            acc += backend_effective_weight(&route->backends[bi]);
            if (slot < acc) return bi;
        }
        return route->backend_count - 1;
    }

    case LB_IP_HASH: {
        uint64_t h = xxhash64(&client_ip, sizeof(client_ip));
        return (int)(h % (uint64_t)route->backend_count);
    }

    case LB_LEAST_CONN: {
        uint32_t idx = __atomic_fetch_add(&r->rr_counters[route_idx], 1, __ATOMIC_RELAXED);
        uint32_t min_active = UINT32_MAX;
        int best = 0;
        for (int off = 0; off < route->backend_count; off++) {
            int bi = (int)((idx + (uint32_t)off) % route->backend_count);
            uint32_t active = __atomic_load_n(&g_backend_active[route_idx][bi], __ATOMIC_RELAXED);
            if (active < min_active) {
                min_active = active;
                best = bi;
            }
        }
        return best;
    }

    default: {
        uint32_t idx = __atomic_fetch_add(&r->rr_counters[route_idx], 1, __ATOMIC_RELAXED);
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

void router_backend_active_inc(int route_idx, int backend_idx)
{
    if (route_idx < 0 || route_idx >= VORTEX_MAX_ROUTES || backend_idx < 0 ||
        backend_idx >= VORTEX_MAX_BACKENDS)
        return;
    __atomic_fetch_add(&g_backend_active[route_idx][backend_idx], 1, __ATOMIC_RELAXED);
}

void router_backend_active_dec(int route_idx, int backend_idx)
{
    if (route_idx < 0 || route_idx >= VORTEX_MAX_ROUTES || backend_idx < 0 ||
        backend_idx >= VORTEX_MAX_BACKENDS)
        return;

    uint32_t cur;
    do {
        cur = __atomic_load_n(&g_backend_active[route_idx][backend_idx], __ATOMIC_RELAXED);
        if (cur == 0) return;
    } while (!__atomic_compare_exchange_n(&g_backend_active[route_idx][backend_idx], &cur, cur - 1,
                                          false, __ATOMIC_RELAXED, __ATOMIC_RELAXED));
}
