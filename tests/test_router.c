#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/config.h"
#include "../include/router.h"

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL [%s:%d]: %s\n", __FILE__, __LINE__, msg); \
        exit(1); \
    } \
    printf("  PASS: %s\n", msg); \
} while (0)

static void init_weighted_route(struct vortex_config *cfg)
{
    config_set_defaults(cfg);
    cfg->route_count = 1;
    cfg->routes[0].backend_count = 2;
    cfg->routes[0].lb_algo = LB_WEIGHTED_ROUND_ROBIN;
    snprintf(cfg->routes[0].backends[0].address, sizeof(cfg->routes[0].backends[0].address),
             "%s", "10.0.0.1:8080");
    snprintf(cfg->routes[0].backends[1].address, sizeof(cfg->routes[0].backends[1].address),
             "%s", "10.0.0.2:8080");
    cfg->routes[0].backends[0].weight = 3;
    cfg->routes[0].backends[1].weight = 1;
}

static void init_least_conn_route(struct vortex_config *cfg)
{
    config_set_defaults(cfg);
    cfg->route_count = 1;
    cfg->routes[0].backend_count = 2;
    cfg->routes[0].lb_algo = LB_LEAST_CONN;
    snprintf(cfg->routes[0].backends[0].address, sizeof(cfg->routes[0].backends[0].address),
             "%s", "10.0.0.1:8080");
    snprintf(cfg->routes[0].backends[1].address, sizeof(cfg->routes[0].backends[1].address),
             "%s", "10.0.0.2:8080");
}

int main(void)
{
    printf("=== test_router ===\n");

    {
        struct vortex_config cfg;
        struct router r;
        int counts[2] = {0, 0};

        init_weighted_route(&cfg);
        ASSERT(router_init(&r, &cfg) == 0, "router_init weighted route");
        for (int i = 0; i < 8; i++) {
            int bi = router_select_backend(&r, 0, 0);
            ASSERT(bi >= 0 && bi < 2, "weighted RR selected valid backend");
            counts[bi]++;
        }
        ASSERT(counts[0] == 6, "weighted RR gives backend 0 six of eight selections");
        ASSERT(counts[1] == 2, "weighted RR gives backend 1 two of eight selections");
        router_destroy(&r);
    }

    {
        struct vortex_config cfg;
        struct router r;

        init_least_conn_route(&cfg);
        ASSERT(router_init(&r, &cfg) == 0, "router_init least_conn route");
        ASSERT(router_select_backend(&r, 0, 0) == 0, "least_conn tie breaks to backend 0 first");
        router_backend_active_inc(0, 0);
        ASSERT(router_select_backend(&r, 0, 0) == 1, "least_conn prefers less-loaded backend");
        router_backend_active_dec(0, 0);
        router_destroy(&r);
    }

    printf("\n=== ALL TESTS PASSED ===\n");
    return 0;
}
