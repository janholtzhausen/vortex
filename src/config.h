#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <linux/limits.h>

#define VORTEX_MAX_ROUTES    64
#define VORTEX_MAX_BACKENDS  16
#define VORTEX_MAX_HOSTNAME  256

typedef enum {
    LB_ROUND_ROBIN = 0,
    LB_WEIGHTED_ROUND_ROBIN,
    LB_LEAST_CONN,
    LB_IP_HASH,
} lb_algo_t;

typedef enum {
    CERT_PROVIDER_STATIC = 0,
    CERT_PROVIDER_ACME_HTTP01,
    CERT_PROVIDER_ACME_DNS01,
} cert_provider_type_t;

typedef enum {
    XDP_MODE_AUTO = 0,
    XDP_MODE_NATIVE,
    XDP_MODE_SKB,
} xdp_mode_t;

struct backend_config {
    char     address[256];
    uint16_t weight;
    int      pool_size;
};

struct cache_route_config {
    bool     enabled;
    uint32_t ttl;
    char     key_pattern[256];
};

#define VORTEX_MAX_AUTH_USERS 32

struct route_auth_config {
    bool enabled;
    char credentials[VORTEX_MAX_AUTH_USERS][320]; /* "username:password" each */
    int  credential_count;
};

struct route_config {
    char     hostname[VORTEX_MAX_HOSTNAME];
    struct backend_config backends[VORTEX_MAX_BACKENDS];
    uint8_t  backend_count;
    lb_algo_t lb_algo;

    cert_provider_type_t cert_provider;
    char cert_path[PATH_MAX];
    char key_path[PATH_MAX];

    struct cache_route_config cache;
    struct route_auth_config auth;

    /* Optional API key injected as X-Api-Key: header on backend requests */
    char x_api_key[256];
};

struct xdp_config {
    xdp_mode_t mode;
    bool       rate_limit_enabled;
    uint32_t   rate_limit_rps;
    uint32_t   rate_limit_burst;
    char       blocklist_file[PATH_MAX];
};

struct tls_config {
    int      min_version;   /* TLS_1_2_VERSION etc. */
    int      max_version;
    char     ciphersuites[512];
    uint32_t session_timeout;
    uint32_t session_ticket_rotation;
    bool     ktls;
};

struct cache_config {
    bool     enabled;
    uint32_t index_entries;
    uint64_t slab_size_bytes;        /* 0 = auto (30% of system RAM) */
    uint32_t default_ttl;
    bool     use_hugepages;
    char     disk_cache_path[PATH_MAX]; /* "" = RAM-only; else file-backed disk slab */
    uint64_t disk_slab_size_bytes;      /* 0 = auto (50% of free space at disk_cache_path) */
};

struct acme_config {
    bool   enabled;
    char   email[256];
    char   directory_url[512];
    char   account_key_path[PATH_MAX];
    char   storage_path[PATH_MAX];
    int    renewal_days;
    char   preferred_challenge[32]; /* "http-01" or "dns-01" */
    char   dns_provider[64];
    char   dns_api_token[512];
};

struct metrics_config {
    bool     enabled;
    char     bind_address[64];
    uint16_t port;
    char     path[64];
};

struct vortex_config {
    /* global */
    int      workers;        /* 0 = auto (nproc) */
    bool     sqpoll;         /* io_uring SQPOLL: kernel thread polls SQ, zero-syscall submit */
    bool     hugepages;      /* use 2MB huge pages for conn buffer slabs (requires vm.nr_hugepages) */
    bool     cpu_affinity;   /* pin worker N to CPU N (reduces cache misses on hot path) */
    char     bind_address[64];
    uint16_t bind_port;
    uint16_t http_port;
    char     interface[64];
    char     log_level[16];
    char     log_format[16];
    char     pid_file[PATH_MAX];

    struct tls_config     tls;
    struct xdp_config     xdp;
    struct cache_config   cache;
    struct acme_config    acme;
    struct metrics_config metrics;

    struct route_config routes[VORTEX_MAX_ROUTES];
    int                 route_count;
};

int  config_load(const char *path, struct vortex_config *cfg);
void config_free(struct vortex_config *cfg);
int  config_reload(const char *path, struct vortex_config *cfg);
void config_set_defaults(struct vortex_config *cfg);
