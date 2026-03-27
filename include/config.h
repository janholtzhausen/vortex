#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <linux/limits.h>
#include <sys/socket.h>   /* sockaddr_storage, socklen_t */

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
    char     sni[256];
    uint16_t weight;
    int      pool_size;
    bool     tls;
    bool     verify_peer;
    bool     verify_peer_set;
    /* insecure_skip_verify=true disables both certificate-chain and hostname
     * verification for this backend TLS leg. Prefer verify_peer=false in new
     * configs; this alias exists to make the risk explicit. */
    /* Pre-resolved at config load — eliminates blocking getaddrinfo on hot path */
    struct sockaddr_storage resolved_addr;
    socklen_t               resolved_addrlen; /* 0 = not resolved */
};

struct cache_route_config {
    bool     enabled;
    uint32_t ttl;
    char     key_pattern[256];
};

#define VORTEX_MAX_AUTH_USERS 32
#define VORTEX_AUTH_MAX_USERNAME 64
#define VORTEX_AUTH_MAX_SALT_LEN 32
#define VORTEX_AUTH_MAX_HASH_LEN 64

struct auth_verifier {
    char     username[VORTEX_AUTH_MAX_USERNAME];
    uint32_t log_n;
    uint32_t r;
    uint32_t p;
    uint8_t  salt[VORTEX_AUTH_MAX_SALT_LEN];
    uint8_t  hash[VORTEX_AUTH_MAX_HASH_LEN];
    uint8_t  salt_len;
    uint8_t  hash_len;
};

struct route_auth_config {
    bool enabled;
    char file[PATH_MAX];
    struct auth_verifier verifiers[VORTEX_MAX_AUTH_USERS];
    int  credential_count;
};

struct route_rate_limit_config {
    bool     enabled;
    uint32_t rps;    /* requests per second (sustained) */
    uint32_t burst;  /* max instantaneous burst above rps */
};

struct route_health_config {
    uint32_t fail_threshold; /* consecutive connect failures to open circuit (0 = default 3) */
    uint32_t open_ms;        /* ms to keep circuit open before probe attempt (0 = default 10000) */
};

struct route_config {
    char     hostname[VORTEX_MAX_HOSTNAME];
    struct backend_config backends[VORTEX_MAX_BACKENDS];
    uint8_t  backend_count;
    lb_algo_t lb_algo;

    cert_provider_type_t cert_provider;
    char cert_path[PATH_MAX];
    char key_path[PATH_MAX];

    struct cache_route_config      cache;
    struct route_auth_config       auth;
    struct route_rate_limit_config rate_limit;
    struct route_health_config     health;

    /* Max ms to wait for first byte from backend (0 = default 30 000 ms) */
    uint32_t backend_timeout_ms;

    /* Optional API key injected as X-Api-Key: header on backend requests */
    char x_api_key[256];

    /* Optional upstream Basic Auth credentials ("user:pass") injected as
     * Authorization: Basic <b64> on backend requests, after stripping
     * any proxy-level Authorization header.  Useful when the backend
     * requires its own HTTP auth independently of the proxy auth layer. */
    char backend_credentials[320];

    /* Per-route Server header override.  Empty = use global server_header. */
    char server_header[128];

    /* TCP congestion control algorithm for backend connections on this route.
     * Empty = use the kernel default (typically cubic).  Per-route override of
     * the global congestion_control setting.  Only effective if the algorithm
     * is loaded on the host (check /proc/sys/net/ipv4/tcp_allowed_congestion_control). */
    char congestion_control[16];
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

struct dashboard_config {
    bool     enabled;
    char     bind_address[64];
    uint16_t port;
};

struct vortex_config {
    /* global */
    int      workers;        /* 0 = auto (nproc) */
    int      compress_pool_threads; /* 0 = synchronous compression in worker thread */
    bool     sqpoll;         /* io_uring SQPOLL: kernel thread polls SQ, zero-syscall submit */
    bool     hugepages;      /* use 2MB huge pages for conn buffer slabs (requires vm.nr_hugepages) */
    bool     cpu_affinity;   /* pin worker N to CPU N (reduces cache misses on hot path) */
    /* When true (default), bind an AF_INET socket only.
     * When false, bind an AF_INET6 socket with IPV6_V6ONLY=0 for dual-stack
     * (accepts both IPv4-mapped and native IPv6 connections on one fd).
     * Note: XDP/tarpit blocklist is IPv4-only regardless of this setting. */
    bool     ipv4_only;
    char     bind_address[64];
    uint16_t bind_port;
    uint16_t http_port;
    char     interface[64];
    char     log_level[16];
    char     log_format[16];
    char     pid_file[PATH_MAX];
    /* Server header sent to clients (replaces backend's Server header).
     * Empty string = pass backend's Server header through unchanged. */
    char     server_header[128];

    /* Global TCP congestion control algorithm for backend connections.
     * Per-route congestion_control overrides this.  Empty = kernel default. */
    char congestion_control[16];

    /* Maximum buffered client request body size for HTTP/2 and HTTP/3/QUIC.
     * 0 disables the limit. */
    uint32_t max_request_body_bytes;

    struct tls_config      tls;
    struct xdp_config      xdp;
    struct cache_config    cache;
    struct acme_config     acme;
    struct metrics_config  metrics;
    struct dashboard_config dashboard;

    struct route_config routes[VORTEX_MAX_ROUTES];
    int                 route_count;
};

int  config_load(const char *path, struct vortex_config *cfg);
void config_free(struct vortex_config *cfg);
int  config_reload(const char *path, struct vortex_config *cfg);
void config_set_defaults(struct vortex_config *cfg);
void config_resolve_backends(struct vortex_config *cfg);
