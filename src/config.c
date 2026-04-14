#include "config.h"
#include "auth.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <yaml.h>
#include <sys/statvfs.h>
#include <netdb.h>
#include <errno.h>

/* Environment variable substitution: replaces ${VAR} or $VAR */
static void expand_env(char *buf, size_t bufsz, const char *src)
{
    size_t out = 0;
    const char *p = src;

    while (*p && out < bufsz - 1) {
        if (p[0] == '$' && p[1] == '{') {
            const char *end = strchr(p + 2, '}');
            if (end) {
                char var[256];
                size_t vlen = (size_t)(end - (p + 2));
                if (vlen >= sizeof(var)) vlen = sizeof(var) - 1;
                memcpy(var, p + 2, vlen);
                var[vlen] = '\0';
                const char *val = getenv(var);
                if (val) {
                    size_t vl = strlen(val);
                    if (out + vl < bufsz - 1) {
                        memcpy(buf + out, val, vl);
                        out += vl;
                    }
                }
                p = end + 1;
                continue;
            }
        }
        buf[out++] = *p++;
    }
    buf[out] = '\0';
}

static int validate_no_crlf(const char *val, const char *field_name, int route_idx)
{
    for (const char *p = val; *p; p++) {
        if (*p == '\r' || *p == '\n') {
            log_error("config",
                      "route %d %s contains CR/LF - refusing to start",
                      route_idx, field_name);
            return -1;
        }
    }
    return 0;
}

void config_set_defaults(struct vortex_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->workers        = 0; /* auto */
    cfg->compress_pool_threads = 0;
    cfg->sqpoll         = false;
    cfg->hugepages      = false;
    cfg->cpu_affinity   = true;  /* on by default — safe, scheduler can override */
    cfg->ipv4_only      = true;  /* dual-stack off by default; set false to bind AF_INET6 with v4-mapped support */
    snprintf(cfg->bind_address, sizeof(cfg->bind_address), "%s", "0.0.0.0");
    cfg->bind_port      = 443;
    cfg->http_port      = 80;
    snprintf(cfg->interface,     sizeof(cfg->interface),     "%s", "eth0");
    snprintf(cfg->log_level,     sizeof(cfg->log_level),     "%s", "info");
    snprintf(cfg->log_format,    sizeof(cfg->log_format),    "%s", "json");
    snprintf(cfg->pid_file,      sizeof(cfg->pid_file),      "%s", "/run/vortex.pid");
    snprintf(cfg->server_header, sizeof(cfg->server_header), "%s", "CSWS/2.4.62 OpenVMS/V9.2-2 (Alpha)");
    cfg->max_request_body_bytes   = 8U * 1024U * 1024U;
    cfg->max_request_header_bytes = 32U * 1024U;  /* 32 KB — covers any legitimate header block */
    cfg->run_as_user[0]           = '\0';          /* no privilege drop by default */

    /* TLS defaults */
    cfg->tls.min_version = 0x0303; /* TLS 1.2 */
    cfg->tls.max_version = 0x0304; /* TLS 1.3 */
    snprintf(cfg->tls.ciphersuites, sizeof(cfg->tls.ciphersuites), "%s",
        "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384");
    cfg->tls.session_timeout         = 3600;
    cfg->tls.session_ticket_rotation = 3600;
    cfg->tls.ktls                    = true;

    /* XDP defaults */
    cfg->xdp.mode               = XDP_MODE_AUTO;
    cfg->xdp.rate_limit_enabled = true;
    cfg->xdp.rate_limit_rps     = 1000;
    cfg->xdp.rate_limit_burst   = 2000;
    cfg->xdp.protected_ports[0] = 80;
    cfg->xdp.protected_ports[1] = 443;
    cfg->xdp.protected_ports_count = 2;

    /* Cache defaults — slab sized to 30% of system RAM */
    cfg->cache.enabled       = true;
    cfg->cache.etag_sha256   = false;
    cfg->cache.verify_crc    = false;
    cfg->cache.index_entries = 16384;
    {
        long pages = sysconf(_SC_PHYS_PAGES);
        long pgsz  = sysconf(_SC_PAGE_SIZE);
        if (pages > 0 && pgsz > 0) {
            uint64_t total_ram = (uint64_t)pages * (uint64_t)pgsz;
            cfg->cache.slab_size_bytes = total_ram * 30 / 100;
        } else {
            cfg->cache.slab_size_bytes = 64ULL * 1024 * 1024;
        }
        /* Floor at 64 MB, cap at 4 GB */
        if (cfg->cache.slab_size_bytes < 64ULL * 1024 * 1024)
            cfg->cache.slab_size_bytes = 64ULL * 1024 * 1024;
        if (cfg->cache.slab_size_bytes > 4ULL * 1024 * 1024 * 1024)
            cfg->cache.slab_size_bytes = 4ULL * 1024 * 1024 * 1024;
    }
    cfg->cache.default_ttl   = 300;
    cfg->cache.use_hugepages = true;
    /* disk_cache_path defaults to empty (disabled); enabled in config */
    cfg->cache.disk_cache_path[0]    = '\0';
    cfg->cache.disk_slab_size_bytes  = 0; /* auto: 50% of free space */

    /* ACME defaults */
    cfg->acme.enabled       = false;
    cfg->acme.renewal_days  = 30;
    snprintf(cfg->acme.preferred_challenge, sizeof(cfg->acme.preferred_challenge), "%s", "http-01");
    snprintf(cfg->acme.directory_url, sizeof(cfg->acme.directory_url), "%s",
        "https://acme-v02.api.letsencrypt.org/directory");

    /* Metrics defaults */
    cfg->metrics.enabled = true;
    snprintf(cfg->metrics.bind_address, sizeof(cfg->metrics.bind_address), "%s", "127.0.0.1");
    cfg->metrics.port = 9090;
    snprintf(cfg->metrics.path, sizeof(cfg->metrics.path), "%s", "/metrics");

    /* Dashboard defaults */
    cfg->dashboard.enabled = false;
    snprintf(cfg->dashboard.bind_address, sizeof(cfg->dashboard.bind_address), "%s", "127.0.0.1");
    cfg->dashboard.port = 9091;
}

/* ---- Minimal YAML parser ---- */
/* We use a simple key=value state machine over the YAML event stream */

typedef enum {
    P_ROOT,
    P_GLOBAL,
    P_TLS,
    P_XDP,
    P_XDP_RATELIMIT,
    P_XDP_PROTECTED_PORTS,
    P_CACHE,
    P_ACME,
    P_ACME_DNS_CFG,
    P_METRICS,
    P_DASHBOARD,
    P_ROUTES,
    P_ROUTE,
    P_ROUTE_BACKENDS,
    P_ROUTE_BACKEND,
    P_ROUTE_CACHE,
    P_ROUTE_AUTH,
    P_ROUTE_AUTH_USERS,
    P_ROUTE_RATELIMIT,
    P_ROUTE_HEALTH,
    P_ROUTE_BACKEND_HEADERS,
    P_ROUTE_BACKEND_HEADER,
    P_ROUTE_RESPONSE_HEADERS,
    P_ROUTE_RESPONSE_HEADER,
} parse_state_t;

typedef struct {
    struct vortex_config *cfg;
    parse_state_t        state;
    char                 key[256];
    int                  route_idx;
    int                  backend_idx;
    int                  backend_header_idx;
    int                  response_header_idx;
    int                  depth;          /* mapping depth */
    int                  seq_depth;      /* sequence depth */
    int                  error;
} parser_ctx_t;

static const char *backend_addr_hostport(const char *addr, bool *tls_out)
{
    if (tls_out)
        *tls_out = false;
    if (!addr)
        return "";
    if (strncmp(addr, "https://", 8) == 0) {
        if (tls_out)
            *tls_out = true;
        return addr + 8;
    }
    if (strncmp(addr, "http://", 7) == 0)
        return addr + 7;
    return addr;
}

static void handle_scalar(parser_ctx_t *ctx, const char *val_raw)
{
    char val[512];
    expand_env(val, sizeof(val), val_raw);

    struct vortex_config *c = ctx->cfg;
    const char *k = ctx->key;

    switch (ctx->state) {
    case P_GLOBAL:
        if      (!strcmp(k, "workers"))      c->workers        = atoi(val);
        else if (!strcmp(k, "compress_pool_threads")) c->compress_pool_threads = atoi(val);
        else if (!strcmp(k, "sqpoll"))       c->sqpoll         = !strcmp(val,"true") || !strcmp(val,"yes");
        else if (!strcmp(k, "hugepages"))    c->hugepages      = !strcmp(val,"true") || !strcmp(val,"yes");
        else if (!strcmp(k, "cpu_affinity")) c->cpu_affinity   = !strcmp(val,"true") || !strcmp(val,"yes");
        else if (!strcmp(k, "ipv4_only"))    c->ipv4_only      = !strcmp(val,"true") || !strcmp(val,"yes");
        else if (!strcmp(k, "bind_address")) snprintf(c->bind_address, sizeof(c->bind_address), "%s", val);
        else if (!strcmp(k, "bind_port"))    c->bind_port      = (uint16_t)atoi(val);
        else if (!strcmp(k, "http_port"))    c->http_port      = (uint16_t)atoi(val);
        else if (!strcmp(k, "interface"))    snprintf(c->interface, sizeof(c->interface), "%s", val);
        else if (!strcmp(k, "log_level"))      snprintf(c->log_level, sizeof(c->log_level), "%s", val);
        else if (!strcmp(k, "log_format"))     snprintf(c->log_format, sizeof(c->log_format), "%s", val);
        else if (!strcmp(k, "pid_file"))       snprintf(c->pid_file, sizeof(c->pid_file), "%s", val);
        else if (!strcmp(k, "server_header"))       snprintf(c->server_header, sizeof(c->server_header), "%s", !strcmp(val,"none") ? "" : val);
        else if (!strcmp(k, "congestion_control"))  snprintf(c->congestion_control, sizeof(c->congestion_control), "%s", val);
        else if (!strcmp(k, "max_request_body_mb")) c->max_request_body_bytes = (uint32_t)atol(val) * 1024U * 1024U;
        else if (!strcmp(k, "max_request_body_bytes")) c->max_request_body_bytes = (uint32_t)atol(val);
        else if (!strcmp(k, "max_request_header_bytes")) c->max_request_header_bytes = (uint32_t)atol(val);
        else if (!strcmp(k, "run_as_user")) snprintf(c->run_as_user, sizeof(c->run_as_user), "%s", val);
        break;

    case P_TLS:
        if      (!strcmp(k, "min_version")) c->tls.min_version = !strcmp(val,"1.2") ? 0x0303 : 0x0304;
        else if (!strcmp(k, "max_version")) c->tls.max_version = !strcmp(val,"1.3") ? 0x0304 : 0x0303;
        else if (!strcmp(k, "ciphersuites"))snprintf(c->tls.ciphersuites, sizeof(c->tls.ciphersuites), "%s", val);
        else if (!strcmp(k, "session_timeout")) c->tls.session_timeout = (uint32_t)atol(val);
        else if (!strcmp(k, "session_ticket_rotation")) c->tls.session_ticket_rotation = (uint32_t)atol(val);
        else if (!strcmp(k, "ktls"))        c->tls.ktls = !strcmp(val,"true") || !strcmp(val,"yes");
        break;

    case P_XDP:
        if (!strcmp(k, "mode")) {
            if      (!strcmp(val,"native")) c->xdp.mode = XDP_MODE_NATIVE;
            else if (!strcmp(val,"skb"))    c->xdp.mode = XDP_MODE_SKB;
            else                            c->xdp.mode = XDP_MODE_AUTO;
        } else if (!strcmp(k, "blocklist_file")) snprintf(c->xdp.blocklist_file, sizeof(c->xdp.blocklist_file), "%s", val);
        break;

    case P_XDP_RATELIMIT:
        if      (!strcmp(k, "enabled"))          c->xdp.rate_limit_enabled = !strcmp(val,"true");
        else if (!strcmp(k, "requests_per_second")) c->xdp.rate_limit_rps  = (uint32_t)atol(val);
        else if (!strcmp(k, "burst"))            c->xdp.rate_limit_burst   = (uint32_t)atol(val);
        break;

    case P_XDP_PROTECTED_PORTS:
        /* Each scalar is a port number */
        if (c->xdp.protected_ports_count < 16) {
            uint16_t port = (uint16_t)atoi(val);
            if (port > 0 && port <= 65535) {
                c->xdp.protected_ports[c->xdp.protected_ports_count++] = port;
            } else {
                log_warn("config", "invalid port number in protected_ports: %s", val);
            }
        } else {
            log_warn("config", "too many protected ports (max 16), ignoring: %s", val);
        }
        break;

    case P_CACHE:
        if      (!strcmp(k, "enabled"))          c->cache.enabled          = !strcmp(val,"true");
        else if (!strcmp(k, "etag_sha256"))      c->cache.etag_sha256      = !strcmp(val,"true") || !strcmp(val,"yes");
        else if (!strcmp(k, "verify_crc"))       c->cache.verify_crc       = !strcmp(val,"true") || !strcmp(val,"yes");
        else if (!strcmp(k, "index_entries"))    c->cache.index_entries    = (uint32_t)atol(val);
        else if (!strcmp(k, "slab_size_mb"))     c->cache.slab_size_bytes  = (uint64_t)atol(val) * 1024 * 1024;
        else if (!strcmp(k, "default_ttl"))      c->cache.default_ttl      = (uint32_t)atol(val);
        else if (!strcmp(k, "use_hugepages"))    c->cache.use_hugepages    = !strcmp(val,"true");
        else if (!strcmp(k, "disk_cache_path"))  snprintf(c->cache.disk_cache_path, sizeof(c->cache.disk_cache_path), "%s", val);
        else if (!strcmp(k, "disk_slab_size_mb")) c->cache.disk_slab_size_bytes = (uint64_t)atol(val) * 1024 * 1024;
        break;

    case P_ACME:
        if      (!strcmp(k, "enabled"))           c->acme.enabled        = !strcmp(val,"true");
        else if (!strcmp(k, "email"))              snprintf(c->acme.email, sizeof(c->acme.email), "%s", val);
        else if (!strcmp(k, "directory_url"))      snprintf(c->acme.directory_url, sizeof(c->acme.directory_url), "%s", val);
        else if (!strcmp(k, "account_key_path"))   snprintf(c->acme.account_key_path, sizeof(c->acme.account_key_path), "%s", val);
        else if (!strcmp(k, "storage_path"))       snprintf(c->acme.storage_path, sizeof(c->acme.storage_path), "%s", val);
        else if (!strcmp(k, "renewal_days_before_expiry")) c->acme.renewal_days = atoi(val);
        else if (!strcmp(k, "preferred_challenge")) snprintf(c->acme.preferred_challenge, sizeof(c->acme.preferred_challenge), "%s", val);
        else if (!strcmp(k, "dns_provider"))       snprintf(c->acme.dns_provider, sizeof(c->acme.dns_provider), "%s", val);
        break;

    case P_ACME_DNS_CFG:
        if (!strcmp(k, "api_token")) snprintf(c->acme.dns_api_token, sizeof(c->acme.dns_api_token), "%s", val);
        break;

    case P_METRICS:
        if      (!strcmp(k, "enabled"))      c->metrics.enabled = !strcmp(val,"true");
        else if (!strcmp(k, "bind_address")) snprintf(c->metrics.bind_address, sizeof(c->metrics.bind_address), "%s", val);
        else if (!strcmp(k, "port"))         c->metrics.port    = (uint16_t)atoi(val);
        else if (!strcmp(k, "path"))         snprintf(c->metrics.path, sizeof(c->metrics.path), "%s", val);
        break;

    case P_DASHBOARD:
        if      (!strcmp(k, "enabled"))      c->dashboard.enabled = !strcmp(val,"true");
        else if (!strcmp(k, "bind_address")) snprintf(c->dashboard.bind_address, sizeof(c->dashboard.bind_address), "%s", val);
        else if (!strcmp(k, "port"))         c->dashboard.port = (uint16_t)atoi(val);
        break;

    case P_ROUTE: {
        struct route_config *r = &c->routes[ctx->route_idx];
        if      (!strcmp(k, "backend_timeout_ms")) r->backend_timeout_ms = (uint32_t)atol(val);
        else if (!strcmp(k, "x_api_key"))    snprintf(r->x_api_key, sizeof(r->x_api_key), "%s", val);
        else if (!strcmp(k, "backend_credentials")) snprintf(r->backend_credentials, sizeof(r->backend_credentials), "%s", val);
        else if (!strcmp(k, "server_header"))      snprintf(r->server_header, sizeof(r->server_header), "%s", !strcmp(val,"none") ? "" : val);
        else if (!strcmp(k, "congestion_control")) snprintf(r->congestion_control, sizeof(r->congestion_control), "%s", val);
        else if (!strcmp(k, "backend_auth")) {
            if      (!strcmp(val, "passthrough")) r->backend_auth_mode = BACKEND_AUTH_PASSTHROUGH;
            else if (!strcmp(val, "rewrite"))     r->backend_auth_mode = BACKEND_AUTH_REWRITE;
            else                                  r->backend_auth_mode = BACKEND_AUTH_BLOCK;
        }
        else if (!strcmp(k, "hostname"))     snprintf(r->hostname, sizeof(r->hostname), "%s", val);
        else if (!strcmp(k, "protocol")) {
            if (!strcmp(val, "tcp")) r->route_type = ROUTE_TYPE_TCP_TUNNEL;
            else                     r->route_type = ROUTE_TYPE_HTTP;
        }
        else if (!strcmp(k, "load_balancing")) {
            if      (!strcmp(val,"weighted_round_robin")) r->lb_algo = LB_WEIGHTED_ROUND_ROBIN;
            else if (!strcmp(val,"least_conn"))           r->lb_algo = LB_LEAST_CONN;
            else if (!strcmp(val,"ip_hash"))              r->lb_algo = LB_IP_HASH;
            else                                          r->lb_algo = LB_ROUND_ROBIN;
        }
        else if (!strcmp(k, "cert_provider")) {
            if      (!strcmp(val,"acme_http01")) r->cert_provider = CERT_PROVIDER_ACME_HTTP01;
            else if (!strcmp(val,"acme_dns01"))  r->cert_provider = CERT_PROVIDER_ACME_DNS01;
            else                                 r->cert_provider = CERT_PROVIDER_STATIC;
        }
        else if (!strcmp(k, "cert_path")) snprintf(r->cert_path, sizeof(r->cert_path), "%s", val);
        else if (!strcmp(k, "key_path"))  snprintf(r->key_path, sizeof(r->key_path), "%s", val);
        break;
    }

    case P_ROUTE_BACKEND: {
        struct backend_config *b = &c->routes[ctx->route_idx].backends[ctx->backend_idx];
        if (!strcmp(k, "address")) {
            bool addr_tls = false;
            const char *hostport = backend_addr_hostport(val, &addr_tls);
            snprintf(b->address, sizeof(b->address), "%s", hostport);
            if (addr_tls)
                b->tls = true;
        } else if (!strcmp(k, "weight")) {
            b->weight = (uint16_t)atoi(val);
        } else if (!strcmp(k, "pool_size")) {
            b->pool_size = atoi(val);
        } else if (!strcmp(k, "sni") || !strcmp(k, "server_name")) {
            snprintf(b->sni, sizeof(b->sni), "%s", val);
        } else if (!strcmp(k, "tls")) {
            b->tls = !strcmp(val, "true") || !strcmp(val, "yes");
        } else if (!strcmp(k, "scheme")) {
            b->tls = !strcmp(val, "https");
        } else if (!strcmp(k, "verify_peer")) {
            b->verify_peer = !strcmp(val, "true") || !strcmp(val, "yes");
            b->verify_peer_set = true;
        } else if (!strcmp(k, "insecure_skip_verify")) {
            bool insecure = !strcmp(val, "true") || !strcmp(val, "yes");
            b->verify_peer = !insecure;
            b->verify_peer_set = true;
        }
        break;
    }

    case P_ROUTE_CACHE: {
        struct cache_route_config *rc = &c->routes[ctx->route_idx].cache;
        if      (!strcmp(k, "enabled")) rc->enabled = !strcmp(val,"true");
        else if (!strcmp(k, "ttl"))     rc->ttl     = (uint32_t)atol(val);
        else if (!strcmp(k, "key"))     snprintf(rc->key_pattern, sizeof(rc->key_pattern), "%s", val);
        break;
    }

    case P_ROUTE_AUTH: {
        struct route_auth_config *a = &c->routes[ctx->route_idx].auth;
        if (!strcmp(k, "enabled")) a->enabled = !strcmp(val, "true");
        else if (!strcmp(k, "file")) snprintf(a->file, sizeof(a->file), "%s", val);
        break;
    }
    case P_ROUTE_AUTH_USERS: {
        /* Each scalar in this sequence is a "username:$scrypt$..." verifier */
        struct route_auth_config *a = &c->routes[ctx->route_idx].auth;
        if (a->credential_count < VORTEX_MAX_AUTH_USERS) {
            if (!auth_parse_verifier(&a->verifiers[a->credential_count], val)) {
                log_error("config_load",
                          "route=%s invalid auth verifier for user entry %d",
                          c->routes[ctx->route_idx].hostname[0]
                              ? c->routes[ctx->route_idx].hostname
                              : "<unknown>",
                          a->credential_count);
                ctx->error = -1;
                break;
            }
            a->credential_count++;
        }
        break;
    }

    case P_ROUTE_RATELIMIT: {
        struct route_rate_limit_config *rl = &c->routes[ctx->route_idx].rate_limit;
        if      (!strcmp(k, "enabled")) rl->enabled = !strcmp(val,"true");
        else if (!strcmp(k, "rps"))     rl->rps     = (uint32_t)atol(val);
        else if (!strcmp(k, "burst"))   rl->burst   = (uint32_t)atol(val);
        break;
    }

    case P_ROUTE_HEALTH: {
        struct route_health_config *hc = &c->routes[ctx->route_idx].health;
        if      (!strcmp(k, "fail_threshold")) hc->fail_threshold = (uint32_t)atol(val);
        else if (!strcmp(k, "open_ms"))        hc->open_ms        = (uint32_t)atol(val);
        break;
    }

    case P_ROUTE_BACKEND_HEADER: {
        struct route_config *r = &c->routes[ctx->route_idx];
        if (ctx->backend_header_idx < 0 ||
            ctx->backend_header_idx >= VORTEX_MAX_BACKEND_HEADER_RULES) break;
        struct backend_header_rule *hr = &r->backend_headers[ctx->backend_header_idx];
        if (!strcmp(k, "name")) {
            snprintf(hr->name, sizeof(hr->name), "%s", val);
        } else if (!strcmp(k, "action")) {
            if      (!strcmp(val, "set"))   hr->action = HEADER_ACTION_SET;
            else                            hr->action = HEADER_ACTION_BLOCK;
        } else if (!strcmp(k, "value")) {
            snprintf(hr->value, sizeof(hr->value), "%s", val);
        }
        break;
    }

    case P_ROUTE_RESPONSE_HEADER: {
        struct route_config *r = &c->routes[ctx->route_idx];
        if (ctx->response_header_idx < 0 ||
            ctx->response_header_idx >= VORTEX_MAX_RESPONSE_HEADER_RULES) break;
        struct backend_header_rule *hr = &r->response_headers[ctx->response_header_idx];
        if (!strcmp(k, "name")) {
            snprintf(hr->name, sizeof(hr->name), "%s", val);
        } else if (!strcmp(k, "action")) {
            if      (!strcmp(val, "set"))   hr->action = HEADER_ACTION_SET;
            else                            hr->action = HEADER_ACTION_BLOCK;
        } else if (!strcmp(k, "value")) {
            snprintf(hr->value, sizeof(hr->value), "%s", val);
        }
        break;
    }

    default: break;
    }
}

int config_load(const char *path, struct vortex_config *cfg)
{
    config_set_defaults(cfg);

    FILE *f = fopen(path, "r");
    if (!f) {
        log_error("config_load", "cannot open %s", path);
        return -1;
    }

    yaml_parser_t parser;
    if (!yaml_parser_initialize(&parser)) {
        fclose(f);
        return -1;
    }
    yaml_parser_set_input_file(&parser, f);

    parser_ctx_t ctx = {
        .cfg       = cfg,
        .state     = P_ROOT,
        .route_idx = -1,
        .backend_idx = -1,
        .backend_header_idx = -1,
        .response_header_idx = -1,
    };

    bool got_key    = false;
    (void)0; /* route/backend tracking done via state machine */

    yaml_event_t ev;
    int ret = 0;

    while (1) {
        if (!yaml_parser_parse(&parser, &ev)) {
            log_error("config_load", "YAML parse error at line %zu: %s",
                parser.problem_mark.line, parser.problem);
            ret = -1;
            break;
        }

        if (ev.type == YAML_STREAM_END_EVENT) {
            yaml_event_delete(&ev);
            break;
        }

        switch (ev.type) {
        case YAML_MAPPING_START_EVENT:
            ctx.depth++;
            /* A mapping start consumes the pending key without a scalar value */
            got_key = false;
            if (ctx.state == P_ROUTES) {
                /* New route mapping starting */
                if (ctx.route_idx < (int)VORTEX_MAX_ROUTES - 1) {
                    ctx.route_idx++;
                    cfg->route_count = ctx.route_idx + 1;
                }
                ctx.state = P_ROUTE;
            } else if (ctx.state == P_ROUTE_BACKENDS) {
                ctx.backend_idx++;
                if (ctx.backend_idx < VORTEX_MAX_BACKENDS) {
                    cfg->routes[ctx.route_idx].backend_count = ctx.backend_idx + 1;
                }
                ctx.state = P_ROUTE_BACKEND;
            } else if (ctx.state == P_ROUTE_BACKEND_HEADERS) {
                ctx.backend_header_idx++;
                if (ctx.backend_header_idx < VORTEX_MAX_BACKEND_HEADER_RULES)
                    cfg->routes[ctx.route_idx].backend_header_count = ctx.backend_header_idx + 1;
                ctx.state = P_ROUTE_BACKEND_HEADER;
            } else if (ctx.state == P_ROUTE_RESPONSE_HEADERS) {
                ctx.response_header_idx++;
                if (ctx.response_header_idx < VORTEX_MAX_RESPONSE_HEADER_RULES)
                    cfg->routes[ctx.route_idx].response_header_count = ctx.response_header_idx + 1;
                ctx.state = P_ROUTE_RESPONSE_HEADER;
            }
            break;

        case YAML_MAPPING_END_EVENT:
            ctx.depth--;
            /* Pop state back up the hierarchy */
            if      (ctx.state == P_ROUTE_BACKEND)         { ctx.state = P_ROUTE_BACKENDS; }
            else if (ctx.state == P_ROUTE_BACKENDS)        { ctx.state = P_ROUTE; }
            else if (ctx.state == P_ROUTE_CACHE)           { ctx.state = P_ROUTE; }
            else if (ctx.state == P_ROUTE_AUTH)            { ctx.state = P_ROUTE; }
            else if (ctx.state == P_ROUTE_RATELIMIT)       { ctx.state = P_ROUTE; }
            else if (ctx.state == P_ROUTE_HEALTH)          { ctx.state = P_ROUTE; }
            else if (ctx.state == P_ROUTE_BACKEND_HEADER)   { ctx.state = P_ROUTE_BACKEND_HEADERS; }
            else if (ctx.state == P_ROUTE_RESPONSE_HEADER)  { ctx.state = P_ROUTE_RESPONSE_HEADERS; }
            else if (ctx.state == P_ROUTE)                 { ctx.state = P_ROUTES; }
            else if (ctx.state == P_ACME_DNS_CFG)     { ctx.state = P_ACME; }
            else if (ctx.state == P_XDP_RATELIMIT)    { ctx.state = P_XDP; }
            /* Section mappings pop back to root */
            else if (ctx.state == P_GLOBAL    || ctx.state == P_TLS      ||
                     ctx.state == P_XDP       || ctx.state == P_CACHE    ||
                     ctx.state == P_ACME      || ctx.state == P_METRICS  ||
                     ctx.state == P_DASHBOARD) {
                ctx.state = P_ROOT;
            }
            break;

        case YAML_SEQUENCE_START_EVENT:
            ctx.seq_depth++;
            got_key = false;
            if (!strcmp(ctx.key, "routes")) {
                ctx.state = P_ROUTES;
            } else if (!strcmp(ctx.key, "backends")) {
                ctx.state = P_ROUTE_BACKENDS;
                ctx.backend_idx = -1;
            } else if (ctx.state == P_ROUTE_AUTH && !strcmp(ctx.key, "users")) {
                ctx.state = P_ROUTE_AUTH_USERS;
            } else if (ctx.state == P_XDP && !strcmp(ctx.key, "protected_ports")) {
                ctx.state = P_XDP_PROTECTED_PORTS;
                cfg->xdp.protected_ports_count = 0;
            } else if (ctx.state == P_ROUTE && !strcmp(ctx.key, "backend_headers")) {
                ctx.state = P_ROUTE_BACKEND_HEADERS;
                ctx.backend_header_idx = -1;
            } else if (ctx.state == P_ROUTE && !strcmp(ctx.key, "response_headers")) {
                ctx.state = P_ROUTE_RESPONSE_HEADERS;
                ctx.response_header_idx = -1;
            }
            break;

        case YAML_SEQUENCE_END_EVENT:
            ctx.seq_depth--;
            if (ctx.state == P_ROUTE_AUTH_USERS) {
                ctx.state = P_ROUTE_AUTH;
            } else if (ctx.state == P_XDP_PROTECTED_PORTS) {
                ctx.state = P_XDP;
            } else if (ctx.state == P_ROUTE_BACKEND_HEADERS) {
                ctx.state = P_ROUTE;
            } else if (ctx.state == P_ROUTE_RESPONSE_HEADERS) {
                ctx.state = P_ROUTE;
            } else if (ctx.state == P_ROUTES) {
                ctx.state = P_ROOT;
            } else if (ctx.state == P_ROUTE_BACKENDS) {
                ctx.state = P_ROUTE;
            }
            break;

        case YAML_SCALAR_EVENT: {
            const char *sv = (const char *)ev.data.scalar.value;
            /* Sequence of plain scalars — treat each as a value directly */
            if (ctx.state == P_ROUTE_AUTH_USERS) {
                handle_scalar(&ctx, sv);
                got_key = false;
                break;
            }
            if (!got_key) {
                snprintf(ctx.key, sizeof(ctx.key), "%s", sv);
                got_key = true;

                /* State transitions on key */
                if (ctx.state == P_ROOT) {
                    if      (!strcmp(sv, "global"))  ctx.state = P_GLOBAL;
                    else if (!strcmp(sv, "tls"))     ctx.state = P_TLS;
                    else if (!strcmp(sv, "xdp"))     ctx.state = P_XDP;
                    else if (!strcmp(sv, "cache"))   ctx.state = P_CACHE;
                    else if (!strcmp(sv, "acme"))    ctx.state = P_ACME;
                    else if (!strcmp(sv, "metrics"))   ctx.state = P_METRICS;
                    else if (!strcmp(sv, "dashboard")) ctx.state = P_DASHBOARD;
                    else if (!strcmp(sv, "routes"))  { /* handled in sequence */ }
                } else if (ctx.state == P_XDP && !strcmp(sv, "rate_limit")) {
                    ctx.state = P_XDP_RATELIMIT;
                    got_key = false;
                } else if (ctx.state == P_ACME && !strcmp(sv, "dns_provider_config")) {
                    ctx.state = P_ACME_DNS_CFG;
                    got_key = false;
                } else if (ctx.state == P_ROUTE) {
                    if      (!strcmp(sv, "backends"))        ctx.state = P_ROUTE_BACKENDS;
                    else if (!strcmp(sv, "cache"))           ctx.state = P_ROUTE_CACHE;
                    else if (!strcmp(sv, "auth"))            ctx.state = P_ROUTE_AUTH;
                    else if (!strcmp(sv, "rate_limit"))      ctx.state = P_ROUTE_RATELIMIT;
                    else if (!strcmp(sv, "health_check"))    ctx.state = P_ROUTE_HEALTH;
                    else if (!strcmp(sv, "backend_headers")) ctx.state = P_ROUTE_BACKEND_HEADERS;
                }
            } else {
                handle_scalar(&ctx, sv);
                got_key = false;
            }
            break;
        }

        default: break;
        }

        yaml_event_delete(&ev);
    }

    yaml_parser_delete(&parser);
    fclose(f);

    if (ret == 0 && ctx.error == 0) {
        for (int i = 0; i < cfg->route_count; i++) {
            struct route_config *route = &cfg->routes[i];
            if (route->auth.file[0]) {
                if (!auth_load_verifiers_file(&route->auth,
                                              route->auth.file,
                                              route->hostname)) {
                    log_error("config_load",
                              "route=%s failed to load auth file %s",
                              route->hostname[0] ? route->hostname : "<unknown>",
                              route->auth.file);
                    ret = -1;
                    break;
                }
            }
            if (route->auth.enabled && route->auth.credential_count == 0) {
                log_error("config_load",
                          "route=%s auth enabled but no verifiers configured",
                          route->hostname[0] ? route->hostname : "<unknown>");
                ret = -1;
                break;
            }
            if (validate_no_crlf(route->x_api_key, "x_api_key", i) != 0 ||
                validate_no_crlf(route->backend_credentials, "backend_credentials", i) != 0 ||
                validate_no_crlf(route->server_header, "server_header", i) != 0 ||
                validate_no_crlf(route->congestion_control, "congestion_control", i) != 0) {
                ret = -1;
                break;
            }
        }
    }

    if (ret == 0 && ctx.error == 0) {
        log_info("config_loaded", "path=%s routes=%d", path, cfg->route_count);
    } else if (ret == 0) {
        ret = -1;
    }
    return ret;
}

void config_free(struct vortex_config *cfg)
{
    (void)cfg; /* nothing heap-allocated */
}

int config_reload(const char *path, struct vortex_config *cfg)
{
    struct vortex_config new_cfg;
    if (config_load(path, &new_cfg) != 0) return -1;
    if (new_cfg.route_count != cfg->route_count) {
        log_warn("config_reload",
                 "refusing reload: route_count changed from %d to %d; restart required",
                 cfg->route_count, new_cfg.route_count);
        return -1;
    }
    for (int ri = 0; ri < cfg->route_count; ri++) {
        const struct route_config *old_route = &cfg->routes[ri];
        const struct route_config *new_route = &new_cfg.routes[ri];
        if (strcmp(old_route->hostname, new_route->hostname) != 0) {
            log_warn("config_reload",
                     "refusing reload: route %d hostname changed (%s -> %s); restart required",
                     ri, old_route->hostname, new_route->hostname);
            return -1;
        }
        if (old_route->backend_count != new_route->backend_count) {
            log_warn("config_reload",
                     "refusing reload: route %d backend_count changed (%u -> %u); restart required",
                     ri, old_route->backend_count, new_route->backend_count);
            return -1;
        }
        for (int bi = 0; bi < old_route->backend_count; bi++) {
            const struct backend_config *old_backend = &old_route->backends[bi];
            const struct backend_config *new_backend = &new_route->backends[bi];
            if (strcmp(old_backend->address, new_backend->address) != 0 ||
                old_backend->tls != new_backend->tls) {
                log_warn("config_reload",
                         "refusing reload: route %d backend %d changed (%s/%d -> %s/%d); restart required",
                         ri, bi,
                         old_backend->address, old_backend->tls,
                         new_backend->address, new_backend->tls);
                return -1;
            }
        }
    }
    /* Atomic copy — caller must handle live state */
    memcpy(cfg, &new_cfg, sizeof(*cfg));
    /* Scrub credential fields from the stack-local copy so they don't linger
     * in memory after this frame returns (core-dump hygiene). */
    for (int _ri = 0; _ri < new_cfg.route_count; _ri++) {
        explicit_bzero(new_cfg.routes[_ri].backend_credentials,
                       sizeof(new_cfg.routes[_ri].backend_credentials));
        explicit_bzero(new_cfg.routes[_ri].x_api_key,
                       sizeof(new_cfg.routes[_ri].x_api_key));
    }
    return 0;
}

/* Resolve all backend addresses at startup so getaddrinfo never runs on the
 * hot path.  Logs a warning for any backend that fails resolution (the
 * address string is kept so it can be retried on SIGHUP reload). */
void config_resolve_backends(struct vortex_config *cfg)
{
    for (int ri = 0; ri < cfg->route_count; ri++) {
        struct route_config *route = &cfg->routes[ri];
        for (int bi = 0; bi < route->backend_count; bi++) {
            struct backend_config *b = &route->backends[bi];
            b->resolved_addrlen = 0;
            if (b->tls && !b->verify_peer_set)
                b->verify_peer = true;

            const char *addr_str = b->address;
            const char *colon = strrchr(addr_str, ':');
            if (!colon) {
                log_warn("config_resolve", "route=%s backend=%s: no port in address",
                         route->hostname, addr_str);
                continue;
            }

            char host[256];
            char port_str[16];
            size_t hlen = (size_t)(colon - addr_str);
            if (hlen >= sizeof(host)) continue;
            memcpy(host, addr_str, hlen);
            host[hlen] = '\0';
            snprintf(port_str, sizeof(port_str), "%s", colon + 1);

            struct addrinfo hints = {
                .ai_family   = AF_UNSPEC,
                .ai_socktype = SOCK_STREAM,
                .ai_flags    = AI_ADDRCONFIG,
            };
            struct addrinfo *res = NULL;
            if (getaddrinfo(host, port_str, &hints, &res) != 0) {
                log_warn("config_resolve", "route=%s backend=%s: getaddrinfo failed: %s",
                         route->hostname, addr_str, strerror(errno));
                continue;
            }

            /* Prefer IPv4 on hosts without working IPv6 routing; fall back to any. */
            for (int pass = 0; pass < 2 && b->resolved_addrlen == 0; pass++) {
                int family = (pass == 0) ? AF_INET : AF_UNSPEC;
                for (struct addrinfo *rp = res; rp; rp = rp->ai_next) {
                    if (family != AF_UNSPEC && rp->ai_family != family)
                        continue;
                    if (rp->ai_addrlen <= sizeof(b->resolved_addr)) {
                        memcpy(&b->resolved_addr, rp->ai_addr, rp->ai_addrlen);
                        b->resolved_addrlen = (socklen_t)rp->ai_addrlen;
                        break;
                    }
                }
            }
            freeaddrinfo(res);

            if (b->resolved_addrlen > 0) {
                log_info("config_resolve", "route=%s backend=%s: resolved ok",
                         route->hostname, addr_str);
            } else {
                log_warn("config_resolve", "route=%s backend=%s: no usable address",
                         route->hostname, addr_str);
            }
        }
    }
}
