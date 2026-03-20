#include "config.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <yaml.h>
#include <sys/statvfs.h>

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

void config_set_defaults(struct vortex_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->workers        = 0; /* auto */
    strncpy(cfg->bind_address, "0.0.0.0", sizeof(cfg->bind_address) - 1);
    cfg->bind_port      = 443;
    cfg->http_port      = 80;
    strncpy(cfg->interface, "eth0", sizeof(cfg->interface) - 1);
    strncpy(cfg->log_level, "info", sizeof(cfg->log_level) - 1);
    strncpy(cfg->log_format, "json", sizeof(cfg->log_format) - 1);
    strncpy(cfg->pid_file, "/run/vortex.pid", sizeof(cfg->pid_file) - 1);

    /* TLS defaults */
    cfg->tls.min_version = 0x0303; /* TLS 1.2 */
    cfg->tls.max_version = 0x0304; /* TLS 1.3 */
    strncpy(cfg->tls.ciphersuites,
        "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384",
        sizeof(cfg->tls.ciphersuites) - 1);
    cfg->tls.session_timeout         = 3600;
    cfg->tls.session_ticket_rotation = 3600;
    cfg->tls.ktls                    = true;

    /* XDP defaults */
    cfg->xdp.mode               = XDP_MODE_AUTO;
    cfg->xdp.rate_limit_enabled = true;
    cfg->xdp.rate_limit_rps     = 1000;
    cfg->xdp.rate_limit_burst   = 2000;

    /* Cache defaults — slab sized to 30% of system RAM */
    cfg->cache.enabled       = true;
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
    strncpy(cfg->acme.preferred_challenge, "http-01",
        sizeof(cfg->acme.preferred_challenge) - 1);
    strncpy(cfg->acme.directory_url,
        "https://acme-v02.api.letsencrypt.org/directory",
        sizeof(cfg->acme.directory_url) - 1);

    /* Metrics defaults */
    cfg->metrics.enabled = true;
    strncpy(cfg->metrics.bind_address, "127.0.0.1",
        sizeof(cfg->metrics.bind_address) - 1);
    cfg->metrics.port = 9090;
    strncpy(cfg->metrics.path, "/metrics", sizeof(cfg->metrics.path) - 1);
}

/* ---- Minimal YAML parser ---- */
/* We use a simple key=value state machine over the YAML event stream */

typedef enum {
    P_ROOT,
    P_GLOBAL,
    P_TLS,
    P_XDP,
    P_XDP_RATELIMIT,
    P_CACHE,
    P_ACME,
    P_ACME_DNS_CFG,
    P_METRICS,
    P_ROUTES,
    P_ROUTE,
    P_ROUTE_BACKENDS,
    P_ROUTE_BACKEND,
    P_ROUTE_CACHE,
    P_ROUTE_AUTH,
    P_ROUTE_AUTH_USERS,
} parse_state_t;

typedef struct {
    struct vortex_config *cfg;
    parse_state_t        state;
    char                 key[256];
    int                  route_idx;
    int                  backend_idx;
    int                  depth;          /* mapping depth */
    int                  seq_depth;      /* sequence depth */
} parser_ctx_t;

static void handle_scalar(parser_ctx_t *ctx, const char *val_raw)
{
    char val[512];
    expand_env(val, sizeof(val), val_raw);

    struct vortex_config *c = ctx->cfg;
    const char *k = ctx->key;

    switch (ctx->state) {
    case P_GLOBAL:
        if      (!strcmp(k, "workers"))      c->workers        = atoi(val);
        else if (!strcmp(k, "bind_address")) strncpy(c->bind_address, val, sizeof(c->bind_address)-1);
        else if (!strcmp(k, "bind_port"))    c->bind_port      = (uint16_t)atoi(val);
        else if (!strcmp(k, "http_port"))    c->http_port      = (uint16_t)atoi(val);
        else if (!strcmp(k, "interface"))    strncpy(c->interface, val, sizeof(c->interface)-1);
        else if (!strcmp(k, "log_level"))    strncpy(c->log_level, val, sizeof(c->log_level)-1);
        else if (!strcmp(k, "log_format"))   strncpy(c->log_format, val, sizeof(c->log_format)-1);
        else if (!strcmp(k, "pid_file"))     strncpy(c->pid_file, val, sizeof(c->pid_file)-1);
        break;

    case P_TLS:
        if      (!strcmp(k, "min_version")) c->tls.min_version = !strcmp(val,"1.2") ? 0x0303 : 0x0304;
        else if (!strcmp(k, "max_version")) c->tls.max_version = !strcmp(val,"1.3") ? 0x0304 : 0x0303;
        else if (!strcmp(k, "ciphersuites"))strncpy(c->tls.ciphersuites, val, sizeof(c->tls.ciphersuites)-1);
        else if (!strcmp(k, "session_timeout")) c->tls.session_timeout = (uint32_t)atol(val);
        else if (!strcmp(k, "session_ticket_rotation")) c->tls.session_ticket_rotation = (uint32_t)atol(val);
        else if (!strcmp(k, "ktls"))        c->tls.ktls = !strcmp(val,"true") || !strcmp(val,"yes");
        break;

    case P_XDP:
        if (!strcmp(k, "mode")) {
            if      (!strcmp(val,"native")) c->xdp.mode = XDP_MODE_NATIVE;
            else if (!strcmp(val,"skb"))    c->xdp.mode = XDP_MODE_SKB;
            else                            c->xdp.mode = XDP_MODE_AUTO;
        } else if (!strcmp(k, "blocklist_file")) strncpy(c->xdp.blocklist_file, val, sizeof(c->xdp.blocklist_file)-1);
        break;

    case P_XDP_RATELIMIT:
        if      (!strcmp(k, "enabled"))          c->xdp.rate_limit_enabled = !strcmp(val,"true");
        else if (!strcmp(k, "requests_per_second")) c->xdp.rate_limit_rps  = (uint32_t)atol(val);
        else if (!strcmp(k, "burst"))            c->xdp.rate_limit_burst   = (uint32_t)atol(val);
        break;

    case P_CACHE:
        if      (!strcmp(k, "enabled"))          c->cache.enabled          = !strcmp(val,"true");
        else if (!strcmp(k, "index_entries"))    c->cache.index_entries    = (uint32_t)atol(val);
        else if (!strcmp(k, "slab_size_mb"))     c->cache.slab_size_bytes  = (uint64_t)atol(val) * 1024 * 1024;
        else if (!strcmp(k, "default_ttl"))      c->cache.default_ttl      = (uint32_t)atol(val);
        else if (!strcmp(k, "use_hugepages"))    c->cache.use_hugepages    = !strcmp(val,"true");
        else if (!strcmp(k, "disk_cache_path"))  strncpy(c->cache.disk_cache_path, val, sizeof(c->cache.disk_cache_path)-1);
        else if (!strcmp(k, "disk_slab_size_mb")) c->cache.disk_slab_size_bytes = (uint64_t)atol(val) * 1024 * 1024;
        break;

    case P_ACME:
        if      (!strcmp(k, "enabled"))           c->acme.enabled        = !strcmp(val,"true");
        else if (!strcmp(k, "email"))              strncpy(c->acme.email, val, sizeof(c->acme.email)-1);
        else if (!strcmp(k, "directory_url"))      strncpy(c->acme.directory_url, val, sizeof(c->acme.directory_url)-1);
        else if (!strcmp(k, "account_key_path"))   strncpy(c->acme.account_key_path, val, sizeof(c->acme.account_key_path)-1);
        else if (!strcmp(k, "storage_path"))       strncpy(c->acme.storage_path, val, sizeof(c->acme.storage_path)-1);
        else if (!strcmp(k, "renewal_days_before_expiry")) c->acme.renewal_days = atoi(val);
        else if (!strcmp(k, "preferred_challenge")) strncpy(c->acme.preferred_challenge, val, sizeof(c->acme.preferred_challenge)-1);
        else if (!strcmp(k, "dns_provider"))       strncpy(c->acme.dns_provider, val, sizeof(c->acme.dns_provider)-1);
        break;

    case P_ACME_DNS_CFG:
        if (!strcmp(k, "api_token")) strncpy(c->acme.dns_api_token, val, sizeof(c->acme.dns_api_token)-1);
        break;

    case P_METRICS:
        if      (!strcmp(k, "enabled"))      c->metrics.enabled = !strcmp(val,"true");
        else if (!strcmp(k, "bind_address")) strncpy(c->metrics.bind_address, val, sizeof(c->metrics.bind_address)-1);
        else if (!strcmp(k, "port"))         c->metrics.port    = (uint16_t)atoi(val);
        else if (!strcmp(k, "path"))         strncpy(c->metrics.path, val, sizeof(c->metrics.path)-1);
        break;

    case P_ROUTE: {
        struct route_config *r = &c->routes[ctx->route_idx];
        if      (!strcmp(k, "x_api_key"))    strncpy(r->x_api_key, val, sizeof(r->x_api_key)-1);
        else if (!strcmp(k, "hostname"))     strncpy(r->hostname, val, sizeof(r->hostname)-1);
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
        else if (!strcmp(k, "cert_path")) strncpy(r->cert_path, val, sizeof(r->cert_path)-1);
        else if (!strcmp(k, "key_path"))  strncpy(r->key_path,  val, sizeof(r->key_path)-1);
        break;
    }

    case P_ROUTE_BACKEND: {
        struct backend_config *b = &c->routes[ctx->route_idx].backends[ctx->backend_idx];
        if      (!strcmp(k, "address"))   strncpy(b->address, val, sizeof(b->address)-1);
        else if (!strcmp(k, "weight"))    b->weight    = (uint16_t)atoi(val);
        else if (!strcmp(k, "pool_size")) b->pool_size = atoi(val);
        break;
    }

    case P_ROUTE_CACHE: {
        struct cache_route_config *rc = &c->routes[ctx->route_idx].cache;
        if      (!strcmp(k, "enabled")) rc->enabled = !strcmp(val,"true");
        else if (!strcmp(k, "ttl"))     rc->ttl     = (uint32_t)atol(val);
        else if (!strcmp(k, "key"))     strncpy(rc->key_pattern, val, sizeof(rc->key_pattern)-1);
        break;
    }

    case P_ROUTE_AUTH: {
        struct route_auth_config *a = &c->routes[ctx->route_idx].auth;
        if (!strcmp(k, "enabled")) a->enabled = !strcmp(val, "true");
        break;
    }
    case P_ROUTE_AUTH_USERS: {
        /* Each scalar in this sequence is a "user:pass" credential */
        struct route_auth_config *a = &c->routes[ctx->route_idx].auth;
        if (a->credential_count < VORTEX_MAX_AUTH_USERS) {
            strncpy(a->credentials[a->credential_count], val,
                    sizeof(a->credentials[0]) - 1);
            a->credential_count++;
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
            }
            break;

        case YAML_MAPPING_END_EVENT:
            ctx.depth--;
            /* Pop state back up the hierarchy */
            if      (ctx.state == P_ROUTE_BACKEND)    { ctx.state = P_ROUTE_BACKENDS; }
            else if (ctx.state == P_ROUTE_BACKENDS)   { ctx.state = P_ROUTE; }
            else if (ctx.state == P_ROUTE_CACHE)      { ctx.state = P_ROUTE; }
            else if (ctx.state == P_ROUTE_AUTH)       { ctx.state = P_ROUTE; }
            else if (ctx.state == P_ROUTE)            { ctx.state = P_ROUTES; }
            else if (ctx.state == P_ACME_DNS_CFG)     { ctx.state = P_ACME; }
            else if (ctx.state == P_XDP_RATELIMIT)    { ctx.state = P_XDP; }
            /* Section mappings pop back to root */
            else if (ctx.state == P_GLOBAL  || ctx.state == P_TLS   ||
                     ctx.state == P_XDP     || ctx.state == P_CACHE  ||
                     ctx.state == P_ACME    || ctx.state == P_METRICS) {
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
            }
            break;

        case YAML_SEQUENCE_END_EVENT:
            ctx.seq_depth--;
            if (ctx.state == P_ROUTES) {
                ctx.state = P_ROOT;
            } else if (ctx.state == P_ROUTE_BACKENDS) {
                ctx.state = P_ROUTE;
            } else if (ctx.state == P_ROUTE_AUTH_USERS) {
                ctx.state = P_ROUTE_AUTH;
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
                strncpy(ctx.key, sv, sizeof(ctx.key) - 1);
                got_key = true;

                /* State transitions on key */
                if (ctx.state == P_ROOT) {
                    if      (!strcmp(sv, "global"))  ctx.state = P_GLOBAL;
                    else if (!strcmp(sv, "tls"))     ctx.state = P_TLS;
                    else if (!strcmp(sv, "xdp"))     ctx.state = P_XDP;
                    else if (!strcmp(sv, "cache"))   ctx.state = P_CACHE;
                    else if (!strcmp(sv, "acme"))    ctx.state = P_ACME;
                    else if (!strcmp(sv, "metrics")) ctx.state = P_METRICS;
                    else if (!strcmp(sv, "routes"))  { /* handled in sequence */ }
                } else if (ctx.state == P_XDP && !strcmp(sv, "rate_limit")) {
                    ctx.state = P_XDP_RATELIMIT;
                    got_key = false;
                } else if (ctx.state == P_ACME && !strcmp(sv, "dns_provider_config")) {
                    ctx.state = P_ACME_DNS_CFG;
                    got_key = false;
                } else if (ctx.state == P_ROUTE) {
                    if (!strcmp(sv, "backends"))    ctx.state = P_ROUTE_BACKENDS;
                    else if (!strcmp(sv, "cache"))  ctx.state = P_ROUTE_CACHE;
                    else if (!strcmp(sv, "auth"))   ctx.state = P_ROUTE_AUTH;
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

    if (ret == 0) {
        log_info("config_loaded", "path=%s routes=%d", path, cfg->route_count);
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
    /* Atomic copy — caller must handle live state */
    memcpy(cfg, &new_cfg, sizeof(*cfg));
    return 0;
}
