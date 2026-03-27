#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <getopt.h>

#include "log.h"
#include "config.h"
#include "bpf_loader.h"
#include "version.h"

#include "worker.h"
#include "pool.h"
#include "metrics.h"
#include "dashboard.h"
#include "tls.h"
#ifdef VORTEX_QUIC
#include "quic.h"
#endif

#ifdef VORTEX_PHASE_TLS
#include "tls_pool.h"
#include "cert_provider.h"
#include "static_file.h"
#include "acme_client.h"
#include "acme_http01.h"
#include "acme_dns01.h"
#include "dns_cloudflare.h"
#include <time.h>
#endif

static volatile sig_atomic_t g_running  = 1;
static volatile sig_atomic_t g_reload   = 0;
static const char            *g_config_path = NULL;
static struct vortex_config   g_cfg;
static int                    g_pid_file_written = 0;

static void sig_handler(int sig)
{
    if (sig == SIGTERM || sig == SIGINT) {
        g_running = 0;
    } else if (sig == SIGHUP) {
        g_reload = 1;
    }
}

static void setup_signals(void)
{
    struct sigaction sa = {
        .sa_handler = sig_handler,
        .sa_flags   = SA_RESTART,
    };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGHUP,  &sa, NULL);
    signal(SIGPIPE, SIG_IGN);
}

static int write_pid_file(const char *path)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        log_warn("pid_file", "cannot write pid file %s: %s", path, strerror(errno));
        return -1;
    }
    char buf[32];
    int n = snprintf(buf, sizeof(buf), "%d\n", (int)getpid());
    if (write(fd, buf, n) < 0) {
        log_warn("pid_file", "write pid failed: %s", strerror(errno));
    }
    close(fd);
    return 0;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [options]\n"
        "  -c <config>   Path to config file (default: /etc/vortex/vortex.yaml)\n"
        "  -d            Daemonise into the background\n"
        "  -f            Foreground (default; accepted for compatibility)\n"
        "  -t            Test config and exit\n"
        "  -v            Verbose (debug logging)\n"
        "  -h            Show this help\n",
        prog);
}

static char   g_bpf_obj_path[512] = "";
static int    g_no_xdp = 0;
static int    g_no_tls = 0;

#ifdef VORTEX_PHASE_TLS
static bool config_uses_backend_tls(const struct vortex_config *cfg)
{
    for (int ri = 0; ri < cfg->route_count; ri++) {
        const struct route_config *route = &cfg->routes[ri];
        for (int bi = 0; bi < route->backend_count; bi++) {
            if (route->backends[bi].tls)
                return true;
        }
    }
    return false;
}
#endif

#define MAX_WORKERS 64
static struct worker  g_workers[MAX_WORKERS];
static int            g_num_workers = 0;
static struct cache   g_shared_cache;
static struct metrics_server g_metrics;
static struct dashboard_server g_dashboard;
static int            g_dashboard_started = 0;
#ifdef VORTEX_QUIC
static struct quic_server *g_quic = NULL;
#endif

#ifdef VORTEX_PHASE_TLS
static struct metrics_cert_info g_cert_info[VORTEX_MAX_ROUTES];
static int                      g_cert_info_count = 0;
#endif
#ifdef VORTEX_PHASE_TLS
static struct tls_ctx g_tls;

/* ---- Cert manager ---- */
static struct acme_http01_server g_http01_srv;
static int                       g_http01_started = 0;
static struct acme_client        g_acme_client;
static int                       g_acme_inited = 0;

/* DNS-01 provider context */
static struct acme_dns01_ctx g_dns01_ctx;
static int                   g_dns01_inited = 0;

/* Renewal background thread */
static pthread_t g_renewal_thread;
static int       g_renewal_running = 0;
static pthread_mutex_t g_renewal_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_renewal_cv = PTHREAD_COND_INITIALIZER;

static void *renewal_thread_fn(void *arg)
{
    (void)arg;
    while (g_renewal_running) {
        pthread_mutex_lock(&g_renewal_mu);
        if (g_renewal_running) {
            struct timespec wake;
            clock_gettime(CLOCK_REALTIME, &wake);
            wake.tv_sec += 3600;
            pthread_cond_timedwait(&g_renewal_cv, &g_renewal_mu, &wake);
        }
        pthread_mutex_unlock(&g_renewal_mu);
        if (!g_renewal_running) break;

        if (!g_acme_inited) continue;

        for (int i = 0; i < g_cfg.route_count; i++) {
            const struct route_config *r = &g_cfg.routes[i];
            if (r->cert_provider != CERT_PROVIDER_ACME_HTTP01 &&
                r->cert_provider != CERT_PROVIDER_ACME_DNS01) continue;

            int days = g_cfg.acme.renewal_days > 0 ? g_cfg.acme.renewal_days : 30;
            if (!acme_needs_renewal(g_cfg.acme.storage_path,
                                    r->hostname, days)) continue;

            log_info("renewal", "renewing cert for %s", r->hostname);
            struct cert_result res;
            memset(&res, 0, sizeof(res));
            int ok = -1;
            if (r->cert_provider == CERT_PROVIDER_ACME_HTTP01
                && g_http01_started) {
                ok = acme_obtain_http01(&g_acme_client, r->hostname,
                                         &g_http01_srv, &res);
            } else if (r->cert_provider == CERT_PROVIDER_ACME_DNS01
                       && g_dns01_inited) {
                ok = acme_obtain_dns01(&g_dns01_ctx, r->hostname, &res);
            }
            if (ok == 0) {
                tls_rotate_cert(&g_tls, i, res.cert_pem, res.key_pem);
                log_info("renewal", "cert rotated for %s, not_after=%ld",
                    r->hostname, (long)res.not_after);
            } else {
                log_warn("renewal", "renewal failed for %s", r->hostname);
            }
            cert_result_free(&res);
        }
    }
    return NULL;
}

/* Initialise cert management: obtain missing certs, populate cert_path/key_path
 * in cfg (so tls_init can load them), start HTTP-01 server and renewal thread. */
static int cert_manager_init(struct vortex_config *cfg)
{
    int need_acme_http01 = 0, need_acme_dns01 = 0;
    for (int i = 0; i < cfg->route_count; i++) {
        if (cfg->routes[i].cert_provider == CERT_PROVIDER_ACME_HTTP01)
            need_acme_http01 = 1;
        if (cfg->routes[i].cert_provider == CERT_PROVIDER_ACME_DNS01)
            need_acme_dns01 = 1;
    }
    int need_acme = need_acme_http01 || need_acme_dns01;

    if (need_acme_http01 && cfg->acme.enabled && cfg->http_port > 0) {
        if (acme_http01_start(&g_http01_srv, cfg->http_port) == 0) {
            g_http01_started = 1;
        } else {
            log_warn("cert_manager", "HTTP-01 server failed to start on port %d",
                cfg->http_port);
        }
    }

    if (need_acme && cfg->acme.enabled) {
        memset(&g_acme_client, 0, sizeof(g_acme_client));
        snprintf(g_acme_client.directory_url, sizeof(g_acme_client.directory_url), "%s", cfg->acme.directory_url);
        snprintf(g_acme_client.account_key_path, sizeof(g_acme_client.account_key_path), "%s", cfg->acme.account_key_path);
        snprintf(g_acme_client.storage_path, sizeof(g_acme_client.storage_path), "%s", cfg->acme.storage_path);
        snprintf(g_acme_client.email, sizeof(g_acme_client.email), "%s", cfg->acme.email);
        g_acme_client.renewal_days = cfg->acme.renewal_days > 0
                                   ? cfg->acme.renewal_days : 30;
        g_acme_client.libctx = g_tls.libctx; /* may be NULL before tls_init */

        if (acme_client_init(&g_acme_client) == 0) {
            g_acme_inited = 1;
        } else {
            log_warn("cert_manager", "ACME client init failed — "
                "ACME routes will not have certificates");
        }
    }

    /* Init DNS-01 provider if needed */
    if (need_acme_dns01 && cfg->acme.enabled && g_acme_inited) {
        memset(&g_dns01_ctx, 0, sizeof(g_dns01_ctx));
        /* Copy the shared acme_client config into dns01 ctx */
        g_dns01_ctx.client = g_acme_client;
        g_dns01_ctx.propagation_wait_s = 90;

        /* Select DNS provider */
        if (strcmp(cfg->acme.dns_provider, "cloudflare") == 0) {
            g_dns01_ctx.dns_ops = &cloudflare_dns_provider;
            void *dns_ctx = NULL;
            if (g_dns01_ctx.dns_ops->init(&dns_ctx, cfg->acme.dns_api_token) == 0) {
                g_dns01_ctx.dns_ctx = dns_ctx;
                g_dns01_inited = 1;
            } else {
                log_warn("cert_manager", "DNS provider init failed");
            }
        } else {
            log_warn("cert_manager", "unknown dns_provider '%s'",
                cfg->acme.dns_provider);
        }
    }

    /* For each ACME route, ensure cert exists and set cert_path/key_path */
    for (int i = 0; i < cfg->route_count; i++) {
        struct route_config *r = &cfg->routes[i];

        if (r->cert_provider == CERT_PROVIDER_ACME_HTTP01 ||
            r->cert_provider == CERT_PROVIDER_ACME_DNS01) {

            char cp[4096], kp[4096];
            snprintf(cp, sizeof(cp), "%s/%s/cert.pem",
                cfg->acme.storage_path, r->hostname);
            snprintf(kp, sizeof(kp), "%s/%s/key.pem",
                cfg->acme.storage_path, r->hostname);

            int days = cfg->acme.renewal_days > 0 ? cfg->acme.renewal_days : 30;
            int needs = acme_needs_renewal(cfg->acme.storage_path,
                                           r->hostname, days);
            if (needs) {
                struct cert_result res;
                memset(&res, 0, sizeof(res));
                log_info("cert_manager", "obtaining cert for %s", r->hostname);

                int ok = -1;
                if (r->cert_provider == CERT_PROVIDER_ACME_HTTP01
                    && g_acme_inited && g_http01_started) {
                    ok = acme_obtain_http01(&g_acme_client, r->hostname,
                                            &g_http01_srv, &res);
                } else if (r->cert_provider == CERT_PROVIDER_ACME_DNS01
                           && g_dns01_inited) {
                    ok = acme_obtain_dns01(&g_dns01_ctx, r->hostname, &res);
                }

                if (ok == 0) {
                    cert_result_free(&res);
                } else {
                    log_warn("cert_manager", "cert obtain failed for %s",
                        r->hostname);
                    continue;
                }
            }

            /* Point route at the stored cert files */
            snprintf(r->cert_path, sizeof(r->cert_path), "%s", cp);
            snprintf(r->key_path, sizeof(r->key_path), "%s", kp);
        }
    }

    /* Start renewal thread */
    if (g_acme_inited) {
        g_renewal_running = 1;
        pthread_create(&g_renewal_thread, NULL, renewal_thread_fn, NULL);
    }

    return 0;
}

static void cert_manager_reload_static(void)
{
    /* Grow route_count if new routes were added since last init.
     * IMPORTANT: zero-init new slots and load their ssl_ctx BEFORE publishing
     * the new route_count.  Workers read route_count atomically; if we bumped
     * it first, a worker could attempt a handshake for a route whose ssl_ctx
     * is still NULL, falling back to route 0 and presenting the wrong cert. */
    if (g_cfg.route_count > g_tls.route_count) {
        for (int i = g_tls.route_count; i < g_cfg.route_count; i++)
            memset(&g_tls.routes[i], 0, sizeof(g_tls.routes[i]));
        /* ssl_ctx for new routes will be set in the loop below;
         * route_count is updated at the end of this function after the loop. */
    }

    /* On SIGHUP: re-read static certs from disk */
    for (int i = 0; i < g_cfg.route_count; i++) {
        struct route_config *r = &g_cfg.routes[i];
        if (r->cert_provider != CERT_PROVIDER_STATIC) continue;
        if (!r->cert_path[0]) continue;

        struct cert_result res;
        memset(&res, 0, sizeof(res));
        if (static_file_load(r->cert_path, r->key_path, &res) != 0) {
            log_warn("cert_reload", "route=%d failed to reload cert", i);
            cert_result_free(&res);
            continue;
        }

        if (g_tls.routes[i].ssl_ctx) {
            /* Existing route — hot-swap via tls_rotate_cert */
            if (tls_rotate_cert(&g_tls, i, res.cert_pem, res.key_pem) == 0)
                log_info("cert_reload", "route=%d cert reloaded from %s", i, r->cert_path);
            else
                log_warn("cert_reload", "route=%d tls_rotate_cert failed", i);
        } else {
            /* New route — create ssl_ctx with correct hostname */
            SSL_CTX *ctx = tls_create_ctx_from_pem(&g_tls, res.cert_pem,
                                                    res.key_pem, r->hostname);
            if (ctx) {
                __atomic_store_n(&g_tls.routes[i].ssl_ctx, ctx, __ATOMIC_SEQ_CST);
                g_tls.routes[i].route_idx = i;
                log_info("cert_reload", "route=%d cert loaded from %s (new route)",
                    i, r->cert_path);
            } else {
                log_warn("cert_reload", "route=%d tls_create_ctx_from_pem failed", i);
            }
        }
        cert_result_free(&res);
    }

    /* Publish new route_count AFTER all ssl_ctx values have been stored.
     * A full sequential barrier ensures workers that load the new route_count
     * will also see all the ssl_ctx writes that precede it. */
    if (g_cfg.route_count > g_tls.route_count)
        __atomic_store_n(&g_tls.route_count, g_cfg.route_count, __ATOMIC_SEQ_CST);
}
#endif /* VORTEX_PHASE_TLS */

int main(int argc, char *argv[])
{
    const char *config_path = "/etc/vortex/vortex.yaml";
    int foreground  = 1;
    int test_config = 0;
    int verbose     = 0;
    int daemonize   = 0;

    int opt;
    while ((opt = getopt(argc, argv, "c:dftb:XTvh")) != -1) {
        switch (opt) {
        case 'c': config_path = optarg; break;
        case 'd': daemonize   = 1;      break;
        case 'f': foreground  = 1;      break;
        case 't': test_config = 1;      break;
        case 'b': snprintf(g_bpf_obj_path, sizeof(g_bpf_obj_path), "%s", optarg); break;
        case 'X': g_no_xdp = 1;         break;
        case 'T': g_no_tls = 1;         break;
        case 'v': verbose   = 1;        break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 1;
        }
    }

    g_config_path = config_path;

    /* Early log init — will be re-inited after config load */
    log_init(verbose ? LOG_DEBUG : LOG_INFO, LOG_FMT_TEXT, NULL);

    if (config_load(config_path, &g_cfg) != 0) {
        fprintf(stderr, "Failed to load config: %s\n", config_path);
        return 1;
    }
    config_resolve_backends(&g_cfg);

    if (test_config) {
        printf("Config OK: %d routes\n", g_cfg.route_count);
        return 0;
    }

    /* Re-init logging with config settings */
    log_level_t  lvl = LOG_INFO;
    log_format_t fmt = LOG_FMT_JSON;
    if (!strcmp(g_cfg.log_level, "debug")) lvl = LOG_DEBUG;
    else if (!strcmp(g_cfg.log_level, "warn"))  lvl = LOG_WARN;
    else if (!strcmp(g_cfg.log_level, "error")) lvl = LOG_ERROR;
    if (!strcmp(g_cfg.log_format, "text")) fmt = LOG_FMT_TEXT;
    if (verbose) lvl = LOG_DEBUG;
    log_init(lvl, fmt, NULL);

    log_info("vortex_start", "version=%s config=%s", VORTEX_VERSION, config_path);

    setup_signals();

    foreground = !daemonize;

    if (!foreground) {
        /* Daemonise */
        pid_t pid = fork();
        if (pid < 0) { perror("fork"); return 1; }
        if (pid > 0) return 0; /* parent exits */
        setsid();
        /* Redirect stdio */
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            dup2(devnull, STDOUT_FILENO);
            /* Keep stderr for logging */
            close(devnull);
        }
    }

    if (!foreground) {
        if (write_pid_file(g_cfg.pid_file) == 0)
            g_pid_file_written = 1;
    }

    /* Phase 1: Load XDP program if interface and BPF obj are configured */
    int xdp_loaded = 0;
    if (!g_no_xdp && g_bpf_obj_path[0] != '\0' && g_cfg.interface[0] != '\0') {
        if (bpf_loader_init(g_bpf_obj_path, g_cfg.interface) == 0) {
            xdp_loaded = 1;
            log_info("xdp_loaded", "interface=%s", g_cfg.interface);
            /* Phase 5: apply rate limit config and load blocklist */
            bpf_loader_apply_config(&g_cfg.xdp);
        } else {
            log_warn("xdp_load_failed", "continuing without XDP");
        }
    } else {
        log_info("xdp_skip", "no BPF object path or interface configured — skipping XDP");
    }

#ifdef VORTEX_PHASE_TLS
    /* Phase 6: cert manager — obtain missing ACME certs, sets cert_path/key_path
     * in cfg routes so that tls_init can load them.
     * Runs before tls_init so that ACME routes have certs available. */
    int tls_needed = 0;
    if (!g_no_tls) {
        for (int i = 0; i < g_cfg.route_count; i++) {
            struct route_config *r = &g_cfg.routes[i];
            if (r->cert_path[0] != '\0' ||
                r->cert_provider == CERT_PROVIDER_ACME_HTTP01) {
                tls_needed = 1;
                break;
            }
        }
    }
    struct tls_ctx *tls_ptr = NULL;
    if (tls_needed) {
        /* Init TLS providers first so cert_manager can use libctx for ACME HTTPS */
        if (tls_init(&g_tls, &g_cfg) != 0) {
            log_error("main", "TLS init failed");
            if (xdp_loaded) bpf_loader_detach();
            return 1;
        }
        /* Now run cert manager (needs g_tls.libctx for outbound HTTPS) */
        cert_manager_init(&g_cfg);
        /* Re-init TLS contexts with any newly obtained certs */
        tls_destroy(&g_tls);
        if (tls_init(&g_tls, &g_cfg) != 0) {
            log_error("main", "TLS re-init after cert obtain failed");
            if (xdp_loaded) bpf_loader_detach();
            return 1;
        }
        tls_ptr = &g_tls;
        log_info("main", "TLS subsystem initialised");
    } else {
        log_info("main", "TLS disabled (no certs configured or -T flag)");
    }
#else
    struct tls_ctx *tls_ptr = NULL;
#endif

    /* Determine worker count */
    int num_workers = g_cfg.workers;
    if (num_workers <= 0) {
        num_workers = (int)sysconf(_SC_NPROCESSORS_ONLN);
        if (num_workers <= 0) num_workers = 1;
    }
    if (num_workers > MAX_WORKERS) num_workers = MAX_WORKERS;

    /* Connection pool capacity: 50% of available RAM split across workers */
    uint32_t pool_cap = worker_pool_capacity(num_workers, 0.50);

    /* Shared backend connection pool — must be initialised before workers start */
    global_pool_init();

    struct cache *shared_cache = NULL;
    if (g_cfg.cache.enabled) {
        uint32_t entries = g_cfg.cache.index_entries > 0 ?
            g_cfg.cache.index_entries : 16384;
        size_t slab_bytes = g_cfg.cache.slab_size_bytes > 0 ?
            g_cfg.cache.slab_size_bytes : (64ULL * 1024 * 1024);
        size_t disk_bytes = (size_t)g_cfg.cache.disk_slab_size_bytes;
        const char *disk_path = g_cfg.cache.disk_cache_path[0] ?
            g_cfg.cache.disk_cache_path : NULL;
        if (cache_init(&g_shared_cache, entries, slab_bytes,
                       g_cfg.cache.use_hugepages, disk_path, disk_bytes,
                       g_cfg.cache.etag_sha256) == 0) {
            shared_cache = &g_shared_cache;
        } else {
            log_warn("main", "shared cache init failed — running without cache");
        }
    }

#ifdef VORTEX_PHASE_TLS
    /* TLS handshake thread pool — shared across all workers */
    bool need_tls_pool = (tls_ptr != NULL) || config_uses_backend_tls(&g_cfg);
    if (need_tls_pool) tls_pool_init();
#endif
    bool need_compress_pool = g_cfg.compress_pool_threads > 0;
    if (need_compress_pool)
        compress_pool_init(g_cfg.compress_pool_threads);

    /* Create one SO_REUSEPORT listen socket per worker.
     * The kernel distributes incoming connections across them by hashing the
     * 4-tuple, eliminating accept-queue contention and thundering herd. */
    g_num_workers = num_workers;
    for (int i = 0; i < num_workers; i++) {
        int lfd = worker_create_listener(g_cfg.bind_address,
                                         g_cfg.bind_port, 1024, g_cfg.ipv4_only);
        if (lfd < 0) {
            log_error("main", "failed to create listener %d on %s:%d",
                i, g_cfg.bind_address, g_cfg.bind_port);
            num_workers = i;
            break;
        }
        if (worker_init(&g_workers[i], i, lfd, pool_cap, &g_cfg, tls_ptr,
                        shared_cache) != 0) {
            log_error("main", "worker_init failed for worker %d", i);
            close(lfd);
            num_workers = i;
            break;
        }
        if (worker_start(&g_workers[i]) != 0) {
            log_error("main", "worker_start failed for worker %d", i);
            num_workers = i;
            break;
        }
    }
    if (num_workers == 0) {
        log_error("main", "no workers started");
        if (xdp_loaded) bpf_loader_detach();
        return 1;
    }

    /* Start metrics server */
    struct worker *worker_ptrs[MAX_WORKERS];
    for (int i = 0; i < num_workers; i++) worker_ptrs[i] = &g_workers[i];
    if (g_cfg.metrics.enabled) {
        metrics_init(&g_metrics, g_cfg.metrics.bind_address,
            g_cfg.metrics.port, worker_ptrs, num_workers, shared_cache);
#ifdef VORTEX_PHASE_TLS
        /* Populate cert expiry info for Prometheus */
        g_cert_info_count = 0;
        for (int i = 0; i < g_cfg.route_count && i < VORTEX_MAX_ROUTES; i++) {
            const struct route_config *r = &g_cfg.routes[i];
            if (!r->cert_path[0]) continue;
            struct cert_result cr;
            memset(&cr, 0, sizeof(cr));
            if (static_file_load(r->cert_path, r->key_path, &cr) == 0) {
                snprintf(g_cert_info[g_cert_info_count].hostname, sizeof(g_cert_info[0].hostname), "%s", r->hostname);
                g_cert_info[g_cert_info_count].not_after = cr.not_after;
                g_cert_info_count++;
                cert_result_free(&cr);
            }
        }
        if (g_cert_info_count > 0) {
            g_metrics.cert_info       = g_cert_info;
            g_metrics.cert_info_count = g_cert_info_count;
        }
#endif
        metrics_start(&g_metrics);
    }

    if (g_cfg.dashboard.enabled) {
        if (dashboard_init(&g_dashboard, g_cfg.dashboard.bind_address,
                           g_cfg.dashboard.port, worker_ptrs, num_workers,
                           shared_cache, &g_cfg) == 0) {
            if (dashboard_start(&g_dashboard) != 0) {
                log_warn("main", "dashboard thread start failed");
                if (g_dashboard.listen_fd >= 0) {
                    close(g_dashboard.listen_fd);
                    g_dashboard.listen_fd = -1;
                }
            }
            else g_dashboard_started = 1;
        } else {
            log_warn("main", "dashboard init failed");
        }
    }

#ifdef VORTEX_QUIC
    /* Start QUIC/HTTP3 server (needs TLS to have been set up) */
    if (tls_ptr && tls_ptr->route_count > 0) {
        if (quic_server_init(&g_quic, tls_ptr, shared_cache, &g_cfg,
                             g_cfg.bind_address, g_cfg.bind_port) == 0) {
            if (quic_server_start(g_quic) != 0) {
                log_warn("main", "QUIC thread start failed");
                quic_server_destroy(g_quic);
                g_quic = NULL;
            }
        } else {
            log_warn("main", "QUIC server init failed — HTTP/3 disabled");
        }
    } else {
        log_info("main", "QUIC/HTTP3 skipped (no TLS routes)");
    }
#endif

    log_info("vortex_running", "pid=%d workers=%d port=%d",
        (int)getpid(), num_workers, g_cfg.bind_port);

    /* Main loop — monitor signals */
    while (g_running) {
        if (g_reload) {
            g_reload = 0;
            log_info("config_reload", "SIGHUP received, reloading %s", g_config_path);
            if (config_reload(g_config_path, &g_cfg) == 0) {
                config_resolve_backends(&g_cfg);
                if (xdp_loaded) {
                    bpf_loader_apply_config(&g_cfg.xdp);
                }
#ifdef VORTEX_PHASE_TLS
                if (tls_ptr) {
                    cert_manager_reload_static();
                }
#endif
            } else {
                log_warn("config_reload", "reload rejected; keeping current configuration");
            }
        }

        if (xdp_loaded) {
            struct vortex_metrics m;
            if (bpf_metrics_read(&m) == 0) {
                log_debug("xdp_metrics",
                    "rx_pkts=%llu rx_bytes=%llu passed=%llu "
                    "drop_rl=%llu drop_bl=%llu drop_inv=%llu drop_ct=%llu",
                    (unsigned long long)m.rx_packets,
                    (unsigned long long)m.rx_bytes,
                    (unsigned long long)m.passed,
                    (unsigned long long)m.dropped_ratelimit,
                    (unsigned long long)m.dropped_blocklist,
                    (unsigned long long)m.dropped_invalid,
                    (unsigned long long)m.dropped_conntrack);
            }
        }

        sleep(1);
    }

    /* Shutdown */
#ifdef VORTEX_QUIC
    if (g_quic) {
        quic_server_stop(g_quic);
        quic_server_join(g_quic);
        quic_server_destroy(g_quic);
        g_quic = NULL;
    }
#endif
    if (g_dashboard_started) {
        dashboard_stop(&g_dashboard);
        dashboard_join(&g_dashboard);
        g_dashboard_started = 0;
    }
    for (int i = 0; i < num_workers; i++) worker_stop(&g_workers[i]);
    for (int i = 0; i < num_workers; i++) {
        worker_join(&g_workers[i]);
    }
    if (need_compress_pool)
        compress_pool_destroy();
    for (int i = 0; i < num_workers; i++) {
        worker_destroy(&g_workers[i]);
    }
    global_pool_destroy();
#ifdef VORTEX_PHASE_TLS
    if (need_tls_pool) tls_pool_destroy();
#endif
    if (g_cfg.metrics.enabled) {
        metrics_stop(&g_metrics);
        metrics_join(&g_metrics);
    }
    if (shared_cache) {
        cache_destroy(shared_cache);
        shared_cache = NULL;
    }

    log_info("vortex_shutdown", "shutting down");

#ifdef VORTEX_PHASE_TLS
    /* Stop renewal thread and HTTP-01 server */
    if (g_renewal_running) {
        pthread_mutex_lock(&g_renewal_mu);
        g_renewal_running = 0;
        pthread_cond_signal(&g_renewal_cv);
        pthread_mutex_unlock(&g_renewal_mu);
        pthread_join(g_renewal_thread, NULL);
        pthread_mutex_destroy(&g_renewal_mu);
        pthread_cond_destroy(&g_renewal_cv);
    }
    if (g_http01_started) {
        acme_http01_stop(&g_http01_srv);
        g_http01_started = 0;
    }
    if (g_acme_inited) {
        acme_client_destroy(&g_acme_client);
        g_acme_inited = 0;
    }
    if (g_dns01_inited) {
        if (g_dns01_ctx.dns_ops && g_dns01_ctx.dns_ctx)
            g_dns01_ctx.dns_ops->destroy(g_dns01_ctx.dns_ctx);
        g_dns01_inited = 0;
    }
    if (tls_ptr) tls_destroy(&g_tls);
#endif

    if (xdp_loaded) {
        bpf_loader_detach();
    }

    if (g_pid_file_written)
        unlink(g_cfg.pid_file);
    log_close();
    return 0;
}
