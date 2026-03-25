#include "metrics.h"
#include "log.h"
#include "bpf_loader.h"
#include "tls_pool.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define METRICS_BUF_SIZE (64 * 1024)

static void write_metric_counter(char *buf, size_t *pos, size_t bufsz,
    const char *name, const char *help, uint64_t val)
{
    *pos += snprintf(buf + *pos, bufsz - *pos,
        "# HELP %s %s\n# TYPE %s counter\n%s %llu\n",
        name, help, name, name, (unsigned long long)val);
}

static void write_metric_gauge(char *buf, size_t *pos, size_t bufsz,
    const char *name, const char *help, uint64_t val)
{
    *pos += snprintf(buf + *pos, bufsz - *pos,
        "# HELP %s %s\n# TYPE %s gauge\n%s %llu\n",
        name, help, name, name, (unsigned long long)val);
}

static void generate_metrics(struct metrics_server *ms, char *buf, size_t bufsz,
    size_t *out_len)
{
    size_t pos = 0;
    time_t now = time(NULL);

    write_metric_gauge(buf, &pos, bufsz,
        "vortex_uptime_seconds", "Seconds since vortex started",
        (uint64_t)(now - (time_t)ms->start_time));

    write_metric_gauge(buf, &pos, bufsz,
        "vortex_worker_threads", "Number of worker threads",
        (uint64_t)ms->num_workers);

    pos += snprintf(buf + pos, bufsz - pos,
        "# HELP vortex_worker_pool_exhausted Pool exhaustion events per worker\n"
        "# TYPE vortex_worker_pool_exhausted counter\n");
    for (int i = 0; i < ms->num_workers; i++) {
        pos += snprintf(buf + pos, bufsz - pos,
            "vortex_worker_pool_exhausted{worker=\"%d\"} %llu\n",
            i, (unsigned long long)ms->workers[i]->pool_exhausted);
    }

    /* Aggregate worker stats */
    uint64_t total_accepted  = 0, total_completed = 0, total_errors = 0;
    uint64_t total_active    = 0;
    uint64_t total_tls12     = 0, total_tls13 = 0, total_ktls = 0;
    for (int i = 0; i < ms->num_workers; i++) {
        total_accepted  += ms->workers[i]->accepted;
        total_completed += ms->workers[i]->completed;
        total_errors    += ms->workers[i]->errors;
        total_active    += ms->workers[i]->pool.active;
        total_tls12     += ms->workers[i]->tls12_count;
        total_tls13     += ms->workers[i]->tls13_count;
        total_ktls      += ms->workers[i]->ktls_count;
    }

    write_metric_gauge(buf, &pos, bufsz,
        "vortex_connections_active", "Currently active connections", total_active);
    write_metric_counter(buf, &pos, bufsz,
        "vortex_connections_total", "Total accepted connections", total_accepted);

    /* TLS stats */
    if (total_tls12 + total_tls13 > 0) {
        write_metric_counter(buf, &pos, bufsz,
            "vortex_tls12_handshakes_total", "TLS 1.2 handshakes completed", total_tls12);
        write_metric_counter(buf, &pos, bufsz,
            "vortex_tls13_handshakes_total", "TLS 1.3 handshakes completed", total_tls13);
        write_metric_gauge(buf, &pos, bufsz,
            "vortex_ktls_connections_total", "Connections using kernel TLS", total_ktls);
    }

    {
        struct tls_pool_stats tls_stats = {0};
        tls_pool_snapshot(&tls_stats);
        write_metric_gauge(buf, &pos, bufsz,
            "vortex_tls_pool_queue_depth", "Pending TLS handshakes in the pool queue",
            tls_stats.queue_depth);
        write_metric_gauge(buf, &pos, bufsz,
            "vortex_tls_pool_active_handshakes", "TLS handshakes currently executing",
            tls_stats.active_handshakes);
        write_metric_counter(buf, &pos, bufsz,
            "vortex_tls_pool_submitted_total", "TLS handshakes submitted to the pool",
            tls_stats.submitted_total);
        write_metric_counter(buf, &pos, bufsz,
            "vortex_tls_pool_completed_total", "TLS handshakes completed successfully",
            tls_stats.completed_total);
        write_metric_counter(buf, &pos, bufsz,
            "vortex_tls_pool_failed_total", "TLS handshakes that failed in the pool",
            tls_stats.failed_total);
        write_metric_counter(buf, &pos, bufsz,
            "vortex_tls_pool_dropped_total", "TLS handshakes dropped because the pool queue was full",
            tls_stats.dropped_total);
    }

    /* Cert expiry */
    if (ms->cert_info && ms->cert_info_count > 0) {
        for (int i = 0; i < ms->cert_info_count; i++) {
            if (!ms->cert_info[i].not_after) continue;
            pos += snprintf(buf + pos, bufsz - pos,
                "# HELP vortex_cert_expiry_seconds Seconds until cert expiry\n"
                "# TYPE vortex_cert_expiry_seconds gauge\n"
                "vortex_cert_expiry_seconds{hostname=\"%s\"} %lld\n",
                ms->cert_info[i].hostname,
                (long long)(ms->cert_info[i].not_after - now));
        }
    }

    uint64_t cache_hits = 0, cache_misses = 0, cache_evictions = 0;
    uint64_t cache_stores = 0, cache_slab_bytes = 0;
    if (ms->cache) {
        cache_hits       = ms->cache->hits;
        cache_misses     = ms->cache->misses;
        cache_evictions  = ms->cache->evictions;
        cache_stores     = ms->cache->stores;
        cache_slab_bytes = ms->cache->slab_size;
    }
    if (cache_hits || cache_misses || cache_evictions || cache_stores || cache_slab_bytes) {
        write_metric_counter(buf, &pos, bufsz,
            "vortex_cache_hits_total", "Cache hits", cache_hits);
        write_metric_counter(buf, &pos, bufsz,
            "vortex_cache_misses_total", "Cache misses", cache_misses);
        write_metric_counter(buf, &pos, bufsz,
            "vortex_cache_evictions_total", "Cache evictions", cache_evictions);
        write_metric_counter(buf, &pos, bufsz,
            "vortex_cache_stores_total", "Cache stores", cache_stores);
        write_metric_gauge(buf, &pos, bufsz,
            "vortex_cache_memory_bytes", "Cache slab memory bytes",
            cache_slab_bytes);
    }

    /* XDP/BPF metrics */
    struct vortex_metrics bpf_m;
    if (bpf_loader_is_active() && bpf_metrics_read(&bpf_m) == 0) {
        write_metric_counter(buf, &pos, bufsz,
            "vortex_xdp_rx_packets_total", "XDP received packets", bpf_m.rx_packets);
        write_metric_counter(buf, &pos, bufsz,
            "vortex_xdp_rx_bytes_total", "XDP received bytes", bpf_m.rx_bytes);
        write_metric_counter(buf, &pos, bufsz,
            "vortex_xdp_dropped_ratelimit_total", "XDP dropped (rate limit)",
            bpf_m.dropped_ratelimit);
        write_metric_counter(buf, &pos, bufsz,
            "vortex_xdp_dropped_blocklist_total", "XDP dropped (blocklist)",
            bpf_m.dropped_blocklist);
    }

    *out_len = pos;
}

static void handle_metrics_request(struct metrics_server *ms, int client_fd)
{
    char req[1024];
    ssize_t n = recv(client_fd, req, sizeof(req) - 1, 0);
    if (n <= 0) { close(client_fd); return; }
    req[n] = '\0';

    /* Check path */
    bool is_metrics = strstr(req, "GET /metrics") != NULL;

    char *body = malloc(METRICS_BUF_SIZE);
    if (!body) { close(client_fd); return; }

    size_t body_len = 0;
    if (is_metrics) {
        generate_metrics(ms, body, METRICS_BUF_SIZE, &body_len);
    }

    char header[512];
    int hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 %s\r\n"
        "Content-Type: text/plain; version=0.0.4\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n\r\n",
        is_metrics ? "200 OK" : "404 Not Found",
        body_len);

    send(client_fd, header, hlen, MSG_NOSIGNAL);
    if (body_len > 0) send(client_fd, body, body_len, MSG_NOSIGNAL);
    free(body);
    close(client_fd);
}

static void *metrics_thread(void *arg)
{
    struct metrics_server *ms = (struct metrics_server *)arg;
    log_info("metrics_start", "listening for Prometheus scrapes");

    while (ms->running) {
        struct sockaddr_in client_addr;
        socklen_t addrlen = sizeof(client_addr);
        int client_fd = accept(ms->listen_fd,
            (struct sockaddr *)&client_addr, &addrlen);
        if (client_fd < 0) {
            if (!ms->running) break;
            continue;
        }
        handle_metrics_request(ms, client_fd);
    }
    return NULL;
}

int metrics_init(struct metrics_server *ms,
                 const char *bind_addr, uint16_t port,
                 struct worker **workers, int num_workers,
                 struct cache *cache)
{
    memset(ms, 0, sizeof(*ms));
    ms->workers     = workers;
    ms->num_workers = num_workers;
    ms->cache       = cache;
    ms->start_time  = (uint64_t)time(NULL);
    ms->listen_fd   = -1;

    struct sockaddr_in sa = {
        .sin_family = AF_INET,
        .sin_port   = htons(port),
    };
    inet_pton(AF_INET, bind_addr, &sa.sin_addr);

    ms->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (ms->listen_fd < 0) {
        log_error("metrics_init", "socket: %s", strerror(errno));
        return -1;
    }

    int one = 1;
    setsockopt(ms->listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    if (bind(ms->listen_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        log_error("metrics_init", "bind %s:%d: %s", bind_addr, port, strerror(errno));
        close(ms->listen_fd);
        ms->listen_fd = -1;
        return -1;
    }

    listen(ms->listen_fd, 8);
    log_info("metrics_init", "metrics endpoint: http://%s:%d/metrics",
        bind_addr, port);
    return 0;
}

int metrics_start(struct metrics_server *ms)
{
    ms->running = 1;
    return pthread_create(&ms->thread, NULL, metrics_thread, ms);
}

void metrics_stop(struct metrics_server *ms)
{
    ms->running = 0;
    if (ms->listen_fd >= 0) {
        shutdown(ms->listen_fd, SHUT_RDWR);
    }
}

void metrics_join(struct metrics_server *ms)
{
    pthread_join(ms->thread, NULL);
    if (ms->listen_fd >= 0) {
        close(ms->listen_fd);
        ms->listen_fd = -1;
    }
}
