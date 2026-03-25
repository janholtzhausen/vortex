#include "tls_pool.h"
#include "log.h"

#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <openssl/ssl.h>

struct tls_pool g_tls_pool;

static void *tls_pool_worker_thread(void *arg)
{
    struct tls_pool *pool = arg;

    for (;;) {
        struct tls_handshake_job job;

        pthread_mutex_lock(&pool->mu);
        while (pool->count == 0 && !pool->shutdown)
            pthread_cond_wait(&pool->cv, &pool->mu);
        if (pool->shutdown && pool->count == 0) {
            pthread_mutex_unlock(&pool->mu);
            break;
        }
        job = pool->queue[pool->head];
        pool->head = (pool->head + 1) % TLS_POOL_QUEUE;
        pool->count--;
        pool->active_handshakes++;
        pthread_mutex_unlock(&pool->mu);

        /* Perform the blocking TLS handshake */
        struct tls_handshake_result res = {
            .cid       = job.cid,
            .client_fd = job.client_fd,
            .ok        = false,
        };

        char sni[256] = {0};
        int route_idx = 0;
        SSL *ssl = tls_accept(job.tls, job.client_fd, &route_idx, sni, sizeof(sni));

        if (!ssl) {
            log_debug("tls_pool", "handshake failed cid=%u fd=%d", job.cid, job.client_fd);
            /* res.ok stays false — worker will close and free the conn */
        } else {
            res.ok           = true;
            res.tls_route_idx = route_idx;
            res.tls_version  = SSL_version(ssl);

            /* Detect ALPN negotiation result */
            const uint8_t *alpn_proto;
            unsigned int   alpn_len;
            SSL_get0_alpn_selected(ssl, &alpn_proto, &alpn_len);
            res.h2_negotiated = (alpn_len == 2 && memcmp(alpn_proto, "h2", 2) == 0);
            if (res.h2_negotiated)
                log_debug("tls_pool", "ALPN=h2 cid=%u", job.cid);

            if (tls_ktls_tx_active(ssl) && tls_ktls_rx_active(ssl)) {
                res.ktls_tx = true;
                res.ktls_rx = true;
                res.ssl     = NULL;
                tls_ssl_free(ssl);
            } else {
                res.ssl = ssl;
            }

            /* Re-set fd to blocking (io_uring works on blocking fds) */
            int flags = fcntl(job.client_fd, F_GETFL);
            fcntl(job.client_fd, F_SETFL, flags & ~O_NONBLOCK);
        }

        /* Write result — sizeof(result) <= PIPE_BUF so this is atomic */
        ssize_t wr = write(job.result_pipe_wr, &res, sizeof(res));
        if (wr != (ssize_t)sizeof(res)) {
            log_error("tls_pool", "result pipe write failed cid=%u", job.cid);
            if (ssl && !res.ktls_tx) SSL_free(ssl);
        }

        pthread_mutex_lock(&pool->mu);
        if (res.ok) pool->completed_total++;
        else pool->failed_total++;
        if (pool->active_handshakes > 0) pool->active_handshakes--;
        pthread_mutex_unlock(&pool->mu);
    }
    return NULL;
}

void tls_pool_init(void)
{
    memset(&g_tls_pool, 0, sizeof(g_tls_pool));
    pthread_mutex_init(&g_tls_pool.mu, NULL);
    pthread_cond_init(&g_tls_pool.cv, NULL);
    g_tls_pool.initialized = true;

    for (int i = 0; i < TLS_POOL_THREADS; i++) {
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setstacksize(&attr, 256 * 1024); /* 256KB per thread */
        pthread_create(&g_tls_pool.threads[i], &attr,
                       tls_pool_worker_thread, &g_tls_pool);
        pthread_attr_destroy(&attr);
    }
    log_info("tls_pool", "started %d handshake threads", TLS_POOL_THREADS);
}

void tls_pool_destroy(void)
{
    if (!g_tls_pool.initialized)
        return;
    pthread_mutex_lock(&g_tls_pool.mu);
    g_tls_pool.shutdown = true;
    while (g_tls_pool.count > 0) {
        struct tls_handshake_job job = g_tls_pool.queue[g_tls_pool.head];
        g_tls_pool.head = (g_tls_pool.head + 1) % TLS_POOL_QUEUE;
        g_tls_pool.count--;
        close(job.client_fd);
    }
    pthread_cond_broadcast(&g_tls_pool.cv);
    pthread_mutex_unlock(&g_tls_pool.mu);

    for (int i = 0; i < TLS_POOL_THREADS; i++)
        pthread_join(g_tls_pool.threads[i], NULL);

    pthread_mutex_destroy(&g_tls_pool.mu);
    pthread_cond_destroy(&g_tls_pool.cv);
    g_tls_pool.initialized = false;
}

bool tls_pool_submit(struct tls_handshake_job job)
{
    if (!g_tls_pool.initialized)
        return false;
    pthread_mutex_lock(&g_tls_pool.mu);
    if (g_tls_pool.count >= TLS_POOL_QUEUE) {
        g_tls_pool.dropped_total++;
        pthread_mutex_unlock(&g_tls_pool.mu);
        log_warn("tls_pool", "queue full — dropping handshake fd=%d", job.client_fd);
        return false;
    }
    g_tls_pool.queue[g_tls_pool.tail] = job;
    g_tls_pool.tail = (g_tls_pool.tail + 1) % TLS_POOL_QUEUE;
    g_tls_pool.count++;
    g_tls_pool.submitted_total++;
    pthread_cond_signal(&g_tls_pool.cv);
    pthread_mutex_unlock(&g_tls_pool.mu);
    return true;
}

void tls_pool_snapshot(struct tls_pool_stats *out)
{
    if (!out) return;
    memset(out, 0, sizeof(*out));
    if (!g_tls_pool.initialized)
        return;
    pthread_mutex_lock(&g_tls_pool.mu);
    out->queue_depth = (uint32_t)g_tls_pool.count;
    out->active_handshakes = g_tls_pool.active_handshakes;
    out->submitted_total = g_tls_pool.submitted_total;
    out->completed_total = g_tls_pool.completed_total;
    out->failed_total = g_tls_pool.failed_total;
    out->dropped_total = g_tls_pool.dropped_total;
    pthread_mutex_unlock(&g_tls_pool.mu);
}
