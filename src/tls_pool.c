#include "tls_pool.h"
#include "tls.h"
#include "log.h"

#include <picotls.h>

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

struct tls_pool g_tls_pool;

_Static_assert(sizeof(struct tls_handshake_result) <= 4096,
    "tls_handshake_result must fit in PIPE_BUF");

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

        struct tls_handshake_result res = {
            .kind      = job.kind,
            .cid       = job.cid,
            .client_fd = job.client_fd,
            .ok        = false,
        };

        if (job.kind == TLS_HANDSHAKE_FRONTEND) {
            char sni[256] = {0};
            int route_idx = 0;
            bool ktls_tx = false, ktls_rx = false, h2 = false;
            uint8_t *pending_data = NULL;
            size_t   pending_data_len = 0;

            ptls_t *ptls = tls_accept(job.tls, job.client_fd,
                                       &route_idx, sni, sizeof(sni),
                                       &ktls_tx, &ktls_rx, &h2,
                                       &pending_data, &pending_data_len);

            if (!ptls && !ktls_tx) {
                log_debug("tls_pool", "frontend handshake failed cid=%u fd=%d",
                          job.cid, job.client_fd);
                free(pending_data);
            } else {
                res.ok               = true;
                res.tls_route_idx    = route_idx;
                res.tls_version      = PTLS_PROTOCOL_VERSION_TLS13;
                res.h2_negotiated    = h2;
                res.ktls_tx          = ktls_tx;
                res.ktls_rx          = ktls_rx;
                res.ssl              = ptls; /* NULL if kTLS took over */
                res.pending_data     = pending_data;
                res.pending_data_len = (uint32_t)pending_data_len;

                if (!ktls_tx) {
                    /* Restore blocking mode for non-kTLS path */
                    int flags = fcntl(job.client_fd, F_GETFL);
                    fcntl(job.client_fd, F_SETFL, flags & ~O_NONBLOCK);
                }
            }
        } else {
            /* TLS_HANDSHAKE_BACKEND */
            char sni_buf[256];
            const char *server_name;

            if (job.backend_sni[0]) {
                server_name = job.backend_sni;
            } else {
                const char *addr = job.backend_addr;
                const char *colon = strrchr(addr, ':');
                size_t host_len = colon ? (size_t)(colon - addr) : strlen(addr);
                if (host_len >= sizeof(sni_buf))
                    host_len = sizeof(sni_buf) - 1;
                memcpy(sni_buf, addr, host_len);
                sni_buf[host_len] = '\0';
                server_name = sni_buf;
            }

            struct tls_session_ticket *new_ticket = NULL;
            ptls_t *ptls = tls_backend_connect(
                job.backend_tls_client_ctx,
                job.client_fd,
                server_name,
                job.timeout_ms ? job.timeout_ms : 30000,
                job.resume_session,
                &new_ticket);

            if (job.resume_session) {
                free(job.resume_session);
                job.resume_session = NULL;
            }

            if (ptls) {
                res.ok             = true;
                res.ssl            = ptls;
                res.backend_session = new_ticket;
            } else {
                free(new_ticket);
                log_warn("tls_pool", "backend handshake failed cid=%u fd=%d sni=%s",
                         job.cid, job.client_fd, server_name);
            }
        }

        /* Free any unconsumed resume_session (error paths) */
        if (job.resume_session) {
            free(job.resume_session);
        }

        /* Push result to the per-worker MPSC ring, then send a 1-byte wakeup.
         * The ring slot is always available because CAP(256) > max in-flight. */
        if (job.result_ring) {
            uint32_t idx = atomic_fetch_add_explicit(&job.result_ring->tail, 1,
                               memory_order_relaxed) % TLS_RESULT_RING_CAP;
            /* Spin until the consumer has cleared this slot (should be instant) */
            while (atomic_load_explicit(&job.result_ring->slots[idx].ready,
                                         memory_order_acquire) != 0)
                ;
            job.result_ring->slots[idx].data = res;
            atomic_store_explicit(&job.result_ring->slots[idx].ready, 1,
                                   memory_order_release);
            const uint8_t wake = 1;
            ssize_t wr = write(job.result_pipe_wr, &wake, sizeof(wake));
            if (wr != 1)
                log_error("tls_pool", "wakeup pipe write failed cid=%u", job.cid);
        } else {
            /* Fallback: write full struct to pipe (should not occur) */
            ssize_t wr = write(job.result_pipe_wr, &res, sizeof(res));
            if (wr != (ssize_t)sizeof(res)) {
                log_error("tls_pool", "result pipe write failed cid=%u", job.cid);
                if (res.ssl && !res.ktls_tx)
                    ptls_free(res.ssl);
                free(res.backend_session);
            }
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
        free(job.resume_session);
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
