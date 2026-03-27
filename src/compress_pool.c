#include "compress_pool.h"
#include "worker_internal.h"
#include "log.h"

#include <string.h>
#include <unistd.h>

struct compress_pool g_compress_pool;

_Static_assert(sizeof(struct compress_result) <= 4096,
    "compress_result must fit in PIPE_BUF");

static void *compress_pool_worker_thread(void *arg)
{
    struct compress_pool *pool = arg;

    for (;;) {
        struct compress_job job;

        pthread_mutex_lock(&pool->mu);
        while (pool->count == 0 && !pool->shutdown)
            pthread_cond_wait(&pool->cv, &pool->mu);
        if (pool->shutdown && pool->count == 0) {
            pthread_mutex_unlock(&pool->mu);
            break;
        }
        job = pool->queue[pool->head];
        pool->head = (pool->head + 1) % COMPRESS_POOL_QUEUE;
        pool->count--;
        pool->active_jobs++;
        pthread_mutex_unlock(&pool->mu);

        struct compress_result res = {
            .cid = job.cid,
            .ok = false,
        };

        res.total_len = compress_http_response_parts(job.headers, job.header_len,
            job.src, job.src_len, job.scratch, job.buf_size,
            job.use_brotli, &res.used_brotli, &res.compressed_len);
        if (res.total_len > 0)
            res.ok = true;

        ssize_t wr = write(job.result_pipe_wr, &res, sizeof(res));
        if (wr != (ssize_t)sizeof(res))
            log_error("compress_pool", "result pipe write failed cid=%u", job.cid);

        pthread_mutex_lock(&pool->mu);
        if (res.ok) pool->completed_total++;
        else pool->failed_total++;
        if (pool->active_jobs > 0) pool->active_jobs--;
        pthread_mutex_unlock(&pool->mu);
    }

    return NULL;
}

void compress_pool_init(int thread_count)
{
    if (thread_count <= 0)
        return;

    memset(&g_compress_pool, 0, sizeof(g_compress_pool));
    g_compress_pool.thread_count = thread_count;
    g_compress_pool.threads = calloc((size_t)thread_count, sizeof(pthread_t));
    if (!g_compress_pool.threads) {
        log_error("compress_pool", "thread allocation failed");
        g_compress_pool.thread_count = 0;
        return;
    }

    pthread_mutex_init(&g_compress_pool.mu, NULL);
    pthread_cond_init(&g_compress_pool.cv, NULL);
    g_compress_pool.initialized = true;

    for (int i = 0; i < thread_count; i++) {
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setstacksize(&attr, 256 * 1024);
        pthread_create(&g_compress_pool.threads[i], &attr,
                       compress_pool_worker_thread, &g_compress_pool);
        pthread_attr_destroy(&attr);
    }
    log_info("compress_pool", "started %d compression threads", thread_count);
}

void compress_pool_destroy(void)
{
    if (!g_compress_pool.initialized)
        return;

    pthread_mutex_lock(&g_compress_pool.mu);
    g_compress_pool.shutdown = true;
    g_compress_pool.count = 0;
    g_compress_pool.head = g_compress_pool.tail = 0;
    pthread_cond_broadcast(&g_compress_pool.cv);
    pthread_mutex_unlock(&g_compress_pool.mu);

    for (int i = 0; i < g_compress_pool.thread_count; i++)
        pthread_join(g_compress_pool.threads[i], NULL);

    free(g_compress_pool.threads);
    g_compress_pool.threads = NULL;
    g_compress_pool.thread_count = 0;
    pthread_mutex_destroy(&g_compress_pool.mu);
    pthread_cond_destroy(&g_compress_pool.cv);
    g_compress_pool.initialized = false;
}

bool compress_pool_submit(struct compress_job job)
{
    if (!g_compress_pool.initialized)
        return false;

    pthread_mutex_lock(&g_compress_pool.mu);
    if (g_compress_pool.count >= COMPRESS_POOL_QUEUE) {
        g_compress_pool.dropped_total++;
        pthread_mutex_unlock(&g_compress_pool.mu);
        log_warn("compress_pool", "queue full — dropping compression cid=%u", job.cid);
        return false;
    }
    g_compress_pool.queue[g_compress_pool.tail] = job;
    g_compress_pool.tail = (g_compress_pool.tail + 1) % COMPRESS_POOL_QUEUE;
    g_compress_pool.count++;
    g_compress_pool.submitted_total++;
    pthread_cond_signal(&g_compress_pool.cv);
    pthread_mutex_unlock(&g_compress_pool.mu);
    return true;
}

void compress_pool_snapshot(struct compress_pool_stats *out)
{
    if (!out) return;
    memset(out, 0, sizeof(*out));
    if (!g_compress_pool.initialized)
        return;

    pthread_mutex_lock(&g_compress_pool.mu);
    out->queue_depth = (uint32_t)g_compress_pool.count;
    out->active_jobs = g_compress_pool.active_jobs;
    out->submitted_total = g_compress_pool.submitted_total;
    out->completed_total = g_compress_pool.completed_total;
    out->failed_total = g_compress_pool.failed_total;
    out->dropped_total = g_compress_pool.dropped_total;
    pthread_mutex_unlock(&g_compress_pool.mu);
}
