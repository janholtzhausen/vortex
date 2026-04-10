#pragma once

#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#define COMPRESS_POOL_QUEUE 128

struct compress_pool_stats {
    uint32_t queue_depth;
    uint32_t active_jobs;
    uint64_t submitted_total;
    uint64_t completed_total;
    uint64_t failed_total;
    uint64_t dropped_total;
};

struct compress_result {
    uint32_t cid;
    bool     ok;
    bool     used_brotli;
    size_t   compressed_len;
    size_t   total_len;
};

/*
 * MPSC result ring for compression results — same design as tls_result_ring.
 * CAP = 256 > COMPRESS_POOL_QUEUE(128) + max pool threads.
 */
#define COMPRESS_RESULT_RING_CAP 256

struct compress_result_slot {
    struct compress_result data;
    _Atomic uint8_t        ready;
};

struct compress_result_ring {
    _Atomic uint32_t          tail;
    char                      _pad[60];
    uint32_t                  head;
    struct compress_result_slot slots[COMPRESS_RESULT_RING_CAP];
};

struct compress_job {
    uint32_t cid;
    int      result_pipe_wr;
    struct compress_result_ring *result_ring;
    uint8_t *src;
    size_t   src_len;
    uint8_t *headers;
    size_t   header_len;
    uint8_t *scratch;
    bool     use_brotli;
    size_t   buf_size;
};

struct compress_pool {
    pthread_t          *threads;
    int                 thread_count;
    pthread_mutex_t     mu;
    pthread_cond_t      cv;
    struct compress_job queue[COMPRESS_POOL_QUEUE];
    int                 head;
    int                 tail;
    int                 count;
    uint32_t            active_jobs;
    uint64_t            submitted_total;
    uint64_t            completed_total;
    uint64_t            failed_total;
    uint64_t            dropped_total;
    bool                initialized;
    bool                shutdown;
};

void compress_pool_init(struct compress_pool *pool, int thread_count);
void compress_pool_destroy(struct compress_pool *pool);
bool compress_pool_submit(struct compress_pool *pool, struct compress_job job);
void compress_pool_snapshot(struct compress_pool *pool, struct compress_pool_stats *out);
