#include "conn.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>

#ifndef MAP_HUGETLB
#define MAP_HUGETLB 0x40000
#endif
#ifndef MAP_HUGE_SHIFT
#define MAP_HUGE_SHIFT 26
#endif
#ifndef MAP_HUGE_2MB
#define MAP_HUGE_2MB (21 << MAP_HUGE_SHIFT)
#endif

/* Allocate a contiguous anonymous slab.  If try_hugepages is set, attempt:
 *   1. MAP_HUGETLB | MAP_HUGE_2MB  — explicit 2MB huge pages (requires
 *      vm.nr_hugepages pre-allocated on the host)
 *   2. Regular mmap + MADV_HUGEPAGE — THP (Transparent Huge Pages), kernel
 *      promotes 4KB pages to 2MB on first touch if khugepaged is enabled
 *   3. Plain mmap — always succeeds (within address-space limits)
 */
static uint8_t *alloc_slab(size_t size, bool try_hugepages)
{
    if (try_hugepages) {
        uint8_t *p = mmap(NULL, size, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | MAP_HUGE_2MB,
                          -1, 0);
        if (p != MAP_FAILED) {
            log_info("conn_pool", "slab %zu MB: explicit 2MB huge pages",
                     size / (1024 * 1024));
            return p;
        }
        p = mmap(NULL, size, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p != MAP_FAILED) {
            madvise(p, size, MADV_HUGEPAGE);
            log_info("conn_pool", "slab %zu MB: THP hint (MADV_HUGEPAGE)",
                     size / (1024 * 1024));
            return p;
        }
    }
    uint8_t *p = mmap(NULL, size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return (p == MAP_FAILED) ? NULL : p;
}

int conn_pool_init(struct conn_pool *pool, uint32_t capacity, size_t buf_size,
                   bool hugepages)
{
    memset(pool, 0, sizeof(*pool));
    pool->capacity = capacity;
    pool->buf_size = buf_size;

    /* Hot array — cache-line aligned */
    pool->hot = aligned_alloc(64, capacity * sizeof(struct conn_hot));
    if (!pool->hot) goto oom;
    memset(pool->hot, 0, capacity * sizeof(struct conn_hot));

    /* Cold array */
    pool->cold = calloc(capacity, sizeof(struct conn_cold));
    if (!pool->cold) goto oom;

    /* Contiguous buffer slabs — one mmap per direction.
     * Contiguous layout is required for io_uring fixed-buffer registration:
     * each connection's buffer is a fixed-size slice of the slab, so the
     * kernel pins the whole range once and per-op page-pinning is skipped. */
    size_t slab_size = (size_t)capacity * buf_size;
    pool->recv_slab = alloc_slab(slab_size, hugepages);
    pool->send_slab = alloc_slab(slab_size, hugepages);
    if (!pool->recv_slab || !pool->send_slab) goto oom;

    /* Per-connection pointer arrays — slices into the slabs */
    pool->recv_bufs = calloc(capacity, sizeof(uint8_t *));
    pool->send_bufs = calloc(capacity, sizeof(uint8_t *));
    if (!pool->recv_bufs || !pool->send_bufs) goto oom;

    for (uint32_t i = 0; i < capacity; i++) {
        pool->recv_bufs[i] = pool->recv_slab + (size_t)i * buf_size;
        pool->send_bufs[i] = pool->send_slab + (size_t)i * buf_size;
    }

    /* Free list — initially all slots are free, pushed in reverse */
    pool->free_list = malloc(capacity * sizeof(uint32_t));
    if (!pool->free_list) goto oom;
    pool->free_top = capacity;
    for (uint32_t i = 0; i < capacity; i++) {
        pool->free_list[i] = capacity - 1 - i;
        pool->hot[i].conn_id   = i;
        pool->hot[i].client_fd  = -1;
        pool->hot[i].backend_fd = -1;
        pool->hot[i].state      = CONN_STATE_FREE;
    }

    log_info("conn_pool_init", "capacity=%u buf_size=%zu", capacity, buf_size);
    return 0;

oom:
    log_error("conn_pool_init", "out of memory allocating pool (capacity=%u)", capacity);
    conn_pool_destroy(pool);
    return -ENOMEM;
}

void conn_pool_destroy(struct conn_pool *pool)
{
    size_t slab_size = (size_t)pool->capacity * pool->buf_size;
    if (pool->recv_slab)
        munmap(pool->recv_slab, slab_size);
    if (pool->send_slab)
        munmap(pool->send_slab, slab_size);
    free(pool->recv_bufs);
    free(pool->send_bufs);
    free(pool->hot);
    free(pool->cold);
    free(pool->free_list);
    memset(pool, 0, sizeof(*pool));
}

uint32_t conn_alloc(struct conn_pool *pool)
{
    if (pool->free_top == 0) {
        log_warn("conn_alloc", "connection pool exhausted (capacity=%u)", pool->capacity);
        return CONN_INVALID;
    }

    uint32_t id = pool->free_list[--pool->free_top];
    pool->active++;

    struct conn_hot *h = &pool->hot[id];
    memset(h, 0, sizeof(*h));
    h->conn_id   = id;
    h->client_fd  = -1;
    h->backend_fd = -1;
    h->state      = CONN_STATE_ACCEPTING;

    memset(&pool->cold[id], 0, sizeof(pool->cold[id]));
    pool->cold[id].splice_pipe[0] = -1;
    pool->cold[id].splice_pipe[1] = -1;

    return id;
}

void conn_free(struct conn_pool *pool, uint32_t id)
{
    if (id >= pool->capacity) return;

    struct conn_hot *h = &pool->hot[id];
    h->state      = CONN_STATE_FREE;
    h->client_fd  = -1;
    h->backend_fd = -1;
    h->ssl        = NULL;
    h->flags      = 0;

    struct conn_cold *cold = &pool->cold[id];
    if (cold->splice_pipe[0] >= 0) { close(cold->splice_pipe[0]); cold->splice_pipe[0] = -1; }
    if (cold->splice_pipe[1] >= 0) { close(cold->splice_pipe[1]); cold->splice_pipe[1] = -1; }
    cold->backend_deadline_ns = 0;
    if (cold->chunk_buf) { free(cold->chunk_buf); cold->chunk_buf = NULL; }
    cold->chunk_buf_cap   = 0;
    cold->chunk_hdr_len   = 0;
    cold->chunk_body_len  = 0;
    cold->chunk_remaining = 0;
    cold->chunk_skip_crlf = false;
    cold->h2 = NULL; /* h2_session_free must have been called by conn_close before conn_free */

    pool->free_list[pool->free_top++] = id;
    if (pool->active > 0) pool->active--;
}
