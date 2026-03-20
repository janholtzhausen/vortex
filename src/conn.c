#include "conn.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>

int conn_pool_init(struct conn_pool *pool, uint32_t capacity, size_t buf_size)
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

    /* Per-connection buffers */
    pool->recv_bufs = calloc(capacity, sizeof(uint8_t *));
    pool->send_bufs = calloc(capacity, sizeof(uint8_t *));
    if (!pool->recv_bufs || !pool->send_bufs) goto oom;

    for (uint32_t i = 0; i < capacity; i++) {
        pool->recv_bufs[i] = malloc(buf_size);
        pool->send_bufs[i] = malloc(buf_size);
        if (!pool->recv_bufs[i] || !pool->send_bufs[i]) goto oom;
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
    if (pool->recv_bufs) {
        for (uint32_t i = 0; i < pool->capacity; i++) free(pool->recv_bufs[i]);
        free(pool->recv_bufs);
    }
    if (pool->send_bufs) {
        for (uint32_t i = 0; i < pool->capacity; i++) free(pool->send_bufs[i]);
        free(pool->send_bufs);
    }
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

    pool->free_list[pool->free_top++] = id;
    if (pool->active > 0) pool->active--;
}
