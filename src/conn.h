#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include "util.h"

/* Connection states */
typedef enum {
    CONN_STATE_FREE = 0,
    CONN_STATE_ACCEPTING,
    CONN_STATE_TLS_HANDSHAKE,
    CONN_STATE_KTLS_INSTALL,
    CONN_STATE_ROUTING,
    CONN_STATE_BACKEND_CONNECT,
    CONN_STATE_PROXYING,
    CONN_STATE_HALF_CLOSE,
    CONN_STATE_CLOSING,
} conn_state_t;

/* Connection flags */
#define CONN_FLAG_KEEPALIVE          (1 << 0)
#define CONN_FLAG_HTTP2              (1 << 1)
#define CONN_FLAG_WEBSOCKET          (1 << 2)
#define CONN_FLAG_KTLS_TX            (1 << 3)
#define CONN_FLAG_KTLS_RX            (1 << 4)
#define CONN_FLAG_BACKEND_TLS        (1 << 5)
#define CONN_FLAG_STREAMING_BACKEND  (1 << 6)  /* backend response not yet EOF */
#define CONN_FLAG_WEBSOCKET_ACTIVE   (1 << 7)  /* post-101, raw passthrough mode */
#define CONN_FLAG_CACHING            (1 << 8)  /* accumulating response into cache slab */
#define CONN_FLAG_BACKEND_POOLED     (1 << 9)  /* backend fd is keep-alive, return to pool after response */
#define CONN_FLAG_BACKEND_CONNECTING (1 << 10) /* async io_uring CONNECT in flight */

/* Hot connection data — 2 cache lines (128 bytes), accessed per-packet */
struct __attribute__((aligned(64))) conn_hot {
    int           client_fd;
    int           backend_fd;
    uint32_t      state;           /* conn_state_t */
    uint32_t      flags;
    uint64_t      last_active_tsc;
    uint32_t      bytes_in;
    uint32_t      bytes_out;
    uint16_t      route_idx;
    uint16_t      backend_idx;
    uint32_t      conn_id;         /* Pool slot index */
    uint8_t       _pad[16];
    /* --- cache line boundary --- */
    void         *ssl;             /* SSL* — NULL after kTLS install */
    void         *uring_data;
    uint32_t      recv_buf_off;    /* Current read offset */
    uint32_t      send_buf_off;    /* Current send offset */
    uint32_t      recv_buf_len;
    uint32_t      send_buf_len;
    uint8_t       _pad2[24];
};
_Static_assert(sizeof(struct conn_hot) == 128, "conn_hot must be 128 bytes");

/* Cold connection data — accessed rarely */
struct conn_cold {
    struct sockaddr_storage client_addr;
    struct sockaddr_storage backend_addr;
    socklen_t      backend_addrlen;      /* length of backend_addr */
    char           sni[256];
    uint64_t       connect_time_ns;
    uint64_t       tls_complete_ns;
    uint32_t       request_count;
    int            last_error;
    char           last_error_str[128];

    /* Backend keep-alive / connection pool tracking */
    uint32_t       backend_content_length; /* expected response body bytes (0 = unknown) */
    uint32_t       backend_body_recv;      /* body bytes received so far */
    uint8_t        backend_pooled;         /* 1 = this backend fd came from the pool */
};

/* Per-worker connection pool */
struct conn_pool {
    struct conn_hot  *hot;      /* Cache-line aligned array */
    struct conn_cold *cold;     /* Separate allocation */
    uint8_t         **recv_bufs; /* Per-connection receive buffers */
    uint8_t         **send_bufs; /* Per-connection send buffers */
    uint32_t          capacity;
    uint32_t          active;
    uint32_t         *free_list;
    uint32_t          free_top;
    size_t            buf_size;
};

int   conn_pool_init(struct conn_pool *pool, uint32_t capacity, size_t buf_size);
void  conn_pool_destroy(struct conn_pool *pool);

uint32_t conn_alloc(struct conn_pool *pool);
void     conn_free(struct conn_pool *pool, uint32_t id);

static inline struct conn_hot  *conn_hot(struct conn_pool *p, uint32_t id)  { return &p->hot[id]; }
static inline struct conn_cold *conn_cold_ptr(struct conn_pool *p, uint32_t id) { return &p->cold[id]; }
static inline uint8_t          *conn_recv_buf(struct conn_pool *p, uint32_t id) { return p->recv_bufs[id]; }
static inline uint8_t          *conn_send_buf(struct conn_pool *p, uint32_t id) { return p->send_bufs[id]; }

#define CONN_INVALID UINT32_MAX
