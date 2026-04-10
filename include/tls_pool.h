#pragma once
/*
 * tls_pool — fixed-size thread pool for blocking TLS handshakes.
 *
 * The io_uring event loop cannot block.  tls_accept() is a blocking
 * SSL_accept() call (bounded by the select timeout inside tls_accept).
 * Under a slowloris-style TLS attack a single slow handshake would stall
 * the entire worker's ring.
 *
 * Solution: a small shared pool of handshake threads.  The worker submits a
 * job (fd + connection-id + per-worker result pipe) and returns immediately.
 * The pool thread calls tls_accept(), then writes a tls_handshake_result to
 * the worker's pipe.  The worker polls the pipe via io_uring RECV and picks
 * up completed results in the normal event loop.
 */

#include "tls.h"
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <pthread.h>
#include <openssl/ssl.h>

#define TLS_POOL_THREADS  4     /* worker threads in the pool */
#define TLS_POOL_QUEUE   128    /* max pending jobs */

struct tls_pool_stats {
    uint32_t queue_depth;
    uint32_t active_handshakes;
    uint64_t submitted_total;
    uint64_t completed_total;
    uint64_t failed_total;
    uint64_t dropped_total;
};

typedef enum {
    TLS_HANDSHAKE_FRONTEND = 0,
    TLS_HANDSHAKE_BACKEND  = 1,
} tls_handshake_kind_t;

/* Result written to the per-worker pipe after handshake completes */
struct tls_handshake_result {
    tls_handshake_kind_t kind;
    uint32_t cid;           /* connection id to resume */
    int      client_fd;     /* original fd (frontend) */
    int      tls_route_idx; /* SNI-matched route (-1 on error) */
    SSL     *ssl;           /* NULL if kTLS took over or on error */
    bool     ok;            /* false = handshake failed, close and free conn */
    bool     ktls_tx;
    bool     ktls_rx;
    bool     h2_negotiated; /* ALPN selected "h2" */
    int      tls_version;   /* SSL_version() result */
    SSL_SESSION *backend_session; /* cached resumable session for HTTPS origins */
};

/*
 * MPSC result ring — pool threads push completed handshake results here;
 * the worker drains it when the 1-byte wakeup signal arrives on the pipe.
 * CAP = 256 > TLS_POOL_QUEUE(128) + TLS_POOL_THREADS(4), so producers never
 * need to spin waiting for a slot.
 */
#define TLS_RESULT_RING_CAP 256

struct tls_result_slot {
    struct tls_handshake_result data;
    _Atomic uint8_t             ready;  /* 0 = empty, 1 = result available */
};

struct tls_result_ring {
    _Atomic uint32_t      tail;              /* next write index (producers) */
    char                  _pad[60];          /* isolate tail from head */
    uint32_t              head;              /* read index (consumer only) */
    struct tls_result_slot slots[TLS_RESULT_RING_CAP];
};

/* Job submitted by the worker to the pool */
struct tls_handshake_job {
    tls_handshake_kind_t kind;
    int             client_fd;
    uint32_t        cid;
    struct tls_ctx *tls;
    int                   result_pipe_wr;  /* write end of per-worker wakeup pipe */
    struct tls_result_ring *result_ring;  /* per-worker MPSC result ring */
    SSL_CTX        *backend_tls_client_ctx;
    uint32_t        timeout_ms;
    bool            verify_peer;
    bool            verify_peer_set;
    char            backend_addr[256];
    char            backend_sni[256];
    SSL_SESSION    *resume_session;
};

struct tls_pool {
    pthread_t       threads[TLS_POOL_THREADS];
    pthread_mutex_t mu;
    pthread_cond_t  cv;
    struct tls_handshake_job queue[TLS_POOL_QUEUE];
    int  head, tail, count;
    uint32_t active_handshakes;
    uint64_t submitted_total;
    uint64_t completed_total;
    uint64_t failed_total;
    uint64_t dropped_total;
    bool initialized;
    bool shutdown;
};

/* Global singleton pool — shared by all workers so handshake threads are not
 * multiplied per worker (avoids thread explosion). */
extern struct tls_pool g_tls_pool;

void tls_pool_init(void);
void tls_pool_destroy(void);

/* Submit a job; returns false if the queue is full (caller should close fd) */
bool tls_pool_submit(struct tls_handshake_job job);
void tls_pool_snapshot(struct tls_pool_stats *out);
