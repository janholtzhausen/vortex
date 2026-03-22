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
#include <pthread.h>
#include <openssl/ssl.h>

#define TLS_POOL_THREADS  4     /* worker threads in the pool */
#define TLS_POOL_QUEUE   128    /* max pending jobs */

/* Result written to the per-worker pipe after handshake completes */
struct tls_handshake_result {
    uint32_t cid;           /* connection id to resume */
    int      client_fd;     /* original fd (for fcntl back to blocking) */
    int      tls_route_idx; /* SNI-matched route (-1 on error) */
    SSL     *ssl;           /* NULL if kTLS took over or on error */
    bool     ok;            /* false = handshake failed, close and free conn */
    bool     ktls_tx;
    bool     ktls_rx;
    bool     h2_negotiated; /* ALPN selected "h2" */
    int      tls_version;   /* SSL_version() result */
};

/* Job submitted by the worker to the pool */
struct tls_handshake_job {
    int             client_fd;
    uint32_t        cid;
    struct tls_ctx *tls;
    int             result_pipe_wr; /* write end of per-worker result pipe */
};

struct tls_pool {
    pthread_t       threads[TLS_POOL_THREADS];
    pthread_mutex_t mu;
    pthread_cond_t  cv;
    struct tls_handshake_job queue[TLS_POOL_QUEUE];
    int  head, tail, count;
    bool shutdown;
};

/* Global singleton pool — shared by all workers so handshake threads are not
 * multiplied per worker (avoids thread explosion). */
extern struct tls_pool g_tls_pool;

void tls_pool_init(void);
void tls_pool_destroy(void);

/* Submit a job; returns false if the queue is full (caller should close fd) */
bool tls_pool_submit(struct tls_handshake_job job);
