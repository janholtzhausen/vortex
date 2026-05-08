#pragma once

#include "config.h"
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>

#ifdef VORTEX_PHASE_TLS
#include <picotls.h>
#include <picotls/minicrypto.h>

/* Per-route TLS context */
struct tls_route_ctx {
    ptls_context_t *ctx; /* picotls context (cert + key for this route) */
    int route_idx;
    const char *hostname;
    unsigned char *ocsp_resp_der; /* DER-encoded OCSP staple, NULL if unavailable */
    int ocsp_resp_der_len;
};

/* Session ticket key (AES-256-GCM) */
struct tls_ticket_key {
    uint8_t key[32];
    uint8_t key_id[8];
    time_t created_at;
};

/* Global TLS state — one instance shared across workers (read-only after init) */
struct tls_ctx {
    struct tls_route_ctx routes[VORTEX_MAX_ROUTES];
    int route_count;
    bool ktls_available;
    uint32_t session_timeout;
    uint32_t session_ticket_rotation;
    pthread_mutex_t ticket_lock;
    struct tls_ticket_key current_ticket_key;
    struct tls_ticket_key previous_ticket_key;
    bool have_current_ticket_key;
    bool have_previous_ticket_key;
    /* Shared encrypt_ticket callback (owns ticket_lock) */
    ptls_encrypt_ticket_t encrypt_ticket_cb;
};

/* Opaque session ticket blob for backend TLS session resumption */
#define TLS_SESSION_TICKET_MAX 4096
struct tls_session_ticket {
    uint8_t data[TLS_SESSION_TICKET_MAX];
    size_t len;
};

/* Initialise TLS — loads cert/key, probes kTLS.
 * Must be called once from main thread before any worker starts. */
int tls_init(struct tls_ctx *tls, const struct vortex_config *cfg);
void tls_destroy(struct tls_ctx *tls);

/*
 * kTLS install result.
 *
 * FAIL        — handshake failed, or TCP_ULP succeeded but TX/RX setsockopt
 *               failed (socket in broken state).  ptls is NULL.  Caller must
 *               close fd — it may no longer support plain ptls_send/recv.
 * USERSPACE   — handshake ok; TCP_ULP not installed; caller does crypto via ptls.
 * KTLS_FULL   — TX+RX both installed; ptls freed; kernel handles all crypto.
 * KTLS_TX_ONLY / KTLS_RX_ONLY — reserved; not produced by the current
 *               implementation (non-negotiable: no half-kTLS by accident).
 */
typedef enum {
    TLS_ACCEPT_FAIL = 0,
    TLS_ACCEPT_USERSPACE,
    TLS_ACCEPT_KTLS_FULL,
    TLS_ACCEPT_KTLS_TX_ONLY,
    TLS_ACCEPT_KTLS_RX_ONLY,
} tls_accept_status_t;

struct tls_accept_result {
    tls_accept_status_t status;
    ptls_t *ptls; /* non-NULL only when status == TLS_ACCEPT_USERSPACE */
    int route_idx; /* SNI-matched route index (0 = default) */
    bool h2; /* ALPN selected "h2" */
    bool ktls_tx; /* kernel TX installed */
    bool ktls_rx; /* kernel RX installed */
    uint8_t *pending_data; /* pre-decrypted bytes from same segment as Finished */
    size_t pending_data_len; /* (heap-alloc'd; caller must free) */
};

/* Snapshot of per-call kTLS install counters (monotonically increasing) */
struct tls_ktls_counters {
    uint64_t attempts; /* kTLS install attempted */
    uint64_t tx_ok; /* TX setsockopt succeeded */
    uint64_t rx_ok; /* RX setsockopt succeeded */
    uint64_t full_ok; /* both TX+RX installed (KTLS_FULL) */
    uint64_t fallback; /* fell back to userspace (TCP_ULP failed) */
    uint64_t fail_close; /* partial install: socket unusable, FAIL returned */
};
void tls_ktls_snapshot(struct tls_ktls_counters *out);

/* Perform blocking TLS 1.3 handshake on an accepted fd (server mode).
 *
 * Returns a tls_accept_result by value.  Check .status first:
 *   FAIL       → handshake or kTLS install failed; close fd, discard conn.
 *   USERSPACE  → .ptls is live; caller does crypto; restore fd blocking mode.
 *   KTLS_FULL  → kernel handles crypto; .ptls is NULL (already freed).
 *
 * .pending_data (if non-NULL) holds pre-decrypted bytes that arrived in the
 * same recv() as the TLS Finished — inject before arming the first io_uring recv.
 * Caller owns the heap allocation and must free it. */
struct tls_accept_result tls_accept(struct tls_ctx *tls, int fd);

/* Free a ptls_t handle safely (no-op if NULL) */
static inline void tls_ssl_free(ptls_t *ssl)
{
    if (ssl) ptls_free(ssl);
}

/* Generate self-signed ECDSA P-256 cert + key for testing */
int tls_gen_self_signed(const char *cert_path, const char *key_path, const char *cn);

/* Hot-swap cert for a route from PEM strings.
 * Thread-safe: new connections see the new cert immediately. */
int tls_rotate_cert(struct tls_ctx *tls, int route_idx, const char *cert_pem, const char *key_pem);

/* Create a new ptls_context_t from PEM strings.
 * Caller must ptls_context_free_minicrypto() when done. */
ptls_context_t *tls_create_ctx_from_pem(struct tls_ctx *tls, const char *cert_pem,
                                        const char *key_pem, const char *hostname);

/* Free resources allocated in a ptls_context_t created by tls_create_ctx_from_pem */
void tls_context_free(ptls_context_t *ctx);

/*
 * Create a minimal TLS 1.3 client context for backend HTTPS connections.
 * No certificate or private key — used for connecting to upstream servers.
 * When verify_peer=true, the certificate chain is verified against the
 * CA bundle at /etc/ssl/certs/ca-certificates.crt.
 * Caller must tls_context_free() when done.
 */
ptls_context_t *tls_create_client_ctx(bool verify_peer);

/*
 * Perform a blocking picotls client handshake on fd.
 * On success returns ptls_t*. On failure returns NULL (fd remains open).
 * resume_session: optional session ticket for resumption.
 * session_ticket_out: if non-NULL, heap-allocates a new session ticket (caller frees).
 */
ptls_t *tls_backend_connect(ptls_context_t *ctx, int fd, const char *server_name,
                            uint32_t timeout_ms, const struct tls_session_ticket *resume_session,
                            struct tls_session_ticket **session_ticket_out);

#else /* !VORTEX_PHASE_TLS */

struct tls_ctx {
    int dummy;
};

static inline int tls_init(struct tls_ctx *t, const struct vortex_config *c)
{
    (void)t;
    (void)c;
    return 0;
}
static inline void tls_destroy(struct tls_ctx *t)
{
    (void)t;
}
typedef enum {
    TLS_ACCEPT_FAIL = 0,
    TLS_ACCEPT_USERSPACE,
    TLS_ACCEPT_KTLS_FULL,
    TLS_ACCEPT_KTLS_TX_ONLY,
    TLS_ACCEPT_KTLS_RX_ONLY,
} tls_accept_status_t;

struct tls_accept_result {
    tls_accept_status_t status;
    void *ptls;
    int route_idx;
    bool h2;
    bool ktls_tx;
    bool ktls_rx;
    uint8_t *pending_data;
    size_t pending_data_len;
};

struct tls_ktls_counters {
    uint64_t attempts, tx_ok, rx_ok, full_ok, fallback, fail_close;
};

static inline void tls_ktls_snapshot(struct tls_ktls_counters *out)
{
    (void)out;
}

static inline struct tls_accept_result tls_accept(struct tls_ctx *t, int fd)
{
    (void)t;
    (void)fd;
    return (struct tls_accept_result){.status = TLS_ACCEPT_FAIL};
}
static inline void tls_ssl_free(void *ssl)
{
    (void)ssl;
}

#endif /* VORTEX_PHASE_TLS */
