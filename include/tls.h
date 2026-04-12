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
    ptls_context_t  *ctx;           /* picotls context (cert + key for this route) */
    int              route_idx;
    const char      *hostname;
    unsigned char   *ocsp_resp_der; /* DER-encoded OCSP staple, NULL if unavailable */
    int              ocsp_resp_der_len;
};

/* Session ticket key (AES-256-GCM) */
struct tls_ticket_key {
    uint8_t  key[32];
    uint8_t  key_id[8];
    time_t   created_at;
};

/* Global TLS state — one instance shared across workers (read-only after init) */
struct tls_ctx {
    struct tls_route_ctx  routes[VORTEX_MAX_ROUTES];
    int                   route_count;
    bool                  ktls_available;
    uint32_t              session_timeout;
    uint32_t              session_ticket_rotation;
    pthread_mutex_t       ticket_lock;
    struct tls_ticket_key current_ticket_key;
    struct tls_ticket_key previous_ticket_key;
    bool                  have_current_ticket_key;
    bool                  have_previous_ticket_key;
    /* Shared encrypt_ticket callback (owns ticket_lock) */
    ptls_encrypt_ticket_t encrypt_ticket_cb;
};

/* Opaque session ticket blob for backend TLS session resumption */
#define TLS_SESSION_TICKET_MAX 4096
struct tls_session_ticket {
    uint8_t  data[TLS_SESSION_TICKET_MAX];
    size_t   len;
};

/* Initialise TLS — loads cert/key, probes kTLS.
 * Must be called once from main thread before any worker starts. */
int  tls_init(struct tls_ctx *tls, const struct vortex_config *cfg);
void tls_destroy(struct tls_ctx *tls);

/* Perform blocking TLS handshake on accepted fd (server mode).
 * On success: returns ptls_t* (NULL if kTLS took over, i.e. *ktls_tx_out = true).
 *   *route_idx_out is set from SNI lookup (or 0 for default).
 *   sni_out filled with negotiated hostname (may be empty).
 *   *ktls_tx_out and *ktls_rx_out set to true if kTLS is installed.
 *   *h2_out is set to true if h2 was ALPN-negotiated.
 *   If the client sent application data bundled with its TLS Finished in the
 *   same recv() call, those bytes are decrypted and returned in *pending_data_out
 *   (heap-alloc'd, caller must free) with *pending_data_len_out set accordingly.
 *   pending_data_out / pending_data_len_out may be NULL (ignored).
 * On failure: returns NULL, *ktls_tx_out = false. Caller must close fd. */
ptls_t *tls_accept(struct tls_ctx *tls, int fd,
                   int *route_idx_out, char *sni_out, size_t sni_max,
                   bool *ktls_tx_out, bool *ktls_rx_out, bool *h2_out,
                   uint8_t **pending_data_out, size_t *pending_data_len_out);

/* Free a ptls_t handle safely (no-op if NULL) */
static inline void tls_ssl_free(ptls_t *ssl)
{
    if (ssl) ptls_free(ssl);
}

/* Generate self-signed ECDSA P-256 cert + key for testing */
int tls_gen_self_signed(const char *cert_path, const char *key_path,
                        const char *cn);

/* Hot-swap cert for a route from PEM strings.
 * Thread-safe: new connections see the new cert immediately. */
int tls_rotate_cert(struct tls_ctx *tls, int route_idx,
                    const char *cert_pem, const char *key_pem);

/* Create a new ptls_context_t from PEM strings.
 * Caller must ptls_context_free_minicrypto() when done. */
ptls_context_t *tls_create_ctx_from_pem(struct tls_ctx *tls,
                                         const char *cert_pem,
                                         const char *key_pem,
                                         const char *hostname);

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
ptls_t *tls_backend_connect(ptls_context_t *ctx, int fd,
                             const char *server_name,
                             uint32_t timeout_ms,
                             const struct tls_session_ticket *resume_session,
                             struct tls_session_ticket **session_ticket_out);

#else /* !VORTEX_PHASE_TLS */

struct tls_ctx { int dummy; };

static inline int  tls_init(struct tls_ctx *t, const struct vortex_config *c)
    { (void)t; (void)c; return 0; }
static inline void tls_destroy(struct tls_ctx *t) { (void)t; }
static inline void *tls_accept(struct tls_ctx *t, int fd, int *ri, char *s, size_t n,
                                bool *tx, bool *rx, bool *h2,
                                uint8_t **pd, size_t *pdl)
    { (void)t; (void)fd; (void)ri; (void)s; (void)n; (void)tx; (void)rx; (void)h2;
      (void)pd; (void)pdl; return NULL; }
static inline void tls_ssl_free(void *ssl) { (void)ssl; }

#endif /* VORTEX_PHASE_TLS */
