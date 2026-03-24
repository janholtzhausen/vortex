#pragma once

#include "config.h"
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>

#ifdef VORTEX_PHASE_TLS
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/provider.h>

/* Per-route SSL_CTX */
struct tls_route_ctx {
    SSL_CTX *ssl_ctx;
    int      route_idx;
    const char *hostname;
    unsigned char *ocsp_resp_der;
    int            ocsp_resp_der_len;
};

struct tls_ticket_key {
    unsigned char name[16];
    unsigned char hmac_key[32];
    unsigned char aes_key[32];
    time_t        created_at;
};

#define VORTEX_TLS_SESSION_CACHE_SIZE 1024

struct tls_session_entry {
    SSL_SESSION  *session;
    unsigned char id[SSL_MAX_SSL_SESSION_ID_LENGTH];
    unsigned int  id_len;
};

/* Global TLS state — one instance shared across workers (read-only after init) */
struct tls_ctx {
    OSSL_LIB_CTX          *libctx;
    OSSL_PROVIDER         *prov_default;
    struct tls_route_ctx   routes[VORTEX_MAX_ROUTES];
    int                    route_count;
    bool                   ktls_available;
    uint32_t               session_timeout;
    uint32_t               session_ticket_rotation;
    pthread_mutex_t        ticket_lock;
    pthread_mutex_t        ocsp_lock;
    pthread_mutex_t        session_lock;
    struct tls_ticket_key  current_ticket_key;
    struct tls_ticket_key  previous_ticket_key;
    bool                   have_current_ticket_key;
    bool                   have_previous_ticket_key;
    struct tls_session_entry session_cache[VORTEX_TLS_SESSION_CACHE_SIZE];
};

/* Initialise TLS — loads providers, creates per-route SSL_CTX, loads certs.
 * Must be called once from main thread before any worker starts. */
int  tls_init(struct tls_ctx *tls, const struct vortex_config *cfg);
void tls_destroy(struct tls_ctx *tls);

/* Perform blocking TLS handshake on accepted fd.
 * On success: returns SSL* with (possibly) kTLS installed.
 *             *route_idx_out is set from SNI lookup (or 0 for default).
 *             sni_out filled with negotiated hostname (may be empty).
 * On failure: returns NULL. Caller must close fd. */
SSL *tls_accept(struct tls_ctx *tls, int fd,
                int *route_idx_out, char *sni_out, size_t sni_max);

/* Check kTLS state after handshake */
bool tls_ktls_tx_active(SSL *ssl);
bool tls_ktls_rx_active(SSL *ssl);

/* Free SSL object — safe to call after kTLS install (kTLS state preserved on fd) */
void tls_ssl_free(SSL *ssl);

/* Generate self-signed cert+key for testing */
int tls_gen_self_signed(const char *cert_path, const char *key_path,
                        const char *cn);

/* Create a new SSL_CTX from PEM strings (used for cert hot-swap).
 * The returned ctx has the hostname set as app_data for SNI matching.
 * Caller must SSL_CTX_free() the old ctx when no longer needed. */
SSL_CTX *tls_create_ctx_from_pem(struct tls_ctx *tls,
                                  const char *cert_pem,
                                  const char *key_pem,
                                  const char *hostname);

/* Atomically replace the SSL_CTX for a route.
 * Thread-safe: new TLS connections see the new ctx immediately.
 * The old ctx is freed after a brief grace period (existing connections
 * that already have a handshake reference keep the old ctx alive via
 * OpenSSL's reference counting). */
int tls_rotate_cert(struct tls_ctx *tls, int route_idx,
                    const char *cert_pem, const char *key_pem);

#else /* !VORTEX_PHASE_TLS */

struct tls_ctx { int dummy; };

static inline int  tls_init(struct tls_ctx *t, const struct vortex_config *c)
    { (void)t; (void)c; return 0; }
static inline void tls_destroy(struct tls_ctx *t) { (void)t; }
static inline void *tls_accept(struct tls_ctx *t, int fd,
                                int *ri, char *s, size_t n)
    { (void)t; (void)fd; (void)ri; (void)s; (void)n; return NULL; }
static inline void tls_ssl_free(void *ssl) { (void)ssl; }

#endif /* VORTEX_PHASE_TLS */
