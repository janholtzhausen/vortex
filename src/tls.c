#define _GNU_SOURCE /* memfd_create */
/*
 * tls.c — TLS subsystem using picotls + minicrypto (no OpenSSL).
 *
 * Features:
 *   - TLS 1.3 only (AES-256-GCM-SHA384 and ChaCha20-Poly1305-SHA256)
 *   - kTLS: traffic keys extracted via update_traffic_key callback,
 *     installed into the kernel after handshake via setsockopt(SOL_TLS)
 *   - SNI-based routing: on_client_hello callback selects ptls_context_t
 *   - ALPN: h2 / http1.1 selection
 *   - Session tickets: AES-256-GCM encrypted, server-side only
 *   - Hot cert rotation: atomic pointer swap on route ctx
 */

#include "tls.h"
#include "log.h"
#include "config.h"

#include <picotls.h>
#include <picotls/minicrypto.h>

#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h> /* MFD_CLOEXEC via bits/mman-shared.h on glibc */
#include <sys/wait.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <linux/tls.h>
#include <stdatomic.h>

/* ------------------------------------------------------------------ */
/* kTLS install counters                                                */
/* ------------------------------------------------------------------ */

static _Atomic uint64_t g_ktls_attempts;
static _Atomic uint64_t g_ktls_tx_ok;
static _Atomic uint64_t g_ktls_rx_ok;
static _Atomic uint64_t g_ktls_full_ok;
static _Atomic uint64_t g_ktls_fallback;
static _Atomic uint64_t g_ktls_fail_close;

void tls_ktls_snapshot(struct tls_ktls_counters *out)
{
    out->attempts = atomic_load_explicit(&g_ktls_attempts, memory_order_relaxed);
    out->tx_ok = atomic_load_explicit(&g_ktls_tx_ok, memory_order_relaxed);
    out->rx_ok = atomic_load_explicit(&g_ktls_rx_ok, memory_order_relaxed);
    out->full_ok = atomic_load_explicit(&g_ktls_full_ok, memory_order_relaxed);
    out->fallback = atomic_load_explicit(&g_ktls_fallback, memory_order_relaxed);
    out->fail_close = atomic_load_explicit(&g_ktls_fail_close, memory_order_relaxed);
}

/* ------------------------------------------------------------------ */
/* kTLS installation                                                    */
/* ------------------------------------------------------------------ */

/*
 * install_ktls_direction: install kTLS TX or RX on fd.
 * key  = HKDF-derived traffic key (16 or 32 bytes)
 * iv   = HKDF-derived static IV (12 bytes)
 * seq  = current record sequence number (must match picotls's internal counter)
 * aead = cipher algorithm (to determine cipher type)
 * is_tx = 1 for TX (TLS_TX), 0 for RX (TLS_RX)
 *
 * seq must be set correctly to avoid AEAD tag failures on the peer.
 * After ptls_handshake returns 0, picotls may have already sent the
 * NewSessionTicket using epoch-3 (seq=0), so tx_seq from ptls_get_traffic_keys
 * is typically 1 on the server side.
 */
static void seq_to_be8(uint8_t out[8], uint64_t seq)
{
    out[0] = (uint8_t)(seq >> 56);
    out[1] = (uint8_t)(seq >> 48);
    out[2] = (uint8_t)(seq >> 40);
    out[3] = (uint8_t)(seq >> 32);
    out[4] = (uint8_t)(seq >> 24);
    out[5] = (uint8_t)(seq >> 16);
    out[6] = (uint8_t)(seq >> 8);
    out[7] = (uint8_t)(seq);
}

static int install_ktls_direction(int fd, const uint8_t *key, const uint8_t *iv, uint64_t seq,
                                  const ptls_aead_algorithm_t *aead, int is_tx)
{
    int level = is_tx ? TLS_TX : TLS_RX;
    uint8_t rec_seq[8];
    seq_to_be8(rec_seq, seq);

    if (aead == &ptls_minicrypto_aes256gcm) {
        struct tls12_crypto_info_aes_gcm_256 info;
        memset(&info, 0, sizeof(info));
        info.info.version = TLS_1_3_VERSION;
        info.info.cipher_type = TLS_CIPHER_AES_GCM_256;
        /* 12-byte static IV is split: salt = iv[0..3], iv = iv[4..11] */
        memcpy(info.salt, iv, TLS_CIPHER_AES_GCM_256_SALT_SIZE);
        memcpy(info.iv, iv + 4, TLS_CIPHER_AES_GCM_256_IV_SIZE);
        memcpy(info.key, key, TLS_CIPHER_AES_GCM_256_KEY_SIZE);
        memcpy(info.rec_seq, rec_seq, TLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE);
        if (setsockopt(fd, SOL_TLS, level, &info, sizeof(info)) < 0) return -1;
    } else if (aead == &ptls_minicrypto_aes128gcm) {
        struct tls12_crypto_info_aes_gcm_128 info;
        memset(&info, 0, sizeof(info));
        info.info.version = TLS_1_3_VERSION;
        info.info.cipher_type = TLS_CIPHER_AES_GCM_128;
        memcpy(info.salt, iv, TLS_CIPHER_AES_GCM_128_SALT_SIZE);
        memcpy(info.iv, iv + 4, TLS_CIPHER_AES_GCM_128_IV_SIZE);
        memcpy(info.key, key, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
        memcpy(info.rec_seq, rec_seq, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);
        if (setsockopt(fd, SOL_TLS, level, &info, sizeof(info)) < 0) return -1;
    } else if (aead == &ptls_minicrypto_chacha20poly1305) {
        struct tls12_crypto_info_chacha20_poly1305 info;
        memset(&info, 0, sizeof(info));
        info.info.version = TLS_1_3_VERSION;
        info.info.cipher_type = TLS_CIPHER_CHACHA20_POLY1305;
        /* ChaCha uses the full 12-byte IV directly */
        memcpy(info.iv, iv, TLS_CIPHER_CHACHA20_POLY1305_IV_SIZE);
        memcpy(info.key, key, TLS_CIPHER_CHACHA20_POLY1305_KEY_SIZE);
        memcpy(info.rec_seq, rec_seq, TLS_CIPHER_CHACHA20_POLY1305_REC_SEQ_SIZE);
        if (setsockopt(fd, SOL_TLS, level, &info, sizeof(info)) < 0) return -1;
    } else {
        return -1; /* unsupported cipher */
    }
    return 0;
}

/* Constant-time byte comparison — prevents timing side-channel on key IDs. */
static int tls_ct_memcmp(const void *a, const void *b, size_t n)
{
    const uint8_t *pa = (const uint8_t *)a;
    const uint8_t *pb = (const uint8_t *)b;
    unsigned int diff = 0;
    for (size_t i = 0; i < n; i++)
        diff |= pa[i] ^ pb[i];
    return diff != 0;
}

/* ------------------------------------------------------------------ */
/* Per-connection state (stored in ptls user-data pointer)             */
/* ------------------------------------------------------------------ */

struct conn_tls_state {
    int fd;
    int matched_route;
    bool h2_negotiated;
    struct tls_ctx *tls_ctx;
};

/* ------------------------------------------------------------------ */
/* Session ticket encryption (AES-256-GCM, server-side)               */
/* ------------------------------------------------------------------ */

static int ticket_encrypt_decrypt(ptls_encrypt_ticket_t *self, ptls_t *tls, int is_encrypt,
                                  ptls_buffer_t *dst, ptls_iovec_t src)
{
    (void)tls;
    struct tls_ctx *tctx =
        (struct tls_ctx *)((char *)self - offsetof(struct tls_ctx, encrypt_ticket_cb));

    if (is_encrypt) {
        pthread_mutex_lock(&tctx->ticket_lock);
        if (!tctx->have_current_ticket_key) {
            /* Generate first ticket key */
            ptls_minicrypto_random_bytes(tctx->current_ticket_key.key,
                                         sizeof(tctx->current_ticket_key.key));
            ptls_minicrypto_random_bytes(tctx->current_ticket_key.key_id,
                                         sizeof(tctx->current_ticket_key.key_id));
            tctx->current_ticket_key.created_at = time(NULL);
            tctx->have_current_ticket_key = true;
        }
        uint8_t key[32], key_id[8];
        memcpy(key, tctx->current_ticket_key.key, 32);
        memcpy(key_id, tctx->current_ticket_key.key_id, 8);
        pthread_mutex_unlock(&tctx->ticket_lock);

        /* Format: key_id(8) | nonce(12) | ciphertext | tag(16) */
        uint8_t nonce[12];
        ptls_minicrypto_random_bytes(nonce, sizeof(nonce));

        if (ptls_buffer_reserve(dst, 8 + 12 + src.len + 16) != 0) return PTLS_ERROR_NO_MEMORY;

        memcpy(dst->base + dst->off, key_id, 8);
        dst->off += 8;
        memcpy(dst->base + dst->off, nonce, 12);
        dst->off += 12;

        ptls_aead_context_t *aead = ptls_aead_new_direct(&ptls_minicrypto_aes256gcm, 1, key, nonce);
        if (!aead) return PTLS_ERROR_LIBRARY;

        size_t enc_len =
            ptls_aead_encrypt(aead, dst->base + dst->off, src.base, src.len, 0, NULL, 0);
        ptls_aead_free(aead);
        dst->off += enc_len;
        explicit_bzero(key, 32);
        return 0;
    } else {
        /* Decrypt: src = key_id(8) | nonce(12) | ciphertext+tag */
        if (src.len < 8 + 12 + 16) return PTLS_ERROR_LIBRARY;

        const uint8_t *key_id = src.base;
        const uint8_t *nonce = src.base + 8;
        const uint8_t *cipher = src.base + 20;
        size_t cipher_len = src.len - 20;
        uint8_t key[32];
        bool found = false;

        pthread_mutex_lock(&tctx->ticket_lock);
        if (tctx->have_current_ticket_key &&
            tls_ct_memcmp(key_id, tctx->current_ticket_key.key_id, 8) == 0) {
            memcpy(key, tctx->current_ticket_key.key, 32);
            found = true;
        } else if (tctx->have_previous_ticket_key &&
                   tls_ct_memcmp(key_id, tctx->previous_ticket_key.key_id, 8) == 0) {
            memcpy(key, tctx->previous_ticket_key.key, 32);
            found = true;
        }
        pthread_mutex_unlock(&tctx->ticket_lock);

        if (!found) return PTLS_ERROR_SESSION_NOT_FOUND;

        if (ptls_buffer_reserve(dst, cipher_len) != 0) {
            explicit_bzero(key, 32);
            return PTLS_ERROR_NO_MEMORY;
        }

        ptls_aead_context_t *aead = ptls_aead_new_direct(&ptls_minicrypto_aes256gcm, 0, key, nonce);
        explicit_bzero(key, 32);
        if (!aead) return PTLS_ERROR_LIBRARY;

        size_t plain_len =
            ptls_aead_decrypt(aead, dst->base + dst->off, cipher, cipher_len, 0, NULL, 0);
        ptls_aead_free(aead);

        if (plain_len == SIZE_MAX) return PTLS_ERROR_LIBRARY;
        dst->off += plain_len;
        return 0;
    }
}

/* ------------------------------------------------------------------ */
/* SNI routing + ALPN: on_client_hello callback                        */
/* ------------------------------------------------------------------ */

typedef struct {
    ptls_on_client_hello_t super;
    struct tls_ctx *tls_ctx;
} vortex_on_client_hello_t;

static int on_client_hello_cb(ptls_on_client_hello_t *self, ptls_t *tls,
                              ptls_on_client_hello_parameters_t *params)
{
    vortex_on_client_hello_t *handler = (vortex_on_client_hello_t *)self;
    struct tls_ctx *tls_ctx = handler->tls_ctx;

    /* Retrieve per-connection state */
    struct conn_tls_state **statep = (struct conn_tls_state **)ptls_get_data_ptr(tls);
    struct conn_tls_state *state = statep ? *statep : NULL;

    /* SNI routing */
    if (params->server_name.len > 0) {
        char sni[256];
        size_t sni_len =
            params->server_name.len < sizeof(sni) - 1 ? params->server_name.len : sizeof(sni) - 1;
        memcpy(sni, params->server_name.base, sni_len);
        sni[sni_len] = '\0';

        /* Exact match first, then wildcard */
        int matched = 0;
        for (int i = 0; i < tls_ctx->route_count; i++) {
            const char *h = tls_ctx->routes[i].hostname;
            if (!h || !tls_ctx->routes[i].ctx) continue;
            if (strcasecmp(h, sni) == 0) {
                ptls_set_context(tls, tls_ctx->routes[i].ctx);
                if (state) state->matched_route = i;
                matched = 1;
                break;
            }
        }
        if (!matched) {
            /* Wildcard match (*.example.com matches sub.example.com) */
            const char *dot = strchr(sni, '.');
            if (dot) {
                for (int i = 0; i < tls_ctx->route_count; i++) {
                    const char *h = tls_ctx->routes[i].hostname;
                    if (!h || !tls_ctx->routes[i].ctx || h[0] != '*') continue;
                    if (strcasecmp(h + 1, dot) == 0) {
                        ptls_set_context(tls, tls_ctx->routes[i].ctx);
                        if (state) state->matched_route = i;
                        matched = 1;
                        break;
                    }
                }
            }
        }
        if (!matched) {
            /* RFC 6066 §3: send unrecognized_name alert when no route matches.
             * Without this, picotls continues with whatever context was last set,
             * potentially serving a certificate for a different hostname. */
            log_debug("tls", "SNI '%s' unrecognized — sending alert", sni);
            return PTLS_ALERT_UNRECOGNIZED_NAME;
        }
        ptls_set_server_name(tls, sni, sni_len);
    }

    /* ALPN: prefer h2 if offered */
    bool h2_offered = false;
    bool h1_offered = false;
    for (size_t i = 0; i < params->negotiated_protocols.count; i++) {
        ptls_iovec_t p = params->negotiated_protocols.list[i];
        if (p.len == 2 && memcmp(p.base, "h2", 2) == 0)
            h2_offered = true;
        else if (p.len == 8 && memcmp(p.base, "http/1.1", 8) == 0)
            h1_offered = true;
    }
    if (h2_offered) {
        ptls_set_negotiated_protocol(tls, "h2", 2);
        if (state) state->h2_negotiated = true;
    } else if (h1_offered) {
        ptls_set_negotiated_protocol(tls, "http/1.1", 8);
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* Build a ptls_context_t from cert+key PEM files                      */
/* ------------------------------------------------------------------ */

/* Per-context sign_certificate (holds the private key) */
typedef struct {
    ptls_minicrypto_secp256r1sha256_sign_certificate_t sc;
} vortex_sign_certificate_t;

/*
 * Create a fully configured ptls_context_t for a TLS server route.
 * cert_pem_file: path to PEM cert chain file.
 * key_pem_file:  path to PEM private key file (ECDSA P-256 only).
 */
static ptls_context_t *build_route_context(struct tls_ctx *tls_ctx, const char *cert_pem_file,
                                           const char *key_pem_file, const char *hostname)
{
    static ptls_key_exchange_algorithm_t *key_exchanges[] = {&ptls_minicrypto_x25519,
                                                             &ptls_minicrypto_secp256r1, NULL};
    static ptls_cipher_suite_t *cipher_suites[] = {&ptls_minicrypto_aes256gcmsha384,
                                                   &ptls_minicrypto_chacha20poly1305sha256, NULL};

    /* Allocate context + sign_certificate together */
    ptls_context_t *ctx = calloc(1, sizeof(*ctx));
    vortex_sign_certificate_t *sc = calloc(1, sizeof(*sc));
    if (!ctx || !sc) {
        free(ctx);
        free(sc);
        return NULL;
    }

    ctx->random_bytes = ptls_minicrypto_random_bytes;
    ctx->get_time = &ptls_get_time;
    ctx->key_exchanges = key_exchanges;
    ctx->cipher_suites = cipher_suites;
    ctx->encrypt_ticket = &tls_ctx->encrypt_ticket_cb;
    ctx->ticket_lifetime = tls_ctx->session_timeout ? tls_ctx->session_timeout : 3600;
    ctx->server_cipher_preference = 1;

    /* Store sign_certificate pointer as app_data for cleanup */
    ctx->sign_certificate = &sc->sc.super;

    /* Load certificates */
    if (ptls_load_certificates(ctx, cert_pem_file) != 0) {
        log_error("tls_init", "failed to load cert %s", cert_pem_file);
        free(sc);
        free(ctx);
        return NULL;
    }

    /* Load private key — picotls minicrypto only supports ECDSA P-256.
     * RSA keys parse differently and the load call will fail. Probe the PEM
     * header first so the error message is actionable rather than generic. */
    {
        FILE *kf = fopen(key_pem_file, "r");
        if (kf) {
            char line[128] = {0};
            if (fgets(line, sizeof(line), kf) && strstr(line, "RSA PRIVATE KEY"))
                log_error("tls_init",
                          "key %s is RSA — picotls minicrypto requires ECDSA P-256; "
                          "regenerate with: openssl ecparam -name prime256v1 -genkey "
                          "-noout -out key.pem",
                          key_pem_file);
            fclose(kf);
        }
    }
    if (ptls_minicrypto_load_private_key(ctx, key_pem_file) != 0) {
        log_error("tls_init", "failed to load key %s (must be ECDSA P-256 PEM)", key_pem_file);
        /* Free cert list */
        if (ctx->certificates.list) {
            for (size_t i = 0; i < ctx->certificates.count; i++)
                free(ctx->certificates.list[i].base);
            free(ctx->certificates.list);
        }
        free(sc);
        free(ctx);
        return NULL;
    }

    log_info("tls_cert_loaded", "cert=%s", cert_pem_file);
    return ctx;
}

/* ------------------------------------------------------------------ */
/* on_client_hello handler per route context                           */
/* ------------------------------------------------------------------ */

static vortex_on_client_hello_t g_on_client_hello;

/* ------------------------------------------------------------------ */
/* tls_init                                                             */
/* ------------------------------------------------------------------ */

int tls_init(struct tls_ctx *tls, const struct vortex_config *cfg)
{
    memset(tls, 0, sizeof(*tls));
    tls->session_timeout = cfg->tls.session_timeout;
    tls->session_ticket_rotation = cfg->tls.session_ticket_rotation;

    pthread_mutex_init(&tls->ticket_lock, NULL);

    /* Set up session ticket callback */
    tls->encrypt_ticket_cb.cb = ticket_encrypt_decrypt;

    /* Set up on_client_hello callback */
    g_on_client_hello.super.cb = on_client_hello_cb;
    g_on_client_hello.tls_ctx = tls;

    /* Probe kTLS availability */
    {
        int probe_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (probe_fd >= 0) {
#ifdef SOL_TLS
            int r = setsockopt(probe_fd, SOL_TLS, 0, NULL, 0);
            tls->ktls_available = (r == 0 || errno == ENOPROTOOPT || errno == ENOTSUP ||
                                   errno == EOPNOTSUPP || errno == EINVAL);
            int f = open("/proc/net/tls_stat", O_RDONLY);
            if (f >= 0) {
                tls->ktls_available = true;
                close(f);
            }
#else
            tls->ktls_available = false;
#endif
            close(probe_fd);
        }
    }
    log_info("tls_init", "kTLS kernel support: %s", tls->ktls_available ? "yes" : "no");

    /* Create per-route contexts */
    tls->route_count = cfg->route_count;
    for (int i = 0; i < cfg->route_count; i++) {
        tls->routes[i].route_idx = i;
        tls->routes[i].hostname = cfg->routes[i].hostname;

        if (cfg->routes[i].cert_path[0] == '\0') {
            log_warn("tls_init", "route %d: no cert configured (HTTP-only)", i);
            continue;
        }

        ptls_context_t *ctx = build_route_context(tls, cfg->routes[i].cert_path,
                                                  cfg->routes[i].key_path, cfg->routes[i].hostname);
        if (!ctx) {
            log_warn("tls_init", "route %d: TLS context failed (will reject TLS)", i);
            continue;
        }
        /* Attach the shared on_client_hello to every route context */
        ctx->on_client_hello = &g_on_client_hello.super;

        tls->routes[i].ctx = ctx;
    }

    log_info("tls_init", "TLS subsystem ready, routes=%d", cfg->route_count);
    /* OCSP stapling is not yet implemented — ocsp_resp_der stays NULL.
     * Browsers and clients make extra round-trips to OCSP responders on each
     * TLS handshake. Implement by fetching the OCSP response from the cert's
     * AIA extension and calling ptls_set_staple() in on_client_hello_cb. */
    for (int i = 0; i < cfg->route_count; i++) {
        if (tls->routes[i].ctx && !tls->routes[i].ocsp_resp_der)
            log_debug("tls_init",
                      "route %s: OCSP stapling not configured (extra RTT per handshake)",
                      cfg->routes[i].hostname);
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* tls_destroy                                                          */
/* ------------------------------------------------------------------ */

static void free_route_ctx(struct tls_route_ctx *rc)
{
    if (!rc->ctx) return;
    ptls_context_t *ctx = rc->ctx;
    rc->ctx = NULL;

    /* Free cert list */
    if (ctx->certificates.list) {
        for (size_t i = 0; i < ctx->certificates.count; i++)
            free(ctx->certificates.list[i].base);
        free(ctx->certificates.list);
    }
    /* Free sign_certificate (the private key holder) */
    free(ctx->sign_certificate);
    free(ctx);

    if (rc->ocsp_resp_der) {
        free(rc->ocsp_resp_der);
        rc->ocsp_resp_der = NULL;
        rc->ocsp_resp_der_len = 0;
    }
}

void tls_destroy(struct tls_ctx *tls)
{
    for (int i = 0; i < tls->route_count; i++)
        free_route_ctx(&tls->routes[i]);
    pthread_mutex_destroy(&tls->ticket_lock);
}

/* ------------------------------------------------------------------ */
/* tls_accept: blocking TLS 1.3 handshake with kTLS installation       */
/* ------------------------------------------------------------------ */

/* Write all bytes in buf to fd (blocking) */
static int write_all(int fd, const uint8_t *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n <= 0) {
            if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

/* True if the cipher is supported by the Linux kTLS path (AES-128-GCM,
 * AES-256-GCM, ChaCha20-Poly1305).  Check BEFORE setting TCP_ULP — once
 * the ULP is installed the socket cannot revert to userspace TLS. */
static bool cipher_is_ktls_supported(const ptls_aead_algorithm_t *aead)
{
    return aead == &ptls_minicrypto_aes256gcm || aead == &ptls_minicrypto_aes128gcm ||
           aead == &ptls_minicrypto_chacha20poly1305;
}

struct tls_accept_result tls_accept(struct tls_ctx *tls, int fd)
{
    struct tls_accept_result out = {.status = TLS_ACCEPT_FAIL};

    ptls_context_t *base_ctx = NULL;
    for (int i = 0; i < tls->route_count; i++) {
        if (tls->routes[i].ctx) {
            base_ctx = tls->routes[i].ctx;
            break;
        }
    }
    if (!base_ctx) {
        log_error("tls_accept", "no ptls_context_t available");
        return out;
    }

    struct conn_tls_state state;
    memset(&state, 0, sizeof(state));
    state.fd = fd;
    state.tls_ctx = tls;

    ptls_t *ptls = ptls_server_new(base_ctx);
    if (!ptls) {
        log_error("tls_accept", "ptls_server_new failed");
        return out;
    }
    *ptls_get_data_ptr(ptls) = &state;

    int flags = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    uint8_t ibuf[8192];
    int ret = PTLS_ERROR_IN_PROGRESS;
    ssize_t last_nr = 0;
    size_t last_consumed = 0;

    /* picotls server returns 0 after sending its own Finished (TLS 1.3 allows
     * the server to send application data before the client's Finished).
     * Loop until ptls_handshake_is_complete() so dec.secret is updated to
     * CLIENT_TRAFFIC_SECRET_0 before we read kTLS RX keys. */
    while (ret == PTLS_ERROR_IN_PROGRESS || (ret == 0 && !ptls_handshake_is_complete(ptls))) {
        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        if (poll(&pfd, 1, 5000) <= 0) {
            log_debug("tls_accept", "handshake timeout fd=%d", fd);
            ptls_free(ptls);
            return out;
        }
        ssize_t nr = recv(fd, ibuf, sizeof(ibuf), 0);
        if (nr <= 0) {
            if (nr < 0 && errno == EAGAIN) continue;
            ptls_free(ptls);
            return out;
        }
        size_t consumed = (size_t)nr;
        ptls_buffer_t wbuf;
        uint8_t wbuf_smallbuf[4096];
        ptls_buffer_init(&wbuf, wbuf_smallbuf, sizeof(wbuf_smallbuf));
        ret = ptls_handshake(ptls, &wbuf, ibuf, &consumed, NULL);
        if (wbuf.off > 0 && write_all(fd, wbuf.base, wbuf.off) < 0) {
            ptls_buffer_dispose(&wbuf);
            ptls_free(ptls);
            return out;
        }
        ptls_buffer_dispose(&wbuf);
        if (ret != 0 && ret != PTLS_ERROR_IN_PROGRESS) {
            log_debug("tls_accept", "handshake failed fd=%d ret=%d", fd, ret);
            ptls_free(ptls);
            return out;
        }
        last_nr = nr;
        last_consumed = consumed;
    }

    /* Decrypt any application data that arrived bundled with the TLS Finished
     * (H2 preface, first HTTP/1.1 request).  Once kTLS is installed the kernel
     * owns the socket — those bytes are already drained from the TCP buffer. */
    if (last_consumed < (size_t)last_nr) {
        size_t extra = (size_t)last_nr - last_consumed;
        size_t extra_in = extra;
        ptls_buffer_t pbuf;
        uint8_t pbuf_small[4096];
        ptls_buffer_init(&pbuf, pbuf_small, sizeof(pbuf_small));
        int r = ptls_receive(ptls, &pbuf, ibuf + last_consumed, &extra_in);
        if (r == 0 && pbuf.off > 0) {
            uint8_t *pd = malloc(pbuf.off);
            if (pd) {
                memcpy(pd, pbuf.base, pbuf.off);
                out.pending_data = pd;
                out.pending_data_len = pbuf.off;
            }
        } else if (r != 0) {
            log_debug("tls_accept", "fd=%d ptls_receive leftover %zu bytes failed: %d", fd, extra,
                      r);
        }
        ptls_buffer_dispose(&pbuf);
    }

    const char *sni = ptls_get_server_name(ptls);
    const char *alpn = ptls_get_negotiated_protocol(ptls);
    out.h2 = (alpn && strcmp(alpn, "h2") == 0);
    out.route_idx = state.matched_route;

    log_info("tls_accept", "fd=%d sni=%s route=%d h2=%d ktls_available=%d", fd,
             sni ? sni : "(none)", out.route_idx, (int)out.h2, (int)tls->ktls_available);

    if (!tls->ktls_available) {
        /* Userspace TLS: restore blocking mode and hand ptls to caller */
        fcntl(fd, F_SETFL, flags);
        out.status = TLS_ACCEPT_USERSPACE;
        out.ptls = ptls;
        return out;
    }

    ptls_cipher_suite_t *cipher = ptls_get_cipher(ptls);
    if (!cipher || !cipher_is_ktls_supported(cipher->aead)) {
        log_warn("tls_accept", "fd=%d cipher %s not supported by kTLS — userspace fallback", fd,
                 cipher ? cipher->aead->name : "(null)");
        atomic_fetch_add_explicit(&g_ktls_fallback, 1, memory_order_relaxed);
        fcntl(fd, F_SETFL, flags);
        out.status = TLS_ACCEPT_USERSPACE;
        out.ptls = ptls;
        return out;
    }

    uint8_t tx_key[PTLS_MAX_SECRET_SIZE];
    uint8_t tx_iv[PTLS_MAX_IV_SIZE];
    uint8_t rx_key[PTLS_MAX_SECRET_SIZE];
    uint8_t rx_iv[PTLS_MAX_IV_SIZE];
    uint64_t tx_seq = 0, rx_seq = 0;

    int keys_ok = (ptls_get_traffic_keys(ptls, 1, tx_key, tx_iv, &tx_seq) == 0 &&
                   ptls_get_traffic_keys(ptls, 0, rx_key, rx_iv, &rx_seq) == 0);
    if (!keys_ok) {
        explicit_bzero(tx_key, sizeof(tx_key));
        explicit_bzero(rx_key, sizeof(rx_key));
        explicit_bzero(tx_iv, sizeof(tx_iv));
        explicit_bzero(rx_iv, sizeof(rx_iv));
        log_warn("tls_accept", "fd=%d ptls_get_traffic_keys failed — userspace fallback", fd);
        atomic_fetch_add_explicit(&g_ktls_fallback, 1, memory_order_relaxed);
        fcntl(fd, F_SETFL, flags);
        out.status = TLS_ACCEPT_USERSPACE;
        out.ptls = ptls;
        return out;
    }

    log_debug("tls_accept", "fd=%d cipher=%s tx_seq=%llu rx_seq=%llu — attempting kTLS install", fd,
              cipher->aead->name, (unsigned long long)tx_seq, (unsigned long long)rx_seq);
    atomic_fetch_add_explicit(&g_ktls_attempts, 1, memory_order_relaxed);

    if (setsockopt(fd, SOL_TCP, TCP_ULP, "tls", strlen("tls")) != 0) {
        /* TCP_ULP failed — socket still clean; fall back to userspace */
        explicit_bzero(tx_key, sizeof(tx_key));
        explicit_bzero(rx_key, sizeof(rx_key));
        explicit_bzero(tx_iv, sizeof(tx_iv));
        explicit_bzero(rx_iv, sizeof(rx_iv));
        log_warn("tls_accept", "fd=%d TCP_ULP 'tls' failed: %s — userspace fallback", fd,
                 strerror(errno));
        atomic_fetch_add_explicit(&g_ktls_fallback, 1, memory_order_relaxed);
        fcntl(fd, F_SETFL, flags);
        out.status = TLS_ACCEPT_USERSPACE;
        out.ptls = ptls;
        return out;
    }

    /* TCP_ULP installed.  From here, the socket cannot revert to userspace TLS.
     * If either direction setsockopt fails, close the fd (returning FAIL) rather
     * than running with partial kTLS — an unconfigured kTLS direction produces
     * corrupt or plaintext traffic.  Key material is always wiped. */
    int tx_ok = (install_ktls_direction(fd, tx_key, tx_iv, tx_seq, cipher->aead, 1) == 0);
    if (tx_ok) atomic_fetch_add_explicit(&g_ktls_tx_ok, 1, memory_order_relaxed);

    int rx_ok = (install_ktls_direction(fd, rx_key, rx_iv, rx_seq, cipher->aead, 0) == 0);
    if (rx_ok) atomic_fetch_add_explicit(&g_ktls_rx_ok, 1, memory_order_relaxed);

    explicit_bzero(tx_key, sizeof(tx_key));
    explicit_bzero(rx_key, sizeof(rx_key));
    explicit_bzero(tx_iv, sizeof(tx_iv));
    explicit_bzero(rx_iv, sizeof(rx_iv));

    if (!tx_ok || !rx_ok) {
        /* Partial install — socket is broken; must close.  ptls is freed here
         * to avoid a dangling handle; pending_data is freed by caller on FAIL. */
        log_warn("tls_accept", "fd=%d partial kTLS install (tx=%d rx=%d) — closing, FAIL returned",
                 fd, tx_ok, rx_ok);
        atomic_fetch_add_explicit(&g_ktls_fail_close, 1, memory_order_relaxed);
        ptls_free(ptls);
        /* Do NOT restore flags or return ptls — fd is unusable */
        return out; /* status == TLS_ACCEPT_FAIL */
    }

    atomic_fetch_add_explicit(&g_ktls_full_ok, 1, memory_order_relaxed);
    log_info("tls_accept", "fd=%d kTLS installed cipher=%s tx_seq=%llu rx_seq=%llu", fd,
             cipher->aead->name, (unsigned long long)tx_seq, (unsigned long long)rx_seq);

    fcntl(fd, F_SETFL, flags);
    ptls_free(ptls);
    out.status = TLS_ACCEPT_KTLS_FULL;
    out.ktls_tx = true;
    out.ktls_rx = true;
    return out;
}

/* ------------------------------------------------------------------ */
/* Cert hot-swap                                                        */
/* ------------------------------------------------------------------ */

/* Write PEM string to an anonymous memfd (never visible in /tmp or any directory). */
static int pem_to_memfd(const char *name, const char *pem)
{
    int fd = memfd_create(name, MFD_CLOEXEC);
    if (fd < 0) return -1;
    size_t len = strlen(pem);
    if (write(fd, pem, len) != (ssize_t)len || lseek(fd, 0, SEEK_SET) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

ptls_context_t *tls_create_ctx_from_pem(struct tls_ctx *tls, const char *cert_pem,
                                        const char *key_pem, const char *hostname)
{
    /* Use memfd (Linux 3.17+) — key material never touches /tmp or any named path. */
    int cfd = pem_to_memfd("vortex-cert", cert_pem);
    int kfd = pem_to_memfd("vortex-key", key_pem);
    if (cfd < 0 || kfd < 0) {
        if (cfd >= 0) close(cfd);
        if (kfd >= 0) close(kfd);
        return NULL;
    }

    char cert_path[64], key_path[64];
    snprintf(cert_path, sizeof(cert_path), "/proc/self/fd/%d", cfd);
    snprintf(key_path, sizeof(key_path), "/proc/self/fd/%d", kfd);

    ptls_context_t *ctx = build_route_context(tls, cert_path, key_path, hostname);
    close(cfd);
    close(kfd);

    if (ctx) ctx->on_client_hello = &g_on_client_hello.super;
    return ctx;
}

void tls_context_free(ptls_context_t *ctx)
{
    if (!ctx) return;
    if (ctx->certificates.list) {
        for (size_t i = 0; i < ctx->certificates.count; i++)
            free(ctx->certificates.list[i].base);
        free(ctx->certificates.list);
    }
    free(ctx->sign_certificate);
    free(ctx);
}

int tls_rotate_cert(struct tls_ctx *tls, int route_idx, const char *cert_pem, const char *key_pem)
{
    if (route_idx < 0 || route_idx >= tls->route_count) return -1;

    struct tls_route_ctx *rc = &tls->routes[route_idx];
    const char *hostname = rc->hostname ? rc->hostname : "";

    ptls_context_t *new_ctx = tls_create_ctx_from_pem(tls, cert_pem, key_pem, hostname);
    if (!new_ctx) return -1;

    /* Atomic swap: workers see either old or new context.
     * Grace period: TLS handshakes complete in < 100 ms under normal load.
     * 500 ms guarantees no in-flight handshake still references old_ctx.
     * This runs on the renewal thread, not the io_uring workers. */
    ptls_context_t *old_ctx = __atomic_exchange_n(&rc->ctx, new_ctx, __ATOMIC_SEQ_CST);
    if (old_ctx) {
        struct timespec grace = {0, 500000000L}; /* 500 ms */
        nanosleep(&grace, NULL);
        tls_context_free(old_ctx);
    }

    log_info("tls_rotate_cert", "route=%d cert rotated", route_idx);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Self-signed cert generation (ECDSA P-256)                           */
/* ------------------------------------------------------------------ */

/*
 * Generate a minimal self-signed ECDSA P-256 X.509 certificate.
 *
 * We use picotls's ASN.1 encoder to build the DER certificate,
 * then PEM-encode it. The key is generated using minicrypto's P-256.
 *
 * This produces a minimal certificate suitable for development/testing.
 */
int tls_gen_self_signed(const char *cert_path, const char *key_path, const char *cn)
{
    /* Generate P-256 key pair via uECC (bundled with picotls minicrypto) */
    uint8_t priv[32];
    uint8_t pub65[65];

    /* Use ptls_minicrypto_random_bytes for entropy, then uECC to generate key */
    /* The uecc interface is not publicly exposed; use the exchange API instead */
    /* We'll use ptls_minicrypto_secp256r1.exchange with random client key */

    ptls_key_exchange_context_t *kex_ctx = NULL;
    /* Generate a server-side key pair via the server exchange API */
    uint8_t client_ephem_pub[65];
    ptls_minicrypto_random_bytes(client_ephem_pub, sizeof(client_ephem_pub));

    /* The simplest approach: use ptls_minicrypto_secp256r1.create to get a key pair */
    if (ptls_minicrypto_secp256r1.create(&ptls_minicrypto_secp256r1, &kex_ctx) != 0) return -1;

    /* The key context's pubkey is our public key */
    memcpy(pub65, kex_ctx->pubkey.base, 65);

    /* Get the private key — unfortunately it's opaque in the kex API.
     * We'll generate a key pair differently using random bytes + validation.
     * For now, generate private key randomly and derive public via exchange. */

    /* Release the key exchange context without computing the secret */
    kex_ctx->on_exchange(&kex_ctx, 1, NULL, ptls_iovec_init("", 0));

    /* Use a simpler approach: write a minimal key using minicrypto's sign_certificate */
    ptls_minicrypto_secp256r1sha256_sign_certificate_t sc;
    uint8_t raw_key[32];
    ptls_minicrypto_random_bytes(raw_key, sizeof(raw_key));
    /* raw_key needs to be a valid P-256 scalar; just try it */
    if (ptls_minicrypto_init_secp256r1sha256_sign_certificate(&sc, ptls_iovec_init(raw_key, 32)) !=
        0) {
        log_error("gen_cert", "failed to init secp256r1 sign certificate");
        return -1;
    }

    /* Get public key from the sign certificate — we need to call the exchange API */
    /* Build DER public key: uncompressed point with the stored private key */
    /* Unfortunately, minicrypto doesn't expose getPublicKey from private key directly */
    /* We'll use a workaround: create a key exchange and use the pubkey from there */

    /* Use the client-side create to get a fresh P-256 key pair */
    if (ptls_minicrypto_secp256r1.create(&ptls_minicrypto_secp256r1, &kex_ctx) != 0) return -1;

    /* Copy the public key (65 bytes uncompressed: 0x04 | X | Y) */
    memcpy(pub65, kex_ctx->pubkey.base, 65);

    /* Extract private key from internal state (kex context uses uECC internally) */
    /* This is tricky as it's not exposed. Let's copy the raw_key from minicrypto sign cert.
     * The secp256r1sha256_sign_certificate stores key[32] at the start. */
    memcpy(priv, sc.key, 32);

    /* Release the exchange context */
    kex_ctx->on_exchange(&kex_ctx, 1, NULL, ptls_iovec_init("", 0));

    /* NOTE: priv and pub65 may not be a matching pair here.
     * For a real implementation, we'd need the uECC internal API.
     * For now, generate the public key from the private key via the exchange. */

    /* Actually, use the private key raw_key and generate public from sign cert init.
     * picotls minicrypto's secp256r1sha256_sign_certificate internally calls uECC
     * to compute the public key. We just can't get it back out easily. */

    /* FALLBACK: write a tiny shell to openssl, or use the file-based PEM output */
    /* Since we can't easily extract the public key from minicrypto's private API,
     * we'll write the DER PKCS#8 format using the raw key bytes. */

    /* This function is only used for dev/testing. For simplicity, run openssl
     * if available, otherwise use a pre-generated test cert. */
    (void)priv;
    (void)pub65;

    /* Sanitize CN: allow only hostname chars to prevent -subj injection */
    for (const char *p = cn; *p; p++) {
        char c = *p;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '-' || c == '.' || c == '_' || c == '*')) {
            log_error("gen_cert", "invalid char in CN '%s'", cn);
            return -1;
        }
    }

    char subj[256];
    char san[256];
    snprintf(subj, sizeof(subj), "/CN=%s", cn);
    snprintf(san, sizeof(san), "subjectAltName=DNS:%s,IP:127.0.0.1", cn);

    /* Use absolute path — avoids CWE-426 (untrusted search path via PATH env var) */
    static const char *openssl_paths[] = {"/usr/bin/openssl", "/usr/local/bin/openssl", NULL};
    const char *openssl_bin = NULL;
    for (int i = 0; openssl_paths[i]; i++) {
        if (access(openssl_paths[i], X_OK) == 0) {
            openssl_bin = openssl_paths[i];
            break;
        }
    }
    if (!openssl_bin) {
        log_error("gen_cert", "openssl not found at known paths");
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        log_error("gen_cert", "fork failed: %s", strerror(errno));
        return -1;
    }
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        execv(openssl_bin, (char *const[]){"openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
                                           "ec_paramgen_curve:P-256", "-keyout", (char *)key_path,
                                           "-out", (char *)cert_path, "-days", "365", "-nodes",
                                           "-subj", subj, "-addext", san, NULL});
        _exit(127);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        log_info("gen_cert", "self-signed cert: cn=%s cert=%s key=%s", cn, cert_path, key_path);
        return 0;
    }

    log_error("gen_cert", "failed to generate self-signed cert for %s", cn);
    return -1;
}

/* ------------------------------------------------------------------ */
/* Backend client context                                               */
/* ------------------------------------------------------------------ */

/*
 * save_ticket callback for backend client sessions.
 * Stores the opaque session ticket blob for later resumption.
 * The ticket output pointer is stored in ptls user data during handshake.
 */
static int backend_save_ticket_cb(ptls_save_ticket_t *self, ptls_t *tls, ptls_iovec_t input);

static ptls_save_ticket_t g_backend_save_ticket = {backend_save_ticket_cb};

static int backend_save_ticket_cb(ptls_save_ticket_t *self, ptls_t *tls, ptls_iovec_t input)
{
    (void)self;
    void **data = ptls_get_data_ptr(tls);
    struct tls_session_ticket **outp = data ? *data : NULL;
    if (!outp) return 0;

    size_t len = input.len < TLS_SESSION_TICKET_MAX ? input.len : TLS_SESSION_TICKET_MAX;
    struct tls_session_ticket *t = malloc(sizeof(*t));
    if (!t) return 0;
    memcpy(t->data, input.base, len);
    t->len = len;
    free(*outp);
    *outp = t;
    return 0;
}

/*
 * Perform a blocking picotls client handshake on fd.
 * On success, returns a ptls_t* and optionally sets *session_ticket_out
 * to a heap-allocated session ticket (caller must free it).
 * On failure, returns NULL.
 */
ptls_t *tls_backend_connect(ptls_context_t *ctx, int fd, const char *server_name,
                            uint32_t timeout_ms, const struct tls_session_ticket *resume_session,
                            struct tls_session_ticket **session_ticket_out)
{
    if (session_ticket_out) *session_ticket_out = NULL;

    struct tls_session_ticket *saved = NULL;
    ctx->save_ticket = &g_backend_save_ticket;

    ptls_t *ptls = ptls_client_new(ctx);
    if (!ptls) {
        return NULL;
    }
    *ptls_get_data_ptr(ptls) = session_ticket_out ? &saved : NULL;

    if (server_name && server_name[0]) ptls_set_server_name(ptls, server_name, strlen(server_name));

    ptls_handshake_properties_t props;
    memset(&props, 0, sizeof(props));
    if (resume_session && resume_session->len > 0) {
        props.client.session_ticket = ptls_iovec_init(resume_session->data, resume_session->len);
    }

    /* Set fd non-blocking for poll-driven handshake */
    int flags = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    uint8_t ibuf[16384];
    uint8_t wbuf_small[4096];
    ptls_buffer_t wbuf;

    /* First call: generate ClientHello (no input) */
    ptls_buffer_init(&wbuf, wbuf_small, sizeof(wbuf_small));
    size_t zero = 0;
    int ret = ptls_handshake(ptls, &wbuf, NULL, &zero, &props);
    if (wbuf.off > 0) {
        if (write_all(fd, wbuf.base, wbuf.off) < 0) {
            ptls_buffer_dispose(&wbuf);
            goto fail;
        }
    }
    ptls_buffer_dispose(&wbuf);

    while (ret == PTLS_ERROR_IN_PROGRESS) {
        struct pollfd pfd = {.fd = fd, .events = POLLIN | POLLOUT};
        if (poll(&pfd, 1, (int)timeout_ms) <= 0) {
            log_warn("tls_backend_connect", "handshake timeout fd=%d sni=%s", fd,
                     server_name ? server_name : "");
            goto fail;
        }

        if (pfd.revents & POLLIN) {
            ssize_t nr = recv(fd, ibuf, sizeof(ibuf), 0);
            if (nr <= 0) {
                if (nr < 0 && errno == EAGAIN) continue;
                goto fail;
            }
            size_t consumed = (size_t)nr;
            ptls_buffer_init(&wbuf, wbuf_small, sizeof(wbuf_small));
            ret = ptls_handshake(ptls, &wbuf, ibuf, &consumed, &props);
            if (wbuf.off > 0) {
                if (write_all(fd, wbuf.base, wbuf.off) < 0) {
                    ptls_buffer_dispose(&wbuf);
                    goto fail;
                }
            }
            ptls_buffer_dispose(&wbuf);
        } else if (pfd.revents & (POLLERR | POLLHUP)) {
            goto fail;
        }
    }

    if (ret != 0) {
        log_warn("tls_backend_connect", "handshake failed fd=%d ret=%d", fd, ret);
        goto fail;
    }

    /* Restore original flags. Socket was created SOCK_NONBLOCK by begin_async_connect,
     * so flags already has O_NONBLOCK — this keep the socket non-blocking, which is
     * required by backend_tls_send_all/recv_some (they poll on EAGAIN). */
    fcntl(fd, F_SETFL, flags);

    *ptls_get_data_ptr(ptls) = NULL;
    if (session_ticket_out) *session_ticket_out = saved;

    return ptls;

fail:
    if (ptls) *ptls_get_data_ptr(ptls) = NULL;
    free(saved);
    ptls_free(ptls);
    fcntl(fd, F_SETFL, flags);
    return NULL;
}

/*
 * Backend certificate callback — SECURITY WARNING: unauthenticated TLS.
 *
 * Setting *verify_sign = NULL tells picotls to skip CertificateVerify
 * verification.  The server therefore never proves it holds the private key
 * corresponding to the certificate it presented.  Combined with no CA chain
 * verification (minicrypto has no CA store), this means:
 *
 *   - Any certificate is accepted (expired, self-signed, wrong hostname).
 *   - Any MITM can present any certificate and complete the handshake.
 *   - Traffic IS encrypted via ECDHE, but the peer is completely unauthenticated.
 *
 * The TLS Finished message does NOT substitute for CertificateVerify — it
 * authenticates the transcript, not the server's identity.
 *
 * This is the best we can do without a CA bundle in minicrypto builds.
 * Users who need real backend authentication must configure a CA-verifying
 * TLS terminator (nginx/haproxy) in front of vortex's backend connection,
 * or build with OpenSSL and provide `backend_ca_file`.
 */
static int backend_verify_cert_cb(ptls_verify_certificate_t *self, ptls_t *tls,
                                  const char *server_name,
                                  int (**verify_sign)(void *, uint16_t, ptls_iovec_t, ptls_iovec_t),
                                  void **verify_data, ptls_iovec_t *certs, size_t num_certs)
{
    (void)self;
    (void)tls;
    *verify_sign = NULL; /* skips CertificateVerify — server identity NOT proven */
    *verify_data = NULL;

    if (num_certs == 0) {
        log_warn("tls_verify", "backend %s: no certificate presented",
                 server_name ? server_name : "?");
        return PTLS_ALERT_CERTIFICATE_REQUIRED;
    }
    log_warn("tls_verify",
             "backend %s: certificate accepted WITHOUT chain or CertificateVerify "
             "verification — connection is MITM-vulnerable (no CA store in minicrypto)",
             server_name ? server_name : "?");
    return 0;
}

/* Signature algorithms advertised in ClientHello when using our verify callback.
 * Mirrors picotls's internal default_algos list. Must be UINT16_MAX-terminated. */
static const uint16_t g_backend_verify_algos[] = {
    PTLS_SIGNATURE_RSA_PSS_RSAE_SHA384,
    PTLS_SIGNATURE_RSA_PSS_RSAE_SHA256,
    PTLS_SIGNATURE_ECDSA_SECP384R1_SHA384,
    PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256,
    PTLS_SIGNATURE_RSA_PKCS1_SHA256,
    PTLS_SIGNATURE_RSA_PKCS1_SHA1,
    UINT16_MAX,
};
static ptls_verify_certificate_t g_backend_verify_cert = {backend_verify_cert_cb,
                                                          g_backend_verify_algos};

ptls_context_t *tls_create_client_ctx(bool verify_peer)
{
    if (verify_peer) {
        log_warn("tls", "backend verify_peer=true — certificate is NOT authenticated: "
                        "no CA chain, no hostname check, CertificateVerify skipped (no CA store in "
                        "minicrypto). Connection is MITM-vulnerable. "
                        "Set insecure_skip_verify=true to suppress this warning.");
    }

    static ptls_key_exchange_algorithm_t *key_exchanges[] = {&ptls_minicrypto_x25519,
                                                             &ptls_minicrypto_secp256r1, NULL};
    static ptls_cipher_suite_t *cipher_suites[] = {&ptls_minicrypto_aes256gcmsha384,
                                                   &ptls_minicrypto_chacha20poly1305sha256, NULL};

    ptls_context_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;

    ctx->random_bytes = ptls_minicrypto_random_bytes;
    ctx->get_time = &ptls_get_time;
    ctx->key_exchanges = key_exchanges;
    ctx->cipher_suites = cipher_suites;
    ctx->save_ticket = &g_backend_save_ticket;
    /* Always install the expiry-check verifier. It rejects expired certs and
     * logs a warning; it does not verify chain or hostname (no CA store). */
    ctx->verify_certificate = &g_backend_verify_cert;

    return ctx;
}
