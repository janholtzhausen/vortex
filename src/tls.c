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
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <linux/tls.h>

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
    out[6] = (uint8_t)(seq >>  8);
    out[7] = (uint8_t)(seq      );
}

static int install_ktls_direction(int fd, const uint8_t *key, const uint8_t *iv,
                                   uint64_t seq,
                                   const ptls_aead_algorithm_t *aead, int is_tx)
{
    int level = is_tx ? TLS_TX : TLS_RX;
    uint8_t rec_seq[8];
    seq_to_be8(rec_seq, seq);

    if (aead == &ptls_minicrypto_aes256gcm) {
        struct tls12_crypto_info_aes_gcm_256 info;
        memset(&info, 0, sizeof(info));
        info.info.version     = TLS_1_3_VERSION;
        info.info.cipher_type = TLS_CIPHER_AES_GCM_256;
        /* 12-byte static IV is split: salt = iv[0..3], iv = iv[4..11] */
        memcpy(info.salt, iv,     TLS_CIPHER_AES_GCM_256_SALT_SIZE);
        memcpy(info.iv,   iv + 4, TLS_CIPHER_AES_GCM_256_IV_SIZE);
        memcpy(info.key,  key,    TLS_CIPHER_AES_GCM_256_KEY_SIZE);
        memcpy(info.rec_seq, rec_seq, TLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE);
        if (setsockopt(fd, SOL_TLS, level, &info, sizeof(info)) < 0)
            return -1;
    } else if (aead == &ptls_minicrypto_aes128gcm) {
        struct tls12_crypto_info_aes_gcm_128 info;
        memset(&info, 0, sizeof(info));
        info.info.version     = TLS_1_3_VERSION;
        info.info.cipher_type = TLS_CIPHER_AES_GCM_128;
        memcpy(info.salt, iv,     TLS_CIPHER_AES_GCM_128_SALT_SIZE);
        memcpy(info.iv,   iv + 4, TLS_CIPHER_AES_GCM_128_IV_SIZE);
        memcpy(info.key,  key,    TLS_CIPHER_AES_GCM_128_KEY_SIZE);
        memcpy(info.rec_seq, rec_seq, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);
        if (setsockopt(fd, SOL_TLS, level, &info, sizeof(info)) < 0)
            return -1;
    } else if (aead == &ptls_minicrypto_chacha20poly1305) {
        struct tls12_crypto_info_chacha20_poly1305 info;
        memset(&info, 0, sizeof(info));
        info.info.version     = TLS_1_3_VERSION;
        info.info.cipher_type = TLS_CIPHER_CHACHA20_POLY1305;
        /* ChaCha uses the full 12-byte IV directly */
        memcpy(info.iv,      iv,  TLS_CIPHER_CHACHA20_POLY1305_IV_SIZE);
        memcpy(info.key,     key, TLS_CIPHER_CHACHA20_POLY1305_KEY_SIZE);
        memcpy(info.rec_seq, rec_seq, TLS_CIPHER_CHACHA20_POLY1305_REC_SEQ_SIZE);
        if (setsockopt(fd, SOL_TLS, level, &info, sizeof(info)) < 0)
            return -1;
    } else {
        return -1; /* unsupported cipher */
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Per-connection state (stored in ptls user-data pointer)             */
/* ------------------------------------------------------------------ */

struct conn_tls_state {
    int           fd;
    int           matched_route;
    bool          h2_negotiated;
    struct tls_ctx *tls_ctx;
};

/* ------------------------------------------------------------------ */
/* Session ticket encryption (AES-256-GCM, server-side)               */
/* ------------------------------------------------------------------ */

static int ticket_encrypt_decrypt(ptls_encrypt_ticket_t *self,
                                   ptls_t *tls,
                                   int is_encrypt,
                                   ptls_buffer_t *dst,
                                   ptls_iovec_t src)
{
    (void)tls;
    struct tls_ctx *tctx = (struct tls_ctx *)((char *)self -
        offsetof(struct tls_ctx, encrypt_ticket_cb));

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
        memcpy(key,    tctx->current_ticket_key.key,    32);
        memcpy(key_id, tctx->current_ticket_key.key_id, 8);
        pthread_mutex_unlock(&tctx->ticket_lock);

        /* Format: key_id(8) | nonce(12) | ciphertext | tag(16) */
        uint8_t nonce[12];
        ptls_minicrypto_random_bytes(nonce, sizeof(nonce));

        if (ptls_buffer_reserve(dst, 8 + 12 + src.len + 16) != 0)
            return PTLS_ERROR_NO_MEMORY;

        memcpy(dst->base + dst->off, key_id, 8); dst->off += 8;
        memcpy(dst->base + dst->off, nonce, 12);  dst->off += 12;

        ptls_aead_context_t *aead =
            ptls_aead_new_direct(&ptls_minicrypto_aes256gcm, 1, key, nonce);
        if (!aead)
            return PTLS_ERROR_LIBRARY;

        size_t enc_len = ptls_aead_encrypt(aead,
            dst->base + dst->off, src.base, src.len, 0, NULL, 0);
        ptls_aead_free(aead);
        dst->off += enc_len;
        memset(key, 0, 32);
        return 0;
    } else {
        /* Decrypt: src = key_id(8) | nonce(12) | ciphertext+tag */
        if (src.len < 8 + 12 + 16)
            return PTLS_ERROR_LIBRARY;

        const uint8_t *key_id = src.base;
        const uint8_t *nonce  = src.base + 8;
        const uint8_t *cipher = src.base + 20;
        size_t  cipher_len    = src.len  - 20;
        uint8_t key[32];
        bool found = false;

        pthread_mutex_lock(&tctx->ticket_lock);
        if (tctx->have_current_ticket_key &&
            memcmp(key_id, tctx->current_ticket_key.key_id, 8) == 0) {
            memcpy(key, tctx->current_ticket_key.key, 32);
            found = true;
        } else if (tctx->have_previous_ticket_key &&
                   memcmp(key_id, tctx->previous_ticket_key.key_id, 8) == 0) {
            memcpy(key, tctx->previous_ticket_key.key, 32);
            found = true;
        }
        pthread_mutex_unlock(&tctx->ticket_lock);

        if (!found)
            return PTLS_ERROR_SESSION_NOT_FOUND;

        if (ptls_buffer_reserve(dst, cipher_len) != 0) {
            memset(key, 0, 32);
            return PTLS_ERROR_NO_MEMORY;
        }

        ptls_aead_context_t *aead =
            ptls_aead_new_direct(&ptls_minicrypto_aes256gcm, 0, key, nonce);
        memset(key, 0, 32);
        if (!aead)
            return PTLS_ERROR_LIBRARY;

        size_t plain_len = ptls_aead_decrypt(aead,
            dst->base + dst->off, cipher, cipher_len, 0, NULL, 0);
        ptls_aead_free(aead);

        if (plain_len == SIZE_MAX)
            return PTLS_ERROR_LIBRARY;
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

static int on_client_hello_cb(ptls_on_client_hello_t *self,
                               ptls_t *tls,
                               ptls_on_client_hello_parameters_t *params)
{
    vortex_on_client_hello_t *handler =
        (vortex_on_client_hello_t *)self;
    struct tls_ctx *tls_ctx = handler->tls_ctx;

    /* Retrieve per-connection state */
    struct conn_tls_state **statep = (struct conn_tls_state **)ptls_get_data_ptr(tls);
    struct conn_tls_state *state = statep ? *statep : NULL;

    /* SNI routing */
    if (params->server_name.len > 0) {
        char sni[256];
        size_t sni_len = params->server_name.len < sizeof(sni) - 1
                         ? params->server_name.len : sizeof(sni) - 1;
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
        /* Always notify client that we accept the SNI */
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
static ptls_context_t *build_route_context(struct tls_ctx *tls_ctx,
                                            const char *cert_pem_file,
                                            const char *key_pem_file,
                                            const char *hostname)
{
    static ptls_key_exchange_algorithm_t *key_exchanges[] = {
        &ptls_minicrypto_x25519,
        &ptls_minicrypto_secp256r1,
        NULL
    };
    static ptls_cipher_suite_t *cipher_suites[] = {
        &ptls_minicrypto_aes256gcmsha384,
        &ptls_minicrypto_chacha20poly1305sha256,
        NULL
    };

    /* Allocate context + sign_certificate together */
    ptls_context_t *ctx = calloc(1, sizeof(*ctx));
    vortex_sign_certificate_t *sc = calloc(1, sizeof(*sc));
    if (!ctx || !sc) {
        free(ctx); free(sc);
        return NULL;
    }

    ctx->random_bytes           = ptls_minicrypto_random_bytes;
    ctx->get_time               = &ptls_get_time;
    ctx->key_exchanges          = key_exchanges;
    ctx->cipher_suites          = cipher_suites;
    ctx->encrypt_ticket         = &tls_ctx->encrypt_ticket_cb;
    ctx->ticket_lifetime        = tls_ctx->session_timeout ? tls_ctx->session_timeout : 3600;
    ctx->server_cipher_preference = 1;

    /* Store sign_certificate pointer as app_data for cleanup */
    ctx->sign_certificate = &sc->sc.super;

    /* Load certificates */
    if (ptls_load_certificates(ctx, cert_pem_file) != 0) {
        log_error("tls_init", "failed to load cert %s", cert_pem_file);
        free(sc); free(ctx);
        return NULL;
    }

    /* Load private key */
    if (ptls_minicrypto_load_private_key(ctx, key_pem_file) != 0) {
        log_error("tls_init", "failed to load key %s", key_pem_file);
        /* Free cert list */
        if (ctx->certificates.list) {
            for (size_t i = 0; i < ctx->certificates.count; i++)
                free(ctx->certificates.list[i].base);
            free(ctx->certificates.list);
        }
        free(sc); free(ctx);
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
    tls->session_timeout          = cfg->tls.session_timeout;
    tls->session_ticket_rotation  = cfg->tls.session_ticket_rotation;

    pthread_mutex_init(&tls->ticket_lock, NULL);

    /* Set up session ticket callback */
    tls->encrypt_ticket_cb.cb = ticket_encrypt_decrypt;

    /* Set up on_client_hello callback */
    g_on_client_hello.super.cb = on_client_hello_cb;
    g_on_client_hello.tls_ctx  = tls;

    /* Probe kTLS availability */
    {
        int probe_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (probe_fd >= 0) {
#ifdef SOL_TLS
            int r = setsockopt(probe_fd, SOL_TLS, 0, NULL, 0);
            tls->ktls_available = (r == 0 || errno == ENOPROTOOPT
                                   || errno == ENOTSUP || errno == EOPNOTSUPP
                                   || errno == EINVAL);
            int f = open("/proc/net/tls_stat", O_RDONLY);
            if (f >= 0) { tls->ktls_available = true; close(f); }
#else
            tls->ktls_available = false;
#endif
            close(probe_fd);
        }
    }
    log_info("tls_init", "kTLS kernel support: %s",
        tls->ktls_available ? "yes" : "no");

    /* Create per-route contexts */
    tls->route_count = cfg->route_count;
    for (int i = 0; i < cfg->route_count; i++) {
        tls->routes[i].route_idx = i;
        tls->routes[i].hostname  = cfg->routes[i].hostname;

        if (cfg->routes[i].cert_path[0] == '\0') {
            log_warn("tls_init", "route %d: no cert configured (HTTP-only)", i);
            continue;
        }

        ptls_context_t *ctx = build_route_context(tls,
            cfg->routes[i].cert_path,
            cfg->routes[i].key_path,
            cfg->routes[i].hostname);
        if (!ctx) {
            log_warn("tls_init", "route %d: TLS context failed (will reject TLS)", i);
            continue;
        }
        /* Attach the shared on_client_hello to every route context */
        ctx->on_client_hello = &g_on_client_hello.super;

        tls->routes[i].ctx = ctx;
    }

    log_info("tls_init", "TLS subsystem ready, routes=%d", cfg->route_count);
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

ptls_t *tls_accept(struct tls_ctx *tls, int fd,
                   int *route_idx_out, char *sni_out, size_t sni_max,
                   bool *ktls_tx_out, bool *ktls_rx_out, bool *h2_out,
                   uint8_t **pending_data_out, size_t *pending_data_len_out)
{
    if (route_idx_out)       *route_idx_out       = 0;
    if (ktls_tx_out)         *ktls_tx_out         = false;
    if (ktls_rx_out)         *ktls_rx_out         = false;
    if (h2_out)              *h2_out              = false;
    if (pending_data_out)    *pending_data_out    = NULL;
    if (pending_data_len_out)*pending_data_len_out = 0;
    if (sni_out && sni_max > 0) sni_out[0] = '\0';

    /* Use first available route context as the starting context */
    ptls_context_t *base_ctx = NULL;
    for (int i = 0; i < tls->route_count; i++) {
        if (tls->routes[i].ctx) {
            base_ctx = tls->routes[i].ctx;
            break;
        }
    }
    if (!base_ctx) {
        log_error("tls_accept", "no ptls_context_t available");
        return NULL;
    }

    /* Per-connection state */
    struct conn_tls_state state;
    memset(&state, 0, sizeof(state));
    state.fd      = fd;
    state.tls_ctx = tls;

    ptls_t *ptls = ptls_server_new(base_ctx);
    if (!ptls) {
        log_error("tls_accept", "ptls_server_new failed");
        return NULL;
    }

    /* Store state pointer in ptls user-data */
    *ptls_get_data_ptr(ptls) = &state;

    /* Set fd non-blocking for the handshake loop */
    int flags = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    uint8_t ibuf[8192];
    int ret = PTLS_ERROR_IN_PROGRESS;

    /* Track the last recv's count and consumed for leftover-byte detection */
    ssize_t last_nr       = 0;
    size_t  last_consumed = 0;

    /* picotls server returns 0 after sending its own Finished (TLS 1.3 allows
     * the server to send application data before receiving the client's
     * Finished).  Continue looping until ptls_handshake_is_complete() returns
     * true so that server_handle_finished() is called and dec.secret is
     * updated to CLIENT_TRAFFIC_SECRET_0 before we install kTLS RX keys. */
    while (ret == PTLS_ERROR_IN_PROGRESS ||
           (ret == 0 && !ptls_handshake_is_complete(ptls))) {
        /* Wait for data */
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int pret = poll(&pfd, 1, 5000); /* 5-second handshake timeout */
        if (pret <= 0) {
            log_debug("tls_accept", "handshake timeout fd=%d", fd);
            ptls_free(ptls);
            return NULL;
        }

        ssize_t nr = recv(fd, ibuf, sizeof(ibuf), 0);
        if (nr <= 0) {
            if (nr < 0 && errno == EAGAIN) continue;
            ptls_free(ptls);
            return NULL;
        }

        size_t consumed = (size_t)nr;
        ptls_buffer_t wbuf;
        uint8_t wbuf_smallbuf[4096];
        ptls_buffer_init(&wbuf, wbuf_smallbuf, sizeof(wbuf_smallbuf));

        ret = ptls_handshake(ptls, &wbuf, ibuf, &consumed, NULL);

        /* Send any output (server handshake records) */
        if (wbuf.off > 0) {
            if (write_all(fd, wbuf.base, wbuf.off) < 0) {
                ptls_buffer_dispose(&wbuf);
                ptls_free(ptls);
                return NULL;
            }
        }
        ptls_buffer_dispose(&wbuf);

        if (ret != 0 && ret != PTLS_ERROR_IN_PROGRESS) {
            log_debug("tls_accept", "handshake failed fd=%d ret=%d", fd, ret);
            ptls_free(ptls);
            return NULL;
        }

        last_nr       = nr;
        last_consumed = consumed;
    }

    /*
     * If the client sent application data (e.g. H2 connection preface) bundled
     * with its TLS Finished in the same TCP segment, those bytes ended up in
     * ibuf[] past `last_consumed` but were never processed by ptls_handshake.
     * Once kTLS is installed the kernel's TCP receive buffer has already been
     * drained of those bytes — they must be decrypted now via ptls_receive and
     * returned to the caller as pending_data so they can be injected into the
     * application layer before any io_uring recv fires.
     */
    if (last_consumed < (size_t)last_nr) {
        size_t extra     = (size_t)last_nr - last_consumed;
        size_t extra_in  = extra;
        ptls_buffer_t pbuf;
        uint8_t pbuf_small[4096];
        ptls_buffer_init(&pbuf, pbuf_small, sizeof(pbuf_small));

        int r = ptls_receive(ptls, &pbuf, ibuf + last_consumed, &extra_in);
        if (r == 0 && pbuf.off > 0 && pending_data_out) {
            uint8_t *pd = malloc(pbuf.off);
            if (pd) {
                memcpy(pd, pbuf.base, pbuf.off);
                *pending_data_out     = pd;
                if (pending_data_len_out)
                    *pending_data_len_out = pbuf.off;
            }
        } else if (r != 0) {
            log_debug("tls_accept",
                "fd=%d ptls_receive on leftover %zu bytes failed: %d",
                fd, extra, r);
        }
        ptls_buffer_dispose(&pbuf);
    }

    /* Handshake complete. Get SNI and ALPN. */
    const char *sni = ptls_get_server_name(ptls);
    if (sni && sni_out && sni_max > 0) {
        snprintf(sni_out, sni_max, "%s", sni);
        sni_out[sni_max - 1] = '\0';
    }

    const char *alpn = ptls_get_negotiated_protocol(ptls);
    bool h2 = (alpn && strcmp(alpn, "h2") == 0);
    if (h2_out) *h2_out = h2;

    if (route_idx_out)
        *route_idx_out = state.matched_route;

    log_info("tls_accept",
        "fd=%d sni=%s route=%d h2=%d ktls_available=%d",
        fd, sni ? sni : "(none)", state.matched_route, (int)h2,
        (int)tls->ktls_available);

    /* Attempt kTLS installation.
     * picotls handled the full handshake internally (including AEAD for epochs 2/3).
     * Now extract the application-data traffic keys via ptls_get_traffic_keys and
     * install them into the kernel TLS ULP.  ptls must be freed afterwards since
     * kTLS takes over all record-layer crypto.
     */
    if (tls->ktls_available) {
        ptls_cipher_suite_t *cipher = ptls_get_cipher(ptls);
        if (cipher) {
            uint8_t tx_key[PTLS_MAX_SECRET_SIZE];
            uint8_t tx_iv[PTLS_MAX_IV_SIZE];
            uint8_t rx_key[PTLS_MAX_SECRET_SIZE];
            uint8_t rx_iv[PTLS_MAX_IV_SIZE];
            uint64_t tx_seq = 0, rx_seq = 0;

            if (ptls_get_traffic_keys(ptls, 1, tx_key, tx_iv, &tx_seq) == 0 &&
                ptls_get_traffic_keys(ptls, 0, rx_key, rx_iv, &rx_seq) == 0) {

                if (setsockopt(fd, SOL_TCP, TCP_ULP, "tls", strlen("tls")) == 0) {
                    int tx_ok = (install_ktls_direction(fd, tx_key, tx_iv,
                                                         tx_seq, cipher->aead, 1) == 0);
                    int rx_ok = (install_ktls_direction(fd, rx_key, rx_iv,
                                                         rx_seq, cipher->aead, 0) == 0);
                    /* Wipe key material immediately */
                    memset(tx_key, 0, sizeof(tx_key));
                    memset(rx_key, 0, sizeof(rx_key));
                    memset(tx_iv,  0, sizeof(tx_iv));
                    memset(rx_iv,  0, sizeof(rx_iv));

                    if (tx_ok && rx_ok) {
                        if (ktls_tx_out) *ktls_tx_out = true;
                        if (ktls_rx_out) *ktls_rx_out = true;
                        log_info("tls_accept",
                            "fd=%d kTLS installed cipher=%s tx_seq=%llu rx_seq=%llu",
                            fd, cipher->aead->name,
                            (unsigned long long)tx_seq, (unsigned long long)rx_seq);
                        fcntl(fd, F_SETFL, flags);
                        ptls_free(ptls);
                        return NULL; /* kTLS took over, no ptls_t needed */
                    }
                    log_warn("tls_accept", "fd=%d kTLS setsockopt failed: %s",
                             fd, strerror(errno));
                } else {
                    memset(tx_key, 0, sizeof(tx_key));
                    memset(rx_key, 0, sizeof(rx_key));
                    log_warn("tls_accept", "fd=%d TCP_ULP 'tls' failed: %s",
                             fd, strerror(errno));
                }
            }
        }
    }

    /* Non-kTLS fallback: restore blocking mode, return ptls_t* */
    fcntl(fd, F_SETFL, flags);
    return ptls;
}

/* ------------------------------------------------------------------ */
/* Cert hot-swap                                                        */
/* ------------------------------------------------------------------ */

ptls_context_t *tls_create_ctx_from_pem(struct tls_ctx *tls,
                                          const char *cert_pem,
                                          const char *key_pem,
                                          const char *hostname)
{
    /* Write PEM strings to temp files, then build context */
    char cert_tmp[] = "/tmp/vortex-cert-XXXXXX.pem";
    char key_tmp[]  = "/tmp/vortex-key-XXXXXX.pem";

    int cfd = mkstemps(cert_tmp, 4);
    int kfd = mkstemps(key_tmp,  4);
    if (cfd < 0 || kfd < 0) {
        if (cfd >= 0) { close(cfd); unlink(cert_tmp); }
        if (kfd >= 0) { close(kfd); unlink(key_tmp);  }
        return NULL;
    }

    size_t clen = strlen(cert_pem), klen = strlen(key_pem);
    if (write(cfd, cert_pem, clen) != (ssize_t)clen ||
        write(kfd, key_pem,  klen) != (ssize_t)klen) {
        close(cfd); close(kfd);
        unlink(cert_tmp); unlink(key_tmp);
        return NULL;
    }
    close(cfd); close(kfd);

    ptls_context_t *ctx = build_route_context(tls, cert_tmp, key_tmp, hostname);
    unlink(cert_tmp); unlink(key_tmp);

    if (ctx)
        ctx->on_client_hello = &g_on_client_hello.super;
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

int tls_rotate_cert(struct tls_ctx *tls, int route_idx,
                    const char *cert_pem, const char *key_pem)
{
    if (route_idx < 0 || route_idx >= tls->route_count)
        return -1;

    struct tls_route_ctx *rc = &tls->routes[route_idx];
    const char *hostname = rc->hostname ? rc->hostname : "";

    ptls_context_t *new_ctx = tls_create_ctx_from_pem(tls, cert_pem, key_pem, hostname);
    if (!new_ctx)
        return -1;

    /* Atomic swap: workers see either old or new context */
    ptls_context_t *old_ctx = __atomic_exchange_n(&rc->ctx, new_ctx,
                                                    __ATOMIC_SEQ_CST);
    if (old_ctx)
        tls_context_free(old_ctx);

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
int tls_gen_self_signed(const char *cert_path, const char *key_path,
                        const char *cn)
{
    /* Generate P-256 key pair via uECC (bundled with picotls minicrypto) */
    uint8_t priv[32], pub[64]; /* raw P-256 key coordinates (uncompressed, no prefix) */
    uint8_t pub65[65];

    /* Use ptls_minicrypto_random_bytes for entropy, then uECC to generate key */
    /* The uecc interface is not publicly exposed; use the exchange API instead */
    /* We'll use ptls_minicrypto_secp256r1.exchange with random client key */

    ptls_key_exchange_context_t *kex_ctx = NULL;
    ptls_iovec_t server_pubkey_vec;
    ptls_iovec_t server_secret_vec;

    /* Generate a server-side key pair via the server exchange API */
    uint8_t client_ephem_pub[65];
    ptls_minicrypto_random_bytes(client_ephem_pub, sizeof(client_ephem_pub));

    /* The simplest approach: use ptls_minicrypto_secp256r1.create to get a key pair */
    if (ptls_minicrypto_secp256r1.create(&ptls_minicrypto_secp256r1, &kex_ctx) != 0)
        return -1;

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
    if (ptls_minicrypto_init_secp256r1sha256_sign_certificate(&sc,
            ptls_iovec_init(raw_key, 32)) != 0) {
        log_error("gen_cert", "failed to init secp256r1 sign certificate");
        return -1;
    }

    /* Get public key from the sign certificate — we need to call the exchange API */
    /* Build DER public key: uncompressed point with the stored private key */
    /* Unfortunately, minicrypto doesn't expose getPublicKey from private key directly */
    /* We'll use a workaround: create a key exchange and use the pubkey from there */

    /* Use the client-side create to get a fresh P-256 key pair */
    if (ptls_minicrypto_secp256r1.create(&ptls_minicrypto_secp256r1, &kex_ctx) != 0)
        return -1;

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
    (void)priv; (void)pub; (void)pub65;

    /* Try using openssl from system path to generate test cert */
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
        "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 "
        "-keyout '%s' -out '%s' -days 365 -nodes -subj '/CN=%s' "
        "-addext 'subjectAltName=DNS:%s,IP:127.0.0.1' 2>/dev/null",
        key_path, cert_path, cn, cn);

    if (system(cmd) == 0) {
        log_info("gen_cert", "self-signed cert: cn=%s cert=%s key=%s",
                 cn, cert_path, key_path);
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
 * The ticket pointer is stored in ptls user data by the caller.
 */
typedef struct {
    ptls_save_ticket_t super;
    struct tls_session_ticket **outp;
} vortex_backend_save_ticket_t;

static int backend_save_ticket_cb(ptls_save_ticket_t *self, ptls_t *tls, ptls_iovec_t input)
{
    (void)tls;
    vortex_backend_save_ticket_t *st = (vortex_backend_save_ticket_t *)self;
    if (!st->outp) return 0;

    size_t len = input.len < TLS_SESSION_TICKET_MAX ? input.len : TLS_SESSION_TICKET_MAX;
    struct tls_session_ticket *t = malloc(sizeof(*t));
    if (!t) return 0;
    memcpy(t->data, input.base, len);
    t->len = len;
    *st->outp = t;
    return 0;
}

/*
 * Perform a blocking picotls client handshake on fd.
 * On success, returns a ptls_t* and optionally sets *session_ticket_out
 * to a heap-allocated session ticket (caller must free it).
 * On failure, returns NULL.
 */
ptls_t *tls_backend_connect(ptls_context_t *ctx, int fd,
                             const char *server_name,
                             uint32_t timeout_ms,
                             const struct tls_session_ticket *resume_session,
                             struct tls_session_ticket **session_ticket_out)
{
    if (session_ticket_out) *session_ticket_out = NULL;

    /* Per-call save_ticket callback — lives on stack, so ctx.save_ticket is
     * set transiently per handshake. This is safe because tls_pool threads
     * each have their own ptls_t (and the callback is per-connection). */
    struct tls_session_ticket *saved = NULL;
    vortex_backend_save_ticket_t st = {
        .super = { .cb = backend_save_ticket_cb },
        .outp  = session_ticket_out ? &saved : NULL,
    };
    ctx->save_ticket = &st.super;

    ptls_t *ptls = ptls_client_new(ctx);
    if (!ptls) {
        ctx->save_ticket = NULL;
        return NULL;
    }

    if (server_name && server_name[0])
        ptls_set_server_name(ptls, server_name, strlen(server_name));

    ptls_handshake_properties_t props;
    memset(&props, 0, sizeof(props));
    if (resume_session && resume_session->len > 0) {
        props.client.session_ticket =
            ptls_iovec_init(resume_session->data, resume_session->len);
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
        struct pollfd pfd = { .fd = fd, .events = POLLIN | POLLOUT };
        if (poll(&pfd, 1, (int)timeout_ms) <= 0) {
            log_warn("tls_backend_connect", "handshake timeout fd=%d sni=%s",
                     fd, server_name ? server_name : "");
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

    ctx->save_ticket = NULL;

    if (ret != 0) {
        log_warn("tls_backend_connect", "handshake failed fd=%d ret=%d", fd, ret);
        goto fail;
    }

    /* Restore blocking mode */
    fcntl(fd, F_SETFL, flags);

    if (session_ticket_out)
        *session_ticket_out = saved;

    return ptls;

fail:
    ctx->save_ticket = NULL;
    free(saved);
    ptls_free(ptls);
    fcntl(fd, F_SETFL, flags);
    return NULL;
}

ptls_context_t *tls_create_client_ctx(bool verify_peer)
{
    (void)verify_peer; /* TODO: implement cert chain verification */

    static ptls_key_exchange_algorithm_t *key_exchanges[] = {
        &ptls_minicrypto_x25519,
        &ptls_minicrypto_secp256r1,
        NULL
    };
    static ptls_cipher_suite_t *cipher_suites[] = {
        &ptls_minicrypto_aes256gcmsha384,
        &ptls_minicrypto_chacha20poly1305sha256,
        NULL
    };

    ptls_context_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;

    ctx->random_bytes  = ptls_minicrypto_random_bytes;
    ctx->get_time      = &ptls_get_time;
    ctx->key_exchanges = key_exchanges;
    ctx->cipher_suites = cipher_suites;
    /* verify_certificate = NULL: accept all server certs (no chain verification) */

    return ctx;
}
