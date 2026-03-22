#include "tls.h"
#include "log.h"
#include "config.h"

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/provider.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* SNI callback data threaded through SSL app_data */
struct sni_data {
    struct tls_ctx *tls;
    int             matched_route;
};

static void log_ssl_errors(const char *ctx_tag)
{
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        log_error(ctx_tag, "OpenSSL: %s", buf);
    }
}

/* SNI callback: select the SSL_CTX matching the requested hostname */
static int sni_callback(SSL *ssl, int *al, void *arg)
{
    (void)al; (void)arg;
    /* Read per-connection data set via SSL_set_app_data() — NOT the CTX-level
     * arg (which is shared across all workers and races on concurrent accepts). */
    struct sni_data *sd = (struct sni_data *)SSL_get_app_data(ssl);
    struct tls_ctx  *tls = sd->tls;

    const char *sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (!sni || sni[0] == '\0') {
        sd->matched_route = 0; /* use default (first) route */
        return SSL_TLSEXT_ERR_OK;
    }

    /* Exact match first, then prefix wildcard */
    for (int i = 0; i < tls->route_count; i++) {
        const char *h = tls->routes[i].ssl_ctx
            ? SSL_CTX_get_app_data(tls->routes[i].ssl_ctx)
            : NULL;
        if (!h) continue;
        if (strcasecmp(h, sni) == 0) {
            SSL_set_SSL_CTX(ssl, tls->routes[i].ssl_ctx);
            sd->matched_route = i;
            log_debug("sni_match", "sni=%s route=%d", sni, i);
            return SSL_TLSEXT_ERR_OK;
        }
    }

    /* Wildcard match *.example.com */
    const char *dot = strchr(sni, '.');
    if (dot) {
        for (int i = 0; i < tls->route_count; i++) {
            const char *h = tls->routes[i].ssl_ctx
                ? SSL_CTX_get_app_data(tls->routes[i].ssl_ctx)
                : NULL;
            if (!h || h[0] != '*') continue;
            if (strcasecmp(h + 1, dot) == 0) {
                SSL_set_SSL_CTX(ssl, tls->routes[i].ssl_ctx);
                sd->matched_route = i;
                log_debug("sni_wildcard", "sni=%s route=%d", sni, i);
                return SSL_TLSEXT_ERR_OK;
            }
        }
    }

    /* No match — use default route, don't abort handshake */
    sd->matched_route = 0;
    return SSL_TLSEXT_ERR_OK;
}

static SSL_CTX *create_ssl_ctx(struct tls_ctx *tls,
                                const struct route_config *route,
                                int route_idx)
{
    SSL_CTX *ctx = SSL_CTX_new_ex(tls->libctx, NULL, TLS_server_method());
    if (!ctx) {
        log_ssl_errors("create_ssl_ctx");
        return NULL;
    }

    /* TLS 1.2 + 1.3 only */
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    /* Prefer AES-GCM for kTLS compatibility */
    SSL_CTX_set_ciphersuites(ctx,
        "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:"
        "TLS_CHACHA20_POLY1305_SHA256");
    SSL_CTX_set_cipher_list(ctx,
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384");

    SSL_CTX_set_options(ctx,
        SSL_OP_CIPHER_SERVER_PREFERENCE |
        SSL_OP_NO_RENEGOTIATION);

    /* Enable kTLS — OpenSSL will install kTLS after handshake if supported */
    if (tls->ktls_available) {
        SSL_CTX_set_options(ctx, SSL_OP_ENABLE_KTLS);
        log_debug("tls_init", "kTLS enabled for route %d", route_idx);
    }

    /* Load certificate and private key */
    if (route->cert_path[0] != '\0') {
        if (SSL_CTX_use_certificate_chain_file(ctx, route->cert_path) != 1) {
            log_error("tls_init", "failed to load cert %s", route->cert_path);
            log_ssl_errors("tls_init");
            SSL_CTX_free(ctx);
            return NULL;
        }
        if (SSL_CTX_use_PrivateKey_file(ctx, route->key_path,
                                         SSL_FILETYPE_PEM) != 1) {
            log_error("tls_init", "failed to load key %s", route->key_path);
            log_ssl_errors("tls_init");
            SSL_CTX_free(ctx);
            return NULL;
        }
        if (SSL_CTX_check_private_key(ctx) != 1) {
            log_error("tls_init", "cert/key mismatch for route %d", route_idx);
            SSL_CTX_free(ctx);
            return NULL;
        }
        log_info("tls_cert_loaded", "route=%d cert=%s",
            route_idx, route->cert_path);
    }

    /* Store hostname for SNI matching — use app_data to hold the pointer */
    SSL_CTX_set_app_data(ctx, (void *)route->hostname);

    /* SNI callback */
    SSL_CTX_set_tlsext_servername_callback(ctx, sni_callback);

    return ctx;
}

int tls_init(struct tls_ctx *tls, const struct vortex_config *cfg)
{
    memset(tls, 0, sizeof(*tls));

    /* Create isolated library context */
    tls->libctx = OSSL_LIB_CTX_new();
    if (!tls->libctx) {
        log_error("tls_init", "OSSL_LIB_CTX_new failed");
        return -1;
    }

    /* Load the default provider (software crypto, includes AES-GCM) */
    tls->prov_default = OSSL_PROVIDER_load(tls->libctx, "default");
    if (!tls->prov_default) {
        log_error("tls_init", "failed to load default OpenSSL provider");
        log_ssl_errors("tls_init");
        OSSL_LIB_CTX_free(tls->libctx);
        return -1;
    }

    /* Probe kTLS availability: try setsockopt on a dummy socket */
    {
        int probe_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (probe_fd >= 0) {
#ifdef SOL_TLS
            /* Check if the kernel tls module is loaded */
            int r = setsockopt(probe_fd, SOL_TLS, 0, NULL, 0);
            tls->ktls_available = (r == 0 || errno == ENOPROTOOPT
                                   || errno == ENOTSUP || errno == EOPNOTSUPP
                                   || errno == EINVAL);
            /* More reliable: check /proc/net/tls_stat */
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

    /* Create per-route SSL_CTX */
    tls->route_count = cfg->route_count;
    for (int i = 0; i < cfg->route_count; i++) {
        tls->routes[i].route_idx = i;
        tls->routes[i].ssl_ctx = create_ssl_ctx(tls, &cfg->routes[i], i);
        if (!tls->routes[i].ssl_ctx) {
            /* Non-fatal for routes without cert — they'll be HTTP-only */
            log_warn("tls_init", "no TLS context for route %d "
                "(missing cert/key — will reject TLS connections)", i);
        }
    }

    log_info("tls_init", "TLS subsystem ready, routes=%d", cfg->route_count);
    return 0;
}

void tls_destroy(struct tls_ctx *tls)
{
    for (int i = 0; i < tls->route_count; i++) {
        if (tls->routes[i].ssl_ctx) {
            SSL_CTX_free(tls->routes[i].ssl_ctx);
            tls->routes[i].ssl_ctx = NULL;
        }
    }
    if (tls->prov_default) {
        OSSL_PROVIDER_unload(tls->prov_default);
        tls->prov_default = NULL;
    }
    if (tls->libctx) {
        OSSL_LIB_CTX_free(tls->libctx);
        tls->libctx = NULL;
    }
}

SSL *tls_accept(struct tls_ctx *tls, int fd,
                int *route_idx_out, char *sni_out, size_t sni_max)
{
    /* Use default (first) route's SSL_CTX to start — SNI callback may switch */
    SSL_CTX *base_ctx = NULL;
    for (int i = 0; i < tls->route_count; i++) {
        if (tls->routes[i].ssl_ctx) {
            base_ctx = tls->routes[i].ssl_ctx;
            break;
        }
    }
    if (!base_ctx) {
        log_error("tls_accept", "no SSL_CTX available");
        return NULL;
    }

    SSL *ssl = SSL_new(base_ctx);
    if (!ssl) {
        log_ssl_errors("tls_accept");
        return NULL;
    }

    /* Thread SNI data through per-connection SSL app_data.
     * Must NOT use SSL_CTX_set_tlsext_servername_arg() here — that sets a
     * shared pointer on the CTX, racing when multiple workers accept concurrently.
     * The callback reads this via SSL_get_app_data(ssl) instead. */
    struct sni_data sd = { .tls = tls, .matched_route = 0 };
    SSL_set_app_data(ssl, &sd);

    /* Attach fd — set non-blocking mode first so handshake doesn't block
     * indefinitely on a slow client; we loop on WANT_READ/WANT_WRITE */
    int flags = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    if (SSL_set_fd(ssl, fd) != 1) {
        log_ssl_errors("tls_accept");
        SSL_free(ssl);
        return NULL;
    }

    /* Handshake loop — non-blocking with select */
    for (;;) {
        int ret = SSL_accept(ssl);
        if (ret == 1) break; /* success */

        int err = SSL_get_error(ssl, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            fd_set rset, wset;
            FD_ZERO(&rset); FD_ZERO(&wset);
            if (err == SSL_ERROR_WANT_READ)  FD_SET(fd, &rset);
            if (err == SSL_ERROR_WANT_WRITE) FD_SET(fd, &wset);
            struct timeval tv = { .tv_sec = 5 };
            int sel = select(fd + 1, &rset, &wset, NULL, &tv);
            if (sel <= 0) {
                log_debug("tls_accept", "handshake timeout fd=%d", fd);
                SSL_free(ssl);
                return NULL;
            }
            continue;
        }

        /* Fatal error */
        if (err != SSL_ERROR_ZERO_RETURN) {
            log_debug("tls_accept", "handshake failed fd=%d err=%d", fd, err);
            log_ssl_errors("tls_accept");
        }
        SSL_free(ssl);
        return NULL;
    }

    /* Extract SNI for logging/routing */
    const char *sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (sni && sni_out && sni_max > 0) {
        strncpy(sni_out, sni, sni_max - 1);
        sni_out[sni_max - 1] = '\0';
    } else if (sni_out && sni_max > 0) {
        sni_out[0] = '\0';
    }

    if (route_idx_out) *route_idx_out = sd.matched_route;

    /* Check if OpenSSL installed kTLS */
    BIO *wbio = SSL_get_wbio(ssl);
    BIO *rbio = SSL_get_rbio(ssl);
    bool ktls_tx = BIO_get_ktls_send(wbio);
    bool ktls_rx = BIO_get_ktls_recv(rbio);

    log_info("tls_accept",
        "fd=%d sni=%s route=%d ver=%s cipher=%s ktls_tx=%d ktls_rx=%d",
        fd,
        sni ? sni : "(none)",
        sd.matched_route,
        SSL_get_version(ssl),
        SSL_get_cipher_name(ssl),
        (int)ktls_tx, (int)ktls_rx);

    return ssl;
}

bool tls_ktls_tx_active(SSL *ssl)
{
    return BIO_get_ktls_send(SSL_get_wbio(ssl));
}

bool tls_ktls_rx_active(SSL *ssl)
{
    return BIO_get_ktls_recv(SSL_get_rbio(ssl));
}

void tls_ssl_free(SSL *ssl)
{
    if (!ssl) return;
    /* SSL_free does NOT undo kTLS state on the fd — safe after kTLS install */
    SSL_free(ssl);
}

/* ---- Certificate hot-swap ---- */

SSL_CTX *tls_create_ctx_from_pem(struct tls_ctx *tls,
                                   const char *cert_pem,
                                   const char *key_pem,
                                   const char *hostname)
{
    SSL_CTX *ctx = SSL_CTX_new_ex(tls->libctx, NULL, TLS_server_method());
    if (!ctx) { log_ssl_errors("tls_create_ctx_from_pem"); return NULL; }

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_ciphersuites(ctx,
        "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:"
        "TLS_CHACHA20_POLY1305_SHA256");
    SSL_CTX_set_cipher_list(ctx,
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384");
    SSL_CTX_set_options(ctx,
        SSL_OP_CIPHER_SERVER_PREFERENCE | SSL_OP_NO_RENEGOTIATION);

    if (tls->ktls_available)
        SSL_CTX_set_options(ctx, SSL_OP_ENABLE_KTLS);

    /* Load cert chain from PEM string */
    BIO *cert_bio = BIO_new_mem_buf(cert_pem, -1);
    if (!cert_bio) { SSL_CTX_free(ctx); return NULL; }

    X509 *leaf = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
    if (!leaf) {
        log_ssl_errors("tls_create_ctx_from_pem");
        BIO_free(cert_bio); SSL_CTX_free(ctx); return NULL;
    }
    if (SSL_CTX_use_certificate(ctx, leaf) != 1) {
        X509_free(leaf); BIO_free(cert_bio); SSL_CTX_free(ctx); return NULL;
    }
    X509_free(leaf);

    /* Chain certs */
    X509 *chain;
    while ((chain = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL)) != NULL) {
        SSL_CTX_add_extra_chain_cert(ctx, chain); /* ctx takes ownership */
    }
    BIO_free(cert_bio);

    /* Load private key */
    BIO *key_bio = BIO_new_mem_buf(key_pem, -1);
    if (!key_bio) { SSL_CTX_free(ctx); return NULL; }
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(key_bio, NULL, NULL, NULL);
    BIO_free(key_bio);
    if (!pkey) {
        log_ssl_errors("tls_create_ctx_from_pem");
        SSL_CTX_free(ctx); return NULL;
    }
    if (SSL_CTX_use_PrivateKey(ctx, pkey) != 1) {
        EVP_PKEY_free(pkey); SSL_CTX_free(ctx); return NULL;
    }
    EVP_PKEY_free(pkey);

    if (SSL_CTX_check_private_key(ctx) != 1) {
        log_error("tls_create_ctx_from_pem", "cert/key mismatch");
        SSL_CTX_free(ctx); return NULL;
    }

    /* Store hostname for SNI — use app_data on the ctx.
     * The hostname string must outlive the ctx; point to route->hostname. */
    if (hostname) SSL_CTX_set_app_data(ctx, (void *)hostname);
    SSL_CTX_set_tlsext_servername_callback(ctx, sni_callback);

    return ctx;
}

int tls_rotate_cert(struct tls_ctx *tls, int route_idx,
                     const char *cert_pem, const char *key_pem)
{
    if (route_idx < 0 || route_idx >= tls->route_count) return -1;

    struct tls_route_ctx *rc = &tls->routes[route_idx];

    /* Get hostname from old ctx (or empty string) */
    const char *hostname = "";
    if (rc->ssl_ctx) {
        void *d = SSL_CTX_get_app_data(rc->ssl_ctx);
        if (d) hostname = (const char *)d;
    }

    SSL_CTX *new_ctx = tls_create_ctx_from_pem(tls, cert_pem, key_pem, hostname);
    if (!new_ctx) return -1;

    /* Atomic swap: workers accessing ssl_ctx see either old or new, both valid.
     * OpenSSL SSL_CTX uses reference counting; SSL_new() increments the ref,
     * so existing handshakes hold a reference to the old ctx. */
    SSL_CTX *old_ctx = __atomic_exchange_n(&rc->ssl_ctx, new_ctx,
                                            __ATOMIC_SEQ_CST);

    /* Free old ctx — if any SSL objects still hold a reference, OpenSSL
     * delays freeing until all references are released. */
    if (old_ctx) SSL_CTX_free(old_ctx);

    log_info("tls_rotate_cert", "route=%d cert rotated", route_idx);
    return 0;
}

/* Generate a self-signed RSA-2048 cert+key for testing */
int tls_gen_self_signed(const char *cert_path, const char *key_path,
                        const char *cn)
{
    int ret = -1;
    EVP_PKEY *pkey = NULL;
    X509 *x509 = NULL;
    EVP_PKEY_CTX *pkctx = NULL;
    FILE *fp = NULL;

    /* Generate RSA-2048 key */
    pkctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (!pkctx) goto done;
    if (EVP_PKEY_keygen_init(pkctx) <= 0) goto done;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pkctx, 2048) <= 0) goto done;
    if (EVP_PKEY_generate(pkctx, &pkey) <= 0) goto done;

    /* Create X.509 certificate */
    x509 = X509_new();
    if (!x509) goto done;

    X509_set_version(x509, 2); /* v3 */
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 365 * 24 * 3600);
    X509_set_pubkey(x509, pkey);

    /* X509_get_subject_name returns const* in OpenSSL 4 — cast is safe here */
    X509_NAME *name = (X509_NAME *)X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        (const unsigned char *)cn, -1, -1, 0);
    X509_set_issuer_name(x509, X509_get_subject_name(x509)); /* self-signed */

    /* Add SAN */
    X509V3_CTX v3ctx;
    X509V3_set_ctx_nodb(&v3ctx);
    X509V3_set_ctx(&v3ctx, x509, x509, NULL, NULL, 0);
    char san_val[320];
    snprintf(san_val, sizeof(san_val), "DNS:%s,IP:127.0.0.1", cn);
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &v3ctx,
        NID_subject_alt_name, san_val);
    if (ext) {
        X509_add_ext(x509, ext, -1);
        X509_EXTENSION_free(ext);
    }

    /* Sign */
    if (X509_sign(x509, pkey, EVP_sha256()) == 0) goto done;

    /* Write key */
    fp = fopen(key_path, "wb");
    if (!fp) { log_error("gen_cert", "cannot write %s: %s", key_path, strerror(errno)); goto done; }
    PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(fp); fp = NULL;

    /* Write cert */
    fp = fopen(cert_path, "wb");
    if (!fp) { log_error("gen_cert", "cannot write %s: %s", cert_path, strerror(errno)); goto done; }
    PEM_write_X509(fp, x509);
    fclose(fp); fp = NULL;

    log_info("gen_cert", "self-signed cert: cn=%s cert=%s key=%s", cn, cert_path, key_path);
    ret = 0;

done:
    if (fp) fclose(fp);
    if (x509) X509_free(x509);
    if (pkey) EVP_PKEY_free(pkey);
    if (pkctx) EVP_PKEY_CTX_free(pkctx);
    if (ret != 0) log_ssl_errors("gen_cert");
    return ret;
}
