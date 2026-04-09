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
#include <openssl/pem.h>
#include <openssl/ocsp.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include <string.h>
#include <stdlib.h>
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

static int g_tls_ctx_ex_index = -1;
static int g_tls_route_ex_index = -1;

static int sni_callback(SSL *ssl, int *al, void *arg);
static int client_hello_cb(SSL *ssl, int *al, void *arg);
static int alpn_select_cb(SSL *ssl, const uint8_t **out, uint8_t *outlen,
                          const uint8_t *in, unsigned int inlen, void *arg);
static int tls_new_session_cb(SSL *ssl, SSL_SESSION *sess);
static SSL_SESSION *tls_get_session_cb(SSL *ssl, const unsigned char *data,
                                       int len, int *copy);
static void tls_remove_session_cb(SSL_CTX *ctx, SSL_SESSION *sess);

static void log_ssl_errors(const char *ctx_tag)
{
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        log_error(ctx_tag, "OpenSSL: %s", buf);
    }
}

static int ensure_ex_indices(void)
{
    if (g_tls_ctx_ex_index < 0) {
        g_tls_ctx_ex_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);
        if (g_tls_ctx_ex_index < 0)
            return -1;
    }
    if (g_tls_route_ex_index < 0) {
        g_tls_route_ex_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);
        if (g_tls_route_ex_index < 0)
            return -1;
    }
    return 0;
}

static void free_route_ocsp(struct tls_route_ctx *route_ctx)
{
    if (!route_ctx->ocsp_resp_der)
        return;
    free(route_ctx->ocsp_resp_der);
    route_ctx->ocsp_resp_der = NULL;
    route_ctx->ocsp_resp_der_len = 0;
}

static struct tls_ctx *tls_from_ssl(SSL *ssl)
{
    SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
    if (!ctx || g_tls_ctx_ex_index < 0)
        return NULL;
    return (struct tls_ctx *)SSL_CTX_get_ex_data(ctx, g_tls_ctx_ex_index);
}

__attribute__((unused)) static struct tls_ctx *tls_from_ctx(SSL_CTX *ctx)
{
    if (!ctx || g_tls_ctx_ex_index < 0)
        return NULL;
    return (struct tls_ctx *)SSL_CTX_get_ex_data(ctx, g_tls_ctx_ex_index);
}

static struct tls_route_ctx *route_from_ssl(SSL *ssl)
{
    SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
    if (!ctx || g_tls_route_ex_index < 0)
        return NULL;
    return (struct tls_route_ctx *)SSL_CTX_get_ex_data(ctx, g_tls_route_ex_index);
}

static int select_route_ctx_for_sni(SSL *ssl, struct tls_ctx *tls, const char *sni)
{
    if (!ssl || !tls)
        return 0;

    if (!sni || sni[0] == '\0')
        return 0;

    for (int i = 0; i < tls->route_count; i++) {
        const char *h = tls->routes[i].ssl_ctx
            ? SSL_CTX_get_app_data(tls->routes[i].ssl_ctx)
            : NULL;
        if (!h) continue;
        if (strcasecmp(h, sni) == 0) {
            SSL_set_SSL_CTX(ssl, tls->routes[i].ssl_ctx);
            return i;
        }
    }

    const char *dot = strchr(sni, '.');
    if (dot) {
        for (int i = 0; i < tls->route_count; i++) {
            const char *h = tls->routes[i].ssl_ctx
                ? SSL_CTX_get_app_data(tls->routes[i].ssl_ctx)
                : NULL;
            if (!h || h[0] != '*') continue;
            if (strcasecmp(h + 1, dot) == 0) {
                SSL_set_SSL_CTX(ssl, tls->routes[i].ssl_ctx);
                return i;
            }
        }
    }

    return 0;
}

static int client_hello_cb(SSL *ssl, int *al, void *arg)
{
    (void)al;
    (void)arg;

    struct sni_data *sd = (struct sni_data *)SSL_get_app_data(ssl);
    struct tls_ctx *tls = sd ? sd->tls : NULL;
    const unsigned char *ext = NULL;
    size_t ext_len = 0;

    if (!tls)
        return SSL_CLIENT_HELLO_SUCCESS;

    if (SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_server_name, &ext, &ext_len) != 1
        || !ext || ext_len < 5) {
        if (sd)
            sd->matched_route = 0;
        return SSL_CLIENT_HELLO_SUCCESS;
    }

    const unsigned char *p = ext;
    if (ext_len < 2)
        return SSL_CLIENT_HELLO_SUCCESS;

    size_t list_len = ((size_t)p[0] << 8) | p[1];
    p += 2;
    if (list_len > ext_len - 2)
        list_len = ext_len - 2;

    while (list_len >= 3) {
        unsigned int name_type = p[0];
        size_t name_len = ((size_t)p[1] << 8) | p[2];
        p += 3;
        list_len -= 3;
        if (name_len > list_len)
            break;
        if (name_type == TLSEXT_NAMETYPE_host_name && name_len > 0) {
            char host[256];
            size_t copy_len = name_len < sizeof(host) - 1 ? name_len : sizeof(host) - 1;
            memcpy(host, p, copy_len);
            host[copy_len] = '\0';
            int route = select_route_ctx_for_sni(ssl, tls, host);
            if (sd)
                sd->matched_route = route;
            return SSL_CLIENT_HELLO_SUCCESS;
        }
        p += name_len;
        list_len -= name_len;
    }

    if (sd)
        sd->matched_route = 0;
    return SSL_CLIENT_HELLO_SUCCESS;
}

static void tls_session_id_prefix(const unsigned char *id, unsigned int id_len,
                                  char *out, size_t out_sz)
{
    if (!out || out_sz == 0) return;
    out[0] = '\0';
    if (!id || id_len == 0) return;
    unsigned int n = id_len < 4 ? id_len : 4;
    size_t off = 0;
    for (unsigned int i = 0; i < n && off + 2 < out_sz; i++) {
        off += (size_t)snprintf(out + off, out_sz - off, "%02X", id[i]);
    }
}

static void tls_log_session_meta(const char *event, SSL_SESSION *sess)
{
    unsigned int id_len = 0, sid_ctx_len = 0;
    const unsigned char *id = SSL_SESSION_get_id(sess, &id_len);
    const unsigned char *sid_ctx = SSL_SESSION_get0_id_context(sess, &sid_ctx_len);
    char id_hex[16];
    char sid_ctx_hex[16];

    tls_session_id_prefix(id, id_len, id_hex, sizeof(id_hex));
    tls_session_id_prefix(sid_ctx, sid_ctx_len, sid_ctx_hex, sizeof(sid_ctx_hex));
    log_info(event, "id=%s sid_ctx_len=%u sid_ctx=%s resumable=%d proto=%d",
             id_hex, sid_ctx_len, sid_ctx_hex,
             SSL_SESSION_is_resumable(sess),
             SSL_SESSION_get_protocol_version(sess));
}

static int build_sid_ctx(const char *hostname, int route_idx,
                         unsigned char *sid_ctx, unsigned int *sid_len)
{
    const uint32_t idx = (uint32_t)route_idx;
    const char *host = hostname ? hostname : "";
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

    if (!mdctx || !sid_ctx || !sid_len)
        return -1;
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1
        || EVP_DigestUpdate(mdctx, "vortex-tls-route", sizeof("vortex-tls-route") - 1) != 1
        || EVP_DigestUpdate(mdctx, &idx, sizeof(idx)) != 1
        || EVP_DigestUpdate(mdctx, host, strlen(host)) != 1
        || EVP_DigestFinal_ex(mdctx, sid_ctx, sid_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }
    EVP_MD_CTX_free(mdctx);
    return 0;
}

static void tls_session_cache_store(struct tls_ctx *tls, SSL_SESSION *sess)
{
    unsigned int id_len = 0;
    const unsigned char *id;
    size_t slot = 0;
    time_t oldest_time = 0;
    bool found_empty = false;

    if (!tls || !sess)
        return;

    id = SSL_SESSION_get_id(sess, &id_len);
    if (!id || id_len == 0 || id_len > SSL_MAX_SSL_SESSION_ID_LENGTH)
        return;

    pthread_mutex_lock(&tls->session_lock);
    for (size_t i = 0; i < VORTEX_TLS_SESSION_CACHE_SIZE; i++) {
        struct tls_session_entry *entry = &tls->session_cache[i];
        if (!entry->session) {
            slot = i;
            found_empty = true;
            break;
        }
        if (entry->id_len == id_len && memcmp(entry->id, id, id_len) == 0) {
            slot = i;
            found_empty = true;
            break;
        }
        time_t t = SSL_SESSION_get_time(entry->session);
        if (i == 0 || t < oldest_time) {
            oldest_time = t;
            slot = i;
        }
    }

    struct tls_session_entry *entry = &tls->session_cache[slot];
    if (entry->session)
        SSL_SESSION_free(entry->session);

    entry->session = SSL_SESSION_dup(sess);
    if (!entry->session) {
        memset(entry, 0, sizeof(*entry));
        pthread_mutex_unlock(&tls->session_lock);
        return;
    }
    entry->id_len = id_len;
    memcpy(entry->id, id, id_len);
    char id_hex[16];
    tls_session_id_prefix(id, id_len, id_hex, sizeof(id_hex));
    log_info("tls_session_store", "id_len=%u slot=%zu id=%s", id_len, slot, id_hex);
    tls_log_session_meta("tls_session_store_meta", sess);
    (void)found_empty;
    pthread_mutex_unlock(&tls->session_lock);
}

static SSL_SESSION *tls_session_cache_lookup(struct tls_ctx *tls,
                                             const unsigned char *id,
                                             unsigned int id_len)
{
    SSL_SESSION *sess = NULL;

    if (!tls || !id || id_len == 0)
        return NULL;

    pthread_mutex_lock(&tls->session_lock);
    for (size_t i = 0; i < VORTEX_TLS_SESSION_CACHE_SIZE; i++) {
        struct tls_session_entry *entry = &tls->session_cache[i];
        if (!entry->session)
            continue;
        if (entry->id_len == id_len && memcmp(entry->id, id, id_len) == 0) {
            sess = entry->session;
            break;
        }
    }
    pthread_mutex_unlock(&tls->session_lock);
    char id_hex[16];
    tls_session_id_prefix(id, id_len, id_hex, sizeof(id_hex));
    if (sess)
        log_info("tls_session_lookup", "id_len=%u hit=1 id=%s", id_len, id_hex);
    else
        log_info("tls_session_lookup", "id_len=%u hit=0 id=%s", id_len, id_hex);
    if (sess)
        tls_log_session_meta("tls_session_lookup_meta", sess);
    return sess;
}

__attribute__((unused)) static void tls_session_cache_remove(struct tls_ctx *tls, SSL_SESSION *sess)
{
    unsigned int id_len = 0;
    const unsigned char *id;

    if (!tls || !sess)
        return;

    id = SSL_SESSION_get_id(sess, &id_len);
    if (!id || id_len == 0)
        return;

    pthread_mutex_lock(&tls->session_lock);
    for (size_t i = 0; i < VORTEX_TLS_SESSION_CACHE_SIZE; i++) {
        struct tls_session_entry *entry = &tls->session_cache[i];
        if (!entry->session)
            continue;
        if (entry->id_len == id_len && memcmp(entry->id, id, id_len) == 0) {
            SSL_SESSION_free(entry->session);
            memset(entry, 0, sizeof(*entry));
            break;
        }
    }
    pthread_mutex_unlock(&tls->session_lock);
}

static int tls_new_session_cb(SSL *ssl, SSL_SESSION *sess)
{
    struct tls_ctx *tls = tls_from_ssl(ssl);
    struct tls_route_ctx *route = route_from_ssl(ssl);
    unsigned char sid_ctx[SHA256_DIGEST_LENGTH];
    unsigned int sid_len = 0;

    if (route && build_sid_ctx(route->hostname, route->route_idx, sid_ctx, &sid_len) == 0)
        SSL_SESSION_set1_id_context(sess, sid_ctx, sid_len);

    tls_session_cache_store(tls, sess);
    return 1;
}

static SSL_SESSION *tls_get_session_cb(SSL *ssl, const unsigned char *data,
                                       int len, int *copy)
{
    struct tls_ctx *tls = tls_from_ssl(ssl);
    SSL_SESSION *sess;
    const char *sni;

    if (copy)
        *copy = 0;
    if (len <= 0)
        return NULL;

    sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (tls && sni && sni[0] != '\0')
        select_route_ctx_for_sni(ssl, tls, sni);

    sess = tls_session_cache_lookup(tls, data, (unsigned int)len);
    if (!sess)
        return NULL;
    return SSL_SESSION_dup(sess);
}

static void tls_remove_session_cb(SSL_CTX *ctx, SSL_SESSION *sess)
{
    (void)ctx;
    (void)sess;
}

static int ocsp_status_cb(SSL *ssl, void *arg)
{
    struct tls_route_ctx *route_ctx = (struct tls_route_ctx *)arg;
    unsigned char *copy;

    if (!route_ctx || !route_ctx->ocsp_resp_der || route_ctx->ocsp_resp_der_len <= 0)
        return SSL_TLSEXT_ERR_NOACK;

    copy = OPENSSL_malloc((size_t)route_ctx->ocsp_resp_der_len);
    if (!copy)
        return SSL_TLSEXT_ERR_ALERT_FATAL;

    memcpy(copy, route_ctx->ocsp_resp_der, (size_t)route_ctx->ocsp_resp_der_len);
    SSL_set_tlsext_status_ocsp_resp(ssl, copy, route_ctx->ocsp_resp_der_len);
    return SSL_TLSEXT_ERR_OK;
}

static int configure_session_context(struct tls_ctx *tls,
                                     SSL_CTX *ctx,
                                     const char *hostname,
                                     int route_idx)
{
    unsigned char sid_ctx[SHA256_DIGEST_LENGTH];
    unsigned int sid_len = 0;

    if (build_sid_ctx(hostname, route_idx, sid_ctx, &sid_len) != 0)
        return -1;

    SSL_CTX_set_session_cache_mode(ctx,
        SSL_SESS_CACHE_SERVER |
        SSL_SESS_CACHE_NO_INTERNAL_STORE |
        SSL_SESS_CACHE_NO_INTERNAL_LOOKUP);
    SSL_CTX_set_timeout(ctx, tls->session_timeout ? tls->session_timeout : 3600);
    SSL_CTX_set_num_tickets(ctx, 2);
    SSL_CTX_sess_set_new_cb(ctx, tls_new_session_cb);
    SSL_CTX_sess_set_get_cb(ctx, tls_get_session_cb);
    SSL_CTX_sess_set_remove_cb(ctx, tls_remove_session_cb);
    if (SSL_CTX_set_session_id_context(ctx, sid_ctx, sid_len) != 1) {
        log_ssl_errors("tls_session");
        return -1;
    }
    return 0;
}

static int fetch_ocsp_response(struct tls_route_ctx *route_ctx,
                               X509 *leaf,
                               X509 *issuer)
{
    STACK_OF(OPENSSL_STRING) *ocsp_urls = NULL;
    const char *ocsp_url;
    OCSP_CERTID *id = NULL;
    OCSP_REQUEST *req = NULL;
    OCSP_RESPONSE *resp = NULL;
    OCSP_BASICRESP *basic = NULL;
    ASN1_GENERALIZEDTIME *rev = NULL, *thisupd = NULL, *nextupd = NULL;
    char *host = NULL, *port = NULL, *path = NULL;
    BIO *bio = NULL;
    int use_ssl = 0;
    int status = V_OCSP_CERTSTATUS_UNKNOWN;
    int reason = 0;
    unsigned char *der = NULL;
    int der_len = 0;
    int ok = -1;

    ocsp_urls = X509_get1_ocsp(leaf);
    if (!ocsp_urls || sk_OPENSSL_STRING_num(ocsp_urls) == 0)
        goto done;

    ocsp_url = sk_OPENSSL_STRING_value(ocsp_urls, 0);
    if (!ocsp_url || OCSP_parse_url(ocsp_url, &host, &port, &path, &use_ssl) != 1)
        goto done;
    if (use_ssl) {
        log_warn("tls_ocsp", "route=%d OCSP responder uses HTTPS, not fetching", route_ctx->route_idx);
        goto done;
    }

    id = OCSP_cert_to_id(NULL, leaf, issuer);
    req = OCSP_REQUEST_new();
    if (!id || !req || !OCSP_request_add0_id(req, id))
        goto done;
    id = NULL;

    bio = BIO_new_connect(host);
    if (!bio)
        goto done;
    BIO_set_conn_port(bio, port);
    if (BIO_do_connect(bio) <= 0)
        goto done;

    resp = OCSP_sendreq_bio(bio, path, req);
    if (!resp || OCSP_response_status(resp) != OCSP_RESPONSE_STATUS_SUCCESSFUL)
        goto done;

    basic = OCSP_response_get1_basic(resp);
    if (!basic)
        goto done;
    if (!OCSP_resp_find_status(basic, OCSP_onereq_get0_id(OCSP_request_onereq_get0(req, 0)),
                               &status, &reason, &rev, &thisupd, &nextupd))
        goto done;
    if (status != V_OCSP_CERTSTATUS_GOOD)
        goto done;
    if (!OCSP_check_validity(thisupd, nextupd, 300L, -1L))
        goto done;

    der_len = i2d_OCSP_RESPONSE(resp, NULL);
    if (der_len <= 0)
        goto done;

    der = malloc((size_t)der_len);
    if (!der)
        goto done;
    {
        unsigned char *p = der;
        if (i2d_OCSP_RESPONSE(resp, &p) != der_len)
            goto done;
    }

    free_route_ocsp(route_ctx);
    route_ctx->ocsp_resp_der = der;
    route_ctx->ocsp_resp_der_len = der_len;
    der = NULL;
    ok = 0;

done:
    if (ok != 0) {
        if (ERR_peek_error() != 0)
            log_ssl_errors("tls_ocsp");
    }
    if (der)
        free(der);
    if (basic)
        OCSP_BASICRESP_free(basic);
    if (resp)
        OCSP_RESPONSE_free(resp);
    if (req)
        OCSP_REQUEST_free(req);
    if (id)
        OCSP_CERTID_free(id);
    if (bio)
        BIO_free_all(bio);
    if (host)
        OPENSSL_free(host);
    if (port)
        OPENSSL_free(port);
    if (path)
        OPENSSL_free(path);
    if (ocsp_urls)
        X509_email_free(ocsp_urls);
    return ok;
}

static void maybe_load_ocsp_from_chain_bio(struct tls_route_ctx *route_ctx, BIO *bio)
{
    X509 *leaf = NULL;
    X509 *issuer = NULL;

    if (!bio)
        return;

    leaf = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (!leaf)
        goto done;
    issuer = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (!issuer)
        goto done;

    if (fetch_ocsp_response(route_ctx, leaf, issuer) == 0)
        log_info("tls_ocsp", "route=%d stapling response loaded", route_ctx->route_idx);

done:
    if (issuer)
        X509_free(issuer);
    if (leaf)
        X509_free(leaf);
}

static void configure_ssl_ctx_common(struct tls_ctx *tls,
                                     SSL_CTX *ctx,
                                     struct tls_route_ctx *route_ctx,
                                     const char *hostname)
{
    const int route_idx = route_ctx ? route_ctx->route_idx : 0;

    if (configure_session_context(tls, ctx, hostname, route_idx) != 0)
        log_warn("tls_session", "route=%d failed to configure session resumption", route_idx);

    SSL_CTX_set_app_data(ctx, (void *)hostname);
    SSL_CTX_set_ex_data(ctx, g_tls_ctx_ex_index, tls);
    SSL_CTX_set_ex_data(ctx, g_tls_route_ex_index, route_ctx);
    SSL_CTX_set_client_hello_cb(ctx, client_hello_cb, NULL);
    SSL_CTX_set_tlsext_servername_callback(ctx, sni_callback);
    SSL_CTX_set_alpn_select_cb(ctx, alpn_select_cb, NULL);
    if (route_ctx) {
        SSL_CTX_set_tlsext_status_cb(ctx, ocsp_status_cb);
        SSL_CTX_set_tlsext_status_arg(ctx, route_ctx);
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

    sd->matched_route = select_route_ctx_for_sni(ssl, tls, sni);
    if (sd->matched_route > 0) {
        log_debug("sni_match", "sni=%s route=%d", sni, sd->matched_route);
        return SSL_TLSEXT_ERR_OK;
    }
    if (tls->route_count > 0) {
        const char *h = tls->routes[0].ssl_ctx
            ? SSL_CTX_get_app_data(tls->routes[0].ssl_ctx)
            : NULL;
        if (h && strcasecmp(h, sni) == 0) {
            log_debug("sni_match", "sni=%s route=0", sni);
            return SSL_TLSEXT_ERR_OK;
        }
        if (h && h[0] == '*') {
            const char *dot = strchr(sni, '.');
            if (dot && strcasecmp(h + 1, dot) == 0) {
                log_debug("sni_wildcard", "sni=%s route=0", sni);
                return SSL_TLSEXT_ERR_OK;
            }
        }
    }

    /* No match — use default route, don't abort handshake */
    sd->matched_route = 0;
    return SSL_TLSEXT_ERR_OK;
}

/* ALPN: prefer h2 over http/1.1 for TCP connections.
 * HTTP/3 clients use QUIC and never reach this callback. */
static int alpn_select_cb(SSL *ssl, const uint8_t **out, uint8_t *outlen,
                           const uint8_t *in, unsigned int inlen, void *arg)
{
    (void)ssl; (void)arg;
    /* Wire-format: length-prefixed protocol names, server preference order */
    static const uint8_t protos[] = {
        2, 'h', '2',
        8, 'h', 't', 't', 'p', '/', '1', '.', '1',
    };
    if (SSL_select_next_proto((uint8_t **)out, outlen,
                              protos, sizeof(protos), in, inlen)
            == OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_OK;
    return SSL_TLSEXT_ERR_NOACK;
}

static SSL_CTX *create_ssl_ctx(struct tls_ctx *tls,
                                struct tls_route_ctx *route_ctx,
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
        "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256");
    SSL_CTX_set_cipher_list(ctx,
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

    configure_ssl_ctx_common(tls, ctx, route_ctx, route->hostname);

    if (route->cert_path[0] != '\0') {
        BIO *cert_bio = BIO_new_file(route->cert_path, "rb");
        maybe_load_ocsp_from_chain_bio(route_ctx, cert_bio);
        if (cert_bio)
            BIO_free(cert_bio);
    }

    return ctx;
}

int tls_init(struct tls_ctx *tls, const struct vortex_config *cfg)
{
    memset(tls, 0, sizeof(*tls));
    tls->session_timeout = cfg->tls.session_timeout;
    tls->session_ticket_rotation = cfg->tls.session_ticket_rotation;

    if (ensure_ex_indices() != 0) {
        log_error("tls_init", "failed to allocate OpenSSL ex_data indices");
        return -1;
    }

    pthread_mutex_init(&tls->ticket_lock, NULL);
    pthread_mutex_init(&tls->ocsp_lock, NULL);
    pthread_mutex_init(&tls->session_lock, NULL);

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
        tls->routes[i].hostname = cfg->routes[i].hostname;
        tls->routes[i].ssl_ctx = create_ssl_ctx(tls, &tls->routes[i], &cfg->routes[i], i);
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
        free_route_ocsp(&tls->routes[i]);
    }
    pthread_mutex_destroy(&tls->ticket_lock);
    pthread_mutex_destroy(&tls->ocsp_lock);
    pthread_mutex_lock(&tls->session_lock);
    for (size_t i = 0; i < VORTEX_TLS_SESSION_CACHE_SIZE; i++) {
        if (tls->session_cache[i].session) {
            SSL_SESSION_free(tls->session_cache[i].session);
            memset(&tls->session_cache[i], 0, sizeof(tls->session_cache[i]));
        }
    }
    pthread_mutex_unlock(&tls->session_lock);
    pthread_mutex_destroy(&tls->session_lock);
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
        snprintf(sni_out, sni_max, "%s", sni);
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
        "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256");
    SSL_CTX_set_cipher_list(ctx,
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

    configure_ssl_ctx_common(tls, ctx, NULL, hostname);
    return ctx;
}

static SSL_CTX *tls_create_ctx_from_pem_for_route(struct tls_ctx *tls,
                                                  struct tls_route_ctx *route_ctx,
                                                  const char *cert_pem,
                                                  const char *key_pem,
                                                  const char *hostname)
{
    SSL_CTX *ctx = SSL_CTX_new_ex(tls->libctx, NULL, TLS_server_method());
    if (!ctx) { log_ssl_errors("tls_create_ctx_from_pem"); return NULL; }

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_ciphersuites(ctx,
        "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256");
    SSL_CTX_set_cipher_list(ctx,
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
        SSL_CTX_add_extra_chain_cert(ctx, chain);
    }

    /* Load OCSP response from the full PEM chain before freeing the BIO */
    (void)BIO_reset(cert_bio);
    maybe_load_ocsp_from_chain_bio(route_ctx, cert_bio);
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

    configure_ssl_ctx_common(tls, ctx, route_ctx, hostname);

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

    SSL_CTX *new_ctx = tls_create_ctx_from_pem_for_route(tls, rc, cert_pem, key_pem, hostname);
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
