/*
 * acme_dns01.c — ACME DNS-01 challenge provider.
 *
 * Protocol flow:
 *   1. newOrder
 *   2. getAuthz
 *   3. Find dns-01 challenge, compute txt_value = base64url(SHA-256(key_auth))
 *   4. Create TXT record via dns_ops
 *   5. Wait propagation_wait_s for DNS propagation
 *   6. Respond to ACME challenge
 *   7. Poll authz until "valid" (max 120s)
 *   8. Delete TXT record
 *   9. Generate CSR, finalize order, download cert
 *  10. Save cert.pem and key.pem to storage_path/domain/
 */

#include "acme_dns01.h"
#include "dns_cloudflare.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>

#ifdef VORTEX_PHASE_TLS

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/provider.h>

/* ══════════════════════════════════════════════════════
 *  Local base64url (duplicated from acme_client.c — static there)
 * ══════════════════════════════════════════════════════ */

static const char B64URL_DNS[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static int dns01_b64url_encode(const unsigned char *in, size_t in_len,
                                char *out, size_t out_max)
{
    size_t i, o = 0;
    for (i = 0; i + 2 < in_len; i += 3) {
        if (o + 4 >= out_max) return -1;
        out[o++] = B64URL_DNS[(in[i]   >> 2)                    & 0x3F];
        out[o++] = B64URL_DNS[((in[i]  << 4) | (in[i+1] >> 4)) & 0x3F];
        out[o++] = B64URL_DNS[((in[i+1]<< 2) | (in[i+2] >> 6)) & 0x3F];
        out[o++] = B64URL_DNS[ in[i+2]                          & 0x3F];
    }
    if (i < in_len) {
        if (o + 2 >= out_max) return -1;
        out[o++] = B64URL_DNS[(in[i] >> 2) & 0x3F];
        if (i + 1 < in_len) {
            out[o++] = B64URL_DNS[((in[i] << 4) | (in[i+1] >> 4)) & 0x3F];
            if (o + 1 >= out_max) return -1;
            out[o++] = B64URL_DNS[(in[i+1] << 2) & 0x3F];
        } else {
            out[o++] = B64URL_DNS[(in[i] << 4) & 0x3F];
        }
    }
    out[o] = '\0';
    return (int)o;
}

/* ══════════════════════════════════════════════════════
 *  Local JSON helpers
 * ══════════════════════════════════════════════════════ */

static int dns01_json_get_str(const char *json, const char *key,
                               char *out, size_t out_max)
{
    char needle[256];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle);
    if (!p) return -1;
    p += strlen(needle);
    while (*p == ' ' || *p == ':' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p != '"') return -1;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < out_max) {
        if (*p == '\\') { p++; if (!*p) break; }
        out[i++] = *p++;
    }
    out[i] = '\0';
    return 0;
}

static int dns01_json_get_array_first(const char *json, const char *key,
                                       char *out, size_t out_max)
{
    char needle[256];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle);
    if (!p) return -1;
    p += strlen(needle);
    while (*p == ' ' || *p == ':' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p != '[') return -1;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p != '"') return -1;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < out_max) out[i++] = *p++;
    out[i] = '\0';
    return 0;
}

/*
 * Find JSON object in challenges array with "type": "dns-01" and extract
 * "token" and "url".
 */
static int dns01_find_dns01_challenge(const char *json,
                                       char *token, size_t token_max,
                                       char *url,   size_t url_max)
{
    const char *p = json;
    while ((p = strstr(p, "\"type\"")) != NULL) {
        const char *tp = p + 6;
        while (*tp == ' ' || *tp == ':' || *tp == '"') tp++;
        if (strncmp(tp, "dns-01", 6) == 0) {
            /* Backtrack to find the enclosing { */
            const char *bp = p;
            int depth = 0;
            while (bp > json && !(depth == 0 && *bp == '{')) {
                if (*bp == '}') depth++;
                if (*bp == '{') depth--;
                bp--;
            }
            /* Walk forward to find matching } */
            const char *ep = p;
            depth = 0;
            while (*ep) {
                if (*ep == '{') depth++;
                if (*ep == '}') { if (--depth <= 0) break; }
                ep++;
            }
            size_t obj_len = (size_t)(ep - bp) + 1;
            char *obj = malloc(obj_len + 1);
            if (!obj) return -1;
            memcpy(obj, bp, obj_len);
            obj[obj_len] = '\0';
            int r1 = dns01_json_get_str(obj, "token", token, token_max);
            int r2 = dns01_json_get_str(obj, "url",   url,   url_max);
            free(obj);
            if (r1 == 0 && r2 == 0) return 0;
        }
        p++;
    }
    return -1;
}

/* ══════════════════════════════════════════════════════
 *  HTTPS client (mirrors acme_client.c pattern)
 * ══════════════════════════════════════════════════════ */

static int dns01_parse_url(const char *url,
                            char *host, size_t host_max,
                            int *port,
                            char *path, size_t path_max)
{
    if (strncmp(url, "https://", 8) != 0 && strncmp(url, "http://", 7) != 0)
        return -1;
    int is_https = (url[4] == 's');
    const char *p = url + (is_https ? 8 : 7);

    const char *slash = strchr(p, '/');
    const char *colon = strchr(p, ':');

    if (colon && (!slash || colon < slash)) {
        size_t hlen = (size_t)(colon - p);
        if (hlen >= host_max) return -1;
        memcpy(host, p, hlen); host[hlen] = '\0';
        *port = atoi(colon + 1);
    } else {
        size_t hlen = slash ? (size_t)(slash - p) : strlen(p);
        if (hlen >= host_max) return -1;
        memcpy(host, p, hlen); host[hlen] = '\0';
        *port = is_https ? 443 : 80;
    }

    if (slash) {
        strncpy(path, slash, path_max - 1);
        path[path_max - 1] = '\0';
    } else {
        strncpy(path, "/", path_max - 1);
    }
    return 0;
}

/*
 * Make an HTTPS request using the acme_client's https_ctx.
 * Returns 0 on success, -1 on failure.
 * *resp_out is heap-allocated (caller frees).
 */
static int dns01_https_request(struct acme_client *cl,
                                const char *method,
                                const char *url,
                                const char *body,
                                size_t body_len,
                                int  *status_out,
                                char *location_out, size_t loc_max,
                                char *nonce_out,    size_t nonce_max,
                                char **resp_out,    size_t *resp_len_out)
{
    char host[256], path[512];
    int port;

    if (dns01_parse_url(url, host, sizeof(host), &port, path, sizeof(path)) < 0) {
        log_error("acme_dns01", "bad url: %s", url);
        return -1;
    }

    char hostport[280];
    snprintf(hostport, sizeof(hostport), "%s:%d", host, port);

    BIO *bio = BIO_new_ssl_connect(cl->https_ctx);
    if (!bio) {
        log_error("acme_dns01", "BIO_new_ssl_connect failed");
        return -1;
    }

    SSL *ssl_ptr = NULL;
    BIO_get_ssl(bio, &ssl_ptr);
    if (ssl_ptr) SSL_set_tlsext_host_name(ssl_ptr, host);

    BIO_set_conn_hostname(bio, hostport);

    if (BIO_do_connect(bio) <= 0) {
        log_error("acme_dns01", "connect to %s failed", hostport);
        BIO_free_all(bio);
        return -1;
    }

    char req_hdr[2048];
    int hdr_len;
    if (body && body_len > 0) {
        hdr_len = snprintf(req_hdr, sizeof(req_hdr),
            "%s %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Content-Type: application/jose+json\r\n"
            "Content-Length: %zu\r\n"
            "Connection: close\r\n"
            "User-Agent: vortex/0.1\r\n"
            "\r\n",
            method, path, host, body_len);
    } else {
        hdr_len = snprintf(req_hdr, sizeof(req_hdr),
            "%s %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Connection: close\r\n"
            "User-Agent: vortex/0.1\r\n"
            "\r\n",
            method, path, host);
    }

    if (BIO_write(bio, req_hdr, hdr_len) != hdr_len) goto io_err;
    if (body && body_len > 0) {
        if (BIO_write(bio, body, (int)body_len) != (int)body_len) goto io_err;
    }
    (void)BIO_flush(bio);

    size_t total = 0, cap = 65536;
    char *rbuf = malloc(cap);
    if (!rbuf) { BIO_free_all(bio); return -1; }

    for (;;) {
        if (total + 1 >= cap) {
            cap *= 2;
            char *tmp = realloc(rbuf, cap);
            if (!tmp) { free(rbuf); BIO_free_all(bio); return -1; }
            rbuf = tmp;
        }
        int n = BIO_read(bio, rbuf + total, (int)(cap - total - 1));
        if (n <= 0) break;
        total += (size_t)n;
    }
    rbuf[total] = '\0';
    BIO_free_all(bio);

    if (total == 0) {
        free(rbuf);
        log_error("acme_dns01", "empty response from %s", url);
        return -1;
    }

    *status_out = 0;
    if (sscanf(rbuf, "HTTP/%*d.%*d %d", status_out) != 1) {
        free(rbuf);
        log_error("acme_dns01", "bad status line");
        return -1;
    }

    if (location_out) location_out[0] = '\0';
    if (nonce_out)    nonce_out[0]    = '\0';

    char *hdrs_end = strstr(rbuf, "\r\n\r\n");
    if (!hdrs_end) hdrs_end = rbuf + total;

    if (nonce_out && nonce_max > 0) {
        const char *nh = strcasestr(rbuf, "\r\nReplay-Nonce:");
        if (nh) {
            nh += 15;
            while (*nh == ' ') nh++;
            const char *ne = strstr(nh, "\r\n");
            size_t nlen = ne ? (size_t)(ne - nh) : strlen(nh);
            if (nlen >= nonce_max) nlen = nonce_max - 1;
            memcpy(nonce_out, nh, nlen);
            nonce_out[nlen] = '\0';
        }
    }

    if (location_out && loc_max > 0) {
        const char *lh = strcasestr(rbuf, "\r\nLocation:");
        if (lh) {
            lh += 11;
            while (*lh == ' ') lh++;
            const char *le = strstr(lh, "\r\n");
            size_t llen = le ? (size_t)(le - lh) : strlen(lh);
            if (llen >= loc_max) llen = loc_max - 1;
            memcpy(location_out, lh, llen);
            location_out[llen] = '\0';
        }
    }

    char *body_start = hdrs_end ? hdrs_end + 4 : rbuf + total;
    size_t body_sz = (size_t)(rbuf + total - body_start);

    if (resp_out) {
        char *copy = malloc(body_sz + 1);
        if (!copy) { free(rbuf); return -1; }
        memcpy(copy, body_start, body_sz);
        copy[body_sz] = '\0';
        *resp_out = copy;
        if (resp_len_out) *resp_len_out = body_sz;
    }

    free(rbuf);
    return 0;

io_err:
    log_error("acme_dns01", "I/O error writing to %s", hostport);
    BIO_free_all(bio);
    return -1;
}

/* ══════════════════════════════════════════════════════
 *  JWK / JWS helpers (duplicated locally — static in acme_client.c)
 * ══════════════════════════════════════════════════════ */

static int dns01_eckey_to_jwk(EVP_PKEY *pkey, char *out, size_t out_max)
{
    unsigned char pub[65];
    size_t pub_len = sizeof(pub);
    if (EVP_PKEY_get_octet_string_param(pkey, "pub", pub, pub_len, &pub_len) <= 0)
        return -1;
    if (pub_len != 65 || pub[0] != 0x04) return -1;

    char xb64[64], yb64[64];
    if (dns01_b64url_encode(pub + 1,  32, xb64, sizeof(xb64)) < 0) return -1;
    if (dns01_b64url_encode(pub + 33, 32, yb64, sizeof(yb64)) < 0) return -1;

    int n = snprintf(out, out_max,
        "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"%s\",\"y\":\"%s\"}",
        xb64, yb64);
    return (n > 0 && (size_t)n < out_max) ? 0 : -1;
}

static int dns01_ecdsa_sign_raw(EVP_PKEY *pkey,
                                 const unsigned char *msg, size_t msg_len,
                                 unsigned char *sig_out, size_t *sig_len_out)
{
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) return -1;

    unsigned char der_sig[128];
    size_t der_len = sizeof(der_sig);

    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) != 1 ||
        EVP_DigestSign(mdctx, der_sig, &der_len, msg, msg_len) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }
    EVP_MD_CTX_free(mdctx);

    ECDSA_SIG *esig = d2i_ECDSA_SIG(NULL, &(const unsigned char *){ der_sig },
                                     (long)der_len);
    if (!esig) return -1;

    const BIGNUM *r, *s;
    ECDSA_SIG_get0(esig, &r, &s);

    *sig_len_out = 64;
    memset(sig_out, 0, 64);
    int rlen = BN_num_bytes(r), slen = BN_num_bytes(s);
    BN_bn2bin(r, sig_out + 32 - rlen);
    BN_bn2bin(s, sig_out + 64 - slen);
    ECDSA_SIG_free(esig);
    return 0;
}

/*
 * Build a JWS-signed request body.
 * kid != NULL → use kid header; kid == NULL → embed JWK (for newAccount only).
 */
static char *dns01_make_jws(EVP_PKEY *pkey,
                              const char *nonce,
                              const char *url,
                              const char *payload_json,
                              const char *kid)
{
    char hdr_json[1024];
    if (kid && kid[0]) {
        snprintf(hdr_json, sizeof(hdr_json),
            "{\"alg\":\"ES256\",\"nonce\":\"%s\",\"url\":\"%s\","
            "\"kid\":\"%s\"}",
            nonce, url, kid);
    } else {
        char jwk[256];
        if (dns01_eckey_to_jwk(pkey, jwk, sizeof(jwk)) < 0) return NULL;
        snprintf(hdr_json, sizeof(hdr_json),
            "{\"alg\":\"ES256\",\"nonce\":\"%s\",\"url\":\"%s\","
            "\"jwk\":%s}",
            nonce, url, jwk);
    }

    char hdr_b64[1024], pay_b64[4096];
    if (dns01_b64url_encode((unsigned char *)hdr_json, strlen(hdr_json),
                             hdr_b64, sizeof(hdr_b64)) < 0) return NULL;

    const char *payload = payload_json ? payload_json : "";
    if (dns01_b64url_encode((unsigned char *)payload, strlen(payload),
                             pay_b64, sizeof(pay_b64)) < 0) return NULL;

    char si[8192];
    int si_len = snprintf(si, sizeof(si), "%s.%s", hdr_b64, pay_b64);
    if (si_len <= 0 || (size_t)si_len >= sizeof(si)) return NULL;

    unsigned char raw_sig[64];
    size_t raw_sig_len;
    if (dns01_ecdsa_sign_raw(pkey, (unsigned char *)si, (size_t)si_len,
                              raw_sig, &raw_sig_len) < 0) return NULL;

    char sig_b64[128];
    if (dns01_b64url_encode(raw_sig, raw_sig_len, sig_b64, sizeof(sig_b64)) < 0)
        return NULL;

    size_t jws_max = strlen(hdr_b64) + strlen(pay_b64) + strlen(sig_b64) + 256;
    char *jws = malloc(jws_max);
    if (!jws) return NULL;
    snprintf(jws, jws_max,
        "{\"protected\":\"%s\",\"payload\":\"%s\",\"signature\":\"%s\"}",
        hdr_b64, pay_b64, sig_b64);
    return jws;
}

static int dns01_get_nonce(struct acme_client *cl,
                            char *nonce, size_t nmax)
{
    int status;
    char loc[8] = "";
    if (dns01_https_request(cl, "HEAD", cl->newNonce_url,
                             NULL, 0,
                             &status, loc, sizeof(loc),
                             nonce, nmax,
                             NULL, NULL) < 0) return -1;
    if (nonce[0] == '\0') {
        log_error("acme_dns01", "no nonce in HEAD response");
        return -1;
    }
    return 0;
}

/* ══════════════════════════════════════════════════════
 *  CSR generation (duplicated locally — static in acme_client.c)
 * ══════════════════════════════════════════════════════ */

static int dns01_make_csr_der(const char *domain,
                               EVP_PKEY **pkey_out,
                               unsigned char **csr_der, size_t *csr_len)
{
    EVP_PKEY_CTX *pkctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!pkctx) return -1;
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen_init(pkctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pkctx, NID_X9_62_prime256v1) <= 0 ||
        EVP_PKEY_generate(pkctx, &pkey) <= 0)
    {
        EVP_PKEY_CTX_free(pkctx);
        return -1;
    }
    EVP_PKEY_CTX_free(pkctx);

    X509_REQ *req = X509_REQ_new();
    if (!req) { EVP_PKEY_free(pkey); return -1; }

    X509_REQ_set_pubkey(req, pkey);

    X509_NAME *name = (X509_NAME *)X509_REQ_get_subject_name(req);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        (unsigned char *)domain, -1, -1, 0);

    STACK_OF(X509_EXTENSION) *exts = sk_X509_EXTENSION_new_null();
    char san[320];
    snprintf(san, sizeof(san), "DNS:%s", domain);
    X509V3_CTX v3ctx;
    X509V3_set_ctx_nodb(&v3ctx);
    X509V3_set_ctx(&v3ctx, NULL, NULL, req, NULL, 0);
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &v3ctx,
                           NID_subject_alt_name, san);
    if (ext) {
        sk_X509_EXTENSION_push(exts, ext);
        X509_REQ_add_extensions(req, exts);
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    }

    if (X509_REQ_sign(req, pkey, EVP_sha256()) == 0) {
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        return -1;
    }

    *csr_len = (size_t)i2d_X509_REQ(req, NULL);
    *csr_der = malloc(*csr_len);
    if (!*csr_der) { X509_REQ_free(req); EVP_PKEY_free(pkey); return -1; }
    unsigned char *p = *csr_der;
    i2d_X509_REQ(req, &p);
    X509_REQ_free(req);

    *pkey_out = pkey;
    return 0;
}

/* ══════════════════════════════════════════════════════
 *  Poll order/authz for a specific status
 * ══════════════════════════════════════════════════════ */

static int dns01_poll_for_status(struct acme_client *cl,
                                  const char *url,
                                  const char *want_status,
                                  int timeout_s)
{
    time_t deadline = time(NULL) + timeout_s;
    for (;;) {
        char nonce[256], loc[8] = "";
        char *body = NULL;
        int status;

        if (dns01_get_nonce(cl, nonce, sizeof(nonce)) < 0) return -1;

        char *jws = dns01_make_jws(cl->account_key, nonce, url,
                                   NULL /* POST-as-GET */,
                                   cl->account_url);
        if (!jws) return -1;

        int r = dns01_https_request(cl, "POST", url,
                                     jws, strlen(jws),
                                     &status, loc, sizeof(loc),
                                     nonce, sizeof(nonce),
                                     &body, NULL);
        free(jws);
        if (r < 0) { free(body); return -1; }

        char obj_status[64] = "";
        dns01_json_get_str(body ? body : "", "status",
                           obj_status, sizeof(obj_status));
        free(body);

        log_debug("acme_dns01", "poll %s → status=%s (want %s)",
                  url, obj_status, want_status);

        if (strcmp(obj_status, want_status) == 0) return 0;
        if (strcmp(obj_status, "invalid")   == 0) {
            log_error("acme_dns01", "order/authz went invalid at %s", url);
            return -1;
        }

        if (time(NULL) >= deadline) {
            log_error("acme_dns01", "timeout polling %s (last status=%s)",
                      url, obj_status);
            return -1;
        }
        sleep(3);
    }
}

/* ══════════════════════════════════════════════════════
 *  Storage helpers
 * ══════════════════════════════════════════════════════ */

static int dns01_ensure_dir(const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0) return S_ISDIR(st.st_mode) ? 0 : -1;
    return mkdir(path, 0700);
}

/* ══════════════════════════════════════════════════════
 *  Main: obtain certificate via DNS-01
 * ══════════════════════════════════════════════════════ */

int acme_obtain_dns01(struct acme_dns01_ctx *dctx,
                       const char *domain,
                       struct cert_result *out)
{
    struct acme_client *cl = &dctx->client;
    char nonce[256], loc[ACME_MAX_URL] = "";
    char *resp = NULL;
    int status;
    int rc = -1;

    /* Track the TXT record for cleanup */
    char txt_record_id[512] = "";
    char txt_name[320]      = "";
    int  txt_created        = 0;

    /* Track domain key for cleanup on error paths */
    EVP_PKEY *domain_key = NULL;

    /* ── 1. new-order ── */
    if (dns01_get_nonce(cl, nonce, sizeof(nonce)) < 0) goto done;
    {
        char pay[512];
        snprintf(pay, sizeof(pay),
            "{\"identifiers\":[{\"type\":\"dns\",\"value\":\"%s\"}]}", domain);
        char *jws = dns01_make_jws(cl->account_key, nonce, cl->newOrder_url,
                                   pay, cl->account_url);
        if (!jws) goto done;
        int r = dns01_https_request(cl, "POST", cl->newOrder_url,
                                     jws, strlen(jws),
                                     &status, loc, sizeof(loc),
                                     nonce, sizeof(nonce),
                                     &resp, NULL);
        free(jws);
        if (r < 0 || (status != 201 && status != 200)) {
            log_error("acme_dns01", "newOrder returned %d: %s",
                      status, resp ? resp : "");
            goto done;
        }
    }

    char order_url[ACME_MAX_URL];
    strncpy(order_url, loc, sizeof(order_url) - 1);
    order_url[sizeof(order_url) - 1] = '\0';

    char finalize_url[ACME_MAX_URL] = "";
    char authz_url[ACME_MAX_URL]    = "";
    dns01_json_get_str(resp, "finalize", finalize_url, sizeof(finalize_url));
    dns01_json_get_array_first(resp, "authorizations", authz_url, sizeof(authz_url));
    free(resp); resp = NULL;

    if (!finalize_url[0] || !authz_url[0]) {
        log_error("acme_dns01", "order missing finalize or authorizations");
        goto done;
    }

    /* ── 2. Get authorization ── */
    if (dns01_get_nonce(cl, nonce, sizeof(nonce)) < 0) goto done;
    {
        char loc2[8] = "";
        char *jws = dns01_make_jws(cl->account_key, nonce, authz_url,
                                   NULL /* POST-as-GET */, cl->account_url);
        if (!jws) goto done;
        int r = dns01_https_request(cl, "POST", authz_url,
                                     jws, strlen(jws),
                                     &status, loc2, sizeof(loc2),
                                     nonce, sizeof(nonce),
                                     &resp, NULL);
        free(jws);
        if (r < 0 || status != 200) {
            log_error("acme_dns01", "get authz returned %d", status);
            goto done;
        }
    }

    char challenge_token[256]      = "";
    char challenge_url[ACME_MAX_URL] = "";
    if (dns01_find_dns01_challenge(resp ? resp : "",
                                   challenge_token, sizeof(challenge_token),
                                   challenge_url,   sizeof(challenge_url)) < 0) {
        log_error("acme_dns01", "no dns-01 challenge in authorization");
        goto done;
    }
    free(resp); resp = NULL;

    /* ── 3. Compute key_auth and TXT value ── */
    /* key_auth = token + "." + thumbprint */
    char key_auth[512];
    {
        int n = snprintf(key_auth, sizeof(key_auth), "%s.%s",
                         challenge_token, cl->jwk_thumbprint);
        if (n <= 0 || (size_t)n >= sizeof(key_auth)) {
            log_error("acme_dns01", "key_auth buffer overflow");
            goto done;
        }
    }

    /* txt_value = base64url(SHA-256(key_auth)) */
    char txt_value[64] = "";
    {
        unsigned char digest[32];
        unsigned int dlen = 0;
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        if (!mdctx) goto done;
        if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1 ||
            EVP_DigestUpdate(mdctx, key_auth, strlen(key_auth)) != 1 ||
            EVP_DigestFinal_ex(mdctx, digest, &dlen) != 1)
        {
            EVP_MD_CTX_free(mdctx);
            log_error("acme_dns01", "SHA-256 of key_auth failed");
            goto done;
        }
        EVP_MD_CTX_free(mdctx);
        if (dns01_b64url_encode(digest, 32, txt_value, sizeof(txt_value)) < 0) {
            log_error("acme_dns01", "base64url of digest failed");
            goto done;
        }
    }

    /* ── 4. Create TXT record ── */
    snprintf(txt_name, sizeof(txt_name), "_acme-challenge.%s", domain);

    if (dctx->dns_ops->create_txt(dctx->dns_ctx,
                                   txt_name, txt_value,
                                   txt_record_id, sizeof(txt_record_id)) < 0) {
        log_error("acme_dns01", "failed to create TXT record for %s", txt_name);
        goto done;
    }
    txt_created = 1;
    log_info("acme_dns01", "TXT record created: %s = %s", txt_name, txt_value);

    /* ── 5. Wait for DNS propagation ── */
    {
        int wait_s = dctx->propagation_wait_s > 0
                   ? dctx->propagation_wait_s : 90;
        log_info("acme_dns01", "waiting %ds for DNS propagation...", wait_s);
        sleep((unsigned int)wait_s);
    }

    /* ── 6. Respond to challenge ── */
    if (dns01_get_nonce(cl, nonce, sizeof(nonce)) < 0) goto done;
    {
        char loc2[8] = "";
        char *jws = dns01_make_jws(cl->account_key, nonce, challenge_url,
                                   "{}", cl->account_url);
        if (!jws) goto done;
        int r = dns01_https_request(cl, "POST", challenge_url,
                                     jws, strlen(jws),
                                     &status, loc2, sizeof(loc2),
                                     nonce, sizeof(nonce),
                                     &resp, NULL);
        free(jws);
        if (r < 0 || (status != 200 && status != 202)) {
            log_error("acme_dns01", "respond to challenge returned %d: %s",
                      status, resp ? resp : "");
            goto done;
        }
        free(resp); resp = NULL;
    }
    log_info("acme_dns01", "notified ACME of DNS-01 challenge response");

    /* ── 7. Poll authz until valid (max 120s) ── */
    if (dns01_poll_for_status(cl, authz_url, "valid", 120) < 0) {
        log_error("acme_dns01", "authz did not become valid");
        goto done;
    }
    log_info("acme_dns01", "authz is valid");

    /* ── 8. Delete TXT record ── */
    if (txt_created) {
        dctx->dns_ops->delete_txt(dctx->dns_ctx,
                                   dctx->zone_id[0] ? dctx->zone_id : "",
                                   txt_record_id);
        txt_created = 0;
        log_info("acme_dns01", "TXT record deleted");
    }

    /* ── 9. Generate CSR ── */
    unsigned char *csr_der = NULL;
    size_t csr_len = 0;
    if (dns01_make_csr_der(domain, &domain_key, &csr_der, &csr_len) < 0) {
        log_error("acme_dns01", "CSR generation failed");
        goto done;
    }

    /* ── 10. Finalize order ── */
    {
        char csr_b64[4096];
        if (dns01_b64url_encode(csr_der, csr_len, csr_b64, sizeof(csr_b64)) < 0) {
            free(csr_der);
            log_error("acme_dns01", "base64url encode of CSR failed");
            goto done;
        }
        free(csr_der); csr_der = NULL;

        char pay[5000];
        snprintf(pay, sizeof(pay), "{\"csr\":\"%s\"}", csr_b64);

        if (dns01_get_nonce(cl, nonce, sizeof(nonce)) < 0) goto done;

        char loc2[8] = "";
        char *jws = dns01_make_jws(cl->account_key, nonce, finalize_url,
                                   pay, cl->account_url);
        if (!jws) goto done;

        int r = dns01_https_request(cl, "POST", finalize_url,
                                     jws, strlen(jws),
                                     &status, loc2, sizeof(loc2),
                                     nonce, sizeof(nonce),
                                     &resp, NULL);
        free(jws);
        if (r < 0 || (status != 200 && status != 201)) {
            log_error("acme_dns01", "finalize returned %d: %s",
                      status, resp ? resp : "");
            goto done;
        }
        free(resp); resp = NULL;
    }

    /* ── 11. Poll order until valid ── */
    if (order_url[0]) {
        if (dns01_poll_for_status(cl, order_url, "valid", 120) < 0) {
            log_error("acme_dns01", "order did not become valid");
            goto done;
        }
    }

    /* ── 12. Re-fetch order to get certificate URL ── */
    {
        if (dns01_get_nonce(cl, nonce, sizeof(nonce)) < 0) goto done;
        char loc2[8] = "";
        char *jws = dns01_make_jws(cl->account_key, nonce, order_url,
                                   NULL /* POST-as-GET */, cl->account_url);
        if (!jws) goto done;
        int r = dns01_https_request(cl, "POST", order_url,
                                     jws, strlen(jws),
                                     &status, loc2, sizeof(loc2),
                                     nonce, sizeof(nonce),
                                     &resp, NULL);
        free(jws);
        if (r < 0 || status != 200) {
            log_error("acme_dns01", "order fetch returned %d", status);
            goto done;
        }
    }

    char cert_url[ACME_MAX_URL] = "";
    dns01_json_get_str(resp ? resp : "", "certificate",
                       cert_url, sizeof(cert_url));
    free(resp); resp = NULL;

    if (!cert_url[0]) {
        log_error("acme_dns01", "no certificate URL in finalized order");
        goto done;
    }

    /* ── 13. Download certificate ── */
    if (dns01_get_nonce(cl, nonce, sizeof(nonce)) < 0) goto done;
    {
        char loc2[8] = "";
        char *jws = dns01_make_jws(cl->account_key, nonce, cert_url,
                                   NULL /* POST-as-GET */, cl->account_url);
        if (!jws) goto done;
        int r = dns01_https_request(cl, "POST", cert_url,
                                     jws, strlen(jws),
                                     &status, loc2, sizeof(loc2),
                                     nonce, sizeof(nonce),
                                     &resp, NULL);
        free(jws);
        if (r < 0 || status != 200) {
            log_error("acme_dns01", "cert download returned %d", status);
            goto done;
        }
    }

    /* resp contains the PEM certificate chain */

    /* Encode domain private key to PEM */
    BIO *keybio = BIO_new(BIO_s_mem());
    if (!keybio) { free(resp); goto done; }
    PEM_write_bio_PrivateKey(keybio, domain_key, NULL, NULL, 0, NULL, NULL);
    BUF_MEM *bm = NULL;
    BIO_get_mem_ptr(keybio, &bm);
    char *key_pem = malloc(bm->length + 1);
    if (key_pem) {
        memcpy(key_pem, bm->data, bm->length);
        key_pem[bm->length] = '\0';
    }
    BIO_free(keybio);
    EVP_PKEY_free(domain_key); domain_key = NULL;

    if (!key_pem) { free(resp); goto done; }

    /* ── 14. Save cert.pem and key.pem to storage_path/domain/ ── */
    {
        char dom_dir[4096];
        snprintf(dom_dir, sizeof(dom_dir), "%s/%s",
                 cl->storage_path, domain);
        dns01_ensure_dir(cl->storage_path);
        dns01_ensure_dir(dom_dir);

        /* cert.pem */
        char cert_path[4096];
        snprintf(cert_path, sizeof(cert_path), "%s/%s/cert.pem",
                 cl->storage_path, domain);
        FILE *cf = fopen(cert_path, "wb");
        if (cf) { fwrite(resp, 1, strlen(resp), cf); fclose(cf); }

        /* key.pem — mode 0600 */
        char key_path[4096];
        snprintf(key_path, sizeof(key_path), "%s/%s/key.pem",
                 cl->storage_path, domain);
        int kfd = open(key_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (kfd >= 0) {
            FILE *kf = fdopen(kfd, "wb");
            if (kf) { fwrite(key_pem, 1, strlen(key_pem), kf); fclose(kf); }
            else close(kfd);
        }
        log_info("acme_dns01", "certificate saved: %s", cert_path);
    }

    /* Fill result */
    out->cert_pem  = resp; resp = NULL;
    out->key_pem   = key_pem;
    out->not_after = 0;
    {
        BIO *bio = BIO_new_mem_buf(out->cert_pem, -1);
        X509 *x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        BIO_free(bio);
        if (x509) {
            const ASN1_TIME *na = X509_get0_notAfter(x509);
            struct tm tm_val;
            memset(&tm_val, 0, sizeof(tm_val));
            ASN1_TIME_to_tm(na, &tm_val);
            out->not_after = timegm(&tm_val);
            X509_free(x509);
        }
    }
    rc = 0;

done:
    free(resp);
    if (domain_key) EVP_PKEY_free(domain_key);

    /* Clean up TXT record if something failed after it was created */
    if (txt_created) {
        log_warn("acme_dns01", "cleaning up TXT record after failure");
        dctx->dns_ops->delete_txt(dctx->dns_ctx,
                                   dctx->zone_id[0] ? dctx->zone_id : "",
                                   txt_record_id);
    }

    return rc;
}

/* ══════════════════════════════════════════════════════
 *  cert_provider_ops vtable implementation
 * ══════════════════════════════════════════════════════ */

static int dns01_provider_init(void **provider_ctx,
                                const struct vortex_config *cfg)
{
    struct acme_dns01_ctx *dctx = calloc(1, sizeof(*dctx));
    if (!dctx) return -1;

    /* Configure the embedded acme_client from cfg->acme */
    const struct acme_config *ac = &cfg->acme;
    strncpy(dctx->client.directory_url,    ac->directory_url,
            sizeof(dctx->client.directory_url) - 1);
    strncpy(dctx->client.account_key_path, ac->account_key_path,
            sizeof(dctx->client.account_key_path) - 1);
    strncpy(dctx->client.storage_path,     ac->storage_path,
            sizeof(dctx->client.storage_path) - 1);
    strncpy(dctx->client.email,            ac->email,
            sizeof(dctx->client.email) - 1);
    dctx->client.renewal_days = ac->renewal_days;

    if (acme_client_init(&dctx->client) < 0) {
        log_error("acme_dns01", "acme_client_init failed");
        free(dctx);
        return -1;
    }

    /* Select DNS provider — currently only Cloudflare is built in */
    if (strcmp(ac->dns_provider, "cloudflare") == 0 ||
        ac->dns_provider[0] == '\0')
    {
        dctx->dns_ops = &cloudflare_dns_provider;
    } else {
        log_error("acme_dns01", "unknown dns_provider: %s", ac->dns_provider);
        acme_client_destroy(&dctx->client);
        free(dctx);
        return -1;
    }

    if (dctx->dns_ops->init(&dctx->dns_ctx, ac->dns_api_token) < 0) {
        log_error("acme_dns01", "dns provider init failed");
        acme_client_destroy(&dctx->client);
        free(dctx);
        return -1;
    }

    dctx->propagation_wait_s = 90;

    *provider_ctx = dctx;
    return 0;
}

static int dns01_provider_obtain(void *provider_ctx, const char *domain,
                                  struct cert_result *out)
{
    return acme_obtain_dns01((struct acme_dns01_ctx *)provider_ctx,
                              domain, out);
}

static int dns01_provider_renew(void *provider_ctx, const char *domain,
                                 struct cert_result *out)
{
    return acme_obtain_dns01((struct acme_dns01_ctx *)provider_ctx,
                              domain, out);
}

static void dns01_provider_free_result(struct cert_result *result)
{
    cert_result_free(result);
}

static void dns01_provider_destroy(void *provider_ctx)
{
    struct acme_dns01_ctx *dctx = (struct acme_dns01_ctx *)provider_ctx;
    if (!dctx) return;
    acme_client_destroy(&dctx->client);
    if (dctx->dns_ops && dctx->dns_ctx)
        dctx->dns_ops->destroy(dctx->dns_ctx);
    free(dctx);
}

const struct cert_provider_ops acme_dns01_provider = {
    .name        = "acme_dns01",
    .init        = dns01_provider_init,
    .obtain      = dns01_provider_obtain,
    .renew       = dns01_provider_renew,
    .free_result = dns01_provider_free_result,
    .destroy     = dns01_provider_destroy,
};

#else /* !VORTEX_PHASE_TLS */

int acme_obtain_dns01(struct acme_dns01_ctx *ctx,
                       const char *domain,
                       struct cert_result *out)
{ (void)ctx; (void)domain; (void)out; return -1; }

static int dns01_provider_init_stub(void **ctx,
                                     const struct vortex_config *cfg)
{ (void)ctx; (void)cfg; return -1; }

static int dns01_provider_obtain_stub(void *ctx, const char *domain,
                                       struct cert_result *out)
{ (void)ctx; (void)domain; (void)out; return -1; }

static int dns01_provider_renew_stub(void *ctx, const char *domain,
                                      struct cert_result *out)
{ (void)ctx; (void)domain; (void)out; return -1; }

static void dns01_provider_free_result_stub(struct cert_result *r)
{ (void)r; }

static void dns01_provider_destroy_stub(void *ctx) { (void)ctx; }

const struct cert_provider_ops acme_dns01_provider = {
    .name        = "acme_dns01",
    .init        = dns01_provider_init_stub,
    .obtain      = dns01_provider_obtain_stub,
    .renew       = dns01_provider_renew_stub,
    .free_result = dns01_provider_free_result_stub,
    .destroy     = dns01_provider_destroy_stub,
};

#endif /* VORTEX_PHASE_TLS */
