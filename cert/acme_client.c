/*
 * acme_client.c — RFC 8555 ACME client, HTTP-01 challenge
 *
 * Protocol flow:
 *   1. Load/generate ECDSA P-256 account key
 *   2. Fetch ACME directory to learn endpoint URLs
 *   3. Register account (or find existing via key)
 *   4. For each domain: new-order → get-authz → HTTP-01 challenge →
 *      finalize (with CSR) → download cert
 */

#include "acme_client.h"
#include "log.h"
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

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
 *  Base64url helpers (RFC 4648 §5 — no padding)
 * ══════════════════════════════════════════════════════ */

static const char B64URL[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

int b64url_encode(const unsigned char *in, size_t in_len,
                  char *out, size_t out_max)
{
    size_t i, o = 0;
    for (i = 0; i + 2 < in_len; i += 3) {
        if (o + 4 >= out_max) return -1;
        out[o++] = B64URL[(in[i]   >> 2)                     & 0x3F];
        out[o++] = B64URL[((in[i]  << 4) | (in[i+1] >> 4))  & 0x3F];
        out[o++] = B64URL[((in[i+1]<< 2) | (in[i+2] >> 6))  & 0x3F];
        out[o++] = B64URL[ in[i+2]                           & 0x3F];
    }
    if (i < in_len) {
        if (o + 2 >= out_max) return -1;
        out[o++] = B64URL[(in[i] >> 2) & 0x3F];
        if (i + 1 < in_len) {
            out[o++] = B64URL[((in[i] << 4) | (in[i+1] >> 4)) & 0x3F];
            if (o + 1 >= out_max) return -1;
            out[o++] = B64URL[(in[i+1] << 2) & 0x3F];
        } else {
            out[o++] = B64URL[(in[i] << 4) & 0x3F];
        }
    }
    out[o] = '\0';
    return (int)o;
}

int b64url_decode(const char *in, size_t in_len,
                  unsigned char *out, size_t out_max)
{
    static const signed char dtab[256] = {
        ['-'] = 62, ['_'] = 63,
        ['A']=0,['B']=1,['C']=2,['D']=3,['E']=4,['F']=5,['G']=6,
        ['H']=7,['I']=8,['J']=9,['K']=10,['L']=11,['M']=12,
        ['N']=13,['O']=14,['P']=15,['Q']=16,['R']=17,['S']=18,
        ['T']=19,['U']=20,['V']=21,['W']=22,['X']=23,['Y']=24,
        ['Z']=25,
        ['a']=26,['b']=27,['c']=28,['d']=29,['e']=30,['f']=31,
        ['g']=32,['h']=33,['i']=34,['j']=35,['k']=36,['l']=37,
        ['m']=38,['n']=39,['o']=40,['p']=41,['q']=42,['r']=43,
        ['s']=44,['t']=45,['u']=46,['v']=47,['w']=48,['x']=49,
        ['y']=50,['z']=51,
        ['0']=52,['1']=53,['2']=54,['3']=55,['4']=56,['5']=57,
        ['6']=58,['7']=59,['8']=60,['9']=61,
    };
    size_t o = 0;
    uint32_t acc = 0;
    int bits = 0;
    for (size_t i = 0; i < in_len; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '=') break;
        int v = dtab[c];
        if (v < 0) continue;
        acc = (acc << 6) | (unsigned)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o >= out_max) return -1;
            out[o++] = (unsigned char)(acc >> bits);
        }
    }
    return (int)o;
}

/* ══════════════════════════════════════════════════════
 *  Minimal JSON helpers
 *  (ACME responses are predictable; no full parser needed)
 * ══════════════════════════════════════════════════════ */

/* Extract value of first `"key": "value"` occurrence.
 * Returns 0 on success, -1 if not found. */
static int json_get_str(const char *json, const char *key,
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

/* Get the first string element of a JSON array at `key`.
 * E.g.  "authorizations": ["https://..."]  */
static int json_get_array_first(const char *json, const char *key,
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

/* Find JSON object in array that has `"type": "http-01"` and extract `token`
 * and `url`. */
static int json_find_http01_challenge(const char *json,
                                      char *token, size_t token_max,
                                      char *url,   size_t url_max)
{
    const char *p = json;
    while ((p = strstr(p, "\"type\"")) != NULL) {
        p += 6;
        while (*p == ' ' || *p == ':' || *p == '"') p++;
        if (strncmp(p, "http-01", 7) == 0) {
            /* Found the http-01 object; backtrack to find surrounding {  */
            const char *obj_start = p;
            /* Walk back to '{' */
            const char *bp = p;
            int depth = 0;
            while (bp > json && !(depth == 0 && *bp == '{')) {
                if (*bp == '}') depth++;
                if (*bp == '{') depth--;
                bp--;
            }
            /* Extract from bp to matching } */
            const char *ep = p;
            depth = 0;
            while (*ep) {
                if (*ep == '{') depth++;
                if (*ep == '}') { if (--depth <= 0) break; }
                ep++;
            }
            /* Now [bp..ep] contains the challenge object */
            size_t obj_len = (size_t)(ep - bp) + 1;
            char *obj = malloc(obj_len + 1);
            if (!obj) return -1;
            memcpy(obj, bp, obj_len);
            obj[obj_len] = '\0';
            int r1 = json_get_str(obj, "token", token, token_max);
            int r2 = json_get_str(obj, "url",   url,   url_max);
            free(obj);
            (void)obj_start;
            if (r1 == 0 && r2 == 0) return 0;
        }
        p++;
    }
    return -1;
}

/* ══════════════════════════════════════════════════════
 *  HTTPS client (using OpenSSL BIO)
 * ══════════════════════════════════════════════════════ */

/* Parse https://host[:port]/path */
static int parse_url(const char *url, char *host, size_t host_max,
                     int *port, char *path, size_t path_max)
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
        path[path_max-1] = '\0';
    } else {
        strncpy(path, "/", path_max - 1);
    }
    return 0;
}

/* Make an HTTP/HTTPS request.
 * Returns 0 on success and populates *resp_out (caller must free).
 * Also extracts status_code, Location, Replay-Nonce headers. */
static int https_request(struct acme_client *cl,
                         const char *method,
                         const char *url,
                         const char *content_type,
                         const char *body,
                         size_t body_len,
                         int  *status_out,
                         char *location_out, size_t loc_max,
                         char *nonce_out,    size_t nonce_max,
                         char **resp_out,    size_t *resp_len_out)
{
    char host[256], path[512];
    int port;

    if (parse_url(url, host, sizeof(host), &port, path, sizeof(path)) < 0) {
        log_error("acme_https", "bad url: %s", url);
        return -1;
    }

    /* Connect via BIO */
    char hostport[280];
    snprintf(hostport, sizeof(hostport), "%s:%d", host, port);

    BIO *bio = BIO_new_ssl_connect(cl->https_ctx);
    if (!bio) {
        log_error("acme_https", "BIO_new_ssl_connect failed");
        return -1;
    }

    SSL *ssl_ptr = NULL;
    BIO_get_ssl(bio, &ssl_ptr);
    if (ssl_ptr) SSL_set_tlsext_host_name(ssl_ptr, host); /* SNI */

    BIO_set_conn_hostname(bio, hostport);

    if (BIO_do_connect(bio) <= 0) {
        log_error("acme_https", "connect to %s failed", hostport);
        BIO_free_all(bio);
        return -1;
    }

    /* Build and send request */
    char req_hdr[2048];
    int hdr_len;
    if (body && body_len > 0) {
        hdr_len = snprintf(req_hdr, sizeof(req_hdr),
            "%s %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Content-Type: %s\r\n"
            "Content-Length: %zu\r\n"
            "Connection: close\r\n"
            "User-Agent: vortex/0.1\r\n"
            "\r\n",
            method, path, host,
            content_type ? content_type : "application/jose+json",
            body_len);
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

    /* Read response into dynamic buffer */
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
        log_error("acme_https", "empty response from %s", url);
        return -1;
    }

    /* Parse status line: HTTP/x.y STATUS ... */
    *status_out = 0;
    if (sscanf(rbuf, "HTTP/%*d.%*d %d", status_out) != 1) {
        free(rbuf);
        log_error("acme_https", "bad status line");
        return -1;
    }

    /* Extract headers we care about */
    if (location_out) location_out[0] = '\0';
    if (nonce_out)    nonce_out[0]    = '\0';

    char *hdrs_end = strstr(rbuf, "\r\n\r\n");
    if (!hdrs_end) hdrs_end = rbuf + total;

    /* Replay-Nonce */
    if (nonce_out && nonce_max > 0) {
        const char *nh = strcasestr(rbuf, "\r\nReplay-Nonce:");
        if (nh) {
            nh += 15; /* skip \r\nReplay-Nonce: */
            while (*nh == ' ') nh++;
            const char *ne = strstr(nh, "\r\n");
            size_t nlen = ne ? (size_t)(ne - nh) : strlen(nh);
            if (nlen >= nonce_max) nlen = nonce_max - 1;
            memcpy(nonce_out, nh, nlen);
            nonce_out[nlen] = '\0';
        }
    }
    /* Location */
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

    /* Body starts after \r\n\r\n */
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
    log_error("acme_https", "I/O error writing to %s", hostport);
    BIO_free_all(bio);
    return -1;
}

/* ══════════════════════════════════════════════════════
 *  JWK / JWS helpers
 * ══════════════════════════════════════════════════════ */

/* Export ECDSA P-256 public key as JWK {crv, kty, x, y} string.
 * Returns 0 on success. */
static int eckey_to_jwk(EVP_PKEY *pkey, char *out, size_t out_max)
{
    /* Get raw X/Y coordinates */
    unsigned char pub[65]; /* uncompressed: 04 || X || Y */
    size_t pub_len = sizeof(pub);
    if (EVP_PKEY_get_octet_string_param(pkey, "pub", pub, pub_len, &pub_len) <= 0)
        return -1;
    if (pub_len != 65 || pub[0] != 0x04) return -1;

    char xb64[64], yb64[64];
    if (b64url_encode(pub + 1,  32, xb64, sizeof(xb64)) < 0) return -1;
    if (b64url_encode(pub + 33, 32, yb64, sizeof(yb64)) < 0) return -1;

    int n = snprintf(out, out_max,
        "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"%s\",\"y\":\"%s\"}",
        xb64, yb64);
    return (n > 0 && (size_t)n < out_max) ? 0 : -1;
}

/* Compute JWK thumbprint: base64url(SHA-256(canonical JWK JSON)) */
static int compute_jwk_thumbprint(EVP_PKEY *pkey,
                                   char *out, size_t out_max)
{
    char jwk[256];
    if (eckey_to_jwk(pkey, jwk, sizeof(jwk)) < 0) return -1;

    unsigned char digest[32];
    unsigned int dlen = 0;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) return -1;
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(mdctx, jwk, strlen(jwk)) != 1 ||
        EVP_DigestFinal_ex(mdctx, digest, &dlen) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }
    EVP_MD_CTX_free(mdctx);

    return (b64url_encode(digest, 32, out, out_max) >= 0) ? 0 : -1;
}

/* Sign data with ECDSA P-256, return DER-encoded raw R||S (64 bytes). */
static int ecdsa_sign_raw(EVP_PKEY *pkey,
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

    /* Convert DER SEQUENCE{INTEGER r, INTEGER s} → 64-byte R||S */
    ECDSA_SIG *esig = d2i_ECDSA_SIG(NULL, &(const unsigned char *){ der_sig },
                                     (long)der_len);
    if (!esig) return -1;

    const BIGNUM *r, *s;
    ECDSA_SIG_get0(esig, &r, &s);

    *sig_len_out = 64;
    memset(sig_out, 0, 64);
    /* pad r and s to 32 bytes each */
    int rlen = BN_num_bytes(r), slen = BN_num_bytes(s);
    BN_bn2bin(r, sig_out + 32 - rlen);
    BN_bn2bin(s, sig_out + 64 - slen);
    ECDSA_SIG_free(esig);
    return 0;
}

/* Build a JWS compact-serialised request body.
 * If kid is set → use kid in header; else embed JWK (for newAccount).
 * Returns heap-allocated JSON string or NULL.
 */
static char *make_jws(EVP_PKEY *pkey,
                      const char *nonce,
                      const char *url,
                      const char *payload_json, /* NULL → POST-as-GET ("") */
                      const char *kid,           /* NULL → embed JWK */
                      const char *thumbprint)
{
    (void)thumbprint;

    /* Protected header */
    char hdr_json[1024];
    if (kid && kid[0]) {
        snprintf(hdr_json, sizeof(hdr_json),
            "{\"alg\":\"ES256\",\"nonce\":\"%s\",\"url\":\"%s\","
            "\"kid\":\"%s\"}",
            nonce, url, kid);
    } else {
        char jwk[256];
        if (eckey_to_jwk(pkey, jwk, sizeof(jwk)) < 0) return NULL;
        snprintf(hdr_json, sizeof(hdr_json),
            "{\"alg\":\"ES256\",\"nonce\":\"%s\",\"url\":\"%s\","
            "\"jwk\":%s}",
            nonce, url, jwk);
    }

    char hdr_b64[1024], pay_b64[4096];
    if (b64url_encode((unsigned char *)hdr_json, strlen(hdr_json),
                      hdr_b64, sizeof(hdr_b64)) < 0) return NULL;

    const char *payload = payload_json ? payload_json : "";
    if (b64url_encode((unsigned char *)payload, strlen(payload),
                      pay_b64, sizeof(pay_b64)) < 0) return NULL;

    /* Signing input: header_b64 + "." + payload_b64 */
    char si[8192];
    int si_len = snprintf(si, sizeof(si), "%s.%s", hdr_b64, pay_b64);
    if (si_len <= 0 || (size_t)si_len >= sizeof(si)) return NULL;

    unsigned char raw_sig[64];
    size_t raw_sig_len;
    if (ecdsa_sign_raw(pkey, (unsigned char *)si, (size_t)si_len,
                        raw_sig, &raw_sig_len) < 0) return NULL;

    char sig_b64[128];
    if (b64url_encode(raw_sig, raw_sig_len, sig_b64, sizeof(sig_b64)) < 0)
        return NULL;

    /* Build JWS JSON */
    size_t jws_max = strlen(hdr_b64) + strlen(pay_b64) + strlen(sig_b64) + 256;
    char *jws = malloc(jws_max);
    if (!jws) return NULL;
    snprintf(jws, jws_max,
        "{\"protected\":\"%s\",\"payload\":\"%s\",\"signature\":\"%s\"}",
        hdr_b64, pay_b64, sig_b64);
    return jws;
}

/* ══════════════════════════════════════════════════════
 *  Nonce management
 * ══════════════════════════════════════════════════════ */

static int get_fresh_nonce(struct acme_client *cl, char *nonce, size_t nmax)
{
    int status;
    char loc[8] = "";
    if (https_request(cl, "HEAD", cl->newNonce_url,
                      NULL, NULL, 0,
                      &status, loc, sizeof(loc),
                      nonce, nmax,
                      NULL, NULL) < 0) return -1;
    if (nonce[0] == '\0') {
        log_error("acme", "no nonce in response from %s", cl->newNonce_url);
        return -1;
    }
    return 0;
}

/* ══════════════════════════════════════════════════════
 *  Account key load/generate
 * ══════════════════════════════════════════════════════ */

static EVP_PKEY *load_or_generate_account_key(const char *path)
{
    /* Try loading */
    FILE *f = fopen(path, "rb");
    if (f) {
        EVP_PKEY *pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
        fclose(f);
        if (pkey) {
            log_info("acme", "loaded account key from %s", path);
            return pkey;
        }
    }

    /* Generate ECDSA P-256 */
    log_info("acme", "generating new ECDSA P-256 account key → %s", path);
    EVP_PKEY_CTX *pkctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!pkctx) return NULL;
    if (EVP_PKEY_keygen_init(pkctx) <= 0) { EVP_PKEY_CTX_free(pkctx); return NULL; }
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pkctx, NID_X9_62_prime256v1) <= 0) {
        EVP_PKEY_CTX_free(pkctx); return NULL;
    }
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_generate(pkctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(pkctx); return NULL;
    }
    EVP_PKEY_CTX_free(pkctx);

    /* Save with mode 0600 */
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        log_error("acme", "cannot create key file %s: %s", path, strerror(errno));
        EVP_PKEY_free(pkey);
        return NULL;
    }
    FILE *wf = fdopen(fd, "wb");
    if (!wf) { close(fd); EVP_PKEY_free(pkey); return NULL; }
    PEM_write_PrivateKey(wf, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(wf);
    return pkey;
}

/* ══════════════════════════════════════════════════════
 *  ACME directory fetch
 * ══════════════════════════════════════════════════════ */

static int fetch_directory(struct acme_client *cl)
{
    int status;
    char *body = NULL;
    char nonce[256] = "", loc[512] = "";

    if (https_request(cl, "GET", cl->directory_url,
                      NULL, NULL, 0,
                      &status, loc, sizeof(loc),
                      nonce, sizeof(nonce),
                      &body, NULL) < 0) return -1;

    if (status != 200) {
        log_error("acme", "directory fetch returned %d", status);
        free(body);
        return -1;
    }

    json_get_str(body, "newNonce",   cl->newNonce_url,   sizeof(cl->newNonce_url));
    json_get_str(body, "newAccount", cl->newAccount_url, sizeof(cl->newAccount_url));
    json_get_str(body, "newOrder",   cl->newOrder_url,   sizeof(cl->newOrder_url));
    free(body);

    if (!cl->newNonce_url[0] || !cl->newAccount_url[0] || !cl->newOrder_url[0]) {
        log_error("acme", "incomplete directory (missing endpoint URLs)");
        return -1;
    }
    log_info("acme", "directory: newNonce=%s newAccount=%s newOrder=%s",
        cl->newNonce_url, cl->newAccount_url, cl->newOrder_url);
    return 0;
}

/* ══════════════════════════════════════════════════════
 *  Account registration / lookup
 * ══════════════════════════════════════════════════════ */

static int register_account(struct acme_client *cl)
{
    char nonce[256];
    if (get_fresh_nonce(cl, nonce, sizeof(nonce)) < 0) return -1;

    char payload[512];
    snprintf(payload, sizeof(payload),
        "{\"termsOfServiceAgreed\":true,"
        "\"contact\":[\"mailto:%s\"]}",
        cl->email[0] ? cl->email : "admin@example.com");

    char *jws = make_jws(cl->account_key, nonce, cl->newAccount_url,
                         payload, NULL, cl->jwk_thumbprint);
    if (!jws) return -1;

    int status;
    char loc[ACME_MAX_URL] = "", nonce2[256] = "";
    char *resp = NULL;
    int r = https_request(cl, "POST", cl->newAccount_url,
                          "application/jose+json",
                          jws, strlen(jws),
                          &status, loc, sizeof(loc),
                          nonce2, sizeof(nonce2),
                          &resp, NULL);
    free(jws);

    if (r < 0) return -1;
    if (status != 200 && status != 201) {
        log_error("acme", "account registration returned %d: %s",
            status, resp ? resp : "(no body)");
        free(resp);
        return -1;
    }

    /* Account URL is in Location header (for new accounts) or in the body */
    if (loc[0]) {
        strncpy(cl->account_url, loc, sizeof(cl->account_url) - 1);
    } else {
        json_get_str(resp ? resp : "", "url", cl->account_url,
                     sizeof(cl->account_url));
    }

    free(resp);
    log_info("acme", "account %s (status=%d)", cl->account_url, status);
    return 0;
}

/* ══════════════════════════════════════════════════════
 *  Public API
 * ══════════════════════════════════════════════════════ */

int acme_client_init(struct acme_client *cl)
{
    /* Build HTTPS SSL_CTX for outbound connections to ACME server */
    cl->https_ctx = SSL_CTX_new_ex(cl->libctx, NULL, TLS_client_method());
    if (!cl->https_ctx) {
        log_error("acme", "SSL_CTX_new_ex for client failed");
        return -1;
    }
    /* Try standard system CA bundle locations in order */
    static const char *ca_files[] = {
        "/etc/ssl/certs/ca-certificates.crt",    /* Debian/Ubuntu */
        "/etc/pki/tls/certs/ca-bundle.crt",      /* RHEL/CentOS */
        "/etc/ssl/ca-bundle.pem",                 /* openSUSE */
        "/etc/ssl/cert.pem",                      /* Alpine/macOS */
        NULL
    };
    int ca_loaded = 0;
    for (int i = 0; ca_files[i]; i++) {
        if (access(ca_files[i], R_OK) == 0) {
            if (SSL_CTX_load_verify_locations(cl->https_ctx, ca_files[i], NULL) == 1) {
                ca_loaded = 1;
                break;
            }
        }
    }
    if (!ca_loaded) {
        /* Fall back to OpenSSL compiled-in defaults */
        SSL_CTX_set_default_verify_paths(cl->https_ctx);
    }
    SSL_CTX_set_verify(cl->https_ctx, SSL_VERIFY_PEER, NULL);

    /* Load or generate account key */
    cl->account_key = load_or_generate_account_key(cl->account_key_path);
    if (!cl->account_key) {
        log_error("acme", "failed to load/generate account key");
        SSL_CTX_free(cl->https_ctx);
        cl->https_ctx = NULL;
        return -1;
    }

    /* Precompute JWK thumbprint */
    if (compute_jwk_thumbprint(cl->account_key,
                               cl->jwk_thumbprint,
                               sizeof(cl->jwk_thumbprint)) < 0) {
        log_error("acme", "failed to compute JWK thumbprint");
        EVP_PKEY_free(cl->account_key);
        SSL_CTX_free(cl->https_ctx);
        return -1;
    }
    log_info("acme", "JWK thumbprint: %s", cl->jwk_thumbprint);

    /* Fetch ACME directory */
    if (fetch_directory(cl) < 0) return -1;

    /* Register / find account */
    if (register_account(cl) < 0) return -1;

    return 0;
}

void acme_client_destroy(struct acme_client *cl)
{
    if (cl->account_key) { EVP_PKEY_free(cl->account_key); cl->account_key = NULL; }
    if (cl->https_ctx)   { SSL_CTX_free(cl->https_ctx);    cl->https_ctx   = NULL; }
}

int acme_key_auth(const char *token, const char *thumbprint,
                   char *out, size_t out_max)
{
    int n = snprintf(out, out_max, "%s.%s", token, thumbprint);
    return (n > 0 && (size_t)n < out_max) ? 0 : -1;
}

/* ══════════════════════════════════════════════════════
 *  CSR generation
 * ══════════════════════════════════════════════════════ */

static int make_csr_der(const char *domain,
                        EVP_PKEY **pkey_out,
                        unsigned char **csr_der, size_t *csr_len)
{
    /* Generate fresh ECDSA P-256 domain key */
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

    /* Add SAN extension */
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

    /* DER encode */
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
 *  Poll helpers
 * ══════════════════════════════════════════════════════ */

static int poll_for_status(struct acme_client *cl, const char *url,
                            const char *want_status, int timeout_s)
{
    time_t deadline = time(NULL) + timeout_s;
    for (;;) {
        char nonce[256], loc[8] = "";
        char *body = NULL;
        int status;

        /* POST-as-GET with empty payload */
        if (get_fresh_nonce(cl, nonce, sizeof(nonce)) < 0) return -1;
        char *jws = make_jws(cl->account_key, nonce, url,
                             NULL /* POST-as-GET */, cl->account_url,
                             cl->jwk_thumbprint);
        if (!jws) return -1;
        int r = https_request(cl, "POST", url,
                              "application/jose+json",
                              jws, strlen(jws),
                              &status, loc, sizeof(loc),
                              nonce, sizeof(nonce),
                              &body, NULL);
        free(jws);
        if (r < 0) { free(body); return -1; }

        char obj_status[64] = "";
        json_get_str(body ? body : "", "status", obj_status, sizeof(obj_status));
        free(body);

        log_debug("acme", "poll %s → status=%s (want %s)", url, obj_status, want_status);

        if (strcmp(obj_status, want_status) == 0) return 0;
        if (strcmp(obj_status, "invalid")   == 0) {
            log_error("acme", "order/authz went invalid at %s", url);
            return -1;
        }

        if (time(NULL) >= deadline) {
            log_error("acme", "timeout polling %s (last status=%s)", url, obj_status);
            return -1;
        }
        sleep(3);
    }
}

/* ══════════════════════════════════════════════════════
 *  Certificate storage helpers
 * ══════════════════════════════════════════════════════ */

static int ensure_dir(const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0) return S_ISDIR(st.st_mode) ? 0 : -1;
    return mkdir(path, 0700);
}

static char *cert_path_for(const char *storage, const char *domain,
                            const char *suffix)
{
    static char buf[4096];
    snprintf(buf, sizeof(buf), "%s/%s/%s", storage, domain, suffix);
    return buf;
}

/* ══════════════════════════════════════════════════════
 *  Main: obtain certificate via HTTP-01
 * ══════════════════════════════════════════════════════ */

int acme_obtain_http01(struct acme_client *cl,
                        const char *domain,
                        struct acme_http01_server *http01_srv,
                        struct cert_result *out)
{
    char nonce[256], loc[ACME_MAX_URL] = "";
    char *resp = NULL;
    int status;
    int rc = -1;

    /* 1. New order */
    if (get_fresh_nonce(cl, nonce, sizeof(nonce)) < 0) goto done;
    {
        char pay[512];
        snprintf(pay, sizeof(pay),
            "{\"identifiers\":[{\"type\":\"dns\",\"value\":\"%s\"}]}", domain);
        char *jws = make_jws(cl->account_key, nonce, cl->newOrder_url,
                             pay, cl->account_url, cl->jwk_thumbprint);
        if (!jws) goto done;
        int r = https_request(cl, "POST", cl->newOrder_url,
                              "application/jose+json",
                              jws, strlen(jws),
                              &status, loc, sizeof(loc),
                              nonce, sizeof(nonce),
                              &resp, NULL);
        free(jws);
        if (r < 0 || (status != 201 && status != 200)) {
            log_error("acme", "newOrder returned %d: %s", status,
                      resp ? resp : "");
            goto done;
        }
    }

    char order_url[ACME_MAX_URL];
    strncpy(order_url, loc, sizeof(order_url) - 1);
    order_url[sizeof(order_url)-1] = '\0';

    char finalize_url[ACME_MAX_URL] = "";
    char authz_url[ACME_MAX_URL]    = "";
    json_get_str(resp, "finalize", finalize_url, sizeof(finalize_url));
    json_get_array_first(resp, "authorizations", authz_url, sizeof(authz_url));
    free(resp); resp = NULL;

    if (!finalize_url[0] || !authz_url[0]) {
        log_error("acme", "order missing finalize or authorizations");
        goto done;
    }

    /* 2. Get authorization */
    if (get_fresh_nonce(cl, nonce, sizeof(nonce)) < 0) goto done;
    {
        char loc2[8] = "";
        char *jws = make_jws(cl->account_key, nonce, authz_url,
                             NULL, cl->account_url, cl->jwk_thumbprint);
        if (!jws) goto done;
        int r = https_request(cl, "POST", authz_url,
                              "application/jose+json",
                              jws, strlen(jws),
                              &status, loc2, sizeof(loc2),
                              nonce, sizeof(nonce),
                              &resp, NULL);
        free(jws);
        if (r < 0 || status != 200) {
            log_error("acme", "get authz returned %d", status);
            goto done;
        }
    }

    char challenge_token[256] = "", challenge_url[ACME_MAX_URL] = "";
    if (json_find_http01_challenge(resp ? resp : "",
                                   challenge_token, sizeof(challenge_token),
                                   challenge_url,   sizeof(challenge_url)) < 0) {
        log_error("acme", "no http-01 challenge in authorization");
        goto done;
    }
    free(resp); resp = NULL;

    /* 3. Serve challenge */
    char key_auth[512];
    acme_key_auth(challenge_token, cl->jwk_thumbprint,
                  key_auth, sizeof(key_auth));
    acme_http01_set_challenge(http01_srv, challenge_token, key_auth);
    log_info("acme", "HTTP-01 challenge ready: token=%s", challenge_token);

    /* 4. Respond to challenge */
    if (get_fresh_nonce(cl, nonce, sizeof(nonce)) < 0) goto done;
    {
        char loc2[8] = "";
        char *jws = make_jws(cl->account_key, nonce, challenge_url,
                             "{}", cl->account_url, cl->jwk_thumbprint);
        if (!jws) goto done;
        int r = https_request(cl, "POST", challenge_url,
                              "application/jose+json",
                              jws, strlen(jws),
                              &status, loc2, sizeof(loc2),
                              nonce, sizeof(nonce),
                              &resp, NULL);
        free(jws);
        if (r < 0 || (status != 200 && status != 202)) {
            log_error("acme", "respond challenge returned %d: %s",
                status, resp ? resp : "");
            goto done;
        }
        free(resp); resp = NULL;
    }

    /* 5. Poll authorization until valid */
    if (poll_for_status(cl, authz_url, "valid", 120) < 0) goto done;
    acme_http01_clear_challenge(http01_srv);

    /* 6. Generate CSR */
    EVP_PKEY *domain_key = NULL;
    unsigned char *csr_der = NULL;
    size_t csr_len = 0;
    if (make_csr_der(domain, &domain_key, &csr_der, &csr_len) < 0) {
        log_error("acme", "CSR generation failed");
        goto done;
    }

    /* 7. Finalize */
    {
        char csr_b64[4096];
        if (b64url_encode(csr_der, csr_len, csr_b64, sizeof(csr_b64)) < 0) {
            free(csr_der); EVP_PKEY_free(domain_key);
            goto done;
        }
        free(csr_der);

        char pay[5000];
        snprintf(pay, sizeof(pay), "{\"csr\":\"%s\"}", csr_b64);

        if (get_fresh_nonce(cl, nonce, sizeof(nonce)) < 0) {
            EVP_PKEY_free(domain_key); goto done;
        }
        char loc2[8] = "";
        char *jws = make_jws(cl->account_key, nonce, finalize_url,
                             pay, cl->account_url, cl->jwk_thumbprint);
        if (!jws) { EVP_PKEY_free(domain_key); goto done; }

        int r = https_request(cl, "POST", finalize_url,
                              "application/jose+json",
                              jws, strlen(jws),
                              &status, loc2, sizeof(loc2),
                              nonce, sizeof(nonce),
                              &resp, NULL);
        free(jws);
        if (r < 0 || (status != 200 && status != 201)) {
            log_error("acme", "finalize returned %d: %s",
                status, resp ? resp : "");
            EVP_PKEY_free(domain_key);
            goto done;
        }
    }

    /* 8. Poll order until valid */
    if (order_url[0]) {
        if (poll_for_status(cl, order_url, "valid", 120) < 0) {
            free(resp); resp = NULL;
            EVP_PKEY_free(domain_key);
            goto done;
        }
    }

    /* Re-fetch order to get certificate URL */
    {
        free(resp); resp = NULL;
        char loc2[8] = "";
        char *jws = make_jws(cl->account_key, nonce, order_url,
                             NULL, cl->account_url, cl->jwk_thumbprint);
        if (!jws) { EVP_PKEY_free(domain_key); goto done; }
        if (get_fresh_nonce(cl, nonce, sizeof(nonce)) < 0) {
            free(jws); EVP_PKEY_free(domain_key); goto done;
        }
        free(jws);
        jws = make_jws(cl->account_key, nonce, order_url,
                       NULL, cl->account_url, cl->jwk_thumbprint);
        if (!jws) { EVP_PKEY_free(domain_key); goto done; }
        int r = https_request(cl, "POST", order_url,
                              "application/jose+json",
                              jws, strlen(jws),
                              &status, loc2, sizeof(loc2),
                              nonce, sizeof(nonce),
                              &resp, NULL);
        free(jws);
        if (r < 0 || status != 200) {
            log_error("acme", "order fetch returned %d", status);
            EVP_PKEY_free(domain_key);
            goto done;
        }
    }

    char cert_url[ACME_MAX_URL] = "";
    json_get_str(resp ? resp : "", "certificate", cert_url, sizeof(cert_url));
    free(resp); resp = NULL;

    if (!cert_url[0]) {
        log_error("acme", "no certificate URL in finalized order");
        EVP_PKEY_free(domain_key);
        goto done;
    }

    /* 9. Download certificate */
    if (get_fresh_nonce(cl, nonce, sizeof(nonce)) < 0) {
        EVP_PKEY_free(domain_key); goto done;
    }
    {
        char loc2[8] = "";
        char *jws = make_jws(cl->account_key, nonce, cert_url,
                             NULL, cl->account_url, cl->jwk_thumbprint);
        if (!jws) { EVP_PKEY_free(domain_key); goto done; }
        int r = https_request(cl, "POST", cert_url,
                              "application/jose+json",
                              jws, strlen(jws),
                              &status, loc2, sizeof(loc2),
                              nonce, sizeof(nonce),
                              &resp, NULL);
        free(jws);
        if (r < 0 || status != 200) {
            log_error("acme", "cert download returned %d", status);
            EVP_PKEY_free(domain_key);
            goto done;
        }
    }

    /* resp contains the cert PEM chain */
    /* Encode domain private key to PEM */
    BIO *keybio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(keybio, domain_key, NULL, NULL, 0, NULL, NULL);
    BUF_MEM *bm = NULL;
    BIO_get_mem_ptr(keybio, &bm);
    char *key_pem = malloc(bm->length + 1);
    if (key_pem) {
        memcpy(key_pem, bm->data, bm->length);
        key_pem[bm->length] = '\0';
    }
    BIO_free(keybio);
    EVP_PKEY_free(domain_key);

    if (!key_pem) { free(resp); goto done; }

    /* 10. Save to storage_path/domain/ */
    {
        char dom_dir[4096];
        snprintf(dom_dir, sizeof(dom_dir), "%s/%s", cl->storage_path, domain);
        ensure_dir(cl->storage_path);
        ensure_dir(dom_dir);

        /* cert.pem */
        const char *cp = cert_path_for(cl->storage_path, domain, "cert.pem");
        FILE *cf = fopen(cp, "wb");
        if (cf) { fwrite(resp, 1, strlen(resp), cf); fclose(cf); }

        /* key.pem — mode 0600 */
        const char *kp = cert_path_for(cl->storage_path, domain, "key.pem");
        int kfd = open(kp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (kfd >= 0) {
            FILE *kf = fdopen(kfd, "wb");
            if (kf) { fwrite(key_pem, 1, strlen(key_pem), kf); fclose(kf); }
            else close(kfd);
        }
        log_info("acme", "certificate saved: %s", cp);
    }

    /* Fill result */
    out->cert_pem  = resp;          resp = NULL;
    out->key_pem   = key_pem;
    out->not_after = 0;
    {
        /* Parse not_after from the cert */
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
    return rc;
}

int acme_needs_renewal(const char *storage_path, const char *domain,
                        int renewal_days)
{
    char path[4096];
    snprintf(path, sizeof(path), "%s/%s/cert.pem", storage_path, domain);

    FILE *f = fopen(path, "rb");
    if (!f) return 1; /* no cert → needs issuance */
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    if (sz <= 0 || sz > 1024 * 1024) { fclose(f); return 1; }
    char *pem = malloc((size_t)sz + 1);
    if (!pem) { fclose(f); return 1; }
    size_t nrd = fread(pem, 1, (size_t)sz, f);
    pem[nrd] = '\0';
    fclose(f);

    BIO *bio = BIO_new_mem_buf(pem, -1);
    X509 *x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    free(pem);
    if (!x509) return 1;

    const ASN1_TIME *na = X509_get0_notAfter(x509);
    struct tm tm_val;
    memset(&tm_val, 0, sizeof(tm_val));
    ASN1_TIME_to_tm(na, &tm_val);
    time_t not_after = timegm(&tm_val);
    X509_free(x509);

    time_t now = time(NULL);
    time_t renew_at = not_after - (time_t)renewal_days * 86400;
    return (now >= renew_at) ? 1 : 0;
}

#else /* !VORTEX_PHASE_TLS */

/* Stub implementations when built without TLS */

int b64url_encode(const unsigned char *in, size_t in_len,
                  char *out, size_t out_max)
{ (void)in; (void)in_len; (void)out; (void)out_max; return -1; }

int b64url_decode(const char *in, size_t in_len,
                  unsigned char *out, size_t out_max)
{ (void)in; (void)in_len; (void)out; (void)out_max; return -1; }

int acme_client_init(struct acme_client *cl)
{ (void)cl; return -1; }

void acme_client_destroy(struct acme_client *cl) { (void)cl; }

int acme_obtain_http01(struct acme_client *cl, const char *domain,
                        struct acme_http01_server *srv,
                        struct cert_result *out)
{ (void)cl; (void)domain; (void)srv; (void)out; return -1; }

int acme_needs_renewal(const char *s, const char *d, int r)
{ (void)s; (void)d; (void)r; return 0; }

int acme_key_auth(const char *t, const char *tp, char *o, size_t m)
{ (void)t; (void)tp; (void)o; (void)m; return -1; }

#endif /* VORTEX_PHASE_TLS */
