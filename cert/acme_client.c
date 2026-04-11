/*
 * acme_client.c — RFC 8555 ACME client, HTTP-01 challenge
 *
 * Migrated from OpenSSL to picotls minicrypto + micro-ecc:
 *   - Account/domain keys: raw ECDSA P-256, stored as PKCS#8 PEM
 *   - SHA-256: ptls_minicrypto_sha256 hash context
 *   - ECDSA signing: uECC_sign() → raw 64-byte R||S
 *   - HTTPS: TCP socket + tls_backend_connect()
 *   - CSR: hand-crafted DER ASN.1
 *   - X.509 notAfter: lightweight DER walker
 */

#include "acme_client.h"
#include "acme_internal.h"
#include "log.h"
#include "config.h"
#include "tls.h"

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
#include <poll.h>

#ifdef VORTEX_PHASE_TLS

#include <picotls.h>
#include <picotls/minicrypto.h>
#include <uECC.h>

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
 *  Standard base64 encoder (for PEM output)
 * ══════════════════════════════════════════════════════ */

static const char B64STD[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int b64std_encode(const uint8_t *in, size_t in_len,
                          char *out, size_t out_max)
{
    size_t i, o = 0;
    for (i = 0; i + 2 < in_len; i += 3) {
        if (o + 4 >= out_max) return -1;
        out[o++] = B64STD[(in[i]   >> 2)                     & 0x3F];
        out[o++] = B64STD[((in[i]  << 4) | (in[i+1] >> 4))  & 0x3F];
        out[o++] = B64STD[((in[i+1]<< 2) | (in[i+2] >> 6))  & 0x3F];
        out[o++] = B64STD[ in[i+2]                           & 0x3F];
    }
    if (i < in_len) {
        if (o + 4 >= out_max) return -1;
        out[o++] = B64STD[(in[i] >> 2) & 0x3F];
        if (i + 1 < in_len) {
            out[o++] = B64STD[((in[i] << 4) | (in[i+1] >> 4)) & 0x3F];
            out[o++] = B64STD[(in[i+1] << 2) & 0x3F];
        } else {
            out[o++] = B64STD[(in[i] << 4) & 0x3F];
            out[o++] = '=';
        }
        out[o++] = '=';
    }
    out[o] = '\0';
    return (int)o;
}

/* Standard base64 decode (skips whitespace, handles padding) */
static int b64std_decode(const char *in, size_t in_len,
                          uint8_t *out, size_t out_max)
{
    static const signed char dtab[256] = {
        ['+'] = 62, ['/'] = 63,
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
        if (c == '=' || c == '\r' || c == '\n' || c == ' ') continue;
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
 *  PKCS#8 PEM codec for P-256 private key
 *
 *  DER layout (exactly 67 bytes, fixed structure):
 *    30 41                         SEQUENCE 65
 *      02 01 00                    version = 0
 *      30 13                       algorithmIdentifier 19
 *        06 07 2a86 48ce 3d02 01   OID ecPublicKey
 *        06 08 2a86 48ce 3d03 0107 OID prime256v1
 *      04 27                       privateKey OCTET STRING 39
 *        30 25                     ECPrivateKey SEQUENCE 37
 *          02 01 01                version = 1
 *          04 20                   privateKey OCTET STRING 32
 *            [32 bytes private key]
 * ══════════════════════════════════════════════════════ */

#define PKCS8_P256_DER_LEN 67
#define PKCS8_P256_KEY_OFFSET 35

static const uint8_t PKCS8_P256_HDR[PKCS8_P256_KEY_OFFSET] = {
    0x30, 0x41,                                        /* SEQUENCE 65 */
    0x02, 0x01, 0x00,                                  /* version 0  */
    0x30, 0x13,                                        /* algId 19   */
      0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, /* ecPublicKey */
      0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, /* prime256v1 */
    0x04, 0x27,                                        /* octet string 39 */
      0x30, 0x25,                                      /* ECPrivateKey 37 */
        0x02, 0x01, 0x01,                              /* version 1  */
        0x04, 0x20,                                    /* key octet string 32 */
};

/* Write PKCS#8 PEM for a raw P-256 private key into out[out_max]. */
int pkcs8_pem_from_priv(const uint8_t priv[32],
                                char *out, size_t out_max)
{
    uint8_t der[PKCS8_P256_DER_LEN];
    memcpy(der, PKCS8_P256_HDR, PKCS8_P256_KEY_OFFSET);
    memcpy(der + PKCS8_P256_KEY_OFFSET, priv, 32);

    /* base64 encode, 64 chars per line */
    char b64[128];
    if (b64std_encode(der, sizeof(der), b64, sizeof(b64)) < 0) return -1;

    int n = snprintf(out, out_max,
        "-----BEGIN PRIVATE KEY-----\n"
        "%.64s\n"
        "%s\n"
        "-----END PRIVATE KEY-----\n",
        b64, b64 + 64);
    return (n > 0 && (size_t)n < out_max) ? 0 : -1;
}

/* Extract 32-byte raw P-256 private key from PKCS#8 PEM string.
 * Expects the exact 67-byte DER template written by pkcs8_pem_from_priv. */
static int priv_from_pkcs8_pem(const char *pem, uint8_t priv[32])
{
    const char *b = strstr(pem, "-----BEGIN PRIVATE KEY-----");
    if (!b) return -1;
    b += 27; /* skip header */
    while (*b == '\r' || *b == '\n') b++;
    const char *e = strstr(b, "-----END PRIVATE KEY-----");
    if (!e) return -1;

    uint8_t der[PKCS8_P256_DER_LEN + 4];
    int n = b64std_decode(b, (size_t)(e - b), der, sizeof(der));
    if (n != PKCS8_P256_DER_LEN) return -1;

    /* Verify the fixed header prefix */
    if (memcmp(der, PKCS8_P256_HDR, PKCS8_P256_KEY_OFFSET) != 0) return -1;

    memcpy(priv, der + PKCS8_P256_KEY_OFFSET, 32);
    return 0;
}

/* ══════════════════════════════════════════════════════
 *  Minimal JSON helpers
 * ══════════════════════════════════════════════════════ */

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

static int json_find_http01_challenge(const char *json,
                                      char *token, size_t token_max,
                                      char *url,   size_t url_max)
{
    const char *p = json;
    while ((p = strstr(p, "\"type\"")) != NULL) {
        p += 6;
        while (*p == ' ' || *p == ':' || *p == '"') p++;
        if (strncmp(p, "http-01", 7) == 0) {
            const char *bp = p;
            int depth = 0;
            while (bp > json && !(depth == 0 && *bp == '{')) {
                if (*bp == '}') depth++;
                if (*bp == '{') depth--;
                bp--;
            }
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
            int r1 = json_get_str(obj, "token", token, token_max);
            int r2 = json_get_str(obj, "url",   url,   url_max);
            free(obj);
            if (r1 == 0 && r2 == 0) return 0;
        }
        p++;
    }
    return -1;
}

/* ══════════════════════════════════════════════════════
 *  HTTPS client via TCP + tls_backend_connect
 * ══════════════════════════════════════════════════════ */

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

/* Write all bytes to fd, blocking. */
static int write_all_fd(int fd, const uint8_t *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

int https_request(struct acme_client *cl,
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

    /* TCP connect */
    struct addrinfo hints, *res0;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char portstr[8];
    snprintf(portstr, sizeof(portstr), "%d", port);
    if (getaddrinfo(host, portstr, &hints, &res0) != 0) {
        log_error("acme_https", "getaddrinfo(%s) failed", host);
        return -1;
    }

    int fd = -1;
    for (struct addrinfo *res = res0; res; res = res->ai_next) {
        fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, res->ai_addr, res->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res0);
    if (fd < 0) {
        log_error("acme_https", "connect to %s:%d failed", host, port);
        return -1;
    }

    /* TLS handshake */
    ptls_t *ptls = NULL;
    if (port == 443 || strncmp(url, "https://", 8) == 0) {
        ptls = tls_backend_connect((ptls_context_t *)cl->https_ctx,
                                    fd, host, 10000, NULL, NULL);
        if (!ptls) {
            log_error("acme_https", "TLS handshake to %s failed", host);
            close(fd);
            return -1;
        }
    }

    /* Build HTTP request */
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

    /* Send request */
    if (ptls) {
        uint8_t wbuf_small[4096];
        ptls_buffer_t wbuf;
        ptls_buffer_init(&wbuf, wbuf_small, sizeof(wbuf_small));
        ptls_send(ptls, &wbuf, req_hdr, (size_t)hdr_len);
        if (body && body_len > 0)
            ptls_send(ptls, &wbuf, body, body_len);
        int err = write_all_fd(fd, wbuf.base, wbuf.off);
        ptls_buffer_dispose(&wbuf);
        if (err < 0) goto io_err;
    } else {
        if (write_all_fd(fd, (uint8_t *)req_hdr, (size_t)hdr_len) < 0) goto io_err;
        if (body && body_len > 0)
            if (write_all_fd(fd, (uint8_t *)body, body_len) < 0) goto io_err;
    }

    /* Read response */
    size_t total = 0, cap = 65536;
    char *rbuf = malloc(cap);
    if (!rbuf) { if (ptls) ptls_free(ptls); close(fd); return -1; }

    for (;;) {
        if (total + 1 >= cap) {
            cap *= 2;
            char *tmp = realloc(rbuf, cap);
            if (!tmp) { free(rbuf); if (ptls) ptls_free(ptls); close(fd); return -1; }
            rbuf = tmp;
        }
        if (ptls) {
            /* Read encrypted data, decrypt via ptls_receive */
            uint8_t ibuf[8192];
            ssize_t nr = recv(fd, ibuf, sizeof(ibuf), 0);
            if (nr < 0 && errno == EINTR) continue;
            if (nr <= 0) break;
            ptls_buffer_t plainbuf;
            uint8_t plainbuf_small[8192];
            ptls_buffer_init(&plainbuf, plainbuf_small, sizeof(plainbuf_small));
            size_t consumed = (size_t)nr;
            int ret = ptls_receive(ptls, &plainbuf, ibuf, &consumed);
            if (ret != 0 && ret != PTLS_ERROR_IN_PROGRESS) {
                ptls_buffer_dispose(&plainbuf);
                break;
            }
            if (plainbuf.off > 0) {
                if (total + plainbuf.off + 1 >= cap) {
                    cap = total + plainbuf.off + 65536;
                    char *tmp = realloc(rbuf, cap);
                    if (!tmp) { ptls_buffer_dispose(&plainbuf); free(rbuf);
                                ptls_free(ptls); close(fd); return -1; }
                    rbuf = tmp;
                }
                memcpy(rbuf + total, plainbuf.base, plainbuf.off);
                total += plainbuf.off;
            }
            ptls_buffer_dispose(&plainbuf);
        } else {
            ssize_t n = recv(fd, rbuf + total, cap - total - 1, 0);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) break;
            total += (size_t)n;
        }
    }
    rbuf[total] = '\0';
    if (ptls) ptls_free(ptls);
    close(fd);

    if (total == 0) {
        free(rbuf);
        log_error("acme_https", "empty response from %s", url);
        return -1;
    }

    *status_out = 0;
    if (sscanf(rbuf, "HTTP/%*d.%*d %d", status_out) != 1) {
        free(rbuf);
        log_error("acme_https", "bad status line from %s", url);
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
    log_error("acme_https", "I/O error writing to %s:%d", host, port);
    if (ptls) ptls_free(ptls);
    close(fd);
    return -1;
}

/* ══════════════════════════════════════════════════════
 *  JWK / JWS helpers — picotls + uECC
 * ══════════════════════════════════════════════════════ */

/* Export P-256 public key (raw 64-byte X||Y) as JWK {crv,kty,x,y}. */
static int eckey_to_jwk(const uint8_t pub64[64], char *out, size_t out_max)
{
    char xb64[64], yb64[64];
    if (b64url_encode(pub64,      32, xb64, sizeof(xb64)) < 0) return -1;
    if (b64url_encode(pub64 + 32, 32, yb64, sizeof(yb64)) < 0) return -1;
    int n = snprintf(out, out_max,
        "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"%s\",\"y\":\"%s\"}",
        xb64, yb64);
    return (n > 0 && (size_t)n < out_max) ? 0 : -1;
}

/* Compute JWK thumbprint: base64url(SHA-256(canonical JWK JSON)) */
static int compute_jwk_thumbprint(const uint8_t pub64[64],
                                   char *out, size_t out_max)
{
    char jwk[256];
    if (eckey_to_jwk(pub64, jwk, sizeof(jwk)) < 0) return -1;

    ptls_hash_context_t *hctx = ptls_minicrypto_sha256.create();
    if (!hctx) return -1;
    uint8_t digest[PTLS_SHA256_DIGEST_SIZE];
    hctx->update(hctx, jwk, strlen(jwk));
    hctx->final(hctx, digest, PTLS_HASH_FINAL_MODE_FREE);

    return (b64url_encode(digest, 32, out, out_max) >= 0) ? 0 : -1;
}

/* SHA-256 + ECDSA P-256 sign: msg → raw 64-byte R||S via uECC. */
static int ecdsa_sign_raw(const uint8_t priv32[32],
                           const unsigned char *msg, size_t msg_len,
                           unsigned char *sig_out, size_t *sig_len_out)
{
    /* Hash message with SHA-256 */
    ptls_hash_context_t *hctx = ptls_minicrypto_sha256.create();
    if (!hctx) return -1;
    uint8_t hash[PTLS_SHA256_DIGEST_SIZE];
    hctx->update(hctx, msg, msg_len);
    hctx->final(hctx, hash, PTLS_HASH_FINAL_MODE_FREE);

    /* Sign with uECC — produces raw 64-byte R||S */
    if (!uECC_sign(priv32, hash, sizeof(hash), sig_out, uECC_secp256r1()))
        return -1;
    *sig_len_out = 64;
    return 0;
}

/* Build a JWS compact-serialised request body.
 * If kid is set → use kid in header; else embed JWK (for newAccount).
 * Returns heap-allocated JSON string or NULL. */
char *make_jws(const uint8_t *priv32, const uint8_t *pub64,
                      const char *nonce,
                      const char *url,
                      const char *payload_json,
                      const char *kid,
                      const char *thumbprint)
{
    (void)thumbprint;

    char hdr_json[1024];
    if (kid && kid[0]) {
        snprintf(hdr_json, sizeof(hdr_json),
            "{\"alg\":\"ES256\",\"nonce\":\"%s\",\"url\":\"%s\","
            "\"kid\":\"%s\"}",
            nonce, url, kid);
    } else {
        char jwk[256];
        if (eckey_to_jwk(pub64, jwk, sizeof(jwk)) < 0) return NULL;
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

    char si[8192];
    int si_len = snprintf(si, sizeof(si), "%s.%s", hdr_b64, pay_b64);
    if (si_len <= 0 || (size_t)si_len >= sizeof(si)) return NULL;

    unsigned char raw_sig[64];
    size_t raw_sig_len;
    if (ecdsa_sign_raw(priv32, (unsigned char *)si, (size_t)si_len,
                        raw_sig, &raw_sig_len) < 0) return NULL;

    char sig_b64[128];
    if (b64url_encode(raw_sig, raw_sig_len, sig_b64, sizeof(sig_b64)) < 0)
        return NULL;

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

static int load_or_generate_account_key(struct acme_client *cl)
{
    /* Try loading existing PKCS#8 PEM key */
    FILE *f = fopen(cl->account_key_path, "rb");
    if (f) {
        fseek(f, 0, SEEK_END);
        long sz = ftell(f);
        rewind(f);
        if (sz > 0 && sz < 4096) {
            char *pem = malloc((size_t)sz + 1);
            if (pem) {
                if (fread(pem, 1, (size_t)sz, f) == (size_t)sz) {
                    pem[sz] = '\0';
                    if (priv_from_pkcs8_pem(pem, cl->account_key_priv) == 0 &&
                        uECC_compute_public_key(cl->account_key_priv,
                                                cl->account_key_pub,
                                                uECC_secp256r1())) {
                        free(pem);
                        fclose(f);
                        log_info("acme", "loaded account key from %s",
                                 cl->account_key_path);
                        return 0;
                    }
                }
                free(pem);
            }
        }
        fclose(f);
    }

    /* Generate new ECDSA P-256 key pair */
    log_info("acme", "generating new ECDSA P-256 account key → %s",
             cl->account_key_path);
    ptls_minicrypto_random_bytes(cl->account_key_priv, 32);
    /* Ensure private key is a valid P-256 scalar via uECC keygen */
    if (!uECC_make_key(cl->account_key_pub, cl->account_key_priv,
                       uECC_secp256r1())) {
        log_error("acme", "uECC_make_key failed");
        return -1;
    }

    /* Save as PKCS#8 PEM with mode 0600 */
    char pem[256];
    if (pkcs8_pem_from_priv(cl->account_key_priv, pem, sizeof(pem)) < 0)
        return -1;

    int fd = open(cl->account_key_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        log_error("acme", "cannot create key file %s: %s",
                  cl->account_key_path, strerror(errno));
        return -1;
    }
    FILE *wf = fdopen(fd, "wb");
    if (!wf) { close(fd); return -1; }
    fwrite(pem, 1, strlen(pem), wf);
    fclose(wf);
    return 0;
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

    char *jws = make_jws(cl->account_key_priv, cl->account_key_pub,
                         nonce, cl->newAccount_url,
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
    /* Create outbound TLS client context (verify ACME server cert) */
    cl->https_ctx = tls_create_client_ctx(true);
    if (!cl->https_ctx) {
        log_error("acme", "tls_create_client_ctx failed");
        return -1;
    }

    /* Load or generate account key */
    if (load_or_generate_account_key(cl) < 0) {
        log_error("acme", "failed to load/generate account key");
        tls_context_free((ptls_context_t *)cl->https_ctx);
        cl->https_ctx = NULL;
        return -1;
    }

    /* Precompute JWK thumbprint */
    if (compute_jwk_thumbprint(cl->account_key_pub,
                               cl->jwk_thumbprint,
                               sizeof(cl->jwk_thumbprint)) < 0) {
        log_error("acme", "failed to compute JWK thumbprint");
        tls_context_free((ptls_context_t *)cl->https_ctx);
        cl->https_ctx = NULL;
        return -1;
    }
    log_info("acme", "JWK thumbprint: %s", cl->jwk_thumbprint);

    if (fetch_directory(cl) < 0) return -1;
    if (register_account(cl) < 0) return -1;

    return 0;
}

void acme_client_destroy(struct acme_client *cl)
{
    if (cl->https_ctx) {
        tls_context_free((ptls_context_t *)cl->https_ctx);
        cl->https_ctx = NULL;
    }
}

int acme_key_auth(const char *token, const char *thumbprint,
                   char *out, size_t out_max)
{
    int n = snprintf(out, out_max, "%s.%s", token, thumbprint);
    return (n > 0 && (size_t)n < out_max) ? 0 : -1;
}

/* ══════════════════════════════════════════════════════
 *  DER ASN.1 builder helpers
 * ══════════════════════════════════════════════════════ */

typedef struct { uint8_t *p; size_t off; size_t cap; } DerBuf;

static int db_byte(DerBuf *d, uint8_t b) {
    if (d->off >= d->cap) return -1;
    d->p[d->off++] = b; return 0;
}

static int db_len(DerBuf *d, size_t len) {
    if (len < 0x80) return db_byte(d, (uint8_t)len);
    if (len < 0x100) {
        if (db_byte(d, 0x81) < 0 || db_byte(d, (uint8_t)len) < 0) return -1;
        return 0;
    }
    if (db_byte(d, 0x82) < 0 ||
        db_byte(d, (uint8_t)(len >> 8)) < 0 ||
        db_byte(d, (uint8_t)(len & 0xff)) < 0) return -1;
    return 0;
}

static int db_bytes(DerBuf *d, const uint8_t *data, size_t len) {
    if (d->off + len > d->cap) return -1;
    memcpy(d->p + d->off, data, len);
    d->off += len;
    return 0;
}

static int db_tlv(DerBuf *d, uint8_t tag, const uint8_t *val, size_t len) {
    if (db_byte(d, tag) < 0) return -1;
    if (db_len(d, len) < 0) return -1;
    if (db_bytes(d, val, len) < 0) return -1;
    return 0;
}

/* Wrap the bytes at d->p[start..d->off] with a DER tag+length.
 * Shifts existing content forward to make room. */
static int db_wrap(DerBuf *d, size_t start, uint8_t tag) {
    size_t content_len = d->off - start;
    /* Determine header size */
    size_t hdr = 2;
    if (content_len >= 0x80 && content_len < 0x100) hdr = 3;
    else if (content_len >= 0x100) hdr = 4;
    if (d->off + hdr > d->cap) return -1;
    memmove(d->p + start + hdr, d->p + start, content_len);
    size_t i = start;
    d->p[i++] = tag;
    if (content_len < 0x80) {
        d->p[i++] = (uint8_t)content_len;
    } else if (content_len < 0x100) {
        d->p[i++] = 0x81;
        d->p[i++] = (uint8_t)content_len;
    } else {
        d->p[i++] = 0x82;
        d->p[i++] = (uint8_t)(content_len >> 8);
        d->p[i++] = (uint8_t)(content_len & 0xff);
    }
    d->off += hdr;
    return 0;
}

/* Convert raw 64-byte R||S to DER-encoded ECDSA signature.
 * Returns number of bytes written. */
static int ecdsa_rs_to_der(const uint8_t rs[64], uint8_t *out, size_t out_max) {
    /* Each of R, S may need a 0x00 pad byte if high bit is set */
    int rpad = (rs[0]    & 0x80) ? 1 : 0;
    int spad = (rs[32]   & 0x80) ? 1 : 0;
    int rlen = 32 + rpad;
    int slen = 32 + spad;
    /* inner: 2+rlen + 2+slen */
    int inner = 2 + rlen + 2 + slen;
    if ((size_t)(2 + inner) > out_max) return -1;
    uint8_t *p = out;
    *p++ = 0x30; *p++ = (uint8_t)inner;
    *p++ = 0x02; *p++ = (uint8_t)rlen;
    if (rpad) *p++ = 0x00;
    memcpy(p, rs,      32); p += 32;
    *p++ = 0x02; *p++ = (uint8_t)slen;
    if (spad) *p++ = 0x00;
    memcpy(p, rs + 32, 32); p += 32;
    return (int)(p - out);
}

/* ══════════════════════════════════════════════════════
 *  CSR generation — hand-crafted DER ASN.1
 * ══════════════════════════════════════════════════════ */

/* Fixed OIDs */
static const uint8_t OID_EC_PUBLIC_KEY[] = {0x2a,0x86,0x48,0xce,0x3d,0x02,0x01};
static const uint8_t OID_PRIME256V1[]    = {0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07};
static const uint8_t OID_COMMON_NAME[]   = {0x55,0x04,0x03};
static const uint8_t OID_SAN[]           = {0x55,0x1d,0x11};
static const uint8_t OID_EXTN_REQ[]      = {0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x09,0x0e};
static const uint8_t OID_ECDSA_SHA256[]  = {0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x02};

/*
 * Build a PKCS#10 CSR for an ECDSA P-256 key with CN=domain and SAN=DNS:domain.
 * priv_out receives the 32-byte raw private key of the new domain key.
 * *csr_out is heap-allocated; *csr_len_out is set to its length.
 */
int make_csr_der(const char *domain,
                        uint8_t priv_out[32],
                        uint8_t **csr_out, size_t *csr_len_out)
{
    /* Generate fresh domain key pair */
    uint8_t priv[32], pub[64];
    if (!uECC_make_key(pub, priv, uECC_secp256r1())) return -1;

    size_t dlen = strlen(domain);

    /* ──────────────────────────────────────────────────────────────────────
     * Clean CSR construction using pre-sized flat buffers.
     * Build inner-to-outer, measuring sizes first.
     * ──────────────────────────────────────────────────────────────────── */

    /* [A] subjectPublicKeyInfo (fixed size) */
    uint8_t spki_buf[128];
    size_t spki_total;
    {
        /* algorithmIdentifier SEQUENCE */
        uint8_t alg[21];
        alg[0] = 0x30; alg[1] = 19;
        alg[2] = 0x06; alg[3] = 7;
        memcpy(alg + 4, OID_EC_PUBLIC_KEY, 7);
        alg[11] = 0x06; alg[12] = 8;
        memcpy(alg + 13, OID_PRIME256V1, 8);
        /* BIT STRING: tag + len + 0x00 + 0x04 + X + Y */
        uint8_t bs[68]; /* 03 42 00 04 + 64 bytes */
        bs[0] = 0x03; bs[1] = 66; bs[2] = 0x00; bs[3] = 0x04;
        memcpy(bs + 4, pub, 64);
        /* wrap in SEQUENCE */
        size_t inner = sizeof(alg) + sizeof(bs); /* 21 + 68 = 89 */
        spki_buf[0] = 0x30;
        spki_buf[1] = (uint8_t)inner;
        memcpy(spki_buf + 2, alg, sizeof(alg));
        memcpy(spki_buf + 2 + sizeof(alg), bs, sizeof(bs));
        spki_total = 2 + inner; /* 91 */
    }

    /* [B] subject SEQUENCE */
    uint8_t subj_buf[256];
    size_t subj_total;
    {
        DerBuf sb = { subj_buf, 0, sizeof(subj_buf) };
        size_t rdns = sb.off;
        db_tlv(&sb, 0x06, OID_COMMON_NAME, sizeof(OID_COMMON_NAME));
        db_tlv(&sb, 0x0c, (const uint8_t *)domain, dlen);
        db_wrap(&sb, rdns, 0x30); /* AttrTypeAndValue SEQUENCE */
        db_wrap(&sb, 0,    0x31); /* RelativeDistinguishedName SET */
        db_wrap(&sb, 0,    0x30); /* Name SEQUENCE */
        subj_total = sb.off;
    }

    /* [C] attributes [0]: extensionRequest with subjectAltName */
    uint8_t san_ext_buf[256];
    size_t san_ext_total;
    {
        /* GeneralNames SEQUENCE { [2] IMPLICIT dNSName domain } */
        uint8_t dns_name[2 + 64 + 2]; /* tag(1)+len(1)+domain */
        dns_name[0] = 0x82; dns_name[1] = (uint8_t)dlen;
        memcpy(dns_name + 2, domain, dlen);
        size_t dns_tlv_len = 2 + dlen;

        /* GeneralNames SEQUENCE wrapping the DNS name */
        uint8_t gnames[4 + 64 + 2];
        gnames[0] = 0x30; gnames[1] = (uint8_t)dns_tlv_len;
        memcpy(gnames + 2, dns_name, dns_tlv_len);
        size_t gnames_len = 2 + dns_tlv_len;

        /* OCTET STRING { GeneralNames SEQUENCE } */
        uint8_t octet_str[6 + 64 + 2];
        octet_str[0] = 0x04; octet_str[1] = (uint8_t)gnames_len;
        memcpy(octet_str + 2, gnames, gnames_len);
        size_t octet_len = 2 + gnames_len;

        /* Extension SEQUENCE { OID subjectAltName, OCTET STRING } */
        uint8_t ext_seq_buf[16 + 64 + 2];
        DerBuf es = { ext_seq_buf, 0, sizeof(ext_seq_buf) };
        db_tlv(&es, 0x06, OID_SAN, sizeof(OID_SAN));
        db_bytes(&es, octet_str, octet_len);
        db_wrap(&es, 0, 0x30); /* Extension SEQUENCE */
        size_t ext_seq_len = es.off;

        /* Extensions SEQUENCE { extension } */
        uint8_t exts_seq_buf[16 + 64 + 2 + 16];
        DerBuf exts = { exts_seq_buf, 0, sizeof(exts_seq_buf) };
        db_bytes(&exts, ext_seq_buf, ext_seq_len);
        db_wrap(&exts, 0, 0x30);
        size_t exts_len = exts.off;

        /* extensionRequest SEQUENCE { OID, SET { Extensions SEQUENCE } } */
        DerBuf se = { san_ext_buf, 0, sizeof(san_ext_buf) };
        size_t oid_start = se.off;
        db_tlv(&se, 0x06, OID_EXTN_REQ, sizeof(OID_EXTN_REQ));
        size_t set_start = se.off;
        db_bytes(&se, exts_seq_buf, exts_len);
        db_wrap(&se, set_start, 0x31); /* SET wrapping extensions */
        db_wrap(&se, oid_start, 0x30); /* Attribute SEQUENCE */
        /* attributes [0] IMPLICIT */
        db_wrap(&se, 0, 0xa0);
        san_ext_total = se.off;
    }

    /* [D] CertificationRequestInfo SEQUENCE {version, subject, spki, attrs} */
    uint8_t cri_buf[1024];
    size_t cri_total;
    {
        DerBuf cri = { cri_buf, 0, sizeof(cri_buf) };
        /* version INTEGER 0 */
        uint8_t ver[] = {0x02, 0x01, 0x00};
        db_bytes(&cri, ver, 3);
        /* subject */
        db_bytes(&cri, subj_buf, subj_total);
        /* subjectPublicKeyInfo */
        db_bytes(&cri, spki_buf, spki_total);
        /* attributes */
        db_bytes(&cri, san_ext_buf, san_ext_total);
        /* wrap in SEQUENCE */
        db_wrap(&cri, 0, 0x30);
        cri_total = cri.off;
    }

    /* [E] Sign CertificationRequestInfo with SHA-256 + ECDSA P-256 */
    ptls_hash_context_t *hctx = ptls_minicrypto_sha256.create();
    if (!hctx) return -1;
    uint8_t cri_hash[32];
    hctx->update(hctx, cri_buf, cri_total);
    hctx->final(hctx, cri_hash, PTLS_HASH_FINAL_MODE_FREE);

    uint8_t rs[64];
    if (!uECC_sign(priv, cri_hash, 32, rs, uECC_secp256r1())) return -1;

    /* DER-encode the signature */
    uint8_t sig_der[74]; /* max: 30 48 02 21 00 [32] 02 21 00 [32] */
    int sig_der_len = ecdsa_rs_to_der(rs, sig_der, sizeof(sig_der));
    if (sig_der_len < 0) return -1;

    /* [F] Build full CSR */
    size_t csr_max = cri_total + 16 + (size_t)sig_der_len + 16;
    uint8_t *csr_buf = malloc(csr_max);
    if (!csr_buf) return -1;

    DerBuf csr = { csr_buf, 0, csr_max };
    /* CertificationRequestInfo (already SEQUENCE-wrapped) */
    db_bytes(&csr, cri_buf, cri_total);
    /* signatureAlgorithm SEQUENCE { OID ecdsa-with-SHA256 } */
    {
        size_t sa_start = csr.off;
        db_tlv(&csr, 0x06, OID_ECDSA_SHA256, sizeof(OID_ECDSA_SHA256));
        db_wrap(&csr, sa_start, 0x30);
    }
    /* signature BIT STRING: 0x00 + DER_sig */
    {
        uint8_t bs[76];
        bs[0] = 0x00;
        memcpy(bs + 1, sig_der, (size_t)sig_der_len);
        db_tlv(&csr, 0x03, bs, 1 + (size_t)sig_der_len);
    }
    /* wrap entire CSR in SEQUENCE */
    db_wrap(&csr, 0, 0x30);

    *csr_out = csr_buf;
    *csr_len_out = csr.off;
    memcpy(priv_out, priv, 32);
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

        if (get_fresh_nonce(cl, nonce, sizeof(nonce)) < 0) return -1;
        char *jws = make_jws(cl->account_key_priv, cl->account_key_pub,
                             nonce, url,
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
 *  X.509 notAfter parser (lightweight DER walker)
 * ══════════════════════════════════════════════════════ */

/* Skip a DER TLV, return offset after the element or 0 on error. */
static size_t der_skip(const uint8_t *der, size_t off, size_t max)
{
    if (off + 2 > max) return 0;
    off++; /* skip tag */
    uint8_t lb = der[off++];
    size_t len;
    if (lb < 0x80) {
        len = lb;
    } else if (lb == 0x81) {
        if (off + 1 > max) return 0;
        len = der[off++];
    } else if (lb == 0x82) {
        if (off + 2 > max) return 0;
        len = ((size_t)der[off] << 8) | der[off+1]; off += 2;
    } else { return 0; }
    off += len;
    return (off <= max) ? off : 0;
}

/* Enter a SEQUENCE or context tag: returns offset of first child or 0. */
static size_t der_enter(const uint8_t *der, size_t off, size_t max, uint8_t tag)
{
    if (off + 2 > max || der[off] != tag) return 0;
    off++;
    uint8_t lb = der[off++];
    if (lb < 0x80) { (void)lb; }
    else if (lb == 0x81) { if (off + 1 > max) return 0; off++; }
    else if (lb == 0x82) { if (off + 2 > max) return 0; off += 2; }
    else return 0;
    return off;
}

/* Parse X.509 Time (UTCTime 0x17 or GeneralizedTime 0x18) → time_t.
 * UTCTime:        YYMMDDHHMMSSZ  (13 chars)
 * GeneralizedTime: YYYYMMDDHHMMSSZ (15 chars) */
static time_t parse_x509_time(const uint8_t *der, size_t off, size_t max)
{
    if (off + 2 > max) return 0;
    uint8_t tag = der[off];
    if (tag != 0x17 && tag != 0x18) return 0;
    off++;
    size_t len = der[off++];
    if (off + len > max || (len != 13 && len != 15)) return 0;

    const char *s = (const char *)(der + off);
    struct tm t;
    memset(&t, 0, sizeof(t));

    if (len == 13) { /* UTCTime: YYMMDDHHMMSSZ */
        t.tm_year = (s[0]-'0')*10 + (s[1]-'0');
        t.tm_year += (t.tm_year < 50) ? 100 : 0; /* RFC 5280 pivot */
        t.tm_mon  = (s[2]-'0')*10 + (s[3]-'0') - 1;
        t.tm_mday = (s[4]-'0')*10 + (s[5]-'0');
        t.tm_hour = (s[6]-'0')*10 + (s[7]-'0');
        t.tm_min  = (s[8]-'0')*10 + (s[9]-'0');
        t.tm_sec  = (s[10]-'0')*10 + (s[11]-'0');
    } else { /* GeneralizedTime: YYYYMMDDHHMMSSZ */
        t.tm_year = (s[0]-'0')*1000 + (s[1]-'0')*100 +
                    (s[2]-'0')*10   + (s[3]-'0') - 1900;
        t.tm_mon  = (s[4]-'0')*10 + (s[5]-'0') - 1;
        t.tm_mday = (s[6]-'0')*10 + (s[7]-'0');
        t.tm_hour = (s[8]-'0')*10 + (s[9]-'0');
        t.tm_min  = (s[10]-'0')*10 + (s[11]-'0');
        t.tm_sec  = (s[12]-'0')*10 + (s[13]-'0');
    }
    return timegm(&t);
}

/* Find the notAfter in an X.509 DER cert.
 * Structure: Certificate > TBSCertificate > Validity > notAfter */
time_t der_cert_not_after(const uint8_t *der, size_t der_len)
{
    size_t off = 0;
    /* Certificate SEQUENCE */
    off = der_enter(der, off, der_len, 0x30);
    if (!off) return 0;
    /* TBSCertificate SEQUENCE */
    off = der_enter(der, off, der_len, 0x30);
    if (!off) return 0;
    /* Skip optional version [0] */
    if (off < der_len && der[off] == 0xa0)
        off = der_skip(der, off, der_len);
    if (!off) return 0;
    /* serialNumber INTEGER */
    off = der_skip(der, off, der_len);
    if (!off) return 0;
    /* signature AlgorithmIdentifier */
    off = der_skip(der, off, der_len);
    if (!off) return 0;
    /* issuer Name */
    off = der_skip(der, off, der_len);
    if (!off) return 0;
    /* Validity SEQUENCE */
    off = der_enter(der, off, der_len, 0x30);
    if (!off) return 0;
    /* notBefore */
    off = der_skip(der, off, der_len);
    if (!off) return 0;
    /* notAfter */
    return parse_x509_time(der, off, der_len);
}

/* Decode first PEM CERTIFICATE block → DER bytes (heap-allocated). */
uint8_t *pem_cert_to_der(const char *pem, size_t *der_len_out)
{
    const char *b = strstr(pem, "-----BEGIN CERTIFICATE-----");
    if (!b) return NULL;
    b += 27;
    while (*b == '\r' || *b == '\n') b++;
    const char *e = strstr(b, "-----END CERTIFICATE-----");
    if (!e) return NULL;

    size_t max_der = (size_t)(e - b) * 3 / 4 + 4;
    uint8_t *der = malloc(max_der);
    if (!der) return NULL;
    int n = b64std_decode(b, (size_t)(e - b), der, max_der);
    if (n <= 0) { free(der); return NULL; }
    *der_len_out = (size_t)n;
    return der;
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
        char *jws = make_jws(cl->account_key_priv, cl->account_key_pub,
                             nonce, cl->newOrder_url,
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
        char *jws = make_jws(cl->account_key_priv, cl->account_key_pub,
                             nonce, authz_url,
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
        char *jws = make_jws(cl->account_key_priv, cl->account_key_pub,
                             nonce, challenge_url,
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
    uint8_t domain_priv[32];
    uint8_t *csr_der = NULL;
    size_t csr_len = 0;
    if (make_csr_der(domain, domain_priv, &csr_der, &csr_len) < 0) {
        log_error("acme", "CSR generation failed");
        goto done;
    }

    /* 7. Finalize */
    {
        char csr_b64[4096];
        if (b64url_encode(csr_der, csr_len, csr_b64, sizeof(csr_b64)) < 0) {
            free(csr_der);
            goto done;
        }
        free(csr_der);

        char pay[5000];
        snprintf(pay, sizeof(pay), "{\"csr\":\"%s\"}", csr_b64);

        if (get_fresh_nonce(cl, nonce, sizeof(nonce)) < 0) goto done;
        char loc2[8] = "";
        char *jws = make_jws(cl->account_key_priv, cl->account_key_pub,
                             nonce, finalize_url,
                             pay, cl->account_url, cl->jwk_thumbprint);
        if (!jws) goto done;

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
            goto done;
        }
    }

    /* 8. Poll order until valid */
    if (order_url[0]) {
        if (poll_for_status(cl, order_url, "valid", 120) < 0) {
            free(resp); resp = NULL;
            goto done;
        }
    }

    /* Re-fetch order to get certificate URL */
    {
        free(resp); resp = NULL;
        if (get_fresh_nonce(cl, nonce, sizeof(nonce)) < 0) goto done;
        char loc2[8] = "";
        char *jws = make_jws(cl->account_key_priv, cl->account_key_pub,
                             nonce, order_url,
                             NULL, cl->account_url, cl->jwk_thumbprint);
        if (!jws) goto done;
        int r = https_request(cl, "POST", order_url,
                              "application/jose+json",
                              jws, strlen(jws),
                              &status, loc2, sizeof(loc2),
                              nonce, sizeof(nonce),
                              &resp, NULL);
        free(jws);
        if (r < 0 || status != 200) {
            log_error("acme", "order fetch returned %d", status);
            goto done;
        }
    }

    char cert_url[ACME_MAX_URL] = "";
    json_get_str(resp ? resp : "", "certificate", cert_url, sizeof(cert_url));
    free(resp); resp = NULL;

    if (!cert_url[0]) {
        log_error("acme", "no certificate URL in finalized order");
        goto done;
    }

    /* 9. Download certificate */
    if (get_fresh_nonce(cl, nonce, sizeof(nonce)) < 0) goto done;
    {
        char loc2[8] = "";
        char *jws = make_jws(cl->account_key_priv, cl->account_key_pub,
                             nonce, cert_url,
                             NULL, cl->account_url, cl->jwk_thumbprint);
        if (!jws) goto done;
        int r = https_request(cl, "POST", cert_url,
                              "application/jose+json",
                              jws, strlen(jws),
                              &status, loc2, sizeof(loc2),
                              nonce, sizeof(nonce),
                              &resp, NULL);
        free(jws);
        if (r < 0 || status != 200) {
            log_error("acme", "cert download returned %d", status);
            goto done;
        }
    }

    /* resp contains the cert PEM chain; encode domain key to PKCS#8 PEM */
    char key_pem[256];
    if (pkcs8_pem_from_priv(domain_priv, key_pem, sizeof(key_pem)) < 0) {
        free(resp);
        goto done;
    }

    /* 10. Save to storage_path/domain/ */
    {
        char dom_dir[4096];
        snprintf(dom_dir, sizeof(dom_dir), "%s/%s", cl->storage_path, domain);
        ensure_dir(cl->storage_path);
        ensure_dir(dom_dir);

        const char *cp = cert_path_for(cl->storage_path, domain, "cert.pem");
        FILE *cf = fopen(cp, "wb");
        if (cf) { fwrite(resp, 1, strlen(resp), cf); fclose(cf); }

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
    out->cert_pem  = resp; resp = NULL;
    out->key_pem   = strdup(key_pem);
    out->not_after = 0;
    {
        size_t der_len = 0;
        uint8_t *der = pem_cert_to_der(out->cert_pem, &der_len);
        if (der) {
            out->not_after = der_cert_not_after(der, der_len);
            free(der);
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

    size_t der_len = 0;
    uint8_t *der = pem_cert_to_der(pem, &der_len);
    free(pem);
    if (!der) return 1;

    time_t not_after = der_cert_not_after(der, der_len);
    free(der);
    if (!not_after) return 1;

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
