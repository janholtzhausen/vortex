/*
 * quic.c — HTTP/3 server via ngtcp2 + nghttp3 + OpenSSL 4.0
 *
 * Architecture:
 *   - One UDP socket per quic_server (SO_REUSEPORT — one instance total)
 *   - epoll-based event loop in a dedicated thread
 *   - Per-connection ngtcp2_conn + nghttp3_conn state
 *   - Completed requests are proxied to the backend synchronously in a
 *     short-lived thread (QUIC transport is async; backend I/O is blocking)
 *   - worker.c RECV_BACKEND injects Alt-Svc: h3=":443"; ma=86400
 */

#ifdef VORTEX_QUIC

#include "quic.h"
#include "log.h"
#include "router.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>
#include <nghttp3/nghttp3.h>

#include <openssl/ssl.h>
#include <openssl/rand.h>

/* ---- Timestamp ---- */
static ngtcp2_tstamp now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ngtcp2_tstamp)ts.tv_sec * NGTCP2_SECONDS +
           (ngtcp2_tstamp)ts.tv_nsec;
}

/* ---- Per-stream state (needed by forward decls below) ---- */
struct quic_conn;
struct quic_server;

struct quic_stream {
    int64_t  stream_id;

    char     method[16];
    char     url[512];
    char     authority[256];

    uint8_t *req_body;
    size_t   req_body_len;
    bool     req_too_large;
    bool     headers_done;
    bool     request_done;

    uint8_t *resp_buf;
    size_t   resp_len;
    size_t   resp_offset;
    bool     resp_submitted;

    struct quic_conn *conn;
};

static int  conn_send(struct quic_conn *c);
static void conn_free(struct quic_server *qs, struct quic_conn *c);
static void submit_h3_response(struct quic_conn *c, struct quic_stream *s);

static uint8_t *dup_http_response(const char *resp, size_t *out_len)
{
    uint8_t *buf = (uint8_t *)strdup(resp);
    if (out_len) *out_len = buf ? strlen(resp) : 0;
    return buf;
}

/* ---- Per-connection state ---- */
struct quic_conn {
    ngtcp2_conn            *conn;
    ngtcp2_crypto_ossl_ctx *ossl_ctx;
    SSL                    *ssl;
    nghttp3_conn           *h3conn;

    ngtcp2_crypto_conn_ref  conn_ref;

    struct sockaddr_storage peer_addr;
    socklen_t               peer_addrlen;

    struct quic_stream *streams[QUIC_MAX_STREAMS];
    int                 stream_count;

    uint8_t  send_buf[65536];
    ngtcp2_tstamp last_active;
    bool     handshake_done;
    bool     closing;

    struct quic_server *server;
};

/* ---- Async backend proxy completion ring ---- */
#define QUIC_COMP_RING_SIZE 1024

struct proxy_completion {
    struct sockaddr_storage peer_addr;
    socklen_t               peer_addrlen;
    int64_t                 stream_id;
    uint8_t                *resp_buf;
    size_t                  resp_len;
};

/* ---- Server state ---- */
struct quic_server {
    int    udp_fd;
    int    epoll_fd;

    SSL_CTX *ssl_ctx[VORTEX_MAX_ROUTES];
    int      ssl_ctx_count;

    struct quic_conn *conns[QUIC_MAX_CONNS];
    int               conn_count;

    struct vortex_config *cfg;
    struct cache         *cache;
    struct router         router;

    struct sockaddr_storage local_addr;
    socklen_t               local_addrlen;

    pthread_t    thread;
    volatile int stop;

    /* Completion ring for detached proxy threads */
    int                    comp_efd;
    pthread_mutex_t        comp_mu;
    struct proxy_completion comp_ring[QUIC_COMP_RING_SIZE];
    int                    comp_head;
    int                    comp_tail;
};

/* ---- Stream helpers ---- */

static struct quic_stream *stream_find(struct quic_conn *c, int64_t sid)
{
    for (int i = 0; i < QUIC_MAX_STREAMS; i++)
        if (c->streams[i] && c->streams[i]->stream_id == sid)
            return c->streams[i];
    return NULL;
}

static struct quic_stream *stream_get_or_alloc(struct quic_conn *c, int64_t sid)
{
    struct quic_stream *s = stream_find(c, sid);
    if (s) return s;
    if (c->stream_count >= QUIC_MAX_STREAMS) return NULL;
    s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->stream_id = sid;
    s->conn      = c;
    for (int i = 0; i < QUIC_MAX_STREAMS; i++) {
        if (!c->streams[i]) { c->streams[i] = s; c->stream_count++; return s; }
    }
    free(s);
    return NULL;
}

static void stream_free(struct quic_conn *c, struct quic_stream *s)
{
    if (!s) return;
    free(s->req_body);
    free(s->resp_buf);
    for (int i = 0; i < QUIC_MAX_STREAMS; i++) {
        if (c->streams[i] == s) { c->streams[i] = NULL; c->stream_count--; break; }
    }
    free(s);
}

/* ---- Backend proxy (detached, async via completion ring) ---- */

struct proxy_args {
    struct quic_server     *server;
    struct sockaddr_storage peer_addr;
    socklen_t               peer_addrlen;
    int64_t                 stream_id;
    int                     route_idx;
    int                     backend_idx;
    char                    backend_addr[256];
    char                    method[16];
    char                    url[512];
    char                    authority[256];
    uint8_t                *req_body;
    size_t                  req_body_len;
};

/* Decode chunked transfer-encoding in-place; returns new body length. */
static size_t dechunk_body(uint8_t *body, size_t body_len)
{
    uint8_t *src = body, *dst = body, *end = body + body_len;
    while (src < end) {
        uint8_t *crlf = memmem(src, (size_t)(end - src), "\r\n", 2);
        if (!crlf) break;
        size_t sz_len = (size_t)(crlf - src);
        if (sz_len == 0 || sz_len > 16) break;
        char sz_buf[20] = {0};
        memcpy(sz_buf, src, sz_len);
        size_t chunk = (size_t)strtoul(sz_buf, NULL, 16);
        src = crlf + 2;
        if (chunk == 0) break; /* last-chunk */
        if (src + chunk > end) {
            size_t avail = (size_t)(end - src);
            memmove(dst, src, avail);
            dst += avail;
            break;
        }
        memmove(dst, src, chunk);
        dst += chunk;
        src += chunk + 2; /* skip chunk-data CRLF */
    }
    return (size_t)(dst - body);
}

static void *proxy_thread(void *arg)
{
    struct proxy_args *pa = arg;
    uint8_t *resp_buf = NULL;
    size_t   resp_len = 0;

    char host[256] = {0}, port_str[16] = {0};
    const char *colon = strrchr(pa->backend_addr, ':');
    if (!colon) goto push;
    size_t hlen = (size_t)(colon - pa->backend_addr);
    if (hlen >= sizeof(host)) goto push;
    memcpy(host, pa->backend_addr, hlen);
    snprintf(port_str, sizeof(port_str), "%s", colon + 1);

    {
        struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM };
        struct addrinfo *res = NULL;
        if (getaddrinfo(host, port_str, &hints, &res) != 0) goto push;

        int fd = -1;
        for (struct addrinfo *rp = res; rp; rp = rp->ai_next) {
            fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (fd < 0) continue;
            if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
            close(fd); fd = -1;
        }
        freeaddrinfo(res);
        if (fd < 0) goto push;

        /* HTTP/1.1 request */
        char req_hdr[2048];
        int rn = snprintf(req_hdr, sizeof(req_hdr),
            "%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nContent-Length: %zu\r\n\r\n",
            pa->method[0]    ? pa->method    : "GET",
            pa->url[0]       ? pa->url       : "/",
            pa->authority[0] ? pa->authority : host,
            pa->req_body_len);
        send(fd, req_hdr, (size_t)rn, MSG_NOSIGNAL);
        if (pa->req_body && pa->req_body_len)
            send(fd, pa->req_body, pa->req_body_len, MSG_NOSIGNAL);

        /* Read full response */
        size_t cap = 65536, len = 0;
        uint8_t *buf = malloc(cap);
        if (!buf) { close(fd); goto push; }

        while (1) {
            if (len == cap) {
                if (cap >= QUIC_RESP_MAX) break;
                size_t ncap = cap * 2 < QUIC_RESP_MAX ? cap * 2 : QUIC_RESP_MAX;
                uint8_t *nb = realloc(buf, ncap);
                if (!nb) break;
                buf = nb; cap = ncap;
            }
            ssize_t r = recv(fd, buf + len, cap - len, 0);
            if (r <= 0) break;
            len += (size_t)r;
        }
        close(fd);

        /* Dechunk body if Transfer-Encoding: chunked */
        const uint8_t *hdr_end_p = memmem(buf, len, "\r\n\r\n", 4);
        if (hdr_end_p) {
            size_t hdr_area = (size_t)(hdr_end_p - buf);
            const uint8_t *te = memmem(buf, hdr_area, "\r\nTransfer-Encoding:", 20);
            if (!te) te = memmem(buf, hdr_area, "\r\ntransfer-encoding:", 20);
            bool chunked = false;
            if (te) {
                const uint8_t *tv  = te + 20;
                const uint8_t *eol = memmem(tv, (size_t)(hdr_end_p - tv), "\r\n", 2);
                if (!eol) eol = hdr_end_p;
                while (tv < eol && (*tv == ' ' || *tv == '\t')) tv++;
                if ((size_t)(eol - tv) >= 7 &&
                    strncasecmp((const char *)tv, "chunked", 7) == 0)
                    chunked = true;
            }
            if (chunked) {
                size_t hdr_size = hdr_area + 4;
                size_t new_body = dechunk_body(buf + hdr_size, len - hdr_size);
                len = hdr_size + new_body;
            }
        }

        if (pa->server->cache && pa->server->cache->index &&
            strcmp(pa->method, "GET") == 0 && len > 0) {
            const uint8_t *hdr_end2 = memmem(buf, len, "\r\n\r\n", 4);
            if (hdr_end2) {
                size_t hdr_len = (size_t)(hdr_end2 + 4 - buf);
                size_t body_len = len - hdr_len;
                bool is_chunked =
                    memmem(buf, hdr_len, "\r\nTransfer-Encoding:", 20) ||
                    memmem(buf, hdr_len, "\r\ntransfer-encoding:", 20);
                int status = 0;
                if (len > 12) {
                    const char *sp = (const char *)buf + 9;
                    for (int i = 0; i < 3 && sp[i] >= '0' && sp[i] <= '9'; i++)
                        status = status * 10 + (sp[i] - '0');
                }
                uint32_t ttl = cache_ttl_for_url(pa->url);
                if (!is_chunked && status == 200 && ttl > 0 && body_len > 0) {
                    char cache_key[1024];
                    snprintf(cache_key, sizeof(cache_key), "%s|%s", pa->authority, pa->url);
                    cache_store(pa->server->cache, cache_key, strlen(cache_key),
                                (uint16_t)status, ttl, buf, hdr_len, buf + hdr_len, body_len);
                    log_debug("h3_cache_store", "stream=%lld url=%s ttl=%u body=%zu",
                              (long long)pa->stream_id, cache_key, ttl, body_len);
                }
            }
        }

        resp_buf = buf;
        resp_len = len;
    }

push:;
    router_backend_active_dec(pa->route_idx, pa->backend_idx);
    struct quic_server *qs = pa->server;
    pthread_mutex_lock(&qs->comp_mu);
    int next = (qs->comp_tail + 1) % QUIC_COMP_RING_SIZE;
    if (next != qs->comp_head) {
        struct proxy_completion *comp = &qs->comp_ring[qs->comp_tail];
        memcpy(&comp->peer_addr, &pa->peer_addr, pa->peer_addrlen);
        comp->peer_addrlen = pa->peer_addrlen;
        comp->stream_id    = pa->stream_id;
        comp->resp_buf     = resp_buf;
        comp->resp_len     = resp_len;
        qs->comp_tail      = next;
        uint64_t one = 1;
        (void)write(qs->comp_efd, &one, sizeof(one));
        resp_buf = NULL; /* ownership transferred */
    } else {
        log_warn("quic_proxy", "completion ring full, dropping response");
    }
    pthread_mutex_unlock(&qs->comp_mu);

    free(resp_buf); /* NULL if transferred, else discard */
    free(pa->req_body);
    free(pa);
    return NULL;
}

static void dispatch_request(struct quic_conn *c, struct quic_stream *s)
{
    struct quic_server *qs = c->server;

    if (s->req_too_large) {
        static const char r413[] =
            "HTTP/1.1 413 Payload Too Large\r\n"
            "Content-Length: 0\r\n\r\n";
        s->resp_buf = dup_http_response(r413, &s->resp_len);
        return;
    }

    if (qs->cache && qs->cache->index &&
        s->method[0] && strcmp(s->method, "GET") == 0) {
        char cache_key[1024];
        snprintf(cache_key, sizeof(cache_key), "%s|%s", s->authority, s->url);
        struct cached_response cached;
        if (cache_fetch_copy(qs->cache, cache_key, strlen(cache_key), &cached) == 0) {
            s->resp_buf = cached.data;
            s->resp_len = cached.header_len + cached.body_len;
            log_debug("h3_cache_hit", "stream=%lld url=%s",
                      (long long)s->stream_id, cache_key);
            return;
        }
    }

    int route_idx = 0;
    for (int i = 0; i < qs->cfg->route_count; i++) {
        if (s->authority[0] &&
            strcasecmp(s->authority, qs->cfg->routes[i].hostname) == 0) {
            route_idx = i; break;
        }
    }

    const char *addr = NULL;
    int backend_idx = -1;
    if (qs->cfg->route_count > 0) {
        backend_idx = router_select_backend(&qs->router, route_idx, 0);
        addr = router_backend_addr(&qs->router, route_idx, backend_idx);
    }

    if (!addr) goto err_502;

    {
        struct proxy_args *pa = calloc(1, sizeof(*pa));
        if (!pa) goto err_502;
        pa->server       = qs;
        memcpy(&pa->peer_addr, &c->peer_addr, c->peer_addrlen);
        pa->peer_addrlen = c->peer_addrlen;
        pa->stream_id    = s->stream_id;
        pa->route_idx    = route_idx;
        pa->backend_idx  = backend_idx;
        snprintf(pa->backend_addr, sizeof(pa->backend_addr), "%s", addr);
        snprintf(pa->method, sizeof(pa->method), "%s", s->method);
        snprintf(pa->url, sizeof(pa->url), "%s", s->url);
        snprintf(pa->authority, sizeof(pa->authority), "%s", s->authority);
        if (s->req_body_len > 0) {
            pa->req_body = malloc(s->req_body_len);
            if (!pa->req_body) { free(pa); goto err_502; }
            memcpy(pa->req_body, s->req_body, s->req_body_len);
            pa->req_body_len = s->req_body_len;
        }

        pthread_t t;
        pthread_attr_t attr;
        router_backend_active_inc(route_idx, backend_idx);
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&t, &attr, proxy_thread, pa) == 0) {
            pthread_attr_destroy(&attr);
            return; /* proxy thread will push completion via eventfd */
        }
        pthread_attr_destroy(&attr);
        router_backend_active_dec(route_idx, backend_idx);
        free(pa->req_body);
        free(pa);
    }

err_502:;
    static const char r502[] = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
    s->resp_buf = dup_http_response(r502, &s->resp_len);
}

/* ---- ngtcp2 callbacks ---- */

static ngtcp2_conn *quic_get_conn(ngtcp2_crypto_conn_ref *ref)
{
    return ((struct quic_conn *)ref->user_data)->conn;
}

static int cb_recv_client_initial(ngtcp2_conn *conn, const ngtcp2_cid *dcid,
                                   void *user_data)
{
    (void)conn;
    return ngtcp2_crypto_recv_client_initial_cb(
        ((struct quic_conn *)user_data)->conn, dcid, user_data);
}

static int cb_recv_crypto_data(ngtcp2_conn *conn,
                                ngtcp2_encryption_level level,
                                uint64_t offset,
                                const uint8_t *data, size_t datalen,
                                void *user_data)
{
    (void)conn;
    return ngtcp2_crypto_recv_crypto_data_cb(
        ((struct quic_conn *)user_data)->conn,
        level, offset, data, datalen, user_data);
}

static int cb_handshake_completed(ngtcp2_conn *conn, void *user_data);

static int cb_recv_stream_data(ngtcp2_conn *conn, uint32_t flags,
                                int64_t stream_id, uint64_t offset,
                                const uint8_t *data, size_t datalen,
                                void *user_data, void *stream_user_data)
{
    (void)conn; (void)offset; (void)stream_user_data;
    struct quic_conn *c = user_data;
    if (!c->h3conn) return 0;
    nghttp3_ssize consumed = nghttp3_conn_read_stream(
        c->h3conn, stream_id, data, datalen,
        (flags & NGTCP2_STREAM_DATA_FLAG_FIN) ? 1 : 0);
    if (consumed < 0) return NGTCP2_ERR_CALLBACK_FAILURE;
    ngtcp2_conn_extend_max_stream_offset(c->conn, stream_id, (uint64_t)consumed);
    ngtcp2_conn_extend_max_offset(c->conn, (uint64_t)consumed);
    return 0;
}

static int cb_acked_stream_data_offset(ngtcp2_conn *conn, int64_t stream_id,
                                        uint64_t offset, uint64_t datalen,
                                        void *user_data, void *stream_user_data)
{
    (void)conn; (void)offset; (void)stream_user_data;
    struct quic_conn *c = user_data;
    if (c->h3conn)
        nghttp3_conn_add_ack_offset(c->h3conn, stream_id, datalen);
    return 0;
}

static int cb_stream_close(ngtcp2_conn *conn, uint32_t flags,
                            int64_t stream_id, uint64_t app_error_code,
                            void *user_data, void *stream_user_data)
{
    (void)conn; (void)flags; (void)stream_user_data;
    struct quic_conn *c = user_data;
    if (c->h3conn)
        nghttp3_conn_close_stream(c->h3conn, stream_id, app_error_code);
    struct quic_stream *s = stream_find(c, stream_id);
    if (s) stream_free(c, s);
    return 0;
}

static void cb_rand(uint8_t *dest, size_t destlen,
                    const ngtcp2_rand_ctx *rand_ctx)
{
    (void)rand_ctx;
    RAND_bytes(dest, (int)destlen);
}

static int cb_get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                     uint8_t *token, size_t cidlen,
                                     void *user_data)
{
    (void)conn; (void)user_data;
    RAND_bytes(cid->data, (int)cidlen);
    cid->datalen = cidlen;
    RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN);
    return 0;
}

static int cb_get_path_challenge_data(ngtcp2_conn *conn, uint8_t *data,
                                       void *user_data)
{
    (void)conn; (void)user_data;
    RAND_bytes(data, NGTCP2_PATH_CHALLENGE_DATALEN);
    return 0;
}

static const ngtcp2_callbacks g_quic_cbs = {
    .recv_client_initial      = cb_recv_client_initial,
    .recv_crypto_data         = cb_recv_crypto_data,
    .handshake_completed      = cb_handshake_completed,
    .encrypt                  = ngtcp2_crypto_encrypt_cb,
    .decrypt                  = ngtcp2_crypto_decrypt_cb,
    .hp_mask                  = ngtcp2_crypto_hp_mask_cb,
    .recv_stream_data         = cb_recv_stream_data,
    .acked_stream_data_offset = cb_acked_stream_data_offset,
    .stream_close             = cb_stream_close,
    .rand                     = cb_rand,
    .get_new_connection_id    = cb_get_new_connection_id,
    .update_key               = ngtcp2_crypto_update_key_cb,
    .delete_crypto_aead_ctx   = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
    .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
    .get_path_challenge_data  = cb_get_path_challenge_data,
    .version_negotiation      = ngtcp2_crypto_version_negotiation_cb,
};

/* ---- nghttp3 callbacks ---- */

static int h3_begin_headers(nghttp3_conn *h3, int64_t stream_id,
                             void *conn_user_data, void *stream_user_data)
{
    (void)h3; (void)stream_user_data;
    struct quic_conn *c = conn_user_data;
    return stream_get_or_alloc(c, stream_id) ? 0 : NGHTTP3_ERR_CALLBACK_FAILURE;
}

static int h3_recv_header(nghttp3_conn *h3, int64_t stream_id,
                           int32_t token,
                           nghttp3_rcbuf *name, nghttp3_rcbuf *value,
                           uint8_t flags,
                           void *conn_user_data, void *stream_user_data)
{
    (void)h3; (void)token; (void)flags; (void)stream_user_data;
    struct quic_stream *s = stream_find((struct quic_conn *)conn_user_data, stream_id);
    if (!s) return 0;

    nghttp3_vec nv = nghttp3_rcbuf_get_buf(name);
    nghttp3_vec vv = nghttp3_rcbuf_get_buf(value);

#define HDR_COPY(field, hname) \
    do { if (nv.len == sizeof(hname)-1 && memcmp(nv.base, hname, nv.len) == 0) { \
        size_t l = vv.len < sizeof(s->field)-1 ? vv.len : sizeof(s->field)-1; \
        memcpy(s->field, vv.base, l); s->field[l] = '\0'; } } while(0)

    HDR_COPY(method,    ":method");
    HDR_COPY(url,       ":path");
    HDR_COPY(authority, ":authority");
#undef HDR_COPY
    return 0;
}

static int h3_end_headers(nghttp3_conn *h3, int64_t stream_id, int fin,
                           void *conn_user_data, void *stream_user_data)
{
    (void)h3; (void)stream_user_data;
    struct quic_conn *c = conn_user_data;
    struct quic_stream *s = stream_find(c, stream_id);
    if (!s) return 0;
    s->headers_done = true;
    if (fin && !s->request_done) {
        s->request_done = true;
        dispatch_request(c, s);
    }
    return 0;
}

static int h3_recv_data(nghttp3_conn *h3, int64_t stream_id,
                         const uint8_t *data, size_t datalen,
                         void *conn_user_data, void *stream_user_data)
{
    (void)h3; (void)stream_user_data;
    struct quic_conn *c = (struct quic_conn *)conn_user_data;
    struct quic_stream *s = stream_find(c, stream_id);
    if (!s) return 0;
    if (s->req_too_large) return 0;

    uint32_t limit = c->server->cfg->max_request_body_bytes;
    if (limit > 0 && datalen > 0 &&
        (datalen > (size_t)limit || s->req_body_len > (size_t)limit - datalen)) {
        free(s->req_body);
        s->req_body = NULL;
        s->req_body_len = 0;
        s->req_too_large = true;
        return 0;
    }

    uint8_t *nb = realloc(s->req_body, s->req_body_len + datalen);
    if (!nb) return NGHTTP3_ERR_CALLBACK_FAILURE;
    memcpy(nb + s->req_body_len, data, datalen);
    s->req_body = nb;
    s->req_body_len += datalen;
    return 0;
}

static int h3_end_stream(nghttp3_conn *h3, int64_t stream_id,
                          void *conn_user_data, void *stream_user_data)
{
    (void)h3; (void)stream_user_data;
    struct quic_conn *c = conn_user_data;
    struct quic_stream *s = stream_find(c, stream_id);
    if (!s || s->request_done) return 0;
    s->request_done = true;
    dispatch_request(c, s);
    return 0;
}

static int h3_deferred_consume(nghttp3_conn *h3, int64_t stream_id,
                                size_t consumed,
                                void *conn_user_data, void *stream_user_data)
{
    (void)h3; (void)stream_user_data;
    struct quic_conn *c = conn_user_data;
    ngtcp2_conn_extend_max_stream_offset(c->conn, stream_id, consumed);
    ngtcp2_conn_extend_max_offset(c->conn, consumed);
    return 0;
}

static const nghttp3_callbacks g_h3cbs = {
    .begin_headers    = h3_begin_headers,
    .recv_header      = h3_recv_header,
    .end_headers      = h3_end_headers,
    .recv_data        = h3_recv_data,
    .end_stream       = h3_end_stream,
    .deferred_consume = h3_deferred_consume,
};

/* ---- handshake_completed (needs g_h3cbs, placed after) ---- */

static int cb_handshake_completed(ngtcp2_conn *conn, void *user_data)
{
    (void)conn;
    struct quic_conn *c = user_data;
    c->handshake_done = true;

    nghttp3_settings h3s;
    nghttp3_settings_default(&h3s);
    if (nghttp3_conn_server_new(&c->h3conn, &g_h3cbs, &h3s, NULL, c) != 0)
        return NGTCP2_ERR_CALLBACK_FAILURE;

    int64_t ctrl_sid, qenc_sid, qdec_sid;
    if (ngtcp2_conn_open_uni_stream(c->conn, &ctrl_sid, NULL) != 0 ||
        ngtcp2_conn_open_uni_stream(c->conn, &qenc_sid, NULL) != 0 ||
        ngtcp2_conn_open_uni_stream(c->conn, &qdec_sid, NULL) != 0)
        return NGTCP2_ERR_CALLBACK_FAILURE;

    nghttp3_conn_bind_control_stream(c->h3conn, ctrl_sid);
    nghttp3_conn_bind_qpack_streams(c->h3conn, qenc_sid, qdec_sid);
    log_debug("quic_hs", "TLS handshake done, h3conn ready");
    return 0;
}

/* ---- nghttp3 read_data: deliver response body bytes ---- */

static nghttp3_ssize h3_read_data(nghttp3_conn *h3, int64_t stream_id,
                                   nghttp3_vec *vec, size_t veccnt,
                                   uint32_t *pflags,
                                   void *conn_user_data, void *stream_user_data)
{
    (void)h3; (void)stream_id; (void)veccnt; (void)conn_user_data;
    struct quic_stream *s = stream_user_data;
    if (!s || !s->resp_buf) { *pflags = NGHTTP3_DATA_FLAG_EOF; return 0; }

    const char *hdr_end = memmem(s->resp_buf, s->resp_len, "\r\n\r\n", 4);
    if (!hdr_end) { *pflags = NGHTTP3_DATA_FLAG_EOF; return 0; }
    size_t body_start = (size_t)(hdr_end + 4 - (char *)s->resp_buf);
    size_t body_len   = s->resp_len > body_start ? s->resp_len - body_start : 0;

    if (s->resp_offset >= body_len) { *pflags = NGHTTP3_DATA_FLAG_EOF; return 0; }

    vec[0].base     = s->resp_buf + body_start + s->resp_offset;
    vec[0].len      = body_len - s->resp_offset;
    s->resp_offset  = body_len;
    *pflags = NGHTTP3_DATA_FLAG_EOF;
    return 1;
}

/* ---- Submit HTTP/3 response for a completed stream ---- */

static void submit_h3_response(struct quic_conn *c, struct quic_stream *s)
{
    if (!c->h3conn || !s->resp_buf || s->resp_submitted) return;
    s->resp_submitted = true;

    /* Parse status */
    int status = 200;
    if (s->resp_len > 12) {
        const char *sp = (char *)s->resp_buf + 9;
        status = 0;
        for (int i = 0; i < 3 && sp[i] >= '0' && sp[i] <= '9'; i++)
            status = status * 10 + (sp[i] - '0');
    }
    if (status <= 0) status = 502;

    char status_str[8];
    snprintf(status_str, sizeof(status_str), "%d", status);

#define MAX_H3_HDRS 32
    nghttp3_nv nva[MAX_H3_HDRS];
    size_t nvlen = 0;
    bool hsts_seen = false;

    nva[nvlen++] = (nghttp3_nv){
        .name     = (const uint8_t *)":status",
        .value    = (const uint8_t *)status_str,
        .namelen  = 7,
        .valuelen = strlen(status_str),
        .flags    = NGHTTP3_NV_FLAG_NONE };

    nva[nvlen++] = (nghttp3_nv){
        .name     = (const uint8_t *)"alt-svc",
        .value    = (const uint8_t *)"h3=\":443\"; ma=86400",
        .namelen  = 7,
        .valuelen = 18,
        .flags    = NGHTTP3_NV_FLAG_NONE };

    /* Walk HTTP/1.1 headers; skip hop-by-hop */
    const char *p = (char *)s->resp_buf;
    size_t rem    = s->resp_len;
    const char *nl = memmem(p, rem, "\r\n", 2); /* skip status line */
    if (nl) { rem -= (size_t)(nl + 2 - p); p = nl + 2; }

    /* Storage for lowercased name/value copies */
    static __thread char hdr_names[MAX_H3_HDRS][128];
    static __thread char hdr_vals[MAX_H3_HDRS][512];
    int hi = 0;

    while (rem > 2 && nvlen < MAX_H3_HDRS - 1) {
        if (p[0] == '\r' && p[1] == '\n') break;
        const char *colon = memchr(p, ':', rem);
        if (!colon) break;
        const char *lend = memmem(colon, (size_t)(p + rem - colon), "\r\n", 2);
        if (!lend) break;

        size_t nlen = (size_t)(colon - p);
        const char *vs = colon + 1;
        while (vs < lend && (*vs == ' ' || *vs == '\t')) vs++;
        size_t vlen = (size_t)(lend - vs);

        /* Skip hop-by-hop */
        if ((nlen == 10 && strncasecmp(p, "connection", 10) == 0) ||
            (nlen == 17 && strncasecmp(p, "transfer-encoding", 17) == 0) ||
            (nlen == 10 && strncasecmp(p, "keep-alive", 10) == 0) ||
            (nlen ==  6 && strncasecmp(p, "pragma", 6) == 0)) {
            rem -= (size_t)(lend + 2 - p); p = lend + 2; continue;
        }

        if (nlen == 25 && strncasecmp(p, "strict-transport-security", 25) == 0)
            hsts_seen = true;

        size_t nl2 = nlen < sizeof(hdr_names[0])-1 ? nlen : sizeof(hdr_names[0])-1;
        size_t vl2 = vlen < sizeof(hdr_vals[0])-1  ? vlen : sizeof(hdr_vals[0])-1;
        for (size_t i = 0; i < nl2; i++)
            hdr_names[hi][i] = (char)tolower((unsigned char)p[i]);
        hdr_names[hi][nl2] = '\0';
        memcpy(hdr_vals[hi], vs, vl2);
        hdr_vals[hi][vl2] = '\0';

        nva[nvlen++] = (nghttp3_nv){
            .name     = (const uint8_t *)hdr_names[hi],
            .value    = (const uint8_t *)hdr_vals[hi],
            .namelen  = nl2,
            .valuelen = vl2,
            .flags    = NGHTTP3_NV_FLAG_NONE };
        hi++;

        rem -= (size_t)(lend + 2 - p); p = lend + 2;
    }

    if (!hsts_seen && nvlen < MAX_H3_HDRS) {
        static const uint8_t hsts[] = "max-age=31536000; includeSubDomains";
        nva[nvlen++] = (nghttp3_nv){
            .name     = (const uint8_t *)"strict-transport-security",
            .value    = hsts,
            .namelen  = 25,
            .valuelen = sizeof(hsts) - 1,
            .flags    = NGHTTP3_NV_FLAG_NONE };
    }

    /* Body */
    const char *hdr_end = memmem(s->resp_buf, s->resp_len, "\r\n\r\n", 4);
    size_t body_len = 0;
    if (hdr_end) {
        size_t ho = (size_t)(hdr_end + 4 - (char *)s->resp_buf);
        body_len  = s->resp_len > ho ? s->resp_len - ho : 0;
    }

    nghttp3_data_reader dr = { .read_data = h3_read_data };
    int rv = nghttp3_conn_submit_response(c->h3conn, s->stream_id,
                                          nva, nvlen,
                                          body_len ? &dr : NULL);
    if (rv != 0)
        log_error("quic_h3", "submit_response sid=%lld err=%d",
            (long long)s->stream_id, rv);
}

/* ---- QUIC connection send ---- */

static int conn_send(struct quic_conn *c)
{
    ngtcp2_tstamp ts = now_ns();

    if (c->h3conn && c->handshake_done) {
        /* Submit responses for any ready streams */
        for (int i = 0; i < QUIC_MAX_STREAMS; i++) {
            struct quic_stream *s = c->streams[i];
            if (s && s->request_done && s->resp_buf && !s->resp_submitted)
                submit_h3_response(c, s);
        }

        /* Flush nghttp3 → ngtcp2 */
        for (;;) {
            nghttp3_vec vec[16];
            int64_t stream_id;
            int fin;
            nghttp3_ssize sveccnt = nghttp3_conn_writev_stream(
                c->h3conn, &stream_id, &fin, vec, 16);
            if (sveccnt < 0 || (sveccnt == 0 && stream_id < 0)) break;

            size_t total = 0;
            ngtcp2_vec nv[16];
            for (nghttp3_ssize i = 0; i < sveccnt; i++) {
                nv[i].base = vec[i].base; nv[i].len = vec[i].len;
                total += vec[i].len;
            }

            uint32_t wf = fin ? NGTCP2_WRITE_STREAM_FLAG_FIN : 0;
            ngtcp2_ssize n = ngtcp2_conn_writev_stream(
                c->conn, NULL, NULL,
                c->send_buf, sizeof(c->send_buf),
                NULL, wf, stream_id, nv, (size_t)sveccnt, ts);
            if (n <= 0) break;

            sendto(c->server->udp_fd, c->send_buf, (size_t)n, MSG_DONTWAIT,
                   (struct sockaddr *)&c->peer_addr, c->peer_addrlen);

            if (total > 0)
                nghttp3_conn_add_write_offset(c->h3conn, stream_id, total);
        }
    }

    /* Flush ngtcp2 control / ack / handshake packets */
    for (;;) {
        ngtcp2_ssize n = ngtcp2_conn_write_pkt(
            c->conn, NULL, NULL, c->send_buf, sizeof(c->send_buf), ts);
        if (n < 0) { if (n == NGTCP2_ERR_WRITE_MORE) continue; break; }
        if (n == 0) break;
        sendto(c->server->udp_fd, c->send_buf, (size_t)n, MSG_DONTWAIT,
               (struct sockaddr *)&c->peer_addr, c->peer_addrlen);
    }
    return 0;
}

/* ---- Connection lifecycle ---- */

static struct quic_conn *conn_new(struct quic_server *qs,
                                   const struct sockaddr *peer,
                                   socklen_t peer_addrlen,
                                   const uint8_t *pkt, size_t pktlen)
{
    ngtcp2_pkt_hd hd;
    if (ngtcp2_pkt_decode_hd_long(&hd, pkt, pktlen) < 0) return NULL;

    struct quic_conn *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->server = qs;
    memcpy(&c->peer_addr, peer, peer_addrlen);
    c->peer_addrlen = peer_addrlen;

    SSL_CTX *ctx = qs->ssl_ctx_count > 0 ? qs->ssl_ctx[0] : NULL;
    if (!ctx) { free(c); return NULL; }

    c->ssl = SSL_new(ctx);
    if (!c->ssl) { free(c); return NULL; }
    SSL_set_accept_state(c->ssl);

    if (ngtcp2_crypto_ossl_ctx_new(&c->ossl_ctx, c->ssl) != 0) {
        SSL_free(c->ssl); free(c); return NULL;
    }

    c->conn_ref.get_conn  = quic_get_conn;
    c->conn_ref.user_data = c;
    SSL_set_app_data(c->ssl, &c->conn_ref);

    if (ngtcp2_crypto_ossl_configure_server_session(c->ssl) != 0) {
        ngtcp2_crypto_ossl_ctx_del(c->ossl_ctx);
        SSL_free(c->ssl); free(c); return NULL;
    }

    /* Generate server connection ID */
    ngtcp2_cid scid;
    uint8_t scid_data[NGTCP2_MAX_CIDLEN];
    RAND_bytes(scid_data, sizeof(scid_data));
    ngtcp2_cid_init(&scid, scid_data, sizeof(scid_data));

    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    settings.initial_ts = now_ns();

    ngtcp2_transport_params params;
    ngtcp2_transport_params_default(&params);
    params.initial_max_stream_data_bidi_local  = 256 * 1024;
    params.initial_max_stream_data_bidi_remote = 256 * 1024;
    params.initial_max_stream_data_uni         = 256 * 1024;
    params.initial_max_data                    = 1 * 1024 * 1024;
    params.initial_max_streams_bidi            = 100;
    params.initial_max_streams_uni             = 3;
    params.max_idle_timeout                    = 30 * NGTCP2_SECONDS;
    params.active_connection_id_limit          = 7;
    /* Required by ngtcp2: server must echo the client's Initial DCID */
    params.original_dcid                       = hd.dcid;
    params.original_dcid_present               = 1;

    ngtcp2_path path;
    ngtcp2_addr_init(&path.local,
        (const ngtcp2_sockaddr *)&qs->local_addr,
        (ngtcp2_socklen)qs->local_addrlen);
    ngtcp2_addr_init(&path.remote,
        (const ngtcp2_sockaddr *)peer,
        (ngtcp2_socklen)peer_addrlen);

    if (ngtcp2_conn_server_new(&c->conn, &hd.dcid, &scid, &path,
                                hd.version, &g_quic_cbs,
                                &settings, &params, NULL, c) != 0) {
        ngtcp2_crypto_ossl_ctx_del(c->ossl_ctx);
        SSL_free(c->ssl); free(c); return NULL;
    }

    ngtcp2_conn_set_tls_native_handle(c->conn, c->ossl_ctx);
    c->last_active = now_ns();
    log_debug("quic_new", "new connection from %p", (void *)peer);
    return c;
}

static void conn_free(struct quic_server *qs, struct quic_conn *c)
{
    for (int i = 0; i < QUIC_MAX_STREAMS; i++) {
        if (c->streams[i]) stream_free(c, c->streams[i]);
    }
    if (c->h3conn)  { nghttp3_conn_del(c->h3conn);         c->h3conn  = NULL; }
    if (c->conn)    { ngtcp2_conn_del(c->conn);             c->conn    = NULL; }
    if (c->ossl_ctx){ ngtcp2_crypto_ossl_ctx_del(c->ossl_ctx); c->ossl_ctx = NULL; }
    if (c->ssl)     { SSL_free(c->ssl);                     c->ssl     = NULL; }
    for (int i = 0; i < QUIC_MAX_CONNS; i++) {
        if (qs->conns[i] == c) { qs->conns[i] = NULL; qs->conn_count--; break; }
    }
    free(c);
}

static struct quic_conn *conn_find(struct quic_server *qs,
                                    const struct sockaddr *peer,
                                    socklen_t peer_len)
{
    for (int i = 0; i < QUIC_MAX_CONNS; i++) {
        struct quic_conn *c = qs->conns[i];
        if (!c) continue;
        if (c->peer_addrlen == peer_len &&
            memcmp(&c->peer_addr, peer, peer_len) == 0)
            return c;
    }
    return NULL;
}

/* ---- Packet dispatch ---- */

static void dispatch_packet(struct quic_server *qs,
                             const struct sockaddr *peer, socklen_t peer_len,
                             const uint8_t *pkt, size_t pktlen)
{
    struct quic_conn *c = conn_find(qs, peer, peer_len);

    if (!c) {
        /* Only create new connections for long-header (Initial) packets */
        if (pktlen < 1 || (pkt[0] & 0x80) == 0) return;
        c = conn_new(qs, peer, peer_len, pkt, pktlen);
        if (!c) return;
        if (qs->conn_count >= QUIC_MAX_CONNS) { conn_free(qs, c); return; }
        for (int i = 0; i < QUIC_MAX_CONNS; i++) {
            if (!qs->conns[i]) { qs->conns[i] = c; qs->conn_count++; break; }
        }
    }

    ngtcp2_path path;
    ngtcp2_addr_init(&path.local,
        (const ngtcp2_sockaddr *)&qs->local_addr,
        (ngtcp2_socklen)qs->local_addrlen);
    ngtcp2_addr_init(&path.remote,
        (const ngtcp2_sockaddr *)peer,
        (ngtcp2_socklen)peer_len);

    ngtcp2_pkt_info pi = {0};
    int rv = ngtcp2_conn_read_pkt(c->conn, &path, &pi, pkt, pktlen, now_ns());
    if (rv != 0 && rv != NGTCP2_ERR_DRAINING) {
        if (rv != NGTCP2_ERR_CRYPTO)
            log_debug("quic_read", "read_pkt: %s", ngtcp2_strerror(rv));
        conn_free(qs, c);
        return;
    }

    c->last_active = now_ns();
    conn_send(c);
}

/* ---- SSL_CTX for QUIC ---- */

static SSL_CTX *make_quic_ssl_ctx(struct tls_ctx *tls, int route_idx)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) return NULL;

    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    /* ALPN: h3 */
    static const unsigned char alpn[] = "\x02h3";
    SSL_CTX_set_alpn_protos(ctx, alpn + 1, sizeof(alpn) - 2);

    /* Borrow cert+key from the TCP TLS route SSL_CTX */
    if (tls && route_idx < tls->route_count && tls->routes[route_idx].ssl_ctx) {
        SSL_CTX *src = tls->routes[route_idx].ssl_ctx;
        X509 *cert = SSL_CTX_get0_certificate(src);
        EVP_PKEY *key = SSL_CTX_get0_privatekey(src);
        if (cert && SSL_CTX_use_certificate(ctx, cert) != 1) {
            SSL_CTX_free(ctx); return NULL;
        }
        if (key && SSL_CTX_use_PrivateKey(ctx, key) != 1) {
            SSL_CTX_free(ctx); return NULL;
        }
    } else {
        /* No cert — QUIC requires a certificate */
        SSL_CTX_free(ctx);
        return NULL;
    }

    return ctx;
}

/* ---- Event loop ---- */

static void *quic_thread(void *arg)
{
    struct quic_server *qs = arg;

    struct epoll_event ev = { .events = EPOLLIN, .data.fd = qs->udp_fd };
    epoll_ctl(qs->epoll_fd, EPOLL_CTL_ADD, qs->udp_fd, &ev);

    struct epoll_event ev2 = { .events = EPOLLIN, .data.fd = qs->comp_efd };
    epoll_ctl(qs->epoll_fd, EPOLL_CTL_ADD, qs->comp_efd, &ev2);

    uint8_t pkt_buf[65536];

    while (!qs->stop) {
        struct epoll_event events[32];
        int n = epoll_wait(qs->epoll_fd, events, 32, 100 /* ms */);

        /* Check expiry on all connections */
        ngtcp2_tstamp ts = now_ns();
        for (int i = 0; i < QUIC_MAX_CONNS; i++) {
            struct quic_conn *c = qs->conns[i];
            if (!c) continue;
            if (ts - c->last_active > 60ULL * NGTCP2_SECONDS) {
                conn_free(qs, c); continue;
            }
            ngtcp2_tstamp exp = ngtcp2_conn_get_expiry(c->conn);
            if (exp <= ts) {
                ngtcp2_conn_handle_expiry(c->conn, ts);
                conn_send(c);
            }
        }

        if (n <= 0) continue;

        for (int i = 0; i < n; i++) {
            if (events[i].data.fd == qs->comp_efd) {
                /* Drain the proxy completion ring */
                uint64_t val;
                (void)read(qs->comp_efd, &val, sizeof(val));
                for (;;) {
                    pthread_mutex_lock(&qs->comp_mu);
                    if (qs->comp_head == qs->comp_tail) {
                        pthread_mutex_unlock(&qs->comp_mu);
                        break;
                    }
                    struct proxy_completion comp =
                        qs->comp_ring[qs->comp_head];
                    qs->comp_head =
                        (qs->comp_head + 1) % QUIC_COMP_RING_SIZE;
                    pthread_mutex_unlock(&qs->comp_mu);

                    struct quic_conn *qc = conn_find(
                        qs, (struct sockaddr *)&comp.peer_addr,
                        comp.peer_addrlen);
                    if (!qc) { free(comp.resp_buf); continue; }

                    struct quic_stream *ss = stream_find(qc, comp.stream_id);
                    if (!ss || ss->resp_buf) {
                        free(comp.resp_buf); continue;
                    }

                    ss->resp_buf = comp.resp_buf;
                    ss->resp_len = comp.resp_len;
                    conn_send(qc);
                }
            } else if (events[i].data.fd == qs->udp_fd) {
                struct sockaddr_storage peer;
                socklen_t plen = sizeof(peer);
                ssize_t r = recvfrom(qs->udp_fd, pkt_buf, sizeof(pkt_buf), 0,
                                      (struct sockaddr *)&peer, &plen);
                if (r <= 0) continue;
                dispatch_packet(qs, (struct sockaddr *)&peer, plen,
                                 pkt_buf, (size_t)r);
            }
        }
    }

    for (int i = 0; i < QUIC_MAX_CONNS; i++) {
        if (qs->conns[i]) conn_free(qs, qs->conns[i]);
    }
    return NULL;
}

/* ---- Public API ---- */

int quic_server_init(struct quic_server **out,
                     struct tls_ctx *tls,
                     struct cache *cache,
                     struct vortex_config *cfg,
                     const char *bind_addr,
                     uint16_t port)
{
    *out = NULL;
    struct quic_server *qs = calloc(1, sizeof(*qs));
    if (!qs) return -1;
    qs->comp_efd = -1;

    qs->cfg = cfg;
    qs->cache = cache;
    if (router_init(&qs->router, cfg) != 0) { free(qs); return -1; }

    /* Build SSL_CTX per route */
    int nctx = tls ? tls->route_count : 0;
    for (int i = 0; i < nctx && i < VORTEX_MAX_ROUTES; i++) {
        qs->ssl_ctx[i] = make_quic_ssl_ctx(tls, i);
        if (qs->ssl_ctx[i]) qs->ssl_ctx_count = i + 1;
        else log_warn("quic_init", "no SSL_CTX for route %d — skipping", i);
    }
    if (qs->ssl_ctx_count == 0) {
        log_error("quic_init", "no certs available — QUIC disabled");
        router_destroy(&qs->router); free(qs); return -1;
    }

    /* Create UDP socket */
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%u", port);
    struct addrinfo hints = { .ai_family   = AF_UNSPEC,
                              .ai_socktype = SOCK_DGRAM,
                              .ai_flags    = AI_PASSIVE };
    struct addrinfo *res = NULL;
    if (getaddrinfo(bind_addr[0] ? bind_addr : NULL, port_str, &hints, &res) != 0) {
        router_destroy(&qs->router); free(qs); return -1;
    }

    int fd = socket(res->ai_family,
                    res->ai_socktype | SOCK_NONBLOCK | SOCK_CLOEXEC,
                    res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); router_destroy(&qs->router); free(qs); return -1; }

    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));

    if (bind(fd, res->ai_addr, res->ai_addrlen) < 0) {
        log_error("quic_init", "bind %s:%u: %s", bind_addr, port, strerror(errno));
        close(fd); freeaddrinfo(res); router_destroy(&qs->router); free(qs); return -1;
    }

    memcpy(&qs->local_addr, res->ai_addr, res->ai_addrlen);
    qs->local_addrlen = (socklen_t)res->ai_addrlen;
    freeaddrinfo(res);
    qs->udp_fd = fd;

    qs->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (qs->epoll_fd < 0) {
        close(fd); router_destroy(&qs->router); free(qs); return -1;
    }

    qs->comp_efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (qs->comp_efd < 0) {
        close(qs->epoll_fd); close(fd); router_destroy(&qs->router); free(qs); return -1;
    }
    pthread_mutex_init(&qs->comp_mu, NULL);

    ngtcp2_crypto_ossl_init();
    log_info("quic_init", "QUIC server ready on %s:%u (fd=%d)", bind_addr, port, fd);
    *out = qs;
    return 0;
}

int quic_server_start(struct quic_server *qs)
{
    return pthread_create(&qs->thread, NULL, quic_thread, qs);
}

void quic_server_stop(struct quic_server *qs) { qs->stop = 1; }
void quic_server_join(struct quic_server *qs) { pthread_join(qs->thread, NULL); }

void quic_server_destroy(struct quic_server *qs)
{
    if (qs->epoll_fd >= 0) { close(qs->epoll_fd); qs->epoll_fd = -1; }
    if (qs->udp_fd   >= 0) { close(qs->udp_fd);   qs->udp_fd   = -1; }
    if (qs->comp_efd >= 0) { close(qs->comp_efd);  qs->comp_efd = -1; }
    pthread_mutex_destroy(&qs->comp_mu);
    for (int i = 0; i < VORTEX_MAX_ROUTES; i++) {
        if (qs->ssl_ctx[i]) { SSL_CTX_free(qs->ssl_ctx[i]); qs->ssl_ctx[i] = NULL; }
    }
    router_destroy(&qs->router);
    free(qs);
}

#endif /* VORTEX_QUIC */
