#define _GNU_SOURCE
/*
 * worker_h2.c — HTTP/2 frontend via nghttp2.
 *
 * One h2_session is allocated per H2 client connection and lives in
 * conn_cold.h2.  Each HTTP/2 stream gets a slot in sess->streams[].
 * Backend connections are plain TCP per-stream (not fixed-file slots).
 *
 * Data flow:
 *   H2 client → nghttp2 → assemble HTTP/1.1 → backend (plain TCP)
 *   backend response → accumulate → parse → nghttp2_submit_response2 → H2 client
 *
 * io_uring ops used:
 *   VORTEX_OP_H2_RECV_CLIENT   — recv from client into conn recv_buf, fed to nghttp2
 *   VORTEX_OP_H2_SEND_CLIENT   — send nghttp2 output buffer to client
 *   VORTEX_OP_H2_CONNECT       — async TCP connect to backend
 *   VORTEX_OP_H2_SEND_BACKEND  — send assembled HTTP/1.1 request to backend
 *   VORTEX_OP_H2_RECV_BACKEND  — recv backend HTTP/1.1 response into stream resp_buf
 *
 * user_data encoding for backend ops:  URING_UD_H2_ENCODE(op, slot, cid)
 * user_data encoding for client ops:   URING_UD_H2_ENCODE(op, 0, cid)
 */

#include "worker_internal.h"
#include "h2.h"
#include <nghttp2/nghttp2.h>
#include <ctype.h>

/* ------------------------------------------------------------------ */
/* Internal helpers                                                     */
/* ------------------------------------------------------------------ */

static bool h2_resp_grow(struct h2_stream *st, uint32_t need);
static void h2_submit_response(struct h2_session *sess, struct h2_stream *st);
static void h2_send_pending(struct h2_session *sess);
static void h2_stream_rst(struct h2_session *sess, struct h2_stream *st,
                          uint32_t error_code);

static void h2_submit_unauthorized(struct h2_session *sess, struct h2_stream *st)
{
    static const uint8_t status[] = "401";
    static const uint8_t auth[] = "Basic realm=\"vortex\"";
    static const uint8_t zero[] = "0";
    static const uint8_t hsts[] = "max-age=31536000; includeSubDomains";
    nghttp2_nv nvs[] = {
        { .name = (uint8_t *)":status", .value = (uint8_t *)status,
          .namelen = 7, .valuelen = sizeof(status) - 1,
          .flags = NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE },
        { .name = (uint8_t *)"www-authenticate", .value = (uint8_t *)auth,
          .namelen = 16, .valuelen = sizeof(auth) - 1,
          .flags = NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE },
        { .name = (uint8_t *)"content-length", .value = (uint8_t *)zero,
          .namelen = 14, .valuelen = 1,
          .flags = NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE },
        { .name = (uint8_t *)"strict-transport-security", .value = (uint8_t *)hsts,
          .namelen = 25, .valuelen = sizeof(hsts) - 1,
          .flags = NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE },
    };
    if (nghttp2_submit_response(sess->ngh2, st->stream_id, nvs, 4, NULL) == 0) {
        st->resp_submitted = true;
        h2_send_pending(sess);
    } else {
        h2_stream_rst(sess, st, NGHTTP2_INTERNAL_ERROR);
    }
}

static void h2_submit_payload_too_large(struct h2_session *sess, struct h2_stream *st)
{
    if (st->resp_submitted)
        return;
    static const uint8_t status[] = "413";
    static const uint8_t zero[] = "0";
    static const uint8_t hsts[] = "max-age=31536000; includeSubDomains";
    nghttp2_nv nvs[] = {
        { .name = (uint8_t *)":status", .value = (uint8_t *)status,
          .namelen = 7, .valuelen = sizeof(status) - 1,
          .flags = NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE },
        { .name = (uint8_t *)"content-length", .value = (uint8_t *)zero,
          .namelen = 14, .valuelen = 1,
          .flags = NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE },
        { .name = (uint8_t *)"strict-transport-security", .value = (uint8_t *)hsts,
          .namelen = 25, .valuelen = sizeof(hsts) - 1,
          .flags = NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE },
    };
    if (nghttp2_submit_response(sess->ngh2, st->stream_id, nvs, 3, NULL) == 0) {
        st->resp_submitted = true;
        h2_send_pending(sess);
    } else {
        h2_stream_rst(sess, st, NGHTTP2_INTERNAL_ERROR);
    }
}

static bool h2_auth_failed(struct h2_session *sess, struct h2_stream *st)
{
    int ri = conn_hot(&sess->w->pool, sess->cid)->route_idx;
    if (ri < 0 || ri >= sess->w->cfg->route_count)
        return false;
    const struct route_auth_config *auth = &sess->w->cfg->routes[ri].auth;
    if (!auth->enabled)
        return false;
    return !(st->auth_seen && st->auth_ok);
}

static bool h2_send_buf_reserve(struct h2_session *sess, uint32_t need)
{
    uint32_t required = sess->send_buf_len + need;
    if (required <= sess->send_buf_cap) return true;

    uint32_t newcap = sess->send_buf_cap ? sess->send_buf_cap : H2_SEND_BUF_SIZE;
    while (newcap < required) {
        if (newcap > UINT32_MAX / 2) {
            newcap = required;
            break;
        }
        newcap *= 2;
    }

    uint8_t *p = realloc(sess->send_buf, newcap);
    if (!p) return false;
    sess->send_buf = p;
    sess->send_buf_cap = newcap;
    return true;
}

static void h2_make_cache_key(struct h2_stream *st, char *key, size_t key_cap)
{
    snprintf(key, key_cap, "%s|%s", st->authority, st->path);
}

static bool h2_try_cache_hit(struct h2_session *sess, struct h2_stream *st)
{
    struct worker *w = sess->w;
    if (!w->cache || !w->cache->index || strcmp(st->method, "GET") != 0)
        return false;

    char cache_key[2304];
    h2_make_cache_key(st, cache_key, sizeof(cache_key));
    struct cached_response cached;
    if (cache_fetch_copy(w->cache, cache_key, strlen(cache_key), &cached) != 0)
        return false;

    if (!h2_resp_grow(st, cached.header_len + cached.body_len)) {
        cache_cached_response_free(&cached);
        return false;
    }

    memcpy(st->resp_buf, cached.data, cached.header_len + cached.body_len);
    st->resp_buf_len      = cached.header_len + cached.body_len;
    st->resp_hdr_end      = cached.header_len;
    st->resp_headers_done = true;
    st->backend_eof       = true;
    st->is_chunked_resp   = false;
    st->prefer_buffered_resp = false;
    st->state             = H2_STREAM_STREAMING;
    cache_cached_response_free(&cached);

    h2_submit_response(sess, st);
    log_debug("h2_cache_hit", "cid=%u stream=%d url=%s",
              sess->cid, st->stream_id, cache_key);
    return true;
}

static void h2_maybe_cache_store(struct h2_session *sess, struct h2_stream *st)
{
    struct worker *w = sess->w;
    if (!w->cache || !w->cache->index || strcmp(st->method, "GET") != 0)
        return;
    if (!st->resp_headers_done || !st->backend_eof || st->is_chunked_resp)
        return;
    /* The incremental streaming path compacts resp_buf as body bytes are sent.
     * Once that starts, resp_buf no longer contains the full response body, so
     * storing it would poison the shared cache with a truncated payload under
     * the original Content-Length / Content-Encoding headers. */
    if (st->resp_submitted && !st->prefer_buffered_resp)
        return;

    if (st->resp_buf_len < 12 || memcmp(st->resp_buf, "HTTP/", 5) != 0)
        return;

    int status = 0;
    const char *sp = (const char *)st->resp_buf + 9;
    for (int i = 0; i < 3 && sp[i] >= '0' && sp[i] <= '9'; i++)
        status = status * 10 + (sp[i] - '0');
    if (status != 200)
        return;

    uint32_t ttl = cache_ttl_for_url(st->path);
    if (ttl == 0)
        return;

    uint32_t body_len = st->resp_buf_len > st->resp_hdr_end
                        ? st->resp_buf_len - st->resp_hdr_end : 0u;
    if (body_len == 0)
        return;

    char cache_key[2304];
    h2_make_cache_key(st, cache_key, sizeof(cache_key));
    cache_store(w->cache, cache_key, strlen(cache_key), (uint16_t)status, ttl,
                st->resp_buf, st->resp_hdr_end,
                st->resp_buf + st->resp_hdr_end, body_len);
    log_debug("h2_cache_store", "cid=%u stream=%d url=%s ttl=%u body=%u",
              sess->cid, st->stream_id, cache_key, ttl, body_len);
}

/* Drain nghttp2 output into send_buf and arm SEND if not already in flight */
static void h2_send_pending(struct h2_session *sess)
{
    if (sess->send_in_flight) return;

    /* Compact buffer if previous send consumed part of it */
    if (sess->send_buf_off > 0) {
        if (sess->send_buf_off == sess->send_buf_len) {
            sess->send_buf_off = 0;
            sess->send_buf_len = 0;
        } else {
            memmove(sess->send_buf,
                    sess->send_buf + sess->send_buf_off,
                    sess->send_buf_len - sess->send_buf_off);
            sess->send_buf_len -= sess->send_buf_off;
            sess->send_buf_off = 0;
        }
    }

    /* Drain nghttp2 output into send_buf */
    while (1) {
        const uint8_t *data;
        ssize_t n = nghttp2_session_mem_send(sess->ngh2, &data);
        if (n <= 0) break;
        if ((size_t)n > UINT32_MAX || !h2_send_buf_reserve(sess, (uint32_t)n)) {
            log_error("h2_send", "cid=%u failed to grow send buffer for %zd bytes",
                      sess->cid, n);
            conn_close(sess->w, sess->cid, true);
            return;
        }
        memcpy(sess->send_buf + sess->send_buf_len, data, (size_t)n);
        sess->send_buf_len += (uint32_t)n;
    }

    uint32_t pending = sess->send_buf_len - sess->send_buf_off;
    if (pending == 0) return;

    struct conn_hot *h = conn_hot(&sess->w->pool, sess->cid);
    struct io_uring_sqe *sqe = io_uring_get_sqe(&sess->w->uring.ring);
    if (!sqe) return;
    io_uring_prep_send(sqe, h->client_fd,
        sess->send_buf + sess->send_buf_off, pending, MSG_NOSIGNAL);
    sqe->user_data = URING_UD_H2_ENCODE(VORTEX_OP_H2_SEND_CLIENT, 0, sess->cid);
    sess->send_in_flight = true;
    uring_submit(&sess->w->uring);
}

/* Free all resources for a stream slot (does NOT submit RST — caller does) */
static void h2_stream_cleanup(struct h2_session *sess, struct h2_stream *st)
{
    if (st->backend_fd >= 0) { close(st->backend_fd); st->backend_fd = -1; }
    free(st->req_body);   st->req_body   = NULL;
    free(st->resp_buf);   st->resp_buf   = NULL;
    free(st->req_http11); st->req_http11 = NULL;
    if (st->grpc) {
        if (st->grpc->ngh2) { nghttp2_session_del(st->grpc->ngh2); st->grpc->ngh2 = NULL; }
        free(st->grpc->send_buf);
        free(st->grpc);
        st->grpc = NULL;
    }
    st->req_body_len    = 0;
    st->req_body_cap    = 0;
    st->resp_buf_len    = 0;
    st->resp_buf_cap    = 0;
    st->req_http11_len  = 0;
    st->stream_id       = 0;
    st->state           = H2_STREAM_FREE;
    if (sess->active_streams > 0) sess->active_streams--;
}

/* RST_STREAM + clean up the slot */
static void h2_stream_rst(struct h2_session *sess, struct h2_stream *st,
                           uint32_t error_code)
{
    if (st->stream_id > 0)
        nghttp2_submit_rst_stream(sess->ngh2, NGHTTP2_FLAG_NONE,
                                  st->stream_id, error_code);
    h2_stream_cleanup(sess, st);
    h2_send_pending(sess);
}

/* Grow resp_buf to hold at least `need` more bytes.  Returns false on OOM/limit. */
static bool h2_resp_grow(struct h2_stream *st, uint32_t need)
{
    uint32_t required = st->resp_buf_len + need;
    if (required > H2_RESP_MAX) return false;
    if (required <= st->resp_buf_cap) return true;
    uint32_t newcap = st->resp_buf_cap ? st->resp_buf_cap * 2 : 8192u;
    if (newcap < required) newcap = required;
    if (newcap > H2_RESP_MAX) newcap = H2_RESP_MAX;
    uint8_t *p = realloc(st->resp_buf, newcap);
    if (!p) return false;
    st->resp_buf     = p;
    st->resp_buf_cap = newcap;
    return true;
}

/* Arm io_uring RECV_BACKEND for a stream (recv into resp_buf[resp_buf_len..]) */
static void h2_arm_backend_recv(struct h2_session *sess, struct h2_stream *st)
{
    /* Ensure there is at least 4 KB of space in resp_buf */
    if (!h2_resp_grow(st, 4096)) {
        h2_stream_rst(sess, st, NGHTTP2_INTERNAL_ERROR);
        return;
    }
    uint32_t space = st->resp_buf_cap - st->resp_buf_len;
    struct io_uring_sqe *sqe = io_uring_get_sqe(&sess->w->uring.ring);
    if (!sqe) { h2_stream_rst(sess, st, NGHTTP2_INTERNAL_ERROR); return; }
    io_uring_prep_recv(sqe, st->backend_fd,
        st->resp_buf + st->resp_buf_len, space, 0);
    sqe->user_data = URING_UD_H2_ENCODE(VORTEX_OP_H2_RECV_BACKEND, st->slot, sess->cid);
    uring_submit(&sess->w->uring);
}

/* nghttp2 data-provider callback — feeds resp_buf body bytes to nghttp2 */
static ssize_t h2_data_source_read(nghttp2_session *ngh2,
                                    int32_t stream_id,
                                    uint8_t *buf, size_t length,
                                    uint32_t *data_flags,
                                    nghttp2_data_source *source,
                                    void *user_data __attribute__((unused)))
{
    (void)ngh2; (void)stream_id;
    struct h2_stream *st = (struct h2_stream *)source->ptr;

    uint32_t body_start = st->resp_hdr_end;
    uint32_t body_total = st->resp_buf_len > body_start
                          ? st->resp_buf_len - body_start : 0u;
    uint32_t remaining  = body_total - st->resp_body_sent;

    if (remaining == 0) {
        if (st->backend_eof) {
            *data_flags |= NGHTTP2_DATA_FLAG_EOF;
            /* gRPC: keep stream open for trailers (nghttp2_submit_trailer follows) */
            if (st->is_grpc && st->grpc && st->grpc->ntrailers > 0)
                *data_flags |= NGHTTP2_DATA_FLAG_NO_END_STREAM;
        } else {
            /* Streaming: body not yet complete — defer until next backend recv */
            return NGHTTP2_ERR_DEFERRED;
        }
        return 0;
    }

    size_t to_copy = remaining < (uint32_t)length ? (size_t)remaining : length;
    memcpy(buf, st->resp_buf + body_start + st->resp_body_sent, to_copy);
    st->resp_body_sent += (uint32_t)to_copy;

    if (st->resp_body_sent >= body_total && st->backend_eof) {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        if (st->is_grpc && st->grpc && st->grpc->ntrailers > 0)
            *data_flags |= NGHTTP2_DATA_FLAG_NO_END_STREAM;
    }

    return (ssize_t)to_copy;
}

/* Decode HTTP/1.1 chunked transfer encoding in-place.
 * Returns decoded byte count, or -1 on malformed input. */
static int h2_dechunk(uint8_t *body, uint32_t body_len, uint8_t *dst)
{
    const uint8_t *p   = body;
    const uint8_t *end = body + body_len;
    uint8_t       *out = dst;

    while (p < end) {
        const uint8_t *crlf = (const uint8_t *)memmem(p, (size_t)(end - p), "\r\n", 2);
        if (!crlf) return -1;

        uint32_t sz = 0;
        for (const uint8_t *h = p; h < crlf; h++) {
            uint8_t c = *h, d;
            if      (c >= '0' && c <= '9') d = c - '0';
            else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
            else if (c == ';') break;   /* chunk extension */
            else return -1;
            sz = sz * 16 + d;
        }

        p = crlf + 2;
        if (sz == 0) break;                        /* final chunk */
        if ((size_t)(end - p) < sz) return -1;    /* truncated  */
        memmove(out, p, sz);
        out += sz;
        p   += sz;
        if (p + 1 < end && p[0] == '\r' && p[1] == '\n') p += 2;
    }
    return (int)(out - dst);
}

/*
 * Parse the HTTP/1.1 response in resp_buf and call nghttp2_submit_response2.
 * Only called once (resp_submitted guards re-entry).
 */
static void h2_submit_response(struct h2_session *sess, struct h2_stream *st)
{
    if (st->resp_submitted) return;
    if (!st->resp_headers_done) return;

    struct worker *w = sess->w;

    /* Pre-compute Cache-Control rewrite (same URL-TTL logic as H1.1 path) */
    uint32_t ttl = cache_ttl_for_url(st->path);
    char cc_val[64] = "";
    int  cc_val_len = 0;
    if (ttl > 0) {
        if (ttl >= 3600)
            cc_val_len = snprintf(cc_val, sizeof(cc_val),
                "public, max-age=%u, immutable", ttl);
        else
            cc_val_len = snprintf(cc_val, sizeof(cc_val),
                "public, max-age=%u", ttl);
    }
    bool cc_injected = false; /* track whether we already emitted cache-control */
    bool hsts_seen = false;

    const char *buf = (const char *)st->resp_buf;
    size_t      len  = st->resp_buf_len;

    /* Parse status line: "HTTP/1.x SSS Reason\r\n" */
    if (len < 12) return;
    if (memcmp(buf, "HTTP/", 5) != 0) return;
    const char *sp = (const char *)memchr(buf + 5, ' ', len - 5);
    if (!sp || sp - buf + 4 > (ptrdiff_t)len) return;
    int status = 0;
    for (int i = 1; i <= 3; i++) {
        char c = sp[i];
        if (c < '0' || c > '9') return;
        status = status * 10 + (c - '0');
    }

    char status_str[4];
    snprintf(status_str, sizeof(status_str), "%d", status);

    /* Parse headers — skip status line, iterate "Name: Value\r\n" lines */
    const char *p   = (const char *)memmem(buf, len, "\r\n", 2);
    if (!p) return;
    p += 2; /* skip status line */
    const char *hdr_end = buf + st->resp_hdr_end; /* points past \r\n\r\n */

    /* Pre-scan: dechunk body if Transfer-Encoding: chunked */
    {
        const char *q = p;
        while (q < hdr_end - 1) {
            const char *nl = (const char *)memmem(q, (size_t)(hdr_end - q), "\r\n", 2);
            if (!nl || nl == q) break;
            const char *colon = (const char *)memchr(q, ':', (size_t)(nl - q));
            if (colon) {
                size_t nlen = (size_t)(colon - q);
                if (nlen == 17) {
                    char tmp[18]; memcpy(tmp, q, 17); tmp[17] = '\0';
                    for (int i = 0; i < 17; i++)
                        tmp[i] = (char)tolower((unsigned char)tmp[i]);
                    if (memcmp(tmp, "transfer-encoding", 17) == 0) {
                        const char *v = colon + 1;
                        while (v < nl && *v == ' ') v++;
                        size_t vlen = (size_t)(nl - v);
                        if (vlen >= 7 && memmem(v, vlen, "chunked", 7)) {
                            uint8_t *body    = st->resp_buf + st->resp_hdr_end;
                            uint32_t blen    = st->resp_buf_len > st->resp_hdr_end
                                               ? st->resp_buf_len - st->resp_hdr_end : 0u;
                            int decoded = h2_dechunk(body, blen, body);
                            if (decoded < 0) {
                                h2_stream_rst(sess, st, NGHTTP2_INTERNAL_ERROR);
                                return;
                            }
                            st->resp_buf_len = st->resp_hdr_end + (uint32_t)decoded;
                        }
                    }
                }
            }
            q = nl + 2;
        }
    }

    /* First pass: count non-filtered headers */
    int nv_count = 1; /* 1 for :status */
    {
        const char *q = p;
        while (q < hdr_end - 1) {
            const char *nl = (const char *)memmem(q, (size_t)(hdr_end - q), "\r\n", 2);
            if (!nl || nl == q) break;
            if (memchr(q, ':', (size_t)(nl - q)))
                nv_count++;
            q = nl + 2;
        }
    }
    if (nv_count > 60) nv_count = 60; /* cap; leave 4 slots for injected headers */

    /* Allocate nghttp2_nv array (+1 for :status, +4 for injections) */
    nghttp2_nv *nvs = malloc((size_t)(nv_count + 4) * sizeof(nghttp2_nv));
    if (!nvs) return;

    int idx = 0;
    /* :status — nghttp2 copies the value since we pass flags=0 */
    nvs[idx].name    = (uint8_t *)":status";
    nvs[idx].namelen = 7;
    nvs[idx].value   = (uint8_t *)status_str;
    nvs[idx].valuelen = strlen(status_str);
    nvs[idx].flags   = NGHTTP2_NV_FLAG_NO_COPY_NAME; /* literal ":status" is constant */
    idx++;

    /* Second pass: emit headers (lowercase names, skip hop-by-hop, rewrite) */
    while (p < hdr_end - 1 && idx < nv_count) {
        const char *nl = (const char *)memmem(p, (size_t)(hdr_end - p), "\r\n", 2);
        if (!nl || nl == p) break;

        const char *colon = (const char *)memchr(p, ':', (size_t)(nl - p));
        if (!colon) { p = nl + 2; continue; }

        size_t name_len = (size_t)(colon - p);
        const char *val = colon + 1;
        while (val < nl && *val == ' ') val++;
        size_t val_len = (size_t)(nl - val);

        /* Lowercase the header name in-place (resp_buf is ours to mutate) */
        char *name_p = (char *)p;
        for (size_t i = 0; i < name_len; i++)
            name_p[i] = (char)tolower((unsigned char)name_p[i]);

        /* Skip HTTP/1.1 connection management headers */
        if ((name_len == 17 && memcmp(name_p, "transfer-encoding", 17) == 0) ||
            (name_len == 10 && memcmp(name_p, "connection", 10) == 0)        ||
            (name_len == 10 && memcmp(name_p, "keep-alive", 10) == 0)) {
            p = nl + 2;
            continue;
        }

        /* Server header obfuscation — per-route overrides global; "none"/empty = pass through */
        if (name_len == 6 && memcmp(name_p, "server", 6) == 0) {
            int ri = (int)conn_hot(&w->pool, sess->cid)->route_idx;
            const char *srv_hdr =
                (ri >= 0 && ri < w->cfg->route_count &&
                 w->cfg->routes[ri].server_header[0])
                ? w->cfg->routes[ri].server_header
                : w->cfg->server_header;
            if (srv_hdr[0]) {
                nvs[idx].name     = (uint8_t *)"server";
                nvs[idx].namelen  = 6;
                nvs[idx].value    = (uint8_t *)srv_hdr;
                nvs[idx].valuelen = strlen(srv_hdr);
                nvs[idx].flags    = NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE;
                idx++;
                p = nl + 2;
                continue;
            }
            /* srv_hdr is empty → fall through and pass the backend value unchanged */
        }

        /* Cache-Control: override for static assets, pass through for dynamic */
        if (name_len == 13 && memcmp(name_p, "cache-control", 13) == 0) {
            cc_injected = true;
            if (ttl >= 3600) {
                /* Static asset — override backend's no-cache/no-store */
                nvs[idx].name     = (uint8_t *)"cache-control";
                nvs[idx].namelen  = 13;
                nvs[idx].value    = (uint8_t *)cc_val;
                nvs[idx].valuelen = (size_t)cc_val_len;
                nvs[idx].flags    = NGHTTP2_NV_FLAG_NO_COPY_NAME;
                idx++;
            } else if (ttl > 0) {
                /* Dynamic — pass through backend value */
                nvs[idx].name     = (uint8_t *)name_p;
                nvs[idx].namelen  = name_len;
                nvs[idx].value    = (uint8_t *)val;
                nvs[idx].valuelen = val_len;
                nvs[idx].flags    = NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE;
                idx++;
            }
            /* ttl == 0 (API): drop cache-control from backend, leave it uncached */
            p = nl + 2;
            continue;
        }

        if (name_len == 25 && memcmp(name_p, "strict-transport-security", 25) == 0)
            hsts_seen = true;

        /* Strip Pragma and Expires for static assets (Kestrel sends no-cache/-1) */
        if (ttl >= 3600) {
            if ((name_len == 6  && memcmp(name_p, "pragma",  6)  == 0) ||
                (name_len == 7  && memcmp(name_p, "expires", 7)  == 0)) {
                p = nl + 2;
                continue;
            }
        }

        nvs[idx].name     = (uint8_t *)name_p;
        nvs[idx].namelen  = name_len;
        nvs[idx].value    = (uint8_t *)val;
        nvs[idx].valuelen = val_len;
        nvs[idx].flags    = NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE;
        idx++;
        p = nl + 2;
    }

    /* Inject cache-control if backend sent none and we have a TTL */
    if (ttl > 0 && !cc_injected && idx < nv_count + 4) {
        nvs[idx].name     = (uint8_t *)"cache-control";
        nvs[idx].namelen  = 13;
        nvs[idx].value    = (uint8_t *)cc_val;
        nvs[idx].valuelen = (size_t)cc_val_len;
        nvs[idx].flags    = NGHTTP2_NV_FLAG_NO_COPY_NAME;
        idx++;
    }

    if (!hsts_seen && idx < nv_count + 4) {
        static const uint8_t hsts[] = "max-age=31536000; includeSubDomains";
        nvs[idx].name     = (uint8_t *)"strict-transport-security";
        nvs[idx].namelen  = 25;
        nvs[idx].value    = (uint8_t *)hsts;
        nvs[idx].valuelen = sizeof(hsts) - 1;
        nvs[idx].flags    = NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE;
        idx++;
    }

#ifdef VORTEX_QUIC
    /* Advertise HTTP/3 availability */
    if (idx < nv_count + 4) {
        nvs[idx].name     = (uint8_t *)"alt-svc";
        nvs[idx].namelen  = 7;
        nvs[idx].value    = (uint8_t *)"h3=\":443\"; ma=86400";
        nvs[idx].valuelen = 19;
        nvs[idx].flags    = NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE;
        idx++;
    }
#endif

    uint32_t body_len = st->resp_buf_len > st->resp_hdr_end
                        ? st->resp_buf_len - st->resp_hdr_end : 0u;

    nghttp2_data_provider dp = {
        .source        = { .ptr = st },
        .read_callback = h2_data_source_read,
    };

    /* Use a data provider when there is body data OR when the backend is
     * still writing (streaming path — data provider will DEFERRED until
     * more bytes arrive).  Skip only when we are at EOF with zero body. */
    bool use_provider = (body_len > 0) || !st->backend_eof;

    int rv = nghttp2_submit_response(sess->ngh2, st->stream_id,
                                     nvs, (size_t)idx,
                                     use_provider ? &dp : NULL);
    free(nvs);
    if (rv != 0) {
        log_error("h2_resp", "nghttp2_submit_response2 stream=%d: %s",
                  st->stream_id, nghttp2_strerror(rv));
        h2_stream_rst(sess, st, NGHTTP2_INTERNAL_ERROR);
        return;
    }

    st->resp_submitted = true;
    h2_send_pending(sess);
}

/*
 * Build the HTTP/1.1 request in heap-allocated req_http11.
 * Includes method, path, Host header, forwarded headers, and body.
 */
static int h2_build_http11_request(struct h2_stream *st, const char *backend_creds)
{
    /* Base64-encode backend_credentials if present ("user:pass" → b64 string) */
    char auth_hdr[512] = "";
    if (backend_creds && backend_creds[0]) {
        char b64[400];
        b64_encode(backend_creds, strlen(backend_creds), b64, sizeof(b64));
        snprintf(auth_hdr, sizeof(auth_hdr), "Authorization: Basic %s\r\n", b64);
    }

    /* Allocate generously: request line + host + headers + body + margin */
    size_t cap = 16 + strlen(st->path) + 14          /* "METHOD path HTTP/1.1\r\n" */
               + 7 + strlen(st->authority) + 4       /* "Host: authority\r\n" */
               + st->req_hdr_len                     /* forwarded headers */
               + strlen(auth_hdr)                    /* backend auth header (may be "") */
               + 19                                   /* "Connection: close\r\n" */
               + 2                                    /* "\r\n" end-of-headers */
               + st->req_body_len
               + 64;

    st->req_http11 = malloc(cap);
    if (!st->req_http11) return -1;

    char *p   = (char *)st->req_http11;
    char *end = p + cap;

    /* Request line */
    p += snprintf(p, (size_t)(end - p), "%s %s HTTP/1.1\r\n",
                  st->method, st->path);
    /* Host */
    p += snprintf(p, (size_t)(end - p), "Host: %s\r\n", st->authority);
    /* Backend auth (if configured) */
    if (auth_hdr[0])
        p += snprintf(p, (size_t)(end - p), "%s", auth_hdr);
    /* Forwarded request headers (already in "Name: Value\r\n" format) */
    if (st->req_hdr_len > 0 && (size_t)(end - p) > st->req_hdr_len) {
        memcpy(p, st->req_hdr_buf, st->req_hdr_len);
        p += st->req_hdr_len;
    }
    /* Force Connection: close — we use one TCP conn per stream */
    p += snprintf(p, (size_t)(end - p), "Connection: close\r\n\r\n");

    /* Body */
    if (st->req_body_len > 0 && (size_t)(end - p) >= st->req_body_len) {
        memcpy(p, st->req_body, st->req_body_len);
        p += st->req_body_len;
    }

    st->req_http11_len = (uint32_t)(p - (char *)st->req_http11);
    return 0;
}

/*
 * Connect to the backend for an H2 stream.
 * Uses the route/backend selected on TLS_DONE (conn_hot->route_idx/backend_idx).
 */
static void h2_stream_connect_backend(struct worker *w, struct h2_session *sess,
                                       struct h2_stream *st)
{
    struct conn_hot *ch = conn_hot(&w->pool, sess->cid);
    int ri = ch->route_idx;
    int bi = select_available_backend(w, ri, 0);
    if (bi < 0) {
        h2_stream_rst(sess, st, NGHTTP2_REFUSED_STREAM);
        return;
    }

    const struct backend_config *bcfg = &w->cfg->routes[ri].backends[bi];

    /* Create a non-blocking socket */
    struct sockaddr_storage addr;
    socklen_t addrlen;
    if (bcfg->resolved_addrlen > 0) {
        memcpy(&addr, &bcfg->resolved_addr, bcfg->resolved_addrlen);
        addrlen = bcfg->resolved_addrlen;
    } else {
        /* Fallback slow-path: blocking DNS resolution */
        char host[256], port_str[16];
        const char *colon = strrchr(bcfg->address, ':');
        if (!colon) { h2_stream_rst(sess, st, NGHTTP2_INTERNAL_ERROR); return; }
        size_t hlen = (size_t)(colon - bcfg->address);
        if (hlen >= sizeof(host)) { h2_stream_rst(sess, st, NGHTTP2_INTERNAL_ERROR); return; }
        memcpy(host, bcfg->address, hlen);
        host[hlen] = '\0';
        snprintf(port_str, sizeof(port_str), "%s", colon + 1);
        struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM };
        struct addrinfo *res = NULL;
        if (getaddrinfo(host, port_str, &hints, &res) != 0) {
            h2_stream_rst(sess, st, NGHTTP2_CONNECT_ERROR);
            return;
        }
        memcpy(&addr, res->ai_addr, res->ai_addrlen);
        addrlen = (socklen_t)res->ai_addrlen;
        freeaddrinfo(res);
    }

    int fd = socket(addr.ss_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0) { h2_stream_rst(sess, st, NGHTTP2_INTERNAL_ERROR); return; }

    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &one, sizeof(one));

    struct io_uring_sqe *sqe = io_uring_get_sqe(&w->uring.ring);
    if (!sqe) { close(fd); h2_stream_rst(sess, st, NGHTTP2_INTERNAL_ERROR); return; }
    io_uring_prep_connect(sqe, fd, (struct sockaddr *)&addr, addrlen);
    sqe->user_data = URING_UD_H2_ENCODE(VORTEX_OP_H2_CONNECT, st->slot, sess->cid);
    uring_submit(&w->uring);

    st->backend_fd = fd;
    st->state = H2_STREAM_CONNECTING;
    log_debug("h2_connect", "cid=%u stream=%d slot=%u fd=%d -> %s",
              sess->cid, st->stream_id, (unsigned)st->slot, fd, bcfg->address);
}

/* ------------------------------------------------------------------ */
/* nghttp2 session callbacks                                            */
/* ------------------------------------------------------------------ */

static int on_begin_headers_cb(nghttp2_session *ngh2,
                                const nghttp2_frame *frame, void *user_data)
{
    (void)ngh2;
    if (frame->hd.type != NGHTTP2_HEADERS ||
        frame->headers.cat != NGHTTP2_HCAT_REQUEST)
        return 0;

    struct h2_session *sess = (struct h2_session *)user_data;
    if (sess->active_streams >= H2_STREAM_SLOTS) {
        /* No free slots — RST this stream only, keep the session alive */
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }

    /* Find a free slot */
    for (uint8_t i = 0; i < H2_STREAM_SLOTS; i++) {
        if (sess->streams[i].state == H2_STREAM_FREE) {
            struct h2_stream *st = &sess->streams[i];
            memset(st, 0, sizeof(*st));
            st->stream_id  = frame->hd.stream_id;
            st->state      = H2_STREAM_OPEN;
            st->backend_fd = -1;
            st->slot       = i;
            st->cid        = sess->cid;
            sess->active_streams++;
            log_debug("h2_stream", "cid=%u stream=%d slot=%u OPEN",
                      sess->cid, st->stream_id, (unsigned)i);
            return 0;
        }
    }
    return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
}

static int on_header_cb(nghttp2_session *ngh2,
                         const nghttp2_frame *frame,
                         const uint8_t *name, size_t namelen,
                         const uint8_t *value, size_t valuelen,
                         uint8_t flags, void *user_data)
{
    (void)ngh2; (void)flags;
    if (frame->hd.type != NGHTTP2_HEADERS) return 0;

    struct h2_session *sess = (struct h2_session *)user_data;
    /* Find stream */
    struct h2_stream *st = NULL;
    for (uint8_t i = 0; i < H2_STREAM_SLOTS; i++) {
        if (sess->streams[i].state != H2_STREAM_FREE &&
            sess->streams[i].stream_id == frame->hd.stream_id) {
            st = &sess->streams[i];
            break;
        }
    }
    if (!st) return 0;

    /* Pseudo-headers */
    if (namelen > 0 && name[0] == ':') {
        if (namelen == 7 && memcmp(name, ":method", 7) == 0) {
            size_t l = valuelen < sizeof(st->method) - 1 ? valuelen : sizeof(st->method) - 1;
            memcpy(st->method, value, l);
            st->method[l] = '\0';
        } else if (namelen == 5 && memcmp(name, ":path", 5) == 0) {
            size_t l = valuelen < sizeof(st->path) - 1 ? valuelen : sizeof(st->path) - 1;
            memcpy(st->path, value, l);
            st->path[l] = '\0';
        } else if (namelen == 10 && memcmp(name, ":authority", 10) == 0) {
            size_t l = valuelen < sizeof(st->authority) - 1 ? valuelen : sizeof(st->authority) - 1;
            memcpy(st->authority, value, l);
            st->authority[l] = '\0';
        } else if (namelen == 7 && memcmp(name, ":scheme", 7) == 0) {
            size_t l = valuelen < sizeof(st->scheme) - 1 ? valuelen : sizeof(st->scheme) - 1;
            memcpy(st->scheme, value, l);
            st->scheme[l] = '\0';
        }
        return 0;
    }

    /* Regular headers — skip HTTP/2 connection-specific headers */
    if ((namelen == 10 && memcmp(name, "connection", 10) == 0) ||
        (namelen == 17 && memcmp(name, "transfer-encoding", 17) == 0) ||
        (namelen == 2  && memcmp(name, "te", 2) == 0)                 ||
        (namelen == 16 && memcmp(name, "proxy-connection", 16) == 0)  ||
        (namelen == 7  && memcmp(name, "upgrade", 7) == 0))
        return 0;

    /* Detect gRPC by Content-Type: application/grpc[+proto|+json|...] */
    if (namelen == 12 && memcmp(name, "content-type", 12) == 0) {
        if (valuelen >= 16 && memcmp(value, "application/grpc", 16) == 0)
            st->is_grpc = true;
    }

    if (namelen == 13 && memcmp(name, "authorization", 13) == 0) {
        int ri = conn_hot(&sess->w->pool, sess->cid)->route_idx;
        if (ri >= 0 && ri < sess->w->cfg->route_count) {
            st->auth_seen = true;
            st->auth_ok = auth_check_basic_value(&sess->w->cfg->routes[ri].auth,
                                                 (const char *)value, valuelen);
        }
    }

    /* Accept-Encoding: pass through to backend unchanged.
     * The H2 path buffers the full response before submitting to nghttp2 — it
     * does NOT cache, so compressed responses are strictly better (smaller
     * in-memory buffer, fits within H2_RESP_MAX).  Content-Encoding is
     * forwarded as-is in response headers; the H2 client decompresses. */

    /* Accumulate in req_hdr_buf as "name: value\r\n" */
    size_t needed = namelen + 2 + valuelen + 2; /* "name: value\r\n" */
    if (st->req_hdr_len + needed < sizeof(st->req_hdr_buf)) {
        uint8_t *p = st->req_hdr_buf + st->req_hdr_len;
        memcpy(p, name, namelen);     p += namelen;
        memcpy(p, ": ", 2);           p += 2;
        memcpy(p, value, valuelen);   p += valuelen;
        memcpy(p, "\r\n", 2);         p += 2;
        st->req_hdr_len += (uint32_t)needed;
    }
    return 0;
}

static int on_frame_recv_cb(nghttp2_session *ngh2,
                             const nghttp2_frame *frame, void *user_data)
{
    (void)ngh2;
    struct h2_session *sess = (struct h2_session *)user_data;

    /* Only handle request frames (client → us) */
    if (frame->hd.type != NGHTTP2_HEADERS &&
        frame->hd.type != NGHTTP2_DATA)
        return 0;

    /* Find stream */
    struct h2_stream *st = NULL;
    for (uint8_t i = 0; i < H2_STREAM_SLOTS; i++) {
        if (sess->streams[i].state != H2_STREAM_FREE &&
            sess->streams[i].stream_id == frame->hd.stream_id) {
            st = &sess->streams[i];
            break;
        }
    }
    if (!st) return 0;

    bool end_stream = (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) != 0;

    if (frame->hd.type == NGHTTP2_HEADERS &&
        (frame->hd.flags & NGHTTP2_FLAG_END_HEADERS) != 0) {
        if (end_stream) {
            /* No body — start connecting immediately */
            st->req_complete = true;
            if (h2_auth_failed(sess, st))
                h2_submit_unauthorized(sess, st);
            else if (st->req_too_large)
                h2_submit_payload_too_large(sess, st);
            else if (!h2_try_cache_hit(sess, st))
                h2_stream_connect_backend(sess->w, sess, st);
        }
        /* else: wait for DATA frames + END_STREAM */
    }

    if (frame->hd.type == NGHTTP2_DATA && end_stream) {
        st->req_complete = true;
        if (st->state == H2_STREAM_OPEN) {
            if (h2_auth_failed(sess, st))
                h2_submit_unauthorized(sess, st);
            else if (st->req_too_large)
                h2_submit_payload_too_large(sess, st);
            else if (!h2_try_cache_hit(sess, st))
                h2_stream_connect_backend(sess->w, sess, st);
        }
    }

    return 0;
}

static int on_data_chunk_recv_cb(nghttp2_session *ngh2,
                                  uint8_t flags, int32_t stream_id,
                                  const uint8_t *data, size_t len,
                                  void *user_data)
{
    (void)ngh2; (void)flags;
    struct h2_session *sess = (struct h2_session *)user_data;

    struct h2_stream *st = NULL;
    for (uint8_t i = 0; i < H2_STREAM_SLOTS; i++) {
        if (sess->streams[i].state != H2_STREAM_FREE &&
            sess->streams[i].stream_id == stream_id) {
            st = &sess->streams[i];
            break;
        }
    }
    if (!st) return 0;

    if (st->req_too_large)
        return 0;

    uint32_t limit = sess->w->cfg->max_request_body_bytes;
    if (limit > 0 && len > 0 &&
        ((uint32_t)len > limit || st->req_body_len > limit - (uint32_t)len)) {
        st->req_too_large = true;
        free(st->req_body);
        st->req_body = NULL;
        st->req_body_len = 0;
        st->req_body_cap = 0;
        h2_submit_payload_too_large(sess, st);
        return 0;
    }

    /* Grow req_body buffer */
    uint32_t needed = st->req_body_len + (uint32_t)len;
    if (needed > st->req_body_cap) {
        uint32_t newcap = st->req_body_cap ? st->req_body_cap * 2 : 4096u;
        if (newcap < needed) newcap = needed;
        uint8_t *p = realloc(st->req_body, newcap);
        if (!p) return NGHTTP2_ERR_CALLBACK_FAILURE;
        st->req_body     = p;
        st->req_body_cap = newcap;
    }
    memcpy(st->req_body + st->req_body_len, data, len);
    st->req_body_len += (uint32_t)len;
    return 0;
}

static int on_stream_close_cb(nghttp2_session *ngh2,
                               int32_t stream_id, uint32_t error_code,
                               void *user_data)
{
    (void)ngh2; (void)error_code;
    struct h2_session *sess = (struct h2_session *)user_data;
    for (uint8_t i = 0; i < H2_STREAM_SLOTS; i++) {
        if (sess->streams[i].state != H2_STREAM_FREE &&
            sess->streams[i].stream_id == stream_id) {
            log_debug("h2_stream", "cid=%u stream=%d CLOSED err=%u",
                      sess->cid, stream_id, error_code);
            h2_stream_cleanup(sess, &sess->streams[i]);
            return 0;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

int h2_session_init(struct worker *w, uint32_t cid)
{
    struct conn_cold *cc = conn_cold_ptr(&w->pool, cid);

    struct h2_session *sess = calloc(1, sizeof(*sess));
    if (!sess) return -1;

    sess->send_buf = malloc(H2_SEND_BUF_SIZE);
    if (!sess->send_buf) { free(sess); return -1; }
    sess->send_buf_cap = H2_SEND_BUF_SIZE;

    sess->w   = w;
    sess->cid = cid;

    /* Initialise stream slots */
    for (int i = 0; i < H2_STREAM_SLOTS; i++) {
        sess->streams[i].state      = H2_STREAM_FREE;
        sess->streams[i].backend_fd = -1;
        sess->streams[i].slot       = (uint8_t)i;
        sess->streams[i].cid        = cid;
    }

    /* nghttp2 server session */
    nghttp2_session_callbacks *cbs;
    nghttp2_session_callbacks_new(&cbs);
    nghttp2_session_callbacks_set_on_begin_headers_callback(cbs, on_begin_headers_cb);
    nghttp2_session_callbacks_set_on_header_callback(cbs, on_header_cb);
    nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, on_frame_recv_cb);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, on_data_chunk_recv_cb);
    nghttp2_session_callbacks_set_on_stream_close_callback(cbs, on_stream_close_cb);
    int rv = nghttp2_session_server_new(&sess->ngh2, cbs, sess);
    nghttp2_session_callbacks_del(cbs);
    if (rv != 0) { free(sess->send_buf); free(sess); return -1; }

    /* Send initial SETTINGS: max concurrent streams, initial window */
    nghttp2_settings_entry settings[] = {
        { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, H2_MAX_STREAMS },
        { NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,    65535          },
    };
    nghttp2_submit_settings(sess->ngh2, NGHTTP2_FLAG_NONE,
                            settings,
                            sizeof(settings) / sizeof(settings[0]));

    cc->h2 = sess;

    /* Send initial SETTINGS frame immediately */
    h2_send_pending(sess);

    log_debug("h2_init", "cid=%u h2 session created", cid);
    return 0;
}

void h2_session_free(struct h2_session *sess)
{
    if (!sess) return;
    /* Close all open backend connections */
    for (int i = 0; i < H2_STREAM_SLOTS; i++) {
        if (sess->streams[i].state != H2_STREAM_FREE)
            h2_stream_cleanup(sess, &sess->streams[i]);
    }
    if (sess->ngh2)    { nghttp2_session_del(sess->ngh2); sess->ngh2 = NULL; }
    free(sess->send_buf);
    free(sess);
}

void h2_on_recv(struct worker *w, uint32_t cid, int n,
                const uint8_t *data, uint16_t buf_id, bool multishot_active)
{
    struct conn_hot  *h   = conn_hot(&w->pool, cid);
    struct conn_cold *cc  = conn_cold_ptr(&w->pool, cid);
    struct h2_session *sess = cc->h2;

    if (n <= 0) {
        /* Return ring buffer before closing (IORING_CQE_F_BUFFER may not be
         * set on error CQEs, so only return when data is a valid ring pointer) */
        if (w->uring.recv_ring && data &&
            data >= w->uring.recv_ring_mem &&
            data <  w->uring.recv_ring_mem +
                    (size_t)w->uring.recv_ring_count * w->pool.buf_size)
            uring_recv_ring_return(&w->uring, buf_id, w->pool.buf_size);
        conn_close(w, cid, n < 0);
        return;
    }
    if (!sess) {
        if (w->uring.recv_ring && data)
            uring_recv_ring_return(&w->uring, buf_id, w->pool.buf_size);
        conn_close(w, cid, true);
        return;
    }

    h->bytes_in += (uint32_t)n;

    ssize_t ret = nghttp2_session_mem_recv(sess->ngh2, data, (size_t)n);

    /* Return buffer to ring immediately — nghttp2 copies data internally,
     * so the ring buffer is safe to reuse as soon as mem_recv returns. */
    if (w->uring.recv_ring && data)
        uring_recv_ring_return(&w->uring, buf_id, w->pool.buf_size);

    if (ret < 0) {
        log_error("h2_recv", "cid=%u nghttp2_session_mem_recv: %s",
                  cid, nghttp2_strerror((int)ret));
        conn_close(w, cid, true);
        return;
    }

    /* Drain any nghttp2 output (SETTINGS_ACK, WINDOW_UPDATE, etc.) */
    h2_send_pending(sess);

    /* With multishot recv the SQE stays armed — no re-arm needed.
     * Re-arm only when multishot was not active (fallback path or ring stopped). */
    if (!multishot_active) {
        struct io_uring_sqe *sqe = io_uring_get_sqe(&w->uring.ring);
        if (!sqe) { conn_close(w, cid, true); return; }
        if (w->uring.recv_ring) {
            int _pfd = w->uring.files_registered
                       ? FIXED_FD_CLIENT(w, cid) : h->client_fd;
            io_uring_prep_recv_multishot(sqe, _pfd, NULL, 0, 0);
            sqe->buf_group = w->uring.recv_ring_bgid;
            sqe->flags    |= IOSQE_BUFFER_SELECT;
            if (w->uring.files_registered) sqe->flags |= IOSQE_FIXED_FILE;
        } else {
            io_uring_prep_recv(sqe, h->client_fd, conn_recv_buf(&w->pool, cid),
                               w->pool.buf_size, 0);
        }
        sqe->user_data = URING_UD_H2_ENCODE(VORTEX_OP_H2_RECV_CLIENT, 0, cid);
        uring_submit(&w->uring);
    }
}

void h2_on_send_client(struct worker *w, uint32_t cid, int sent)
{
    struct conn_cold  *cc   = conn_cold_ptr(&w->pool, cid);
    struct h2_session *sess = cc->h2;
    if (!sess) return;

    sess->send_in_flight = false;

    if (sent <= 0) {
        conn_close(w, cid, sent < 0);
        return;
    }

    struct conn_hot *h = conn_hot(&w->pool, cid);
    h->bytes_out += (uint32_t)sent;

    sess->send_buf_off += (uint32_t)sent;
    if (sess->send_buf_off >= sess->send_buf_len) {
        sess->send_buf_off = 0;
        sess->send_buf_len = 0;
    }

    /* Drain any remaining nghttp2 output */
    h2_send_pending(sess);

    /* Un-pause any streaming streams that were waiting for the client to drain.
     * The client send just completed, so the send buffer has room; H2 WINDOW
     * may have grown; re-arm backend recvs that were held back. */
    for (int i = 0; i < H2_STREAM_SLOTS; i++) {
        struct h2_stream *st = &sess->streams[i];
        if (!st->backend_recv_paused) continue;
        uint32_t pending = (st->resp_buf_len > st->resp_hdr_end + st->resp_body_sent)
                           ? st->resp_buf_len - st->resp_hdr_end - st->resp_body_sent : 0u;
        if (pending < H2_STREAM_BUF_MAX) {
            st->backend_recv_paused = false;
            h2_arm_backend_recv(sess, st);
        }
    }
}

/* ================================================================== */
/* gRPC h2c backend — nghttp2 as a client against the backend         */
/* ================================================================== */

/* Forward declaration: called from gRPC backend frame callbacks */
static void h2_grpc_backend_init(struct h2_session *sess, struct h2_stream *st);

/* ---------- send helpers ------------------------------------------ */

static bool h2_grpc_send_buf_reserve(struct h2_grpc_backend *grpc, uint32_t need)
{
    uint32_t req = grpc->send_len + need;
    if (req <= grpc->send_cap) return true;
    uint32_t nc  = grpc->send_cap ? grpc->send_cap * 2 : 32768u;
    while (nc < req) nc *= 2;
    uint8_t *p = realloc(grpc->send_buf, nc);
    if (!p) return false;
    grpc->send_buf = p;
    grpc->send_cap = nc;
    return true;
}

/* Drain nghttp2 client output → grpc->send_buf → io_uring SEND to backend */
static void h2_grpc_send_pending(struct h2_session *sess, struct h2_stream *st)
{
    struct h2_grpc_backend *grpc = st->grpc;
    if (grpc->send_in_flight) return;

    /* Compact */
    if (grpc->send_len == 0) { /* nothing buffered */ }

    /* Drain nghttp2 client output (SETTINGS, SETTINGS_ACK, WINDOW_UPDATE, etc.) */
    while (1) {
        const uint8_t *data;
        ssize_t n = nghttp2_session_mem_send(grpc->ngh2, &data);
        if (n <= 0) break;
        if (!h2_grpc_send_buf_reserve(grpc, (uint32_t)n)) {
            h2_stream_rst(sess, st, NGHTTP2_INTERNAL_ERROR);
            return;
        }
        memcpy(grpc->send_buf + grpc->send_len, data, (size_t)n);
        grpc->send_len += (uint32_t)n;
    }

    if (grpc->send_len == 0) return;

    struct io_uring_sqe *sqe = io_uring_get_sqe(&sess->w->uring.ring);
    if (!sqe) { h2_stream_rst(sess, st, NGHTTP2_INTERNAL_ERROR); return; }
    io_uring_prep_send(sqe, st->backend_fd,
        grpc->send_buf, grpc->send_len, MSG_NOSIGNAL);
    sqe->user_data = URING_UD_H2_ENCODE(VORTEX_OP_H2_GRPC_SEND_BACKEND, st->slot, sess->cid);
    grpc->send_in_flight = true;
    uring_submit(&sess->w->uring);
}

static void h2_grpc_arm_backend_recv(struct h2_session *sess, struct h2_stream *st)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&sess->w->uring.ring);
    if (!sqe) { h2_stream_rst(sess, st, NGHTTP2_INTERNAL_ERROR); return; }
    io_uring_prep_recv(sqe, st->backend_fd,
        st->grpc->recv_buf, sizeof(st->grpc->recv_buf), 0);
    sqe->user_data = URING_UD_H2_ENCODE(VORTEX_OP_H2_GRPC_RECV_BACKEND, st->slot, sess->cid);
    uring_submit(&sess->w->uring);
}

/* ---------- submit response to frontend nghttp2 ------------------- */

static void h2_grpc_submit_response(struct h2_session *sess, struct h2_stream *st)
{
    if (st->resp_submitted) return;
    st->resp_submitted = true;

    struct h2_grpc_backend *grpc = st->grpc;

    /* Build nghttp2_nv array: :status + non-pseudo response headers */
    int max_nv = grpc->resp_nhdrs + 1;
    nghttp2_nv *nvs = malloc((size_t)max_nv * sizeof(nghttp2_nv));
    if (!nvs) { h2_stream_rst(sess, st, NGHTTP2_INTERNAL_ERROR); return; }

    char status_str[4];
    snprintf(status_str, sizeof(status_str), "%d",
             grpc->resp_status ? grpc->resp_status : 200);

    int idx = 0;
    nvs[idx++] = (nghttp2_nv){
        .name     = (uint8_t *)":status", .namelen  = 7,
        .value    = (uint8_t *)status_str,
        .valuelen = strlen(status_str),
        .flags    = NGHTTP2_NV_FLAG_NO_COPY_NAME,
    };

    for (int i = 0; i < grpc->resp_nhdrs && idx < max_nv; i++) {
        struct h2_grpc_hdr *hdr = &grpc->resp_hdrs[i];
        if (hdr->name[0] == ':') continue; /* skip pseudo-headers */
        nvs[idx++] = (nghttp2_nv){
            .name     = (uint8_t *)hdr->name,
            .namelen  = strlen(hdr->name),
            .value    = (uint8_t *)hdr->value,
            .valuelen = strlen(hdr->value),
            .flags    = NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE,
        };
    }

    /* Point data source at resp_buf body (resp_hdr_end=0 for gRPC) */
    st->resp_hdr_end     = 0;
    st->resp_headers_done = true;

    nghttp2_data_provider prd = { .source.ptr = st, .read_callback = h2_data_source_read };
    int rv = nghttp2_submit_response(sess->ngh2, st->stream_id, nvs, (size_t)idx, &prd);
    free(nvs);
    if (rv != 0) { h2_stream_rst(sess, st, NGHTTP2_INTERNAL_ERROR); return; }

    /* Trailers (grpc-status, grpc-message, ...) — submitted now, sent after body */
    if (grpc->ntrailers > 0) {
        nghttp2_nv *tvs = malloc((size_t)grpc->ntrailers * sizeof(nghttp2_nv));
        if (tvs) {
            for (int i = 0; i < grpc->ntrailers; i++) {
                struct h2_grpc_hdr *t = &grpc->trailers[i];
                tvs[i] = (nghttp2_nv){
                    .name     = (uint8_t *)t->name,
                    .namelen  = strlen(t->name),
                    .value    = (uint8_t *)t->value,
                    .valuelen = strlen(t->value),
                    .flags    = NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE,
                };
            }
            nghttp2_submit_trailer(sess->ngh2, st->stream_id,
                                   tvs, (size_t)grpc->ntrailers);
            free(tvs);
        }
    }

    h2_send_pending(sess);
}

/* ---------- nghttp2 client callbacks (backend → proxy) ------------ */

static int grpc_be_on_header_cb(nghttp2_session *ngh2,
                                  const nghttp2_frame *frame,
                                  const uint8_t *name, size_t namelen,
                                  const uint8_t *value, size_t valuelen,
                                  uint8_t flags, void *user_data)
{
    (void)ngh2; (void)flags;
    if (frame->hd.type != NGHTTP2_HEADERS) return 0;

    struct h2_stream       *st   = (struct h2_stream *)user_data;
    struct h2_grpc_backend *grpc = st->grpc;

    bool is_trailer = (frame->headers.cat == NGHTTP2_HCAT_HEADERS);

    if (!is_trailer) {
        /* :status pseudo-header */
        if (namelen == 7 && memcmp(name, ":status", 7) == 0)
            grpc->resp_status = atoi((const char *)value);
        /* Store header for forwarding */
        if (grpc->resp_nhdrs < H2_GRPC_MAX_HDRS) {
            struct h2_grpc_hdr *h = &grpc->resp_hdrs[grpc->resp_nhdrs++];
            size_t nl = namelen  < H2_GRPC_HDR_NAME_MAX - 1 ? namelen  : H2_GRPC_HDR_NAME_MAX - 1;
            size_t vl = valuelen < H2_GRPC_HDR_VAL_MAX  - 1 ? valuelen : H2_GRPC_HDR_VAL_MAX  - 1;
            memcpy(h->name,  name,  nl); h->name[nl]  = '\0';
            memcpy(h->value, value, vl); h->value[vl] = '\0';
        }
    } else {
        if (grpc->ntrailers < H2_GRPC_MAX_TRAILERS) {
            struct h2_grpc_hdr *h = &grpc->trailers[grpc->ntrailers++];
            size_t nl = namelen  < H2_GRPC_HDR_NAME_MAX - 1 ? namelen  : H2_GRPC_HDR_NAME_MAX - 1;
            size_t vl = valuelen < H2_GRPC_HDR_VAL_MAX  - 1 ? valuelen : H2_GRPC_HDR_VAL_MAX  - 1;
            memcpy(h->name,  name,  nl); h->name[nl]  = '\0';
            memcpy(h->value, value, vl); h->value[vl] = '\0';
        }
    }
    return 0;
}

static int grpc_be_on_data_chunk_cb(nghttp2_session *ngh2, uint8_t flags,
                                      int32_t stream_id,
                                      const uint8_t *data, size_t len,
                                      void *user_data)
{
    (void)ngh2; (void)flags; (void)stream_id;
    struct h2_stream *st = (struct h2_stream *)user_data;
    if (len == 0) return 0;
    if (st->resp_buf_len + (uint32_t)len > H2_RESP_MAX) {
        log_warn("h2_grpc", "cid=%u stream=%d grpc response too large, RST",
                 st->cid, st->stream_id);
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    if (!h2_resp_grow(st, (uint32_t)len)) return NGHTTP2_ERR_CALLBACK_FAILURE;
    memcpy(st->resp_buf + st->resp_buf_len, data, len);
    st->resp_buf_len += (uint32_t)len;
    return 0;
}

static int grpc_be_on_frame_recv_cb(nghttp2_session *ngh2,
                                     const nghttp2_frame *frame, void *user_data)
{
    (void)ngh2;
    struct h2_stream       *st   = (struct h2_stream *)user_data;
    struct h2_grpc_backend *grpc = st->grpc;

    /* After backend sends SETTINGS, nghttp2 queues SETTINGS_ACK — drain it */
    if (frame->hd.type == NGHTTP2_SETTINGS &&
        !(frame->hd.flags & NGHTTP2_FLAG_ACK))
        h2_grpc_send_pending(grpc->sess, st);

    /* Response HEADERS frame received */
    if (frame->hd.type == NGHTTP2_HEADERS &&
        frame->headers.cat == NGHTTP2_HCAT_RESPONSE)
        grpc->resp_hdrs_done = true;

    /* END_STREAM on DATA or trailing HEADERS → response complete */
    bool end_stream = (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) != 0;
    if (end_stream && !grpc->trailers_done &&
        (frame->hd.type == NGHTTP2_DATA ||
         frame->hd.type == NGHTTP2_HEADERS)) {
        grpc->trailers_done = true;
        h2_grpc_submit_response(grpc->sess, st);
    }
    return 0;
}

/* ---------- nghttp2 client data provider (request body) ----------- */

static ssize_t grpc_req_read_cb(nghttp2_session *ngh2, int32_t stream_id,
                                  uint8_t *buf, size_t length,
                                  uint32_t *data_flags,
                                  nghttp2_data_source *source,
                                  void *user_data __attribute__((unused)))
{
    (void)ngh2; (void)stream_id;
    struct h2_stream       *st   = (struct h2_stream *)source->ptr;
    struct h2_grpc_backend *grpc = st->grpc;

    uint32_t remaining = st->req_body_len - grpc->req_body_sent;
    size_t to_copy = remaining < (uint32_t)length ? (size_t)remaining : length;
    if (to_copy > 0) {
        memcpy(buf, st->req_body + grpc->req_body_sent, to_copy);
        grpc->req_body_sent += (uint32_t)to_copy;
    }
    if (grpc->req_body_sent >= st->req_body_len)
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    return (ssize_t)to_copy;
}

/* ---------- backend init: create nghttp2 client + submit request -- */

static void h2_grpc_backend_init(struct h2_session *sess, struct h2_stream *st)
{
    struct h2_grpc_backend *grpc = calloc(1, sizeof(*grpc));
    if (!grpc) { h2_stream_rst(sess, st, NGHTTP2_INTERNAL_ERROR); return; }
    grpc->sess = sess;
    st->grpc   = grpc;
    st->state  = H2_STREAM_GRPC_ACTIVE;

    /* Create nghttp2 client session */
    nghttp2_session_callbacks *cbs;
    nghttp2_session_callbacks_new(&cbs);
    nghttp2_session_callbacks_set_on_header_callback(cbs, grpc_be_on_header_cb);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, grpc_be_on_data_chunk_cb);
    nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, grpc_be_on_frame_recv_cb);
    int rv = nghttp2_session_client_new(&grpc->ngh2, cbs, st);
    nghttp2_session_callbacks_del(cbs);
    if (rv != 0) { h2_stream_rst(sess, st, NGHTTP2_INTERNAL_ERROR); return; }

    /* Submit client SETTINGS */
    nghttp2_settings_entry settings[] = {
        { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 1 },
        { NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,    (int32_t)H2_RESP_MAX },
    };
    nghttp2_submit_settings(grpc->ngh2, NGHTTP2_FLAG_NONE,
                            settings, sizeof(settings) / sizeof(settings[0]));

    /* Build request header list from stream's accumulated fields + req_hdr_buf */
    /* Count how many extra headers are in req_hdr_buf */
    int extra = 0;
    {
        const uint8_t *p = st->req_hdr_buf, *end = p + st->req_hdr_len;
        while (p < end) {
            const uint8_t *crlf = (const uint8_t *)memmem(p, (size_t)(end - p), "\r\n", 2);
            if (!crlf) break;
            if (memchr(p, ':', (size_t)(crlf - p))) extra++;
            p = crlf + 2;
        }
    }

    int n_fixed = 4; /* :method :path :authority :scheme */
    int n_total = n_fixed + extra;
    nghttp2_nv *nvs = malloc((size_t)n_total * sizeof(nghttp2_nv));
    if (!nvs) { h2_stream_rst(sess, st, NGHTTP2_INTERNAL_ERROR); return; }

    int idx = 0;
    nvs[idx++] = (nghttp2_nv){ (uint8_t *)":method",    7, (uint8_t *)st->method,    strlen(st->method),    NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE };
    nvs[idx++] = (nghttp2_nv){ (uint8_t *)":path",      5, (uint8_t *)st->path,      strlen(st->path),      NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE };
    nvs[idx++] = (nghttp2_nv){ (uint8_t *)":authority", 10,(uint8_t *)st->authority, strlen(st->authority), NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE };
    nvs[idx++] = (nghttp2_nv){ (uint8_t *)":scheme",    7, (uint8_t *)"http",        4,                     NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE };

    /* Parse req_hdr_buf ("Name: Value\r\n") → nghttp2_nv (values live in req_hdr_buf) */
    uint8_t *p = st->req_hdr_buf, *end = p + st->req_hdr_len;
    while (p < end && idx < n_total) {
        uint8_t *crlf  = (uint8_t *)memmem(p, (size_t)(end - p), "\r\n", 2);
        if (!crlf) break;
        uint8_t *colon = (uint8_t *)memchr(p, ':', (size_t)(crlf - p));
        if (!colon) { p = crlf + 2; continue; }

        size_t nlen = (size_t)(colon - p);
        uint8_t *val = colon + 1;
        while (val < crlf && *val == ' ') val++;
        size_t vlen = (size_t)(crlf - val);

        /* Lowercase name in-place (req_hdr_buf is mutable) */
        for (size_t i = 0; i < nlen; i++)
            p[i] = (uint8_t)tolower((unsigned char)p[i]);

        nvs[idx++] = (nghttp2_nv){
            .name = p, .namelen = nlen,
            .value = val, .valuelen = vlen,
            .flags = NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE,
        };
        p = crlf + 2;
    }

    /* Submit the request */
    nghttp2_data_provider prd = { .source.ptr = st, .read_callback = grpc_req_read_cb };
    rv = nghttp2_submit_request(grpc->ngh2, NULL, nvs, (size_t)idx,
                                 st->req_body_len > 0 ? &prd : NULL, st);
    free(nvs);
    if (rv < 0) { h2_stream_rst(sess, st, NGHTTP2_INTERNAL_ERROR); return; }
    grpc->stream_id = rv;

    /* Drain initial output (H2 preface + SETTINGS + HEADERS + DATA) to backend */
    h2_grpc_send_pending(sess, st);

    /* Arm backend recv immediately — we need to receive SETTINGS from backend */
    h2_grpc_arm_backend_recv(sess, st);

    log_debug("h2_grpc", "cid=%u stream=%d gRPC h2c backend init fd=%d",
              sess->cid, st->stream_id, st->backend_fd);
}

/* ---------- CQE handlers ------------------------------------------ */

void h2_on_grpc_backend_send(struct worker *w, uint32_t cid, uint32_t slot, int sent)
{
    struct conn_cold  *cc   = conn_cold_ptr(&w->pool, cid);
    struct h2_session *sess = cc->h2;
    if (!sess) return;
    if (slot >= H2_STREAM_SLOTS) return;

    struct h2_stream *st = &sess->streams[slot];
    if (!st->is_grpc || !st->grpc) return;

    struct h2_grpc_backend *grpc = st->grpc;
    grpc->send_in_flight = false;

    if (sent <= 0) {
        h2_stream_rst(sess, st, NGHTTP2_INTERNAL_ERROR);
        return;
    }

    grpc->send_len = 0; /* all bytes sent in one shot */

    /* Drain any further nghttp2 output queued since the last send */
    h2_grpc_send_pending(sess, st);
}

void h2_on_grpc_backend_recv(struct worker *w, uint32_t cid, uint32_t slot, int n)
{
    struct conn_cold  *cc   = conn_cold_ptr(&w->pool, cid);
    struct h2_session *sess = cc->h2;
    if (!sess) return;
    if (slot >= H2_STREAM_SLOTS) return;

    struct h2_stream *st = &sess->streams[slot];
    if (!st->is_grpc || !st->grpc) return;
    struct h2_grpc_backend *grpc = st->grpc;

    if (n <= 0) {
        /* Backend closed connection — if we already submitted, ignore */
        if (!st->resp_submitted)
            h2_stream_rst(sess, st, n < 0 ? NGHTTP2_INTERNAL_ERROR : NGHTTP2_REFUSED_STREAM);
        return;
    }

    /* Feed raw bytes to nghttp2 client session */
    ssize_t ret = nghttp2_session_mem_recv(grpc->ngh2, grpc->recv_buf, (size_t)n);
    if (ret < 0) {
        log_error("h2_grpc", "cid=%u stream=%d nghttp2_session_mem_recv: %s",
                  cid, st->stream_id, nghttp2_strerror((int)ret));
        h2_stream_rst(sess, st, NGHTTP2_INTERNAL_ERROR);
        return;
    }

    /* Drain any control frames the nghttp2 client wants to send (WINDOW_UPDATE etc.) */
    h2_grpc_send_pending(sess, st);

    /* Continue receiving unless response is already complete */
    if (!grpc->trailers_done)
        h2_grpc_arm_backend_recv(sess, st);
}

void h2_on_backend_connect(struct worker *w, uint32_t cid, uint32_t slot, int res)
{
    struct conn_cold  *cc   = conn_cold_ptr(&w->pool, cid);
    struct h2_session *sess = cc->h2;
    if (!sess) return;
    if (slot >= H2_STREAM_SLOTS) return;

    struct h2_stream *st = &sess->streams[slot];
    if (st->state != H2_STREAM_CONNECTING) return;

    if (res < 0) {
        log_debug("h2_connect", "cid=%u stream=%d connect failed: %s",
                  cid, st->stream_id, strerror(-res));
        h2_stream_rst(sess, st, NGHTTP2_CONNECT_ERROR);
        return;
    }

    /* gRPC streams use h2c to the backend — forward-declared below */
    if (st->is_grpc) {
        h2_grpc_backend_init(sess, st);
        return;
    }

    /* Build and send the HTTP/1.1 request */
    int ri = conn_hot(&w->pool, cid)->route_idx;
    const char *bcreds = (ri >= 0 && ri < (int)w->cfg->route_count)
                         ? w->cfg->routes[ri].backend_credentials : "";
    if (h2_build_http11_request(st, bcreds) != 0) {
        h2_stream_rst(sess, st, NGHTTP2_INTERNAL_ERROR);
        return;
    }

    st->state = H2_STREAM_SENDING_REQ;

    struct io_uring_sqe *sqe = io_uring_get_sqe(&w->uring.ring);
    if (!sqe) { h2_stream_rst(sess, st, NGHTTP2_INTERNAL_ERROR); return; }
    io_uring_prep_send(sqe, st->backend_fd,
        st->req_http11 + st->req_send_off,
        st->req_http11_len - st->req_send_off, MSG_NOSIGNAL);
    sqe->user_data = URING_UD_H2_ENCODE(VORTEX_OP_H2_SEND_BACKEND, slot, cid);
    uring_submit(&w->uring);
}

void h2_on_backend_send(struct worker *w, uint32_t cid, uint32_t slot, int sent)
{
    struct conn_cold  *cc   = conn_cold_ptr(&w->pool, cid);
    struct h2_session *sess = cc->h2;
    if (!sess) return;
    if (slot >= H2_STREAM_SLOTS) return;

    struct h2_stream *st = &sess->streams[slot];
    if (st->state != H2_STREAM_SENDING_REQ) return;

    if (sent <= 0) {
        h2_stream_rst(sess, st, NGHTTP2_CONNECT_ERROR);
        return;
    }

    st->req_send_off += (uint32_t)sent;

    if (st->req_send_off < st->req_http11_len) {
        /* Partial send — continue */
        struct io_uring_sqe *sqe = io_uring_get_sqe(&w->uring.ring);
        if (!sqe) { h2_stream_rst(sess, st, NGHTTP2_INTERNAL_ERROR); return; }
        io_uring_prep_send(sqe, st->backend_fd,
            st->req_http11 + st->req_send_off,
            st->req_http11_len - st->req_send_off, MSG_NOSIGNAL);
        sqe->user_data = URING_UD_H2_ENCODE(VORTEX_OP_H2_SEND_BACKEND, slot, cid);
        uring_submit(&w->uring);
        return;
    }

    /* Request fully sent — arm backend recv */
    st->state = H2_STREAM_WAITING_RESP;
    /* Free request buffers now — no longer needed */
    free(st->req_http11); st->req_http11 = NULL;
    free(st->req_body);   st->req_body   = NULL;
    st->req_body_len = 0;

    h2_arm_backend_recv(sess, st);
}

void h2_on_backend_recv(struct worker *w, uint32_t cid, uint32_t slot, int n)
{
    struct conn_cold  *cc   = conn_cold_ptr(&w->pool, cid);
    struct h2_session *sess = cc->h2;
    if (!sess) return;
    if (slot >= H2_STREAM_SLOTS) return;

    struct h2_stream *st = &sess->streams[slot];
    if (st->state != H2_STREAM_WAITING_RESP &&
        st->state != H2_STREAM_STREAMING) return;

    if (n == 0) {
        /* Backend EOF — response complete */
        st->backend_eof = true;
        if (!st->resp_headers_done) {
            h2_stream_rst(sess, st, NGHTTP2_INTERNAL_ERROR);
            return;
        }
        h2_maybe_cache_store(sess, st);
        if (st->is_chunked_resp || st->prefer_buffered_resp || !st->resp_submitted) {
            /* Buffered path or streaming path where headers just arrived */
            h2_submit_response(sess, st);
        } else {
            /* Streaming path: data provider is deferred — resume so it can signal EOF */
            nghttp2_session_resume_data(sess->ngh2, st->stream_id);
            h2_send_pending(sess);
        }
        return;
    }

    if (n < 0) {
        if (n == -ECONNRESET || n == -EPIPE) {
            st->backend_eof = true;
            if (!st->resp_headers_done) {
                h2_stream_rst(sess, st, NGHTTP2_INTERNAL_ERROR);
            } else {
                h2_maybe_cache_store(sess, st);
                if (st->is_chunked_resp || st->prefer_buffered_resp || !st->resp_submitted) {
                h2_submit_response(sess, st);
                } else {
                    nghttp2_session_resume_data(sess->ngh2, st->stream_id);
                    h2_send_pending(sess);
                }
            }
        } else {
            h2_stream_rst(sess, st, NGHTTP2_INTERNAL_ERROR);
        }
        return;
    }

    st->resp_buf_len += (uint32_t)n;
    st->state = H2_STREAM_STREAMING;

    /* Scan for end of headers (\r\n\r\n) if not yet found */
    if (!st->resp_headers_done) {
        const uint8_t *hdr_end = (const uint8_t *)memmem(
            st->resp_buf, st->resp_buf_len, "\r\n\r\n", 4);
        if (hdr_end) {
            st->resp_headers_done = true;
            st->resp_hdr_end = (uint32_t)(hdr_end - st->resp_buf) + 4;

            /* Detect Transfer-Encoding: chunked → use buffered path */
            const uint8_t *te = (const uint8_t *)memmem(
                st->resp_buf, st->resp_hdr_end, "Transfer-Encoding:", 18);
            if (!te) te = (const uint8_t *)memmem(
                st->resp_buf, st->resp_hdr_end, "transfer-encoding:", 18);
            if (te) {
                const uint8_t *eol = (const uint8_t *)memmem(
                    te, (size_t)(st->resp_buf + st->resp_hdr_end - te), "\r\n", 2);
                if (eol && memmem(te, (size_t)(eol - te), "chunked", 7))
                    st->is_chunked_resp = true;
            }

            /* Static assets and JSON API payloads are safer on the buffered
             * path. Incremental H2 streaming is still used for large dynamic
             * responses, but assets and app API calls that are sensitive to
             * framing/encoding mismatches are buffered to EOF and submitted
             * complete. */
            const uint8_t *ct = (const uint8_t *)memmem(
                st->resp_buf, st->resp_hdr_end, "Content-Type:", 13);
            if (!ct) ct = (const uint8_t *)memmem(
                st->resp_buf, st->resp_hdr_end, "content-type:", 13);
            if (ct) {
                const uint8_t *eol = (const uint8_t *)memmem(
                    ct, (size_t)(st->resp_buf + st->resp_hdr_end - ct), "\r\n", 2);
                if (eol) {
                    const uint8_t *v = ct + 13;
                    while (v < eol && (*v == ' ' || *v == '\t')) v++;
                    size_t vlen = (size_t)(eol - v);
                    if ((vlen >= 6 && memcmp(v, "image/", 6) == 0) ||
                        memmem(v, vlen, "font", 4) != NULL ||
                        (vlen >= 8 && memcmp(v, "text/css", 8) == 0) ||
                        memmem(v, vlen, "javascript", 10) != NULL ||
                        (vlen >= 16 && memcmp(v, "application/json", 16) == 0)) {
                        st->prefer_buffered_resp = true;
                    }
                }
            }

            /* Streaming path: submit response immediately so headers reach the
             * client without waiting for the full body. */
            if (!st->is_chunked_resp && !st->prefer_buffered_resp)
                h2_submit_response(sess, st);
        }
    }

    if (st->is_chunked_resp || st->prefer_buffered_resp) {
        /* Buffered path — accumulate until EOF then submit */
        if (st->resp_buf_len >= H2_RESP_MAX) {
            log_warn("h2_recv", "cid=%u stream=%d chunked response too large (>%u), RST",
                     cid, st->stream_id, H2_RESP_MAX);
            h2_stream_rst(sess, st, NGHTTP2_INTERNAL_ERROR);
            return;
        }
        h2_arm_backend_recv(sess, st);
        return;
    }

    /* Streaming path ------------------------------------------------ */

    /* Compact: discard body bytes already handed to nghttp2 data provider.
     * This bounds resp_buf memory to roughly H2_STREAM_BUF_MAX regardless
     * of total response size. */
    if (st->resp_submitted && st->resp_body_sent > 0) {
        uint32_t body_start = st->resp_hdr_end;
        uint32_t remaining  = st->resp_buf_len - body_start - st->resp_body_sent;
        if (remaining > 0)
            memmove(st->resp_buf + body_start,
                    st->resp_buf + body_start + st->resp_body_sent, remaining);
        st->resp_buf_len  -= st->resp_body_sent;
        st->resp_body_sent = 0;
    }

    /* Wake data provider and flush to client */
    if (st->resp_submitted) {
        nghttp2_session_resume_data(sess->ngh2, st->stream_id);
        h2_send_pending(sess);
    }

    /* Backpressure: pause backend recv when the client is too slow to drain.
     * The recv is re-armed in h2_on_send_client once the client catches up. */
    uint32_t pending = (st->resp_buf_len > st->resp_hdr_end + st->resp_body_sent)
                       ? st->resp_buf_len - st->resp_hdr_end - st->resp_body_sent : 0u;
    if (pending < H2_STREAM_BUF_MAX) {
        h2_arm_backend_recv(sess, st);
    } else {
        st->backend_recv_paused = true;
        log_debug("h2_stream", "cid=%u stream=%d recv paused (pending=%u)",
                  cid, st->stream_id, pending);
    }
}
