#define _GNU_SOURCE
/*
 * worker_proxy.c — HTTP request line parser and the main io_uring completion
 * dispatcher (handle_proxy_data) for the vortex worker event loop.
 *
 * handle_proxy_data() is the central state machine: it is called once per CQE
 * and dispatches to the correct handler based on the VORTEX_OP_* tag encoded
 * in cqe->user_data.  All other worker_*.c files provide helper functions
 * that are called from within the cases here.
 */
#include "worker_internal.h"
#ifdef VORTEX_H2
#include "h2.h"
#endif

static void resume_connected_backend(struct worker *w, uint32_t cid, struct conn_hot *h);

static void try_backend_pool_return(struct worker *w, uint32_t cid, struct conn_hot *h)
{
    if (!(h->flags & CONN_FLAG_STREAMING_BACKEND))
        return;

    int ri = h->route_idx, bi = h->backend_idx;
    int ps = w->cfg->routes[ri].backends[bi].pool_size;
    if (ps <= 0)
        return;

    struct conn_cold *cold = conn_cold_ptr(&w->pool, cid);
    if (cold->backend_content_length == 0 ||
        cold->backend_body_recv < cold->backend_content_length)
        return;

    if (h->backend_fd >= 0) {
        uring_remove_fd(&w->uring, (unsigned)FIXED_FD_BACKEND(w, cid));
        struct global_backend_conn pooled = {
            .fd = h->backend_fd,
            .ssl = cold->backend_ssl,
        };
        global_pool_put(ri, bi, pooled, ps);
        h->backend_fd = -1;
        cold->backend_ssl = NULL;
    }
    h->flags &= ~(CONN_FLAG_STREAMING_BACKEND |
                  CONN_FLAG_BACKEND_POOLED |
                  CONN_FLAG_BACKEND_TLS);
    cold->backend_content_length = 0;
    cold->backend_body_recv      = 0;
    log_debug("backend_pool_return", "conn=%u route=%d backend=%d",
        cid, ri, bi);
}

static void submit_client_response_send(struct worker *w, uint32_t cid,
                                        struct conn_hot *h, int n)
{
    h->send_buf_off = 0;
    h->send_buf_len = (uint32_t)n;
    struct io_uring_sqe *sqe = io_uring_get_sqe(&w->uring.ring);
    if (!sqe) { conn_close(w, cid, true); return; }
    if (w->uring.bufs_registered && !(h->flags & CONN_FLAG_KTLS_TX)) {
        h->zc_notif_count++;
        io_uring_prep_send_zc_fixed(sqe, h->client_fd,
            conn_send_buf(&w->pool, cid), (size_t)n,
            MSG_NOSIGNAL, 0, (unsigned)SEND_IDX_SEND(w, cid));
        if (w->uring.files_registered) sqe->flags |= IOSQE_FIXED_FILE;
        sqe->user_data = URING_UD_ENCODE(VORTEX_OP_SEND_CLIENT_ZC, cid);
    } else {
        PREP_SEND(w, sqe, h->client_fd, FIXED_FD_CLIENT(w, cid),
            conn_send_buf(&w->pool, cid), (size_t)n, MSG_NOSIGNAL, SEND_IDX_SEND(w, cid));
        sqe->user_data = URING_UD_ENCODE(VORTEX_OP_SEND_CLIENT, cid);
    }
    uring_submit(&w->uring);
}

static int inject_response_etag(struct worker *w, uint8_t *buf, int n)
{
    if (n <= 0 || memcmp(buf, "HTTP/", 5) != 0)
        return n;

    uint8_t *hdr_end = (uint8_t *)FIND_HDR_END(buf, (size_t)n);
    if (!hdr_end)
        return n;

    size_t hdr_len = (size_t)(hdr_end - buf) + 4;
    if (memmem(buf, hdr_len, "\r\nETag:", 7) ||
        memmem(buf, hdr_len, "\r\netag:", 7))
        return n;

    bool is_chunked =
        memmem(buf, hdr_len, "\r\nTransfer-Encoding: chunked", 28) ||
        memmem(buf, hdr_len, "\r\ntransfer-encoding: chunked", 28);
    if (is_chunked)
        return n;

    const char *clh = (const char *)memmem(buf, hdr_len, "\r\nContent-Length:", 17);
    if (!clh)
        clh = (const char *)memmem(buf, hdr_len, "\r\ncontent-length:", 17);
    if (!clh)
        return n;

    const char *cv = clh + 17;
    while (*cv == ' ') cv++;
    size_t body_len = (size_t)n - hdr_len;
    if ((size_t)atol(cv) != body_len || body_len == 0)
        return n;

    uint64_t etag = cache_compute_body_etag(w->cfg->cache.etag_sha256,
                                            buf + hdr_len, body_len);
    if (etag == 0)
        return n;

    char etag_hdr[40];
    int etag_len = snprintf(etag_hdr, sizeof(etag_hdr),
        "\r\nETag: \"%016llx\"",
        (unsigned long long)etag);
    if (etag_len <= 0 || n + etag_len > (int)w->pool.buf_size)
        return n;

    size_t hle = (size_t)(hdr_end - buf);
    memmove(buf + hle + etag_len, buf + hle, (size_t)(n - (int)hle));
    memcpy(buf + hle, etag_hdr, (size_t)etag_len);
    return n + etag_len;
}

static int rewrite_backend_connection_header(struct worker *w, uint32_t cid,
                                             struct conn_hot *h, uint8_t *rbuf,
                                             int fwd_n, bool is_ws)
{
    if (is_ws)
        return fwd_n;

    bool use_ka = ((h->flags & CONN_FLAG_BACKEND_POOLED) != 0
                  || (w->cfg->routes[h->route_idx]
                         .backends[h->backend_idx].pool_size > 0));
    const char *conn_val = use_ka ? "keep-alive" : "close";
    size_t conn_val_len = use_ka ? 10 : 5;

    uint8_t *ch = (uint8_t *)memmem(rbuf, (size_t)fwd_n, "\r\nConnection:", 13);
    if (!ch)
        ch = (uint8_t *)memmem(rbuf, (size_t)fwd_n, "\r\nconnection:", 13);
    if (ch) {
        uint8_t *vs = ch + 13;
        while (vs < rbuf + fwd_n && (*vs == ' ' || *vs == '\t')) vs++;
        uint8_t *ve = (uint8_t *)FIND_CRLF(vs, (size_t)(rbuf + fwd_n - vs));
        if (ve && ve > vs) {
            size_t old_len = (size_t)(ve - vs);
            int delta = (int)conn_val_len - (int)old_len;
            if (fwd_n + delta <= (int)w->pool.buf_size && fwd_n + delta > 0) {
                memmove(vs + conn_val_len, ve, (size_t)(rbuf + fwd_n - ve));
                memcpy(vs, conn_val, conn_val_len);
                fwd_n += delta;
            }
        }
    } else {
        const char *eol0 = (const char *)FIND_CRLF(rbuf, (size_t)fwd_n);
        char inj0[32];
        int il0 = snprintf(inj0, sizeof(inj0),
            "Connection: %s\r\n", conn_val);
        if (eol0 && fwd_n + il0 <= (int)w->pool.buf_size) {
            size_t le = (size_t)(eol0 - (const char *)rbuf) + 2;
            memmove(rbuf + le + il0, rbuf + le, (size_t)fwd_n - le);
            memcpy(rbuf + le, inj0, (size_t)il0);
            fwd_n += il0;
        }
    }

    if (use_ka) {
        struct conn_cold *cold = conn_cold_ptr(&w->pool, cid);
        cold->backend_content_length = 0;
        cold->backend_body_recv      = 0;
    }

    return fwd_n;
}

/* Extract method and URL from HTTP/1.x request line.
 * Returns 0 on success, -1 if not a parseable HTTP request. */
int parse_http_request_line(const uint8_t *buf, int len,
                            char *method_out, size_t method_max,
                            char *url_out, size_t url_max)
{
    /* "GET /path HTTP/1.1\r\n..." */
    const char *p = (const char *)buf;
    const char *end = p + len;
    const char *line_end;
    const char *ver;

    /* Method */
    const char *sp = (const char *)memchr(p, ' ', (size_t)(end - p));
    if (!sp || sp == p) return -1;
    size_t mlen = (size_t)(sp - p);
    if (mlen >= method_max) return -1;
    memcpy(method_out, p, mlen);
    method_out[mlen] = '\0';
    p = sp + 1;

    /* URL */
    sp = (const char *)memchr(p, ' ', (size_t)(end - p));
    if (!sp || sp == p) return -1;
    size_t ulen = (size_t)(sp - p);
    if (ulen >= url_max) return -1;   /* URI too long — reject, don't silently truncate */
    memcpy(url_out, p, ulen);
    url_out[ulen] = '\0';
    p = sp + 1;

    line_end = (const char *)memmem(p, (size_t)(end - p), "\r\n", 2);
    if (!line_end || line_end == p)
        return -1;

    ver = p;
    if ((size_t)(line_end - ver) != 8)
        return -1;
    if (memcmp(ver, "HTTP/1.1", 8) != 0 &&
        memcmp(ver, "HTTP/1.0", 8) != 0)
        return -1;

    return 0;
}

static void send_bad_gateway_and_close(struct worker *w, uint32_t cid)
{
    struct conn_hot *h = conn_hot(&w->pool, cid);
    static const char r502[] =
        "HTTP/1.1 502 Bad Gateway\r\n"
        "Content-Length: 11\r\nConnection: close\r\n\r\nBad Gateway";
    send(h->client_fd, r502, sizeof(r502) - 1, MSG_NOSIGNAL);
    conn_close(w, cid, false);
}

static void send_service_unavailable_and_close(struct worker *w, uint32_t cid)
{
    struct conn_hot *h = conn_hot(&w->pool, cid);
    static const char r503[] =
        "HTTP/1.1 503 Service Unavailable\r\n"
        "Content-Length: 19\r\nRetry-After: 5\r\nConnection: close\r\n\r\n"
        "Service Unavailable";
    send(h->client_fd, r503, sizeof(r503) - 1, MSG_NOSIGNAL);
    conn_close(w, cid, false);
}

static void send_bad_request_and_close(struct worker *w, uint32_t cid)
{
    struct conn_hot *h = conn_hot(&w->pool, cid);
    static const char r400[] =
        "HTTP/1.1 400 Bad Request\r\n"
        "Content-Length: 11\r\nConnection: close\r\n\r\nBad Request";
    send(h->client_fd, r400, sizeof(r400) - 1, MSG_NOSIGNAL);
    conn_close(w, cid, false);
}

static bool request_has_ambiguous_framing(const uint8_t *buf, size_t len)
{
    const uint8_t *te;
    const uint8_t *cl;

    te = (const uint8_t *)memmem(buf, len, "\r\nTransfer-Encoding:", 20);
    if (!te) te = (const uint8_t *)memmem(buf, len, "\r\ntransfer-encoding:", 20);
    if (!te)
        return false;

    cl = (const uint8_t *)memmem(buf, len, "\r\nContent-Length:", 17);
    if (!cl) cl = (const uint8_t *)memmem(buf, len, "\r\ncontent-length:", 17);
    return cl != NULL;
}

static void conn_backend_count_assign(struct conn_hot *h, int route_idx, int backend_idx)
{
    if ((h->flags & CONN_FLAG_BACKEND_COUNTED) &&
        (h->route_idx != (uint16_t)route_idx || h->backend_idx != (uint16_t)backend_idx)) {
        router_backend_active_dec((int)h->route_idx, (int)h->backend_idx);
        h->flags &= ~CONN_FLAG_BACKEND_COUNTED;
    }

    h->route_idx = (uint16_t)route_idx;
    h->backend_idx = (uint16_t)backend_idx;

    if (!(h->flags & CONN_FLAG_BACKEND_COUNTED)) {
        router_backend_active_inc(route_idx, backend_idx);
        h->flags |= CONN_FLAG_BACKEND_COUNTED;
    }
}

/* Route to a backend and establish or reuse a connection.
 * Returns 0 on success (recv armed or CONNECT in flight), -1 on failure. */
static int route_and_connect(struct worker *w, uint32_t cid, int route_idx, bool has_pending_data)
{
    struct conn_hot *h = conn_hot(&w->pool, cid);
    /* When has_pending_data is true, the caller already incremented w->accepted
     * and the connection is already in CONN_STATE_PROXYING — we must not
     * re-increment or re-set the state. Request data sits in recv_buf and
     * will be forwarded by the CONNECT completion handler. */
    int backend_idx = select_available_backend(w, route_idx, 0);
    if (backend_idx < 0) {
        send_service_unavailable_and_close(w, cid);
        return -1;
    }

    conn_backend_count_assign(h, route_idx, backend_idx);

    const char *addr = router_backend_addr(&w->router, route_idx, backend_idx);
    if (!addr) {
        send_bad_gateway_and_close(w, cid);
        return -1;
    }

    const struct backend_config *bcfg = &w->cfg->routes[route_idx].backends[backend_idx];
    int cfg_pool = bcfg->pool_size;
    struct global_backend_conn pooled = { .fd = -1, .ssl = NULL };
    bool have_pooled = (cfg_pool > 0) && global_pool_get(route_idx, backend_idx, &pooled);
    if (have_pooled && pooled.fd >= 0) {
        h->backend_fd = pooled.fd;
        conn_cold_ptr(&w->pool, cid)->backend_ssl = pooled.ssl;
        h->flags |= CONN_FLAG_BACKEND_POOLED;
        if (pooled.ssl)
            h->flags |= CONN_FLAG_BACKEND_TLS;
        uring_install_fd(&w->uring, (unsigned)FIXED_FD_BACKEND(w, cid), pooled.fd);

        if (!has_pending_data) {
            h->state = CONN_STATE_PROXYING;
            h->last_active_tsc = rdtsc();
            w->accepted++;

            if (h->flags & CONN_FLAG_TCP_TUNNEL) {
                struct io_uring_sqe *sqe_c = io_uring_get_sqe(&w->uring.ring);
                struct io_uring_sqe *sqe_b = io_uring_get_sqe(&w->uring.ring);
                if (!sqe_c || !sqe_b) { conn_close(w, cid, true); return -1; }
                PREP_RECV(w, sqe_c, h->client_fd, FIXED_FD_CLIENT(w, cid),
                    conn_recv_buf(&w->pool, cid), w->pool.buf_size, 0, SEND_IDX_RECV(w, cid));
                sqe_c->user_data = URING_UD_ENCODE(VORTEX_OP_RECV_CLIENT_WS, cid);
                PREP_RECV(w, sqe_b, h->backend_fd, FIXED_FD_BACKEND(w, cid),
                    conn_send_buf(&w->pool, cid), w->pool.buf_size, 0, SEND_IDX_SEND(w, cid));
                sqe_b->user_data = URING_UD_ENCODE(VORTEX_OP_RECV_BACKEND_WS, cid);
            } else {
                struct io_uring_sqe *sqe = io_uring_get_sqe(&w->uring.ring);
                if (!sqe) { conn_close(w, cid, true); return -1; }
                PREP_RECV(w, sqe, h->client_fd, FIXED_FD_CLIENT(w, cid),
                    conn_recv_buf(&w->pool, cid), h->recv_window, 0, cid);
                sqe->user_data = URING_UD_ENCODE(VORTEX_OP_RECV_CLIENT, cid);
            }
            uring_submit(&w->uring);
        }
        return 0;
    }

    h->backend_fd = begin_async_connect(w, bcfg, cid);
    if (h->backend_fd >= 0)
        uring_install_fd(&w->uring, (unsigned)FIXED_FD_BACKEND(w, cid), h->backend_fd);
    if (h->backend_fd < 0) {
        send_bad_gateway_and_close(w, cid);
        return -1;
    }

    h->flags |= CONN_FLAG_BACKEND_CONNECTING;
    h->state = CONN_STATE_BACKEND_CONNECT;
    if (!has_pending_data) {
        h->last_active_tsc = rdtsc();
        w->accepted++;
    }
    return 0;
}

static void handle_backend_read_result(struct worker *w, uint32_t cid, int n)
{
    struct conn_hot *h = conn_hot(&w->pool, cid);
    struct conn_cold *cold_main = conn_cold_ptr(&w->pool, cid);

    log_debug("recv_backend", "conn=%u n=%d", cid, n);
    if (n > 0 && !(h->flags & CONN_FLAG_BACKEND_TLS)) {
        RECV_WINDOW_GROW(h, n, w->pool.buf_size);
        /* Re-arm TCP_QUICKACK — kernel clears it after each ACK */
        int one = 1;
        setsockopt(h->backend_fd, IPPROTO_TCP, TCP_QUICKACK, &one, sizeof(one));
    }
    if (n == 0) {
        /* Backend EOF */
        if (!(h->flags & CONN_FLAG_STREAMING_BACKEND)) {
            /* No response bytes were ever received — stale pooled connection
             * closed by the backend before it could respond.  The client has
             * already sent its request and is waiting; send 502 and close. */
            send_bad_gateway_and_close(w, cid);
            return;
        }
        /* Normal EOF — backend finished streaming response */
        h->flags &= ~CONN_FLAG_STREAMING_BACKEND;
        /* Backend closed the connection — never return to pool */
        if (cold_main->backend_ssl) {
#ifdef VORTEX_PHASE_TLS
            ptls_free((ptls_t *)cold_main->backend_ssl);
#endif
            cold_main->backend_ssl = NULL;
        }
        if (h->backend_fd >= 0) {
            uring_remove_fd(&w->uring, (unsigned)FIXED_FD_BACKEND(w, cid));
            close(h->backend_fd); h->backend_fd = -1;
        }
        h->flags &= ~(CONN_FLAG_BACKEND_POOLED | CONN_FLAG_BACKEND_TLS);
        /* Keep client alive for next request */
        struct io_uring_sqe *sqe = io_uring_get_sqe(&w->uring.ring);
        if (!sqe) { conn_close(w, cid, false); return; }
        PREP_RECV(w, sqe, h->client_fd, FIXED_FD_CLIENT(w, cid),
            conn_recv_buf(&w->pool, cid), h->recv_window, 0, cid);
        sqe->user_data = URING_UD_ENCODE(VORTEX_OP_RECV_CLIENT, cid);
        uring_submit(&w->uring);
        return;
    }
    /* First response byte received — cancel the backend deadline */
    cold_main->backend_deadline_ns = 0;
    h->flags |= CONN_FLAG_STREAMING_BACKEND;
    h->bytes_out += (uint32_t)n;

    /* Track body bytes for keep-alive pool return */
    {
        int _ri = h->route_idx, _bi = h->backend_idx;
        int _ps = w->cfg->routes[_ri].backends[_bi].pool_size;
        if (_ps > 0) {
            /* Parse Content-Length from the first response chunk */
            if (cold_main->backend_content_length == 0 && n > 12) {
                const uint8_t *sbuf2 = conn_send_buf(&w->pool, cid);
                const char *clh = (const char *)memmem(sbuf2, (size_t)n,
                                                        "\r\nContent-Length:", 17);
                if (!clh) clh = (const char *)memmem(sbuf2, (size_t)n,
                                                       "\r\ncontent-length:", 17);
                if (clh) {
                    const char *cv = clh + 17;
                    while (*cv == ' ') cv++;
                    char *endp;
                    unsigned long cl = strtoul(cv, &endp, 10);
                    if (cl > UINT32_MAX) cl = UINT32_MAX;
                    cold_main->backend_content_length = (uint32_t)cl;
                }
            }
            /* Count body bytes (after \r\n\r\n header terminator) */
            if (cold_main->backend_content_length > 0) {
                const uint8_t *sbuf2 = conn_send_buf(&w->pool, cid);
                const char *hend = (const char *)FIND_HDR_END(sbuf2, (size_t)n);
                if (hend && (hend + 4 <= (const char *)sbuf2 + n)) {
                    size_t body_in_chunk = (size_t)n - (size_t)(hend + 4 - (const char *)sbuf2);
                    cold_main->backend_body_recv += (uint32_t)body_in_chunk;
                } else if (!hend) {
                    cold_main->backend_body_recv += (uint32_t)n;
                }
            }
        }
    }

    /* Chunked TE reassembly: accumulate body on follow-up recvs */
    if ((h->flags & CONN_FLAG_CACHING) &&
        (n < 5 || memcmp(conn_send_buf(&w->pool, cid), "HTTP/", 5) != 0)) {
        if (cold_main->chunk_buf) {
            bool final = chunked_decode_append(cold_main,
                conn_send_buf(&w->pool, cid), (size_t)n);
            if (final) {
                cache_chunked_store(w, cid, h, cold_main);
                h->flags &= ~CONN_FLAG_CACHING;
            }
        }
    }

    /* WebSocket 101 upgrade — backend TLS origins do not support raw io_uring
     * relay yet, so reject before switching to passthrough mode. */
    if ((h->flags & CONN_FLAG_WEBSOCKET_ACTIVE) && n > 12 &&
        memcmp(conn_send_buf(&w->pool, cid), "HTTP/1.1 101", 12) == 0) {
        if (h->flags & CONN_FLAG_BACKEND_TLS) {
            send_bad_gateway_and_close(w, cid);
            return;
        }
        send(h->client_fd, conn_send_buf(&w->pool, cid), (size_t)n, MSG_NOSIGNAL);

        /* Arm both recv directions simultaneously. */
        struct io_uring_sqe *ws_c = io_uring_get_sqe(&w->uring.ring);
        struct io_uring_sqe *ws_b = io_uring_get_sqe(&w->uring.ring);
        if (!ws_c || !ws_b) { conn_close(w, cid, false); return; }

        /* client → backend direction: recv into recv_buf */
        PREP_RECV(w, ws_c, h->client_fd, FIXED_FD_CLIENT(w, cid),
            conn_recv_buf(&w->pool, cid), w->pool.buf_size, 0, SEND_IDX_RECV(w, cid));
        ws_c->user_data = URING_UD_ENCODE(VORTEX_OP_RECV_CLIENT_WS, cid);

        /* backend → client direction: recv into send_buf */
        PREP_RECV(w, ws_b, h->backend_fd, FIXED_FD_BACKEND(w, cid),
            conn_send_buf(&w->pool, cid), w->pool.buf_size, 0, SEND_IDX_SEND(w, cid));
        ws_b->user_data = URING_UD_ENCODE(VORTEX_OP_RECV_BACKEND_WS, cid);

        uring_submit(&w->uring);
        return;
    }

    /* Response header rewrites — only on the first chunk (starts with "HTTP/") */
    if (n > 7 && memcmp(conn_send_buf(&w->pool, cid), "HTTP/", 5) == 0) {
        uint8_t *sbuf = conn_send_buf(&w->pool, cid);

        /* Locate end of headers */
        uint8_t *hdr_end = (uint8_t *)FIND_HDR_END(sbuf, (size_t)n);
        size_t hdr_len = hdr_end ? (size_t)(hdr_end - sbuf) + 4 : (size_t)n;

        /* ---- Replace/inject Server header ----
         * Per-route server_header takes priority over global; empty = pass through. */
        const char *_srv_hdr = w->cfg->routes[h->route_idx].server_header[0]
                               ? w->cfg->routes[h->route_idx].server_header
                               : w->cfg->server_header;
        if (_srv_hdr[0]) {
            const char *new_srv = _srv_hdr;
            size_t new_srv_len  = strlen(new_srv);
            uint8_t *sh = (uint8_t *)memmem(sbuf, hdr_len, "\r\nServer:", 9);
            if (!sh) sh = (uint8_t *)memmem(sbuf, hdr_len, "\r\nserver:", 9);
            if (sh) {
                uint8_t *vs = sh + 9;
                while (vs < sbuf + hdr_len && (*vs == ' ' || *vs == '\t')) vs++;
                uint8_t *ve = (uint8_t *)FIND_CRLF(vs,
                    (size_t)(sbuf + hdr_len - vs));
                if (ve) {
                    size_t old_len = (size_t)(ve - vs);
                    int delta = (int)new_srv_len - (int)old_len;
                    if (n + delta <= (int)w->pool.buf_size && n + delta > 0) {
                        memmove(vs + new_srv_len, ve, (size_t)(sbuf + n - ve));
                        memcpy(vs, new_srv, new_srv_len);
                        n += delta;
                        hdr_end = (uint8_t *)FIND_HDR_END(sbuf, (size_t)n);
                        hdr_len = hdr_end ? (size_t)(hdr_end - sbuf) + 4 : (size_t)n;
                    }
                }
            } else if (hdr_end) {
                /* No Server header — inject one */
                char inj_srv[80];
                int inj_srv_len = snprintf(inj_srv, sizeof(inj_srv),
                    "\r\nServer: %s", new_srv);
                if (n + inj_srv_len <= (int)w->pool.buf_size) {
                    size_t hle = (size_t)(hdr_end - sbuf);
                    memmove(sbuf + hle + inj_srv_len, sbuf + hle,
                            (size_t)(n - (int)hle));
                    memcpy(sbuf + hle, inj_srv, (size_t)inj_srv_len);
                    n += inj_srv_len;
                    hdr_end = (uint8_t *)FIND_HDR_END(sbuf, (size_t)n);
                    hdr_len = hdr_end ? (size_t)(hdr_end - sbuf) + 4 : (size_t)n;
                }
            }
        }

        /* ---- Cache-Control rewrite based on request URL ---- */
        {
            char cc_url[512] = {0};
            char cc_method[16] = {0};
            const uint8_t *req = conn_recv_buf(&w->pool, cid);
            parse_http_request_line(req, (int)w->pool.buf_size,
                                    cc_method, sizeof(cc_method),
                                    cc_url, sizeof(cc_url));
            uint32_t ttl = cache_ttl_for_url(cc_url);

            /* For static assets (ttl >= 3600): override whatever the backend sent —
             * Kestrel/Sonarr sends no-cache,no-store for ALL responses including images.
             * For dynamic content (ttl == 60): only inject if backend sent nothing.
             * For API (ttl == 0): leave Cache-Control untouched. */
            if (hdr_end && ttl > 0) {
                /* Build the value we want */
                char cc_val[64];
                if (ttl >= 3600) snprintf(cc_val, sizeof(cc_val), "public, max-age=%u, immutable", ttl);
                else             snprintf(cc_val, sizeof(cc_val), "public, max-age=%u", ttl);

                uint8_t *cch = (uint8_t *)memmem(sbuf, hdr_len, "\r\nCache-Control:", 16);
                if (!cch) cch = (uint8_t *)memmem(sbuf, hdr_len, "\r\ncache-control:", 16);

                if (cch && ttl >= 3600) {
                    uint8_t *vs = cch + 16;
                    while (vs < sbuf + hdr_len && (*vs == ' ' || *vs == '\t')) vs++;
                    uint8_t *ve = (uint8_t *)FIND_CRLF(vs, (size_t)(sbuf + hdr_len - vs));
                    if (ve) {
                        size_t old_len = (size_t)(ve - vs);
                        int delta = (int)strlen(cc_val) - (int)old_len;
                        if (n + delta <= (int)w->pool.buf_size && n + delta > 0) {
                            memmove(vs + strlen(cc_val), ve, (size_t)(sbuf + n - ve));
                            memcpy(vs, cc_val, strlen(cc_val));
                            n += delta;
                            hdr_end = (uint8_t *)FIND_HDR_END(sbuf, (size_t)n);
                            hdr_len = hdr_end ? (size_t)(hdr_end - sbuf) + 4 : (size_t)n;
                        }
                    }
                } else if (!cch) {
                    /* No Cache-Control present — inject one */
                    char cc_hdr[80];
                    int cc_len = snprintf(cc_hdr, sizeof(cc_hdr),
                        "\r\nCache-Control: %s", cc_val);
                    if (n + cc_len <= (int)w->pool.buf_size) {
                        size_t hle = (size_t)(hdr_end - sbuf);
                        memmove(sbuf + hle + cc_len, sbuf + hle, (size_t)(n - (int)hle));
                        memcpy(sbuf + hle, cc_hdr, (size_t)cc_len);
                        n += cc_len;
                        hdr_end = (uint8_t *)FIND_HDR_END(sbuf, (size_t)n);
                        hdr_len = hdr_end ? (size_t)(hdr_end - sbuf) + 4 : (size_t)n;
                    }
                }

                /* For static assets: also strip Pragma header (no-cache from Kestrel) */
                if (ttl >= 3600 && hdr_end) {
                    uint8_t *ph = (uint8_t *)memmem(sbuf, hdr_len, "\r\nPragma:", 9);
                    if (!ph)
                        ph = (uint8_t *)memmem(sbuf, hdr_len, "\r\npragma:", 9);
                    if (ph) {
                        uint8_t *pe = (uint8_t *)FIND_CRLF(ph + 2,
                            (size_t)(sbuf + n - ph - 2));
                        if (pe) {
                            pe += 2; /* point past the line's \r\n */
                            size_t remove = (size_t)(pe - (ph + 2));
                            memmove(ph + 2, ph + 2 + remove,
                                (size_t)(sbuf + n - (ph + 2 + remove)));
                            n -= (int)remove;
                            hdr_end = (uint8_t *)FIND_HDR_END(sbuf, (size_t)n);
                            hdr_len = hdr_end ? (size_t)(hdr_end - sbuf) + 4 : (size_t)n;
                        }
                    }
                }
            }
        }

        /* ---- Inject HSTS on HTTPS responses when absent ---- */
        if (hdr_end) {
            bool has_hsts =
                memmem(sbuf, hdr_len, "\r\nStrict-Transport-Security:", 28) ||
                memmem(sbuf, hdr_len, "\r\nstrict-transport-security:", 28);
            if (!has_hsts) {
                const char *hsts = "\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains";
                int hsts_len = (int)strlen(hsts);
                if (n + hsts_len <= (int)w->pool.buf_size) {
                    size_t hle = (size_t)(hdr_end - sbuf);
                    memmove(sbuf + hle + hsts_len, sbuf + hle, (size_t)(n - (int)hle));
                    memcpy(sbuf + hle, hsts, (size_t)hsts_len);
                    n += hsts_len;
                    hdr_end = (uint8_t *)FIND_HDR_END(sbuf, (size_t)n);
                    hdr_len = hdr_end ? (size_t)(hdr_end - sbuf) + 4 : (size_t)n;
                }
            }
        }

#ifdef VORTEX_QUIC
        if (hdr_end) {
            const char *altsvc = "\r\nAlt-Svc: h3=\":443\"; ma=86400";
            int as_len = 30;
            if (n + as_len <= (int)w->pool.buf_size) {
                size_t hle = (size_t)(hdr_end - sbuf);
                memmove(sbuf + hle + as_len, sbuf + hle, (size_t)(n - (int)hle));
                memcpy(sbuf + hle, altsvc, (size_t)as_len);
                n += as_len;
                hdr_end = (uint8_t *)FIND_HDR_END(sbuf, (size_t)n);
                hdr_len = hdr_end ? (size_t)(hdr_end - sbuf) + 4 : (size_t)n;
            }
        }
#endif

        {
            uint8_t *ch = (uint8_t *)memmem(sbuf, hdr_len, "\r\nConnection:", 13);
            if (!ch) ch = (uint8_t *)memmem(sbuf, hdr_len, "\r\nconnection:", 13);
            if (ch) {
                uint8_t *vs = ch + 13;
                while (vs < sbuf + hdr_len && (*vs == ' ' || *vs == '\t')) vs++;
                uint8_t *ve = (uint8_t *)FIND_CRLF(vs,
                    (size_t)(sbuf + hdr_len - vs));
                if (ve && ve > vs) {
                    const char *kl = "keep-alive";
                    size_t kl_len = 10;
                    size_t old_len = (size_t)(ve - vs);
                    int delta = (int)kl_len - (int)old_len;
                    if (n + delta <= (int)w->pool.buf_size && n + delta > 0) {
                        memmove(vs + kl_len, ve, (size_t)(sbuf + n - ve));
                        memcpy(vs, kl, kl_len);
                        n += delta;
                        hdr_end = (uint8_t *)FIND_HDR_END(sbuf, (size_t)n);
                        hdr_len = hdr_end ? (size_t)(hdr_end - sbuf) + 4 : (size_t)n;
                    }
                }
            } else if (hdr_end) {
                const int ka_len = 24;
                if (n + ka_len <= (int)w->pool.buf_size) {
                    size_t hle = (size_t)(hdr_end - sbuf);
                    memmove(sbuf + hle + ka_len, sbuf + hle, (size_t)(n - (int)hle));
                    memcpy(sbuf + hle, "\r\nConnection: keep-alive", (size_t)ka_len);
                    n += ka_len;
                    hdr_end = (uint8_t *)FIND_HDR_END(sbuf, (size_t)n);
                    hdr_len = hdr_end ? (size_t)(hdr_end - sbuf) + 4 : (size_t)n;
                }
            }
            (void)hdr_len;
        }

        if (w->cache && w->cache->index) {
            const uint8_t *resp2 = conn_send_buf(&w->pool, cid);
            int status2 = 0;
            if (n > 9) {
                const char *sp = (const char *)resp2 + 9;
                for (int i = 0; i < 3 && sp[i] >= '0' && sp[i] <= '9'; i++)
                    status2 = status2 * 10 + (sp[i] - '0');
            }
            if (status2 == 200) {
                char cc_method2[16] = {0}, cc_url2[512] = {0};
                const uint8_t *req2 = conn_recv_buf(&w->pool, cid);
                if (req2[0] != 0 &&
                    parse_http_request_line(req2, (int)w->pool.buf_size,
                                            cc_method2, sizeof(cc_method2),
                                            cc_url2, sizeof(cc_url2)) == 0 &&
                    strcmp(cc_method2, "GET") == 0) {

                    uint32_t ttl2 = cache_ttl_for_url(cc_url2);
                    if (ttl2 > 0) {
                        const char *he2 = (const char *)FIND_HDR_END(
                            resp2, (size_t)n);
                        if (he2) {
                            size_t hl2 = (size_t)(he2 + 4 - (const char *)resp2);
                            size_t bl2 = (size_t)n - hl2;

                            bool is_chunked =
                                memmem(resp2, hl2, "\r\nTransfer-Encoding: chunked", 28) ||
                                memmem(resp2, hl2, "\r\ntransfer-encoding: chunked", 28);

                            bool cl_ok = false;
                            if (!is_chunked) {
                                const char *clh = (const char *)memmem(
                                    resp2, hl2, "\r\nContent-Length:", 17);
                                if (!clh) clh = (const char *)memmem(
                                    resp2, hl2, "\r\ncontent-length:", 17);
                                if (clh) {
                                    const char *cv = clh + 17;
                                    while (*cv == ' ') cv++;
                                    uint32_t cl = (uint32_t)atol(cv);
                                    cl_ok = (bl2 == cl);
                                }
                            }

                            if (cl_ok) {
                                char cc_key2[640];
                                make_cache_key(req2, (size_t)w->pool.buf_size,
                                               cc_url2, cc_key2, sizeof(cc_key2));
                                cache_store(w->cache, cc_key2, strlen(cc_key2),
                                    (uint16_t)status2, ttl2,
                                    resp2, hl2, resp2 + hl2, bl2);
                                log_debug("cache_store",
                                    "conn=%u url=%s ttl=%u body=%zu",
                                    cid, cc_key2, ttl2, bl2);
                            } else if (is_chunked && !(h->flags & CONN_FLAG_CACHING)) {
                                uint32_t hlen2 = (uint32_t)hl2;
                                uint32_t init_cap = hlen2 + 65536;
                                cold_main->chunk_buf = malloc(init_cap);
                                if (cold_main->chunk_buf) {
                                    cold_main->chunk_buf_cap  = init_cap;
                                    cold_main->chunk_hdr_len  = hlen2;
                                    cold_main->chunk_body_len = 0;
                                    cold_main->chunk_remaining = 0;
                                    cold_main->chunk_skip_crlf = false;
                                    cold_main->chunk_ttl = ttl2;
                                    make_cache_key(req2, (size_t)w->pool.buf_size,
                                                   cc_url2,
                                                   cold_main->chunk_url,
                                                   sizeof(cold_main->chunk_url));
                                    memcpy(cold_main->chunk_buf, resp2, hlen2);
                                    h->flags |= CONN_FLAG_CACHING;
                                    if (bl2 > 0) {
                                        bool fin2 = chunked_decode_append(cold_main,
                                            resp2 + hlen2, bl2);
                                        if (fin2) {
                                            cache_chunked_store(w, cid, h, cold_main);
                                            h->flags &= ~CONN_FLAG_CACHING;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if (n > 7 && memcmp(conn_send_buf(&w->pool, cid), "HTTP/", 5) == 0) {
        uint8_t *sbuf_ct = conn_send_buf(&w->pool, cid);
        const uint8_t *hend_ct = (const uint8_t *)FIND_HDR_END(sbuf_ct, (size_t)n);
        size_t hdr_scan_len = hend_ct
            ? (size_t)(hend_ct - sbuf_ct) + 4
            : (size_t)n;
        const uint8_t *cth2 = (const uint8_t *)memmem(
            sbuf_ct, hdr_scan_len, "\r\nContent-Type:", 15);
        if (!cth2) cth2 = (const uint8_t *)memmem(
            sbuf_ct, hdr_scan_len, "\r\ncontent-type:", 15);
        if (cth2) {
            const uint8_t *ctv2 = cth2 + 15;
            while (*ctv2 == ' ') ctv2++;
            size_t ct_rem2 = (size_t)(sbuf_ct + hdr_scan_len - ctv2);
            h->ct_compressible = is_compressible_type(ctv2, ct_rem2) ? 1 : 0;
        } else {
            h->ct_compressible = 0;
        }
    }

    if ((h->flags & (CONN_FLAG_CLIENT_BR | CONN_FLAG_CLIENT_GZIP)) && n > 0) {
        uint8_t *sbuf_gz = conn_send_buf(&w->pool, cid);
        const uint8_t *hend_gz = (const uint8_t *)FIND_HDR_END(sbuf_gz, (size_t)n);
        if (hend_gz) {
            size_t hdr_end_off = (size_t)(hend_gz - sbuf_gz);
            size_t body_off    = hdr_end_off + 4;
            size_t body_len    = (size_t)n - body_off;

            bool cl_match = false;
            if (body_len >= COMPRESS_MIN_BODY) {
                const char *clh2 = (const char *)memmem(
                    sbuf_gz, hdr_end_off + 4, "\r\nContent-Length:", 17);
                if (!clh2) clh2 = (const char *)memmem(
                    sbuf_gz, hdr_end_off + 4, "\r\ncontent-length:", 17);
                if (clh2) {
                    const char *cv2 = clh2 + 17;
                    while (*cv2 == ' ') cv2++;
                    cl_match = ((size_t)atol(cv2) == body_len);
                }
            }

            if (cl_match) {
                const uint8_t *cth = (const uint8_t *)memmem(
                    sbuf_gz, hdr_end_off + 4, "\r\nContent-Type:", 15);
                if (!cth) cth = (const uint8_t *)memmem(
                    sbuf_gz, hdr_end_off + 4, "\r\ncontent-type:", 15);
                bool already_encoded =
                    memmem(sbuf_gz, hdr_end_off + 4, "\r\nContent-Encoding:", 19) ||
                    memmem(sbuf_gz, hdr_end_off + 4, "\r\ncontent-encoding:", 19);

                if (cth && !already_encoded) {
                    const uint8_t *ct_val = cth + 15;
                    while (*ct_val == ' ') ct_val++;
                    size_t ct_remaining = (size_t)(sbuf_gz + hdr_end_off + 4 - ct_val);

                    if (is_compressible_type(ct_val, ct_remaining)) {
                        bool use_br = (h->flags & CONN_FLAG_CLIENT_BR) != 0;
                        uint8_t *scratch = conn_recv_buf(&w->pool, cid);
                        if (w->cfg->compress_pool_threads > 0 &&
                            w->compress_done_pipe_wr >= 0) {
                            struct compress_job job = {
                                .cid         = cid,
                                .result_pipe_wr = w->compress_done_pipe_wr,
                                .result_ring = &w->compress_result_ring,
                                .src         = sbuf_gz + body_off,
                                .src_len     = body_len,
                                .headers     = sbuf_gz,
                                .header_len  = hdr_end_off + 4,
                                .scratch     = scratch,
                                .use_brotli  = use_br,
                                .buf_size    = w->pool.buf_size,
                            };
                            h->flags |= CONN_FLAG_COMPRESS_PENDING;
                            h->send_buf_off = 0;
                            h->send_buf_len = (uint32_t)n;
                            if (compress_pool_submit(&w->compress_pool, job))
                                return;
                            h->flags &= ~CONN_FLAG_COMPRESS_PENDING;
                        }

                        bool used_br = false;
                        size_t clen = 0;
                        size_t total_len = compress_http_response_parts(sbuf_gz, hdr_end_off + 4,
                            sbuf_gz + body_off, body_len, scratch, w->pool.buf_size,
                            use_br, &used_br, &clen);
                        if (total_len > 0) {
                            n = (int)total_len;
                            log_debug("compress", "conn=%u %s %zu→%zu bytes",
                                      cid, used_br ? "br" : "gzip", body_len, clen);
                        }
                    }
                }
            }
        }
    }

    n = inject_response_etag(w, conn_send_buf(&w->pool, cid), n);
    submit_client_response_send(w, cid, h, n);
}

/*
 * handle_proxy_data — core io_uring completion dispatcher.
 *
 * Called once per CQE (completion queue entry).  The upper 32 bits of
 * user_data encode the operation type (VORTEX_OP_*); the lower 32 bits
 * encode the connection ID (cid) within the worker's conn_pool.
 *
 * State machine — normal (non-WebSocket) flow:
 *
 *   ACCEPT
 *     │  (TLS mode: offload to tls_pool, resume via TLS_DONE)
 *     │  (plain:    inline route selection + async connect)
 *     ▼
 *   CONNECT  ──────────────────────────────────────────────────────────────┐
 *     │  (backend TCP handshake complete)                                  │
 *     ▼                                                               (retry if
 *   RECV_CLIENT  ◄────────── SEND_CLIENT ◄──── RECV_BACKEND              keep-alive)
 *     │                                              ▲
 *     │  (forward request to backend)               │
 *     ▼                                              │
 *   SEND_BACKEND  ──────────────────────────────────►
 *     │  (backend recv armed after send completes)
 *
 * WebSocket upgrade flow (after HTTP 101):
 *
 *   RECV_CLIENT_WS  ──►  SEND_BACKEND_WS  ──► re-arm RECV_CLIENT_WS
 *   RECV_BACKEND_WS ──►  SEND_CLIENT_WS   ──► re-arm RECV_BACKEND_WS
 *     (both chains run concurrently on the same connection)
 *
 * Error handling: any negative cqe->res that is not an expected close
 * condition calls conn_close(), which tears down both fds, frees the
 * SSL context, removes fixed-file slots, and returns the conn to the pool.
 *
 * TIMEOUT op fires periodically from a recurring kernel timeout SQE and
 * is used to expire idle connections and XDP blocklist entries.
 */
#ifdef VORTEX_PHASE_TLS
static void process_tls_result(struct worker *w,
                               const struct tls_handshake_result *res)
{
    uint32_t hcid = res->cid;
    if (hcid >= w->pool.capacity) return;
    struct conn_hot *th = conn_hot(&w->pool, hcid);
    if (th->state == CONN_STATE_FREE) {
        if (res->kind == TLS_HANDSHAKE_BACKEND) {
            if (res->ssl)
                ptls_free(res->ssl);
            free(res->backend_session);
        }
        return;
    }
    if (res->kind == TLS_HANDSHAKE_BACKEND) {
        th->flags &= ~CONN_FLAG_BACKEND_TLS_PENDING;
        if (!res->ok) {
            send_bad_gateway_and_close(w, hcid);
            return;
        }
        if (res->backend_session &&
            th->route_idx < VORTEX_MAX_ROUTES && th->backend_idx < VORTEX_MAX_BACKENDS) {
            struct tls_session_ticket *old =
                w->backend_tls_sessions[th->route_idx][th->backend_idx];
            w->backend_tls_sessions[th->route_idx][th->backend_idx] = res->backend_session;
            free(old);
        } else if (res->backend_session) {
            free(res->backend_session);
        }
        conn_cold_ptr(&w->pool, hcid)->backend_ssl = res->ssl;
        th->flags |= CONN_FLAG_BACKEND_TLS;
        th->flags &= ~CONN_FLAG_BACKEND_POOLED;
        resume_connected_backend(w, hcid, th);
        return;
    }
    if (!res->ok) {
        free(res->pending_data);
        close(res->client_fd);
        conn_free(&w->pool, hcid);
        return;
    }
    if (res->tls_version == PTLS_PROTOCOL_VERSION_TLS13) w->tls13_count++;
    else w->tls12_count++;
    if (res->ktls_tx && res->ktls_rx) {
        th->flags |= CONN_FLAG_KTLS_TX | CONN_FLAG_KTLS_RX;
        th->ssl = NULL;
        w->ktls_count++;
    } else {
        th->ssl = res->ssl;
    }
#ifdef VORTEX_H2
    if (res->h2_negotiated) {
        th->flags |= CONN_FLAG_HTTP2;
        th->state = CONN_STATE_PROXYING;
        th->route_idx = (uint16_t)(res->tls_route_idx >= 0 ? res->tls_route_idx : 0);
        th->last_active_tsc = rdtsc();
        w->accepted++;
        if (h2_session_init(w, hcid) != 0) {
            free(res->pending_data);
            close(res->client_fd);
            conn_free(&w->pool, hcid);
            return;
        }
        /* Inject pre-decrypted data that arrived bundled with the TLS Finished.
         * H2 clients (Chromium, curl) send the connection preface immediately
         * after the handshake — it often lands in the same recv() as the TLS
         * Finished and would be lost once kTLS takes over the socket. */
        if (res->pending_data && res->pending_data_len > 0) {
            bool ok = h2_inject_predata(w, hcid,
                                        res->pending_data, res->pending_data_len);
            free(res->pending_data);
            if (!ok)
                return;
        }
        struct io_uring_sqe *h2sq = io_uring_get_sqe(&w->uring.ring);
        if (!h2sq) { conn_close(w, hcid, true); return; }
        if (w->uring.recv_ring) {
            int _pfd = w->uring.files_registered ? FIXED_FD_CLIENT(w, hcid) : res->client_fd;
            io_uring_prep_recv_multishot(h2sq, _pfd, NULL, 0, 0);
            h2sq->buf_group = w->uring.recv_ring_bgid;
            h2sq->flags |= IOSQE_BUFFER_SELECT;
            if (w->uring.files_registered) h2sq->flags |= IOSQE_FIXED_FILE;
        } else {
            io_uring_prep_recv(h2sq, res->client_fd,
                conn_recv_buf(&w->pool, hcid), w->pool.buf_size, 0);
        }
        h2sq->user_data = URING_UD_H2_ENCODE(VORTEX_OP_H2_RECV_CLIENT, 0, hcid);
        uring_submit(&w->uring);
        return;
    }
#endif
    free(res->pending_data); /* non-H2: free any pending data (shouldn't occur) */
    {
        int route_idx = res->tls_route_idx;
        if (w->cfg->route_count > 0 && route_idx < w->cfg->route_count) {
            if (w->cfg->routes[route_idx].route_type == ROUTE_TYPE_TCP_TUNNEL)
                th->flags |= CONN_FLAG_TCP_TUNNEL;
            if (route_and_connect(w, hcid, route_idx, false) < 0)
                return;
            if (th->flags & CONN_FLAG_BACKEND_CONNECTING)
                return;
        }
    }
    if (th->backend_fd < 0) {
        send_bad_gateway_and_close(w, hcid);
        return;
    }
}
#endif

static void handle_accept(struct worker *w, struct io_uring_cqe *cqe)
{
    int client_fd = cqe->res;
    log_debug("accept_cqe", "worker=%d res=%d flags=0x%x",
        w->worker_id, cqe->res, cqe->flags);
    if (client_fd < 0) {
        /* Multishot accept terminated — re-arm if the listen fd is still open */
        if (!(cqe->flags & IORING_CQE_F_MORE) && w->listen_fd >= 0) {
            log_warn("accept_cqe", "worker=%d multishot accept terminated (res=%d); re-arming",
                w->worker_id, cqe->res);
            struct io_uring_sqe *rasqe = io_uring_get_sqe(&w->uring.ring);
            if (rasqe) {
                io_uring_prep_multishot_accept(rasqe, w->listen_fd, NULL, NULL, 0);
                rasqe->user_data = URING_UD_ENCODE(VORTEX_OP_ACCEPT, 0);
                uring_submit(&w->uring);
            }
        }
        return;
    }

    int one = 1;
    setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    /* Correct-SNI connections: explicitly remove any window clamp so the OS
     * can grow the receive window progressively to its configured maximum. */
    int zero_clamp = 0;
    setsockopt(client_fd, IPPROTO_TCP, TCP_WINDOW_CLAMP, &zero_clamp, sizeof(zero_clamp));
    /* Don't queue more unsent data than one buffer — prevents slow clients
     * from accumulating a backlog of 16KB chunks in the kernel send buffer. */
    int lowat = WORKER_BUF_SIZE;
    setsockopt(client_fd, IPPROTO_TCP, TCP_NOTSENT_LOWAT, &lowat, sizeof(lowat));

    /* Backpressure: at 90% capacity, actively reject with 503 rather than
     * silently dropping once the pool is exhausted. This lets upstream load
     * balancers retry a different instance instead of waiting for a timeout. */
    if (w->pool.active >= w->pool.capacity * 9 / 10) {
        static const char r503[] =
            "HTTP/1.1 503 Service Unavailable\r\n"
            "Content-Length: 19\r\nConnection: close\r\n\r\n"
            "Service Unavailable";
        send(client_fd, r503, sizeof(r503) - 1, MSG_NOSIGNAL | MSG_DONTWAIT);
        close(client_fd);
        return;
    }

    uint32_t new_cid = conn_alloc(&w->pool);
    if (new_cid != CONN_INVALID) {
        /* Record client address for X-Forwarded-For */
        struct conn_cold *cold = conn_cold_ptr(&w->pool, new_cid);
        socklen_t salen = sizeof(cold->client_addr);
        getpeername(client_fd, (struct sockaddr *)&cold->client_addr, &salen);
    }
    if (new_cid == CONN_INVALID) {
        w->pool_exhausted++;
        log_warn("accept", "pool exhausted - dropping connection (total=%llu)",
                 (unsigned long long)w->pool_exhausted);
        close(client_fd);
        return;
    }

    struct conn_hot *nh = conn_hot(&w->pool, new_cid);
    nh->client_fd = client_fd;
    nh->recv_window = WORKER_BUF_INIT;
    uring_install_fd(&w->uring, (unsigned)FIXED_FD_CLIENT(w, new_cid), client_fd);

    int tls_route_idx = 0;
#ifdef VORTEX_PHASE_TLS
    /* TLS handshake — blocking but bounded by select timeout in tls_accept */
    if (w->tls && w->tls->route_count > 0) {
        /* Peek at SNI before the handshake — tarpit unrecognised clients immediately */
        char peek_sni_buf[256] = {0};
        if (peek_client_hello_sni(client_fd, peek_sni_buf, sizeof(peek_sni_buf))) {
            int matched = 0;
            for (int ri = 0; ri < w->cfg->route_count; ri++) {
                if (strcasecmp(peek_sni_buf, w->cfg->routes[ri].hostname) == 0) {
                    matched = 1;
                    break;
                }
            }
            if (!matched) {
                log_info("tarpit", "fd=%d sni=%s total=%llu",
                    client_fd, peek_sni_buf,
                    (unsigned long long)(w->tarpit_total + 1));
                tarpit_conn(w, client_fd);
                conn_free(&w->pool, new_cid);
                return;
            }
        }

        /* Offload blocking SSL_accept to the TLS handshake pool.
         * The worker returns immediately; when the pool thread finishes it
         * writes a tls_handshake_result to tls_done_pipe_wr which wakes the
         * io_uring VORTEX_OP_TLS_DONE handler below. */
        if (w->tls_done_pipe_wr >= 0) {
            struct tls_handshake_job job = {
                .kind           = TLS_HANDSHAKE_FRONTEND,
                .client_fd      = client_fd,
                .cid            = new_cid,
                .tls            = w->tls,
                .result_pipe_wr = w->tls_done_pipe_wr,
                .result_ring    = &w->tls_result_ring,
            };
            if (!tls_pool_submit(job)) {
                /* Queue full — drop the connection */
                close(client_fd);
                conn_free(&w->pool, new_cid);
            }
            /* Return: VORTEX_OP_TLS_DONE will continue this connection */
            return;
        }
        /* Fallback (no pipe): blocking path — should not normally happen */
        char sni_fb[256] = {0};
        bool ktls_tx_fb = false, ktls_rx_fb = false, h2_fb = false;
        ptls_t *ssl_fb = tls_accept(w->tls, client_fd, &tls_route_idx, sni_fb, sizeof(sni_fb),
                                     &ktls_tx_fb, &ktls_rx_fb, &h2_fb, NULL, NULL);
        if (!ssl_fb && !ktls_tx_fb) { close(client_fd); conn_free(&w->pool, new_cid); return; }
        w->tls13_count++;
        if (ktls_tx_fb && ktls_rx_fb) {
            nh->flags |= CONN_FLAG_KTLS_TX | CONN_FLAG_KTLS_RX;
            tls_ssl_free(ssl_fb); nh->ssl = NULL; w->ktls_count++;
        } else { nh->ssl = ssl_fb; }
        int fl = fcntl(client_fd, F_GETFL);
        fcntl(client_fd, F_SETFL, fl & ~O_NONBLOCK);
    }
#endif

    /* Route selection: TLS SNI route takes priority */
    int route_idx = tls_route_idx;
    if (w->cfg->route_count > 0 && route_idx < w->cfg->route_count) {
        if (route_and_connect(w, new_cid, route_idx, false) < 0)
            return;
        if (nh->flags & CONN_FLAG_BACKEND_CONNECTING)
            return;
        if (nh->flags & CONN_FLAG_BACKEND_POOLED) {
            log_debug("accept_pool", "conn=%u reused backend fd=%d",
                (unsigned)new_cid, nh->backend_fd);
        }
    }

    if (nh->backend_fd < 0) {
        send_bad_gateway_and_close(w, new_cid);
        return;
    }

    log_debug("accept_arm", "conn=%u client_fd=%d backend_fd=%d (pooled)",
        (unsigned)new_cid, client_fd, nh->backend_fd);
}

#ifdef VORTEX_PHASE_TLS
static void handle_tls_done(struct worker *w, struct io_uring_cqe *cqe)
{
    /* Re-arm pipe read for the next 1-byte wakeup signal */
    struct io_uring_sqe *rpsqe = io_uring_get_sqe(&w->uring.ring);
    if (rpsqe) {
        io_uring_prep_read(rpsqe, w->tls_done_pipe_rd,
                           w->tls_pipe_buf, sizeof(w->tls_pipe_buf), 0);
        rpsqe->user_data = URING_UD_ENCODE(VORTEX_OP_TLS_DONE, 0);
    }
    uring_submit(&w->uring);

    if (cqe->res <= 0)
        return; /* pipe closed or error — stay armed */

    /* Drain all completed results from the MPSC ring */
    struct tls_result_ring *ring = &w->tls_result_ring;
    for (;;) {
        uint32_t slot = ring->head % TLS_RESULT_RING_CAP;
        if (atomic_load_explicit(&ring->slots[slot].ready,
                                  memory_order_acquire) == 0)
            break;
        struct tls_handshake_result res = ring->slots[slot].data;
        atomic_store_explicit(&ring->slots[slot].ready, 0, memory_order_release);
        ring->head++;
        process_tls_result(w, &res);
    }
}
#endif

static void process_compress_result(struct worker *w, const struct compress_result *res)
{
    uint32_t cid = res->cid;
    if (cid >= w->pool.capacity) return;
    struct conn_hot *h = conn_hot(&w->pool, cid);
    if (h->state == CONN_STATE_FREE) return;
    if (!(h->flags & CONN_FLAG_COMPRESS_PENDING)) return;

    h->flags &= ~CONN_FLAG_COMPRESS_PENDING;
    submit_client_response_send(w, cid, h,
        res->ok ? (int)res->total_len : (int)h->send_buf_len);
}

static void handle_compress_done(struct worker *w, struct io_uring_cqe *cqe)
{
    struct io_uring_sqe *rpsqe = io_uring_get_sqe(&w->uring.ring);
    if (rpsqe) {
        io_uring_prep_read(rpsqe, w->compress_done_pipe_rd,
                           w->compress_pipe_buf, sizeof(w->compress_pipe_buf), 0);
        rpsqe->user_data = URING_UD_ENCODE(VORTEX_OP_COMPRESS_DONE, 0);
    }
    uring_submit(&w->uring);

    if (cqe->res <= 0)
        return;

    struct compress_result_ring *ring = &w->compress_result_ring;
    for (;;) {
        uint32_t slot = ring->head % COMPRESS_RESULT_RING_CAP;
        if (atomic_load_explicit(&ring->slots[slot].ready,
                                  memory_order_acquire) == 0)
            break;
        struct compress_result res = ring->slots[slot].data;
        atomic_store_explicit(&ring->slots[slot].ready, 0, memory_order_release);
        ring->head++;
        process_compress_result(w, &res);
    }
}

#ifdef VORTEX_H2
static bool handle_h2_backend_ops(struct worker *w, struct io_uring_cqe *cqe, uint32_t op)
{
    /* H2 backend ops encode (slot << 12) | cid in the lower 32 bits —
     * extract the real cid with URING_UD_H2_CID before the pool capacity check. */
    if (op != VORTEX_OP_H2_CONNECT        && op != VORTEX_OP_H2_SEND_BACKEND &&
        op != VORTEX_OP_H2_RECV_BACKEND   &&
        op != VORTEX_OP_H2_GRPC_SEND_BACKEND &&
        op != VORTEX_OP_H2_GRPC_RECV_BACKEND) {
        return false;
    }

    uint32_t h2_cid  = URING_UD_H2_CID(cqe->user_data);
    uint32_t h2_slot = URING_UD_H2_SLOT(cqe->user_data);
    if (h2_cid >= w->pool.capacity) return true;
    struct conn_hot *hh = conn_hot(&w->pool, h2_cid);
    if (hh->state == CONN_STATE_FREE) return true;
    if (op == VORTEX_OP_H2_CONNECT)
        h2_on_backend_connect(w, h2_cid, h2_slot, cqe->res);
    else if (op == VORTEX_OP_H2_SEND_BACKEND)
        h2_on_backend_send(w, h2_cid, h2_slot, cqe->res);
    else if (op == VORTEX_OP_H2_RECV_BACKEND)
        h2_on_backend_recv(w, h2_cid, h2_slot, cqe->res);
    else if (op == VORTEX_OP_H2_GRPC_SEND_BACKEND)
        h2_on_grpc_backend_send(w, h2_cid, h2_slot, cqe->res);
    else
        h2_on_grpc_backend_recv(w, h2_cid, h2_slot, cqe->res);
    return true;
}
#endif

static void handle_error(struct worker *w, struct io_uring_cqe *cqe, uint32_t cid, struct conn_hot *h)
{
    uint32_t op = URING_UD_OP(cqe->user_data);

    (void)h;

    /* EIO on kTLS = TLS close_notify or alert — treat as normal close */
    bool is_error = true;
    if (cqe->res == -ECONNRESET || cqe->res == -EPIPE ||
        cqe->res == -EBADF     || cqe->res == -ECANCELED ||
        cqe->res == -EIO       || cqe->res == -ENOBUFS ||
        cqe->res == -EBADMSG) {
        if (cqe->res == -ENOBUFS)
            log_warn("recv_ring",
                "conn=%u op=%u recv buf ring exhausted — closing connection",
                cid, op);
        else
            log_debug("proxy_err", "conn=%u op=%u err=%s",
                      cid, op, strerror(-cqe->res));
        is_error = false; /* expected close conditions */
    } else {
        log_debug("proxy_err", "conn=%u op=%u err=%s", cid, op, strerror(-cqe->res));
    }
    conn_close(w, cid, is_error);
}

static void handle_recv_client(struct worker *w, struct io_uring_cqe *cqe, uint32_t cid, struct conn_hot *h)
{
    int n = cqe->res;
    log_debug("recv_client", "conn=%u n=%d", cid, n);
    if (n == 0) { conn_close(w, cid, false); return; } /* Client EOF */
    RECV_WINDOW_GROW(h, n, w->pool.buf_size);
    h->bytes_in += (uint32_t)n;

    /* Enforce header block size limit before any further processing.
     * If we haven't seen \r\n\r\n yet and the buffer is already at or above
     * max_request_header_bytes, the client is sending an oversized header
     * block — reject immediately.  After \r\n\r\n the limit no longer applies
     * (body limits are handled separately). */
    {
        uint32_t hdr_limit = w->cfg->max_request_header_bytes;
        if (hdr_limit > 0 && (size_t)n >= (size_t)hdr_limit) {
            const uint8_t *rbuf = conn_recv_buf(&w->pool, cid);
            if (memmem(rbuf, (size_t)n, "\r\n\r\n", 4) == NULL) {
                log_warn("bad_request", "conn=%u header block exceeds %u bytes", cid, hdr_limit);
                send_bad_request_and_close(w, cid);
                return;
            }
        }
    }

    /* Reconnect to backend if previous response consumed the connection */
    if (h->backend_fd < 0) {
        int ri = h->route_idx;
        /* Async reconnect: data already in recv_buf — save it so CONNECT can forward it. */
        h->send_buf_len = (uint32_t)n;
        if (route_and_connect(w, cid, ri, true) < 0)
            return;
        if (h->flags & CONN_FLAG_BACKEND_CONNECTING)
            return;
    }

    /* Per-route rate limit (token bucket).
     * Only enforced when the connection pool is ≥75% full — i.e. when a
     * noisy route could actually starve other origins.  Below that
     * threshold every route runs uncapped regardless of config. */
    {
        const struct route_config *rc = &w->cfg->routes[h->route_idx];
        if (rc->rate_limit.enabled && rc->rate_limit.rps > 0 &&
            (uint64_t)w->pool.active * 4 >= (uint64_t)w->pool.capacity * 3) {
            int ri = h->route_idx;
            uint32_t max_tokens = rc->rate_limit.burst ? rc->rate_limit.burst
                                                       : rc->rate_limit.rps;
            struct timespec _rl_ts;
            clock_gettime(CLOCK_MONOTONIC_COARSE, &_rl_ts);
            uint64_t now_ns = (uint64_t)_rl_ts.tv_sec * 1000000000ULL + _rl_ts.tv_nsec;

            if (w->route_rl[ri].last_ns == 0) {
                /* First request — fill to burst */
                w->route_rl[ri].tokens  = max_tokens;
                w->route_rl[ri].last_ns = now_ns;
            } else {
                uint64_t elapsed_ns   = now_ns - w->route_rl[ri].last_ns;
                uint64_t ns_per_token = 1000000000ULL / rc->rate_limit.rps;
                uint32_t new_tokens   = (uint32_t)(elapsed_ns / ns_per_token);
                if (new_tokens > max_tokens) new_tokens = max_tokens; /* cap before add */
                if (new_tokens > 0) {
                    w->route_rl[ri].tokens += new_tokens;
                    if (w->route_rl[ri].tokens > max_tokens)
                        w->route_rl[ri].tokens = max_tokens;
                    /* Advance by whole intervals to preserve fractional remainder */
                    w->route_rl[ri].last_ns += (uint64_t)new_tokens * ns_per_token;
                }
            }

            if (w->route_rl[ri].tokens == 0) {
                static const char r429[] =
                    "HTTP/1.1 429 Too Many Requests\r\n"
                    "Content-Length: 0\r\n"
                    "Retry-After: 1\r\n"
                    "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n"
                    "Connection: keep-alive\r\n\r\n";
                struct io_uring_sqe *sqe429  = io_uring_get_sqe(&w->uring.ring);
                struct io_uring_sqe *sqe429r = io_uring_get_sqe(&w->uring.ring);
                if (!sqe429 || !sqe429r) { conn_close(w, cid, false); return; }
                uint8_t *sbuf = conn_send_buf(&w->pool, cid);
                size_t r429_len = sizeof(r429) - 1;
                memcpy(sbuf, r429, r429_len);
                h->send_buf_off = 0;
                h->send_buf_len = (uint32_t)r429_len;
                h->flags &= ~CONN_FLAG_STREAMING_BACKEND;
                PREP_SEND(w, sqe429, h->client_fd, FIXED_FD_CLIENT(w, cid),
                    sbuf, r429_len, MSG_NOSIGNAL, SEND_IDX_SEND(w, cid));
                sqe429->user_data  = URING_UD_ENCODE(VORTEX_OP_SEND_CLIENT_LINKED, cid);
                sqe429->flags     |= IOSQE_IO_LINK;
                PREP_RECV(w, sqe429r, h->client_fd, FIXED_FD_CLIENT(w, cid),
                    conn_recv_buf(&w->pool, cid), h->recv_window, 0, cid);
                sqe429r->user_data = URING_UD_ENCODE(VORTEX_OP_RECV_CLIENT, cid);
                uring_submit(&w->uring);
                return;
            }
            w->route_rl[ri].tokens--;
        }
    }

    /* Basic Auth check */
    {
        const struct route_config *rc = &w->cfg->routes[h->route_idx];
        const uint8_t *rbuf = conn_recv_buf(&w->pool, cid);
        if (parse_http_request_line(rbuf, n, (char [16]){0}, 16, (char [512]){0}, 512) != 0) {
            send_bad_request_and_close(w, cid);
            return;
        }
        if (request_has_ambiguous_framing(rbuf, (size_t)n)) {
            log_warn("bad_request", "conn=%u ambiguous Content-Length/Transfer-Encoding", cid);
            send_bad_request_and_close(w, cid);
            return;
        }
        if (!auth_check_request(&rc->auth, conn_recv_buf(&w->pool, cid), n)) {
            /* Send 401 and re-arm for next request */
            static const char r401[] =
                "HTTP/1.1 401 Unauthorized\r\n"
                "WWW-Authenticate: Basic realm=\"vortex\"\r\n"
                "Content-Length: 0\r\n"
                "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n"
                "Connection: keep-alive\r\n\r\n";
            struct io_uring_sqe *sqe401 = io_uring_get_sqe(&w->uring.ring);
            struct io_uring_sqe *sqe401r = io_uring_get_sqe(&w->uring.ring);
            if (!sqe401 || !sqe401r) { conn_close(w, cid, false); return; }
            /* Copy 401 to send buf */
            uint8_t *sbuf = conn_send_buf(&w->pool, cid);
            size_t r401_len = sizeof(r401) - 1;
            memcpy(sbuf, r401, r401_len);
            h->send_buf_off = 0;
            h->send_buf_len = (uint32_t)r401_len;
            h->flags &= ~CONN_FLAG_STREAMING_BACKEND;
            PREP_SEND(w, sqe401, h->client_fd, FIXED_FD_CLIENT(w, cid),
                sbuf, r401_len, MSG_NOSIGNAL, SEND_IDX_SEND(w, cid));
            sqe401->user_data = URING_UD_ENCODE(VORTEX_OP_SEND_CLIENT_LINKED, cid);
            sqe401->flags |= IOSQE_IO_LINK;
            /* Pre-arm RECV_CLIENT as linked SQE — kernel starts it immediately after send */
            PREP_RECV(w, sqe401r, h->client_fd, FIXED_FD_CLIENT(w, cid),
                conn_recv_buf(&w->pool, cid), h->recv_window, 0, cid);
            sqe401r->user_data = URING_UD_ENCODE(VORTEX_OP_RECV_CLIENT, cid);
            uring_submit(&w->uring);
            return;
        }
    }

    /* Detect WebSocket upgrade request */
    {
        const uint8_t *rbuf = conn_recv_buf(&w->pool, cid);
        if (memmem(rbuf, (size_t)n, "Upgrade: websocket", 18) != NULL ||
            memmem(rbuf, (size_t)n, "upgrade: websocket", 18) != NULL) {
            h->flags |= CONN_FLAG_WEBSOCKET_ACTIVE;
            if (w->cfg->routes[h->route_idx].backends[h->backend_idx].tls) {
                send_bad_gateway_and_close(w, cid);
                return;
            }
        }
    }

    /* Detect client compression acceptance — cleared each request for keepalive correctness.
     * Prefer brotli (br) over gzip when both are advertised. */
    h->flags &= ~(CONN_FLAG_CLIENT_GZIP | CONN_FLAG_CLIENT_BR);
    {
        const uint8_t *rbuf = conn_recv_buf(&w->pool, cid);
        const uint8_t *ae = (const uint8_t *)memmem(rbuf, (size_t)n, "Accept-Encoding:", 16);
        if (!ae) ae = (const uint8_t *)memmem(rbuf, (size_t)n, "accept-encoding:", 16);
        if (ae) {
            const uint8_t *eol = (const uint8_t *)FIND_CRLF(ae + 16,
                (size_t)n - (size_t)(ae + 16 - rbuf));
            if (eol) {
                size_t ae_val_len = (size_t)(eol - ae - 16);
                if (memmem(ae + 16, ae_val_len, "br", 2))
                    h->flags |= CONN_FLAG_CLIENT_BR;
                if (memmem(ae + 16, ae_val_len, "gzip", 4))
                    h->flags |= CONN_FLAG_CLIENT_GZIP;
            }
        }
    }

    /* Cache check: only for GET requests */
    if (w->cache && w->cache->index) {
        char method[16], url[512];
        const uint8_t *rbuf = conn_recv_buf(&w->pool, cid);
        if (parse_http_request_line(rbuf, n,
                                    method, sizeof(method),
                                    url, sizeof(url)) == 0
            && strcmp(method, "GET") == 0) {

            char cache_key[640];
            make_cache_key(rbuf, (size_t)n, url, cache_key, sizeof(cache_key));
            struct cached_response cached;
            if (cache_fetch_ptr(w->cache, cache_key, strlen(cache_key), &cached) == 0) {
                /* Check If-None-Match for conditional GET */
                char req_etag[64] = {0};
                const uint8_t *inm = (const uint8_t *)memmem(rbuf, (size_t)n,
                                                               "\r\nIf-None-Match:", 16);
                if (!inm)
                    inm = (const uint8_t *)memmem(rbuf, (size_t)n,
                                                   "\r\nif-none-match:", 16);
                if (inm) {
                    const uint8_t *vs = inm + 16;
                    while (vs < rbuf + n && (*vs == ' ' || *vs == '\t')) vs++;
                    if (*vs == '"') vs++;
                    const uint8_t *ve = vs;
                    while (ve < rbuf + n && *ve != '"' && *ve != '\r') ve++;
                    size_t el = (size_t)(ve - vs);
                    if (el < sizeof(req_etag)) memcpy(req_etag, vs, el);
                }

                char etag_str[20];
                snprintf(etag_str, sizeof(etag_str), "%016llx",
                         (unsigned long long)cached.body_etag);

                if (req_etag[0] && strcmp(req_etag, etag_str) == 0) {
                    /* ETag matches → 304 Not Modified */
                    char r304[128];
                    int r304_len = snprintf(r304, sizeof(r304),
                        "HTTP/1.1 304 Not Modified\r\n"
                        "ETag: \"%s\"\r\n"
                        "Connection: keep-alive\r\n\r\n", etag_str);
                    uint8_t *sbuf = conn_send_buf(&w->pool, cid);
                    memcpy(sbuf, r304, (size_t)r304_len);
                    struct io_uring_sqe *sqe  = io_uring_get_sqe(&w->uring.ring);
                    struct io_uring_sqe *sqer = io_uring_get_sqe(&w->uring.ring);
                    if (sqe && sqer) {
                        h->send_buf_off = 0;
                        h->send_buf_len = (uint32_t)r304_len;
                        h->flags &= ~CONN_FLAG_STREAMING_BACKEND;
                        PREP_SEND(w, sqe, h->client_fd, FIXED_FD_CLIENT(w, cid),
                            sbuf, (size_t)r304_len, MSG_NOSIGNAL, SEND_IDX_SEND(w, cid));
                        sqe->user_data = URING_UD_ENCODE(VORTEX_OP_SEND_CLIENT_LINKED, cid);
                        sqe->flags |= IOSQE_IO_LINK;
                        /* Pre-arm RECV_CLIENT — kernel queues it right after send */
                        PREP_RECV(w, sqer, h->client_fd, FIXED_FD_CLIENT(w, cid),
                            conn_recv_buf(&w->pool, cid), h->recv_window, 0, cid);
                        sqer->user_data = URING_UD_ENCODE(VORTEX_OP_RECV_CLIENT, cid);
                        uring_submit(&w->uring);
                        /* cached.data is a slab pointer — no free needed */
                        log_debug("cache_304", "conn=%u url=%s", cid, url);
                        return;
                    }
                }

                /* Full cache HIT — serve stored response + inject ETag / X-Cache */
                /* Extra headers to splice before the final \r\n\r\n */
                char extra[128];
                int extra_len = snprintf(extra, sizeof(extra),
                    "ETag: \"%s\"\r\nX-Cache: HIT\r\n", etag_str);

                uint32_t stored_total = cached.header_len + cached.body_len;
                size_t serve_len = stored_total + (size_t)extra_len;
                uint8_t *sbuf = conn_send_buf(&w->pool, cid);

                if (serve_len <= w->pool.buf_size && cached.header_len >= 4) {
                    /* Copy directly from slab into the send buffer.
                     * Headers minus the blank-line terminator, then injected
                     * ETag/X-Cache headers, then the blank line, then the body. */
                    size_t hdr_body = cached.header_len - 2;
                    memcpy(sbuf, cached.data, hdr_body);
                    memcpy(sbuf + hdr_body, extra, (size_t)extra_len);
                    memcpy(sbuf + hdr_body + extra_len, "\r\n", 2);
                    memcpy(sbuf + cached.header_len + extra_len,
                           cached.data + cached.header_len, cached.body_len);

                    struct io_uring_sqe *sqe = io_uring_get_sqe(&w->uring.ring);
                    if (sqe) {
                        h->send_buf_off = 0;
                        h->send_buf_len = (uint32_t)serve_len;
                        h->flags &= ~CONN_FLAG_STREAMING_BACKEND;
                        PREP_SEND(w, sqe, h->client_fd, FIXED_FD_CLIENT(w, cid),
                            sbuf, serve_len, MSG_NOSIGNAL, SEND_IDX_SEND(w, cid));
                        sqe->user_data = URING_UD_ENCODE(VORTEX_OP_SEND_CLIENT, cid);
                        uring_submit(&w->uring);
                        /* cached.data is a slab pointer — no free needed */
                        log_debug("cache_hit", "conn=%u url=%s", cid, url);
                        return;
                    }
                }
                /* Fall through to backend if response too large or no sqe */
            }
        }
    }

    /* Rewrite backend request headers. All injections go right after the
     * request line so they appear before any client-supplied headers.
     * We build the inject block in one shot to minimise memmoves. */
    const struct route_config *rc_fwd = &w->cfg->routes[h->route_idx];
    int fwd_n = n;
    {
        uint8_t *rbuf = conn_recv_buf(&w->pool, cid);
        bool is_ws = (h->flags & CONN_FLAG_WEBSOCKET_ACTIVE) != 0;

        /* ---- Rewrite Accept-Encoding for backend leg ----
         * The client→proxy leg is WAN; the proxy→backend leg is LAN where
         * bandwidth is cheap and body inspection/caching requires plain text.
         * Rewrite to "identity" so the backend sends uncompressed responses. */
        bool ae_present = false;
        {
            uint8_t *ae = (uint8_t *)memmem(rbuf, (size_t)fwd_n, "\r\nAccept-Encoding:", 18);
            if (!ae)
                ae = (uint8_t *)memmem(rbuf, (size_t)fwd_n, "\r\naccept-encoding:", 18);
            if (ae) {
                ae_present = true;
                /* Replace the header value in-place with "identity" */
                uint8_t *vs = ae + 18;
                while (vs < rbuf + fwd_n && (*vs == ' ' || *vs == '\t')) vs++;
                uint8_t *ve = (uint8_t *)FIND_CRLF(vs, (size_t)(rbuf + fwd_n - vs));
                if (ve && ve > vs) {
                    const char *id = "identity";
                    size_t id_len  = 8;
                    int delta = (int)id_len - (int)(ve - vs);
                    if (fwd_n + delta <= (int)w->pool.buf_size && fwd_n + delta > 0) {
                        memmove(vs + id_len, ve, (size_t)(rbuf + fwd_n - ve));
                        memcpy(vs, id, id_len);
                        fwd_n += delta;
                    }
                }
            }
            /* When absent: injected in the inject block below */
        }

        /* ---- Strip Authorization header ----
         * The proxy consumed it for its own auth check; never forward
         * our proxy credentials to the backend. */
        {
            uint8_t *ah = (uint8_t *)memmem(rbuf, (size_t)fwd_n, "\r\nAuthorization:", 16);
            if (!ah)
                ah = (uint8_t *)memmem(rbuf, (size_t)fwd_n, "\r\nauthorization:", 16);
            if (ah) {
                uint8_t *line_end = (uint8_t *)FIND_CRLF(ah + 2,
                    (size_t)(rbuf + fwd_n - ah - 2));
                if (line_end) {
                    line_end += 2; /* include the \r\n */
                    size_t remove = (size_t)(line_end - ah - 2); /* bytes between \r\n's */
                    /* We want to remove "\r\nAuthorization: ...\r\n" → replace with "\r\n" */
                    /* i.e., shift everything after the line's \r\n back by (remove) bytes */
                    memmove(ah + 2, ah + 2 + remove,
                        (size_t)(rbuf + fwd_n - (ah + 2 + remove)));
                    fwd_n -= (int)remove;
                }
            }
        }

        /* ---- Connection header ----
         * For WebSocket: pass through as-is (must stay "Upgrade").
         * For pooled backends (pool_size > 0): use keep-alive so we can
         * reuse the connection.  For all others: force "close" so the
         * backend signals response completion with EOF. */
        fwd_n = rewrite_backend_connection_header(w, cid, h, rbuf, fwd_n, is_ws);

        /* ---- Inject proxy headers after request line ----
         * X-Forwarded-Proto, X-Forwarded-For, X-Real-IP, X-Api-Key */
        const char *eol = (const char *)FIND_CRLF(rbuf, (size_t)fwd_n);
        if (eol) {
            size_t line_end = (size_t)(eol - (const char *)rbuf) + 2;

            /* Build inject block */
            char inj[HEADER_INJ_BUF_SIZE];
            int inj_len = 0;

            /* NOTE: intentionally do NOT inject X-Forwarded-Proto: https.
             * ASP.NET Core / Kestrel disables ResponseCompression when it
             * sees X-Forwarded-Proto: https (BREACH/CRIME mitigation).
             * We terminate TLS at the proxy; the backend speaks plain HTTP.
             * Sonarr's SPA uses relative URLs so the scheme doesn't matter
             * for link generation. */

            /* X-Real-IP / X-Forwarded-For from stored client address */
            {
                char ipstr[64] = {0};
                struct conn_cold *cold = conn_cold_ptr(&w->pool, cid);
                const struct sockaddr *sa = (const struct sockaddr *)&cold->client_addr;
                if (sa->sa_family == AF_INET)
                    inet_ntop(AF_INET,
                        &((const struct sockaddr_in *)sa)->sin_addr,
                        ipstr, sizeof(ipstr));
                else if (sa->sa_family == AF_INET6)
                    inet_ntop(AF_INET6,
                        &((const struct sockaddr_in6 *)sa)->sin6_addr,
                        ipstr, sizeof(ipstr));
                if (ipstr[0]) {
                    inj_len += snprintf(inj + inj_len, sizeof(inj) - (size_t)inj_len,
                        "X-Real-IP: %s\r\nX-Forwarded-For: %s\r\n", ipstr, ipstr);
                }
            }

            /* Accept-Encoding: identity — only when not already rewritten above */
            if (!ae_present)
                inj_len += snprintf(inj + inj_len, sizeof(inj) - (size_t)inj_len,
                    "Accept-Encoding: identity\r\n");

            /* X-Api-Key if configured */
            if (rc_fwd->x_api_key[0])
                inj_len += snprintf(inj + inj_len, sizeof(inj) - (size_t)inj_len,
                    "X-Api-Key: %s\r\n", rc_fwd->x_api_key);

            /* Backend Basic Auth credentials if configured — inject after
             * the proxy-level Authorization header has been stripped. */
            if (rc_fwd->backend_credentials[0]) {
                char b64[512];
                b64_encode(rc_fwd->backend_credentials,
                           strlen(rc_fwd->backend_credentials), b64, sizeof(b64));
                inj_len += snprintf(inj + inj_len, sizeof(inj) - (size_t)inj_len,
                    "Authorization: Basic %s\r\n", b64);
            }

            if (inj_len > 0 && fwd_n + inj_len <= (int)w->pool.buf_size) {
                memmove(rbuf + line_end + inj_len,
                        rbuf + line_end, (size_t)fwd_n - line_end);
                memcpy(rbuf + line_end, inj, (size_t)inj_len);
                fwd_n += inj_len;
            }
        }
    }

    /* Forward client data to backend */
    if (backend_uses_tls(w, cid)) {
        if (h->flags & CONN_FLAG_WEBSOCKET_ACTIVE) {
            send_bad_gateway_and_close(w, cid);
            return;
        }
        if (backend_tls_send_all(w, cid, conn_recv_buf(&w->pool, cid), (size_t)fwd_n) < 0) {
            send_bad_gateway_and_close(w, cid);
            return;
        }
        backend_deadline_set(w, cid, w->cfg->routes[h->route_idx].backend_timeout_ms);
        {
            int rn = backend_tls_recv_some(w, cid, conn_send_buf(&w->pool, cid), h->recv_window);
            if (rn < 0) {
                send_bad_gateway_and_close(w, cid);
                return;
            }
            handle_backend_read_result(w, cid, rn);
        }
        return;
    }
    h->send_buf_off = 0;
    h->send_buf_len = (uint32_t)fwd_n;
    struct io_uring_sqe *sqe = io_uring_get_sqe(&w->uring.ring);
    if (!sqe) { conn_close(w, cid, true); return; }
    PREP_SEND(w, sqe, h->backend_fd, FIXED_FD_BACKEND(w, cid),
        conn_recv_buf(&w->pool, cid), fwd_n, MSG_NOSIGNAL, SEND_IDX_RECV(w, cid));
    sqe->user_data = URING_UD_ENCODE(VORTEX_OP_SEND_BACKEND, cid);
    uring_submit(&w->uring);
}

static void handle_send_backend(struct worker *w, struct io_uring_cqe *cqe, uint32_t cid, struct conn_hot *h)
{
    int n = cqe->res;
    log_debug("send_backend", "conn=%u n=%d", cid, n);
    if (n < 0) { conn_close(w, cid, true); return; }
    h->send_buf_off += (uint32_t)n;
    if (h->send_buf_off < h->send_buf_len) {
        struct io_uring_sqe *sqe = io_uring_get_sqe(&w->uring.ring);
        if (!sqe) { conn_close(w, cid, true); return; }
        PREP_SEND(w, sqe, h->backend_fd, FIXED_FD_BACKEND(w, cid),
            conn_recv_buf(&w->pool, cid) + h->send_buf_off,
            h->send_buf_len - h->send_buf_off, MSG_NOSIGNAL, SEND_IDX_RECV(w, cid));
        sqe->user_data = URING_UD_ENCODE(VORTEX_OP_SEND_BACKEND, cid);
        uring_submit(&w->uring);
        return;
    }
    h->send_buf_off = 0;
    h->send_buf_len = 0;
    /* All client data forwarded — arm deadline then wait for backend response */
    backend_deadline_set(w, cid, w->cfg->routes[h->route_idx].backend_timeout_ms);
    if (backend_uses_tls(w, cid)) {
        int rn = backend_tls_recv_some(w, cid, conn_send_buf(&w->pool, cid), h->recv_window);
        if (rn < 0) {
            send_bad_gateway_and_close(w, cid);
            return;
        }
        handle_backend_read_result(w, cid, rn);
        return;
    }
    struct io_uring_sqe *sqe = io_uring_get_sqe(&w->uring.ring);
    if (!sqe) { conn_close(w, cid, true); return; }
    PREP_RECV(w, sqe, h->backend_fd, FIXED_FD_BACKEND(w, cid),
        conn_send_buf(&w->pool, cid), h->recv_window, 0, SEND_IDX_SEND(w, cid));
    sqe->user_data = URING_UD_ENCODE(VORTEX_OP_RECV_BACKEND, cid);
    uring_submit(&w->uring);
}

static void handle_recv_backend(struct worker *w, struct io_uring_cqe *cqe, uint32_t cid, struct conn_hot *h)
{
    (void)h;
    handle_backend_read_result(w, cid, cqe->res);
}

static void handle_send_client(struct worker *w, struct io_uring_cqe *cqe, uint32_t cid, struct conn_hot *h)
{
    int sent = cqe->res;
    log_debug("send_client", "conn=%u sent=%d", cid, sent);
    if (sent < 0) { conn_close(w, cid, true); return; }
    h->send_buf_off += (uint32_t)sent;

    if (h->send_buf_off < h->send_buf_len) {
        /* Partial send (kTLS record boundary) — flush remaining bytes */
        struct io_uring_sqe *sqe = io_uring_get_sqe(&w->uring.ring);
        if (!sqe) { conn_close(w, cid, true); return; }
        PREP_SEND(w, sqe, h->client_fd, FIXED_FD_CLIENT(w, cid),
            conn_send_buf(&w->pool, cid) + h->send_buf_off,
            h->send_buf_len - h->send_buf_off, MSG_NOSIGNAL, SEND_IDX_SEND(w, cid));
        sqe->user_data = URING_UD_ENCODE(VORTEX_OP_SEND_CLIENT, cid);
        uring_submit(&w->uring);
        return;
    }

    /* Full chunk sent */
    h->send_buf_off = 0;
    h->send_buf_len = 0;

    try_backend_pool_return(w, cid, h);

    if (h->flags & CONN_FLAG_STREAMING_BACKEND) {
        if (backend_uses_tls(w, cid)) {
            int rn = backend_tls_recv_some(w, cid, conn_send_buf(&w->pool, cid), h->recv_window);
            if (rn < 0) {
                send_bad_gateway_and_close(w, cid);
                return;
            }
            handle_backend_read_result(w, cid, rn);
            return;
        }
        /* Zero-copy splice: only safe for non-compressible types (images, video,
         * already-compressed media), and only without kTLS TX.  Splicing into a
         * kTLS-TX socket causes ERR_CONTENT_LENGTH_MISMATCH on kernel 6.8–6.12
         * (kTLS mis-accounts spliced bytes against the Content-Length already sent).
         * Compressible types also skip splice — compression of the first chunk
         * changes the payload length, but splice delivers subsequent chunks raw. */
        if (!(h->flags & CONN_FLAG_BACKEND_POOLED) &&
            !(h->flags & CONN_FLAG_WEBSOCKET_ACTIVE) &&
            !h->ct_compressible &&
            !(h->flags & CONN_FLAG_KTLS_TX)) {
            begin_splice(w, cid, h);
            return;
        }
        /* Still reading backend response — get next chunk */
        struct io_uring_sqe *sqe = io_uring_get_sqe(&w->uring.ring);
        if (!sqe) { conn_close(w, cid, true); return; }
        PREP_RECV(w, sqe, h->backend_fd, FIXED_FD_BACKEND(w, cid),
            conn_send_buf(&w->pool, cid), h->recv_window, 0, SEND_IDX_SEND(w, cid));
        sqe->user_data = URING_UD_ENCODE(VORTEX_OP_RECV_BACKEND, cid);
        uring_submit(&w->uring);
    } else {
        /* Response complete (cache hit, single chunk, or pool return) — next request */
        struct io_uring_sqe *sqe = io_uring_get_sqe(&w->uring.ring);
        if (!sqe) { conn_close(w, cid, true); return; }
        PREP_RECV(w, sqe, h->client_fd, FIXED_FD_CLIENT(w, cid),
            conn_recv_buf(&w->pool, cid), h->recv_window, 0, cid);
        sqe->user_data = URING_UD_ENCODE(VORTEX_OP_RECV_CLIENT, cid);
        uring_submit(&w->uring);
    }
}

static void handle_send_client_linked(struct worker *w, struct io_uring_cqe *cqe, uint32_t cid, struct conn_hot *h)
{
    /* SEND completed; RECV_CLIENT was pre-armed as a linked SQE.
     * On success the kernel has already queued the recv — nothing more to do.
     * On partial send the client won't pipeline the next request until it
     * receives the full response, so the pre-armed recv is still safe; just
     * flush the remaining bytes via a regular (non-linked) SEND_CLIENT. */
    int sent = cqe->res;
    log_debug("send_client_linked", "conn=%u sent=%d", cid, sent);
    if (sent < 0) {
        /* Send error — linked recv will arrive with -ECANCELED; conn_close
         * is idempotent so the RECV_CLIENT handler can call it again safely. */
        conn_close(w, cid, true);
        return;
    }
    h->send_buf_off += (uint32_t)sent;
    if (h->send_buf_off < h->send_buf_len) {
        /* Partial send — flush remainder; pre-armed recv is still in flight */
        struct io_uring_sqe *sqe = io_uring_get_sqe(&w->uring.ring);
        if (!sqe) { conn_close(w, cid, true); return; }
        PREP_SEND(w, sqe, h->client_fd, FIXED_FD_CLIENT(w, cid),
            conn_send_buf(&w->pool, cid) + h->send_buf_off,
            h->send_buf_len - h->send_buf_off, MSG_NOSIGNAL, SEND_IDX_SEND(w, cid));
        sqe->user_data = URING_UD_ENCODE(VORTEX_OP_SEND_CLIENT, cid);
        uring_submit(&w->uring);
    }
    /* Full send: recv already queued by kernel — nothing else to submit */
    h->send_buf_off = 0;
    h->send_buf_len = 0;
}

static void handle_splice_backend(struct worker *w, struct io_uring_cqe *cqe, uint32_t cid, struct conn_hot *h)
{
    /* Kernel spliced n bytes from backend_fd into splice_pipe[1] */
    int n = cqe->res;
    log_debug("splice_backend", "conn=%u n=%d", cid, n);
    if (n < 0) { conn_close(w, cid, true); return; }
    if (n == 0) {
        /* Backend EOF — done streaming */
        h->flags &= ~(CONN_FLAG_STREAMING_BACKEND | CONN_FLAG_SPLICE_MODE);
        if (h->backend_fd >= 0) {
            uring_remove_fd(&w->uring, (unsigned)FIXED_FD_BACKEND(w, cid));
            close(h->backend_fd); h->backend_fd = -1;
        }
        h->flags &= ~CONN_FLAG_BACKEND_POOLED;
        struct io_uring_sqe *sqe = io_uring_get_sqe(&w->uring.ring);
        if (!sqe) { conn_close(w, cid, false); return; }
        PREP_RECV(w, sqe, h->client_fd, FIXED_FD_CLIENT(w, cid),
            conn_recv_buf(&w->pool, cid), h->recv_window, 0, cid);
        sqe->user_data = URING_UD_ENCODE(VORTEX_OP_RECV_CLIENT, cid);
        uring_submit(&w->uring);
        return;
    }
    /* Bytes are in the pipe — splice pipe[0] → client_fd */
    h->bytes_out += (uint32_t)n;
    struct conn_cold *cold = conn_cold_ptr(&w->pool, cid);
    struct io_uring_sqe *sqe = io_uring_get_sqe(&w->uring.ring);
    if (!sqe) { conn_close(w, cid, true); return; }
    io_uring_prep_splice(sqe, cold->splice_pipe[0], -1,
                         h->client_fd, -1,
                         (unsigned int)n, SPLICE_F_MOVE);
    sqe->user_data = URING_UD_ENCODE(VORTEX_OP_SPLICE_CLIENT, cid);
    uring_submit(&w->uring);
}

static void handle_splice_client(struct worker *w, struct io_uring_cqe *cqe, uint32_t cid, struct conn_hot *h)
{
    /* Kernel spliced bytes from pipe → client_fd */
    int sent = cqe->res;
    log_debug("splice_client", "conn=%u sent=%d", cid, sent);
    if (sent < 0) { conn_close(w, cid, true); return; }
    /* Loop: splice next chunk from backend into pipe */
    if (h->flags & CONN_FLAG_STREAMING_BACKEND) {
        struct conn_cold *cold = conn_cold_ptr(&w->pool, cid);
        struct io_uring_sqe *sqe = io_uring_get_sqe(&w->uring.ring);
        if (!sqe) { conn_close(w, cid, true); return; }
        io_uring_prep_splice(sqe, h->backend_fd, -1,
                             cold->splice_pipe[1], -1,
                             (unsigned int)(1u << 20), SPLICE_F_MOVE);
        sqe->user_data = URING_UD_ENCODE(VORTEX_OP_SPLICE_BACKEND, cid);
        uring_submit(&w->uring);
    } else {
        /* Streaming flag cleared elsewhere (shouldn't normally reach here) */
        struct io_uring_sqe *sqe = io_uring_get_sqe(&w->uring.ring);
        if (!sqe) { conn_close(w, cid, false); return; }
        PREP_RECV(w, sqe, h->client_fd, FIXED_FD_CLIENT(w, cid),
            conn_recv_buf(&w->pool, cid), h->recv_window, 0, cid);
        sqe->user_data = URING_UD_ENCODE(VORTEX_OP_RECV_CLIENT, cid);
        uring_submit(&w->uring);
    }
}

static void resume_connected_backend(struct worker *w, uint32_t cid, struct conn_hot *h)
{
    h->state = CONN_STATE_PROXYING;

    if (h->send_buf_len > 0) {
        /* Reconnect case: request already buffered in recv_buf.
         * Strip the Authorization header (security) then forward. */
        uint32_t saved_n = h->send_buf_len;
        h->send_buf_len = 0;
        uint8_t *rbuf = conn_recv_buf(&w->pool, cid);
        int fwd_n = (int)saved_n;

        /* Strip Authorization so proxy credentials don't reach backend */
        uint8_t *ah = (uint8_t *)memmem(rbuf, (size_t)fwd_n, "\r\nAuthorization:", 16);
        if (!ah)
            ah = (uint8_t *)memmem(rbuf, (size_t)fwd_n, "\r\nauthorization:", 16);
        if (ah) {
            uint8_t *le = (uint8_t *)FIND_CRLF(ah + 2,
                (size_t)(rbuf + fwd_n - ah - 2));
            if (le) {
                le += 2;
                size_t rm = (size_t)(le - ah - 2);
                memmove(ah + 2, ah + 2 + rm,
                    (size_t)(rbuf + fwd_n - (ah + 2 + rm)));
                fwd_n -= (int)rm;
            }
        }

        fwd_n = rewrite_backend_connection_header(w, cid, h, rbuf, fwd_n, false);
        if (backend_uses_tls(w, cid)) {
            if (backend_tls_send_all(w, cid, rbuf, (size_t)fwd_n) < 0) {
                send_bad_gateway_and_close(w, cid);
                return;
            }
            backend_deadline_set(w, cid, w->cfg->routes[h->route_idx].backend_timeout_ms);
            {
                int rn = backend_tls_recv_some(w, cid, conn_send_buf(&w->pool, cid), h->recv_window);
                if (rn < 0) {
                    send_bad_gateway_and_close(w, cid);
                    return;
                }
                handle_backend_read_result(w, cid, rn);
            }
            return;
        }

        h->send_buf_off = 0;
        h->send_buf_len = (uint32_t)fwd_n;
        struct io_uring_sqe *sqe_s = io_uring_get_sqe(&w->uring.ring);
        if (!sqe_s) { conn_close(w, cid, true); return; }
        PREP_SEND(w, sqe_s, h->backend_fd, FIXED_FD_BACKEND(w, cid),
            rbuf, (size_t)fwd_n, MSG_NOSIGNAL, SEND_IDX_RECV(w, cid));
        sqe_s->user_data = URING_UD_ENCODE(VORTEX_OP_SEND_BACKEND, cid);
        uring_submit(&w->uring);
    } else {
        if (h->flags & CONN_FLAG_TCP_TUNNEL) {
            /* TCP tunnel: arm both recv directions simultaneously */
            struct io_uring_sqe *sqe_c = io_uring_get_sqe(&w->uring.ring);
            struct io_uring_sqe *sqe_b = io_uring_get_sqe(&w->uring.ring);
            if (!sqe_c || !sqe_b) { conn_close(w, cid, true); return; }
            PREP_RECV(w, sqe_c, h->client_fd, FIXED_FD_CLIENT(w, cid),
                conn_recv_buf(&w->pool, cid), w->pool.buf_size, 0, SEND_IDX_RECV(w, cid));
            sqe_c->user_data = URING_UD_ENCODE(VORTEX_OP_RECV_CLIENT_WS, cid);
            PREP_RECV(w, sqe_b, h->backend_fd, FIXED_FD_BACKEND(w, cid),
                conn_send_buf(&w->pool, cid), w->pool.buf_size, 0, SEND_IDX_SEND(w, cid));
            sqe_b->user_data = URING_UD_ENCODE(VORTEX_OP_RECV_BACKEND_WS, cid);
        } else {
            struct io_uring_sqe *sqe_c = io_uring_get_sqe(&w->uring.ring);
            if (!sqe_c) { conn_close(w, cid, true); return; }
            PREP_RECV(w, sqe_c, h->client_fd, FIXED_FD_CLIENT(w, cid),
                conn_recv_buf(&w->pool, cid), h->recv_window, 0, cid);
            sqe_c->user_data = URING_UD_ENCODE(VORTEX_OP_RECV_CLIENT, cid);
        }
        uring_submit(&w->uring);
    }
}

static void handle_connect(struct worker *w, struct io_uring_cqe *cqe, uint32_t cid, struct conn_hot *h)
{
    /* Async backend connect completed */
    const struct backend_config *bcfg = &w->cfg->routes[h->route_idx].backends[h->backend_idx];
    h->flags &= ~CONN_FLAG_BACKEND_CONNECTING;
    {
        int _ri = h->route_idx, _bi = h->backend_idx;
        struct timespec _cb_ts;
        clock_gettime(CLOCK_MONOTONIC_COARSE, &_cb_ts);
        uint64_t _now = (uint64_t)_cb_ts.tv_sec * 1000000000ULL + _cb_ts.tv_nsec;
        if (cqe->res < 0) {
            cb_record_failure(w, _ri, _bi, _now,
                w->cfg->routes[_ri].health.fail_threshold,
                w->cfg->routes[_ri].health.open_ms);
        } else {
            cb_record_success(w, _ri, _bi);
        }
    }
    if (cqe->res < 0) {
        log_warn("connect_cqe", "conn=%u backend connect failed: %s",
            cid, strerror(-cqe->res));
        send_bad_gateway_and_close(w, cid);
        return;
    }
    log_debug("connect_cqe", "conn=%u backend_fd=%d connected", cid, h->backend_fd);
#ifdef VORTEX_PHASE_TLS
    if (bcfg->tls) {
        if (w->tls_done_pipe_wr >= 0) {
            struct tls_handshake_job job = {
                .kind = TLS_HANDSHAKE_BACKEND,
                .client_fd = h->backend_fd,
                .cid = cid,
                .result_pipe_wr = w->tls_done_pipe_wr,
                .result_ring    = &w->tls_result_ring,
                .backend_tls_client_ctx = w->backend_tls_client_ctx,
                .timeout_ms = w->cfg->routes[h->route_idx].backend_timeout_ms
                              ? w->cfg->routes[h->route_idx].backend_timeout_ms : 30000,
                .verify_peer = bcfg->verify_peer,
                .verify_peer_set = bcfg->verify_peer_set,
            };
            snprintf(job.backend_addr, sizeof(job.backend_addr), "%s", bcfg->address);
            snprintf(job.backend_sni, sizeof(job.backend_sni), "%s", bcfg->sni);
            if (w->backend_tls_sessions[h->route_idx][h->backend_idx]) {
                /* Duplicate the session ticket for the pool thread to consume */
                struct tls_session_ticket *src =
                    w->backend_tls_sessions[h->route_idx][h->backend_idx];
                struct tls_session_ticket *dup = malloc(sizeof(*dup));
                if (dup) {
                    memcpy(dup, src, sizeof(*dup));
                    job.resume_session = dup;
                }
            }
            if (!tls_pool_submit(job)) {
                free(job.resume_session);
                log_warn("connect_cqe", "conn=%u backend TLS handshake submit failed", cid);
                send_bad_gateway_and_close(w, cid);
                return;
            }
            h->flags |= CONN_FLAG_BACKEND_TLS_PENDING;
            return;
        }
        if (backend_tls_handshake(w, bcfg, cid) != 0) {
            log_warn("connect_cqe", "conn=%u backend TLS handshake failed", cid);
            send_bad_gateway_and_close(w, cid);
            return;
        }
    }
#endif

    resume_connected_backend(w, cid, h);
}

static void handle_recv_client_ws(struct worker *w, struct io_uring_cqe *cqe, uint32_t cid, struct conn_hot *h)
{
    int n = cqe->res;
    if (n <= 0) { conn_close(w, cid, false); return; }
    h->recv_buf_off = 0;
    h->recv_buf_len = (uint32_t)n;
    struct io_uring_sqe *sqe_ws_c = io_uring_get_sqe(&w->uring.ring);
    if (!sqe_ws_c) { conn_close(w, cid, false); return; }
    PREP_SEND(w, sqe_ws_c, h->backend_fd, FIXED_FD_BACKEND(w, cid),
        conn_recv_buf(&w->pool, cid), (size_t)n, MSG_NOSIGNAL, SEND_IDX_RECV(w, cid));
    sqe_ws_c->user_data = URING_UD_ENCODE(VORTEX_OP_SEND_BACKEND_WS, cid);
    uring_submit(&w->uring);
}

static void handle_send_backend_ws(struct worker *w, struct io_uring_cqe *cqe, uint32_t cid, struct conn_hot *h)
{
    int sent = cqe->res;
    if (sent <= 0) { conn_close(w, cid, false); return; }
    h->recv_buf_off += (uint32_t)sent;
    if (h->recv_buf_off < h->recv_buf_len) {
        struct io_uring_sqe *sqe_ws_c = io_uring_get_sqe(&w->uring.ring);
        if (!sqe_ws_c) { conn_close(w, cid, false); return; }
        PREP_SEND(w, sqe_ws_c, h->backend_fd, FIXED_FD_BACKEND(w, cid),
            conn_recv_buf(&w->pool, cid) + h->recv_buf_off,
            (size_t)(h->recv_buf_len - h->recv_buf_off),
            MSG_NOSIGNAL, SEND_IDX_RECV(w, cid));
        sqe_ws_c->user_data = URING_UD_ENCODE(VORTEX_OP_SEND_BACKEND_WS, cid);
        uring_submit(&w->uring);
        return;
    }
    h->recv_buf_off = 0;
    h->recv_buf_len = 0;
    struct io_uring_sqe *sqe_ws_c = io_uring_get_sqe(&w->uring.ring);
    if (!sqe_ws_c) { conn_close(w, cid, false); return; }
    PREP_RECV(w, sqe_ws_c, h->client_fd, FIXED_FD_CLIENT(w, cid),
        conn_recv_buf(&w->pool, cid), w->pool.buf_size, 0, SEND_IDX_RECV(w, cid));
    sqe_ws_c->user_data = URING_UD_ENCODE(VORTEX_OP_RECV_CLIENT_WS, cid);
    uring_submit(&w->uring);
}

static void handle_recv_backend_ws(struct worker *w, struct io_uring_cqe *cqe, uint32_t cid, struct conn_hot *h)
{
    int n = cqe->res;
    if (n <= 0) { conn_close(w, cid, false); return; }
    h->send_buf_off = 0;
    h->send_buf_len = (uint32_t)n;
    struct io_uring_sqe *sqe_ws_b = io_uring_get_sqe(&w->uring.ring);
    if (!sqe_ws_b) { conn_close(w, cid, false); return; }
    PREP_SEND(w, sqe_ws_b, h->client_fd, FIXED_FD_CLIENT(w, cid),
        conn_send_buf(&w->pool, cid), (size_t)n, MSG_NOSIGNAL, SEND_IDX_SEND(w, cid));
    sqe_ws_b->user_data = URING_UD_ENCODE(VORTEX_OP_SEND_CLIENT_WS, cid);
    uring_submit(&w->uring);
}

static void handle_send_client_ws(struct worker *w, struct io_uring_cqe *cqe, uint32_t cid, struct conn_hot *h)
{
    int sent = cqe->res;
    if (sent <= 0) { conn_close(w, cid, false); return; }
    h->send_buf_off += (uint32_t)sent;
    if (h->send_buf_off < h->send_buf_len) {
        struct io_uring_sqe *sqe_ws_b = io_uring_get_sqe(&w->uring.ring);
        if (!sqe_ws_b) { conn_close(w, cid, false); return; }
        PREP_SEND(w, sqe_ws_b, h->client_fd, FIXED_FD_CLIENT(w, cid),
            conn_send_buf(&w->pool, cid) + h->send_buf_off,
            (size_t)(h->send_buf_len - h->send_buf_off),
            MSG_NOSIGNAL, SEND_IDX_SEND(w, cid));
        sqe_ws_b->user_data = URING_UD_ENCODE(VORTEX_OP_SEND_CLIENT_WS, cid);
        uring_submit(&w->uring);
        return;
    }
    h->send_buf_off = 0;
    h->send_buf_len = 0;
    struct io_uring_sqe *sqe_ws_b = io_uring_get_sqe(&w->uring.ring);
    if (!sqe_ws_b) { conn_close(w, cid, false); return; }
    PREP_RECV(w, sqe_ws_b, h->backend_fd, FIXED_FD_BACKEND(w, cid),
        conn_send_buf(&w->pool, cid), w->pool.buf_size, 0, SEND_IDX_SEND(w, cid));
    sqe_ws_b->user_data = URING_UD_ENCODE(VORTEX_OP_RECV_BACKEND_WS, cid);
    uring_submit(&w->uring);
}

static void handle_send_client_zc(struct worker *w, struct io_uring_cqe *cqe, uint32_t cid, struct conn_hot *h)
{
    /*
     * Two CQEs per send_zc_fixed operation:
     *
     * 1. Completion CQE (IORING_CQE_F_MORE set, IORING_CQE_F_NOTIF clear):
     *    res = bytes transferred. Process partial sends here.
     *    Buffer is still pinned — do NOT arm next recv yet.
     *
     * 2. Notification CQE (IORING_CQE_F_NOTIF set):
     *    res = 0. Kernel has released the buffer. Safe to arm next recv.
     *
     * zc_notif_count tracks outstanding notifications so we handle partial
     * sends (multiple in-flight ZC ops) and stale NOTIFs on reused slots.
     */
    if (cqe->flags & IORING_CQE_F_NOTIF) {
        /* Buffer released — decrement counter and arm next recv if all done */
        if (h->zc_notif_count > 0) h->zc_notif_count--;
        if (h->zc_notif_count == 0) {
            try_backend_pool_return(w, cid, h);
            struct io_uring_sqe *sqe = io_uring_get_sqe(&w->uring.ring);
            if (!sqe) { conn_close(w, cid, true); return; }
            if (h->flags & CONN_FLAG_STREAMING_BACKEND) {
                /* More backend data expected — re-arm backend recv */
                PREP_RECV(w, sqe, h->backend_fd, FIXED_FD_BACKEND(w, cid),
                    conn_send_buf(&w->pool, cid), w->pool.buf_size, 0, SEND_IDX_SEND(w, cid));
                sqe->user_data = URING_UD_ENCODE(VORTEX_OP_RECV_BACKEND, cid);
            } else {
                /* Response complete — arm next client request (keep-alive) */
                PREP_RECV(w, sqe, h->client_fd, FIXED_FD_CLIENT(w, cid),
                    conn_recv_buf(&w->pool, cid), h->recv_window, 0, cid);
                sqe->user_data = URING_UD_ENCODE(VORTEX_OP_RECV_CLIENT, cid);
            }
            uring_submit(&w->uring);
        }
        return;
    }

    /* Completion CQE */
    int zc_sent = cqe->res;
    if (zc_sent <= 0) { conn_close(w, cid, true); return; }
    h->bytes_out += (uint32_t)zc_sent;
    /* Note: do NOT arm next recv here — wait for the NOTIF CQE */
}

#ifdef VORTEX_H2
static void handle_h2_recv_client(struct worker *w, struct io_uring_cqe *cqe, uint32_t cid, struct conn_hot *h)
{
    (void)h;

    /* Multishot: IORING_CQE_F_MORE means the recv SQE is still armed.
     * When not set (ring empty, fd closed, etc.) we must re-arm. */
    bool ms_active = (cqe->flags & IORING_CQE_F_MORE) != 0;
    const uint8_t *data;
    uint16_t buf_id = 0;
    if (w->uring.recv_ring && (cqe->flags & IORING_CQE_F_BUFFER)) {
        buf_id = (uint16_t)(cqe->flags >> IORING_CQE_BUFFER_SHIFT);
        data   = uring_recv_ring_buf(&w->uring, buf_id, w->pool.buf_size);
    } else {
        data = conn_recv_buf(&w->pool, cid);
    }
    h2_on_recv(w, cid, cqe->res, data, buf_id, ms_active);
}

static void handle_h2_send_client(struct worker *w, struct io_uring_cqe *cqe, uint32_t cid, struct conn_hot *h)
{
    (void)h;
    h2_on_send_client(w, cid, cqe->res);
}
#endif

void handle_proxy_data(struct worker *w, struct io_uring_cqe *cqe)
{
    uint64_t ud  = cqe->user_data;
    uint32_t op  = URING_UD_OP(ud);
    uint32_t cid = URING_UD_ID(ud);

    /* Accept completions have cid=0 — special handling */
    if (op == VORTEX_OP_ACCEPT) {
        handle_accept(w, cqe);
        return;
    }

#ifdef VORTEX_PHASE_TLS
    if (op == VORTEX_OP_TLS_DONE) {
        handle_tls_done(w, cqe);
        return;
    }
#endif
    if (op == VORTEX_OP_COMPRESS_DONE) {
        handle_compress_done(w, cqe);
        return;
    }

#ifdef VORTEX_H2
    if (handle_h2_backend_ops(w, cqe, op))
        return;
#endif

    /* For all other ops, validate cid */
    if (cid >= w->pool.capacity) return;
    struct conn_hot *h = conn_hot(&w->pool, cid);
    if (h->state == CONN_STATE_FREE) return;

    if (cqe->res < 0 && op != VORTEX_OP_CONNECT) {
        handle_error(w, cqe, cid, h);
        return;
    }

    switch (op) {
    case VORTEX_OP_RECV_CLIENT:
        handle_recv_client(w, cqe, cid, h);
        break;
    case VORTEX_OP_SEND_BACKEND:
        handle_send_backend(w, cqe, cid, h);
        break;
    case VORTEX_OP_RECV_BACKEND:
        handle_recv_backend(w, cqe, cid, h);
        break;
    case VORTEX_OP_SEND_CLIENT:
        handle_send_client(w, cqe, cid, h);
        break;
    case VORTEX_OP_SEND_CLIENT_LINKED:
        handle_send_client_linked(w, cqe, cid, h);
        break;
    case VORTEX_OP_SPLICE_BACKEND:
        handle_splice_backend(w, cqe, cid, h);
        break;
    case VORTEX_OP_SPLICE_CLIENT:
        handle_splice_client(w, cqe, cid, h);
        break;
    case VORTEX_OP_CONNECT:
        handle_connect(w, cqe, cid, h);
        break;
    case VORTEX_OP_RECV_CLIENT_WS:
        handle_recv_client_ws(w, cqe, cid, h);
        break;
    case VORTEX_OP_SEND_BACKEND_WS:
        handle_send_backend_ws(w, cqe, cid, h);
        break;
    case VORTEX_OP_RECV_BACKEND_WS:
        handle_recv_backend_ws(w, cqe, cid, h);
        break;
    case VORTEX_OP_SEND_CLIENT_WS:
        handle_send_client_ws(w, cqe, cid, h);
        break;
    case VORTEX_OP_SEND_CLIENT_ZC:
        handle_send_client_zc(w, cqe, cid, h);
        break;
#ifdef VORTEX_H2
    case VORTEX_OP_H2_RECV_CLIENT:
        handle_h2_recv_client(w, cqe, cid, h);
        break;
    case VORTEX_OP_H2_SEND_CLIENT:
        handle_h2_send_client(w, cqe, cid, h);
        break;
#endif
    default:
        break;
    }
}
