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

/* Extract method and URL from HTTP/1.x request line.
 * Returns 0 on success, -1 if not a parseable HTTP request. */
int parse_http_request_line(const uint8_t *buf, int len,
                            char *method_out, size_t method_max,
                            char *url_out, size_t url_max)
{
    /* "GET /path HTTP/1.1\r\n..." */
    const char *p = (const char *)buf;
    const char *end = p + len;

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
    if (ulen >= url_max) ulen = url_max - 1;
    memcpy(url_out, p, ulen);
    url_out[ulen] = '\0';

    return 0;
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
void handle_proxy_data(struct worker *w, struct io_uring_cqe *cqe)
{
    uint64_t ud  = cqe->user_data;
    uint32_t op  = URING_UD_OP(ud);
    uint32_t cid = URING_UD_ID(ud);

    /* Accept completions have cid=0 — special handling */
    if (op == VORTEX_OP_ACCEPT) {
        int client_fd = cqe->res;
        log_debug("accept_cqe", "worker=%d res=%d flags=0x%x",
            w->worker_id, cqe->res, cqe->flags);
        if (client_fd < 0) {
            /* Multishot accept will continue unless !IORING_CQE_F_MORE */
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

        uint32_t new_cid = conn_alloc(&w->pool);
        if (new_cid != CONN_INVALID) {
            /* Record client address for X-Forwarded-For */
            struct conn_cold *cold = conn_cold_ptr(&w->pool, new_cid);
            socklen_t salen = sizeof(cold->client_addr);
            getpeername(client_fd, (struct sockaddr *)&cold->client_addr, &salen);
        }
        if (new_cid == CONN_INVALID) { close(client_fd); return; }

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
                    .client_fd      = client_fd,
                    .cid            = new_cid,
                    .tls            = w->tls,
                    .result_pipe_wr = w->tls_done_pipe_wr,
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
            SSL *ssl_fb = tls_accept(w->tls, client_fd, &tls_route_idx, sni_fb, sizeof(sni_fb));
            if (!ssl_fb) { close(client_fd); conn_free(&w->pool, new_cid); return; }
            if (SSL_version(ssl_fb) == TLS1_3_VERSION) w->tls13_count++; else w->tls12_count++;
            if (tls_ktls_tx_active(ssl_fb) && tls_ktls_rx_active(ssl_fb)) {
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
            int backend_idx = select_available_backend(w, route_idx, 0);
            if (backend_idx < 0) {
                /* All backends have open circuits — fast-reject with 503 */
                static const char r503[] =
                    "HTTP/1.1 503 Service Unavailable\r\n"
                    "Content-Length: 19\r\nRetry-After: 5\r\nConnection: close\r\n\r\n"
                    "Service Unavailable";
                send(client_fd, r503, sizeof(r503) - 1, MSG_NOSIGNAL);
                close(client_fd);
                conn_free(&w->pool, new_cid);
                return;
            }
            const char *addr = router_backend_addr(&w->router, route_idx, backend_idx);
            nh->route_idx   = (uint16_t)route_idx;
            nh->backend_idx = (uint16_t)backend_idx;

            if (addr) {
                /* Try idle pool first */
                int cfg_pool = w->cfg->routes[route_idx].backends[backend_idx].pool_size;
                int pooled_fd = (cfg_pool > 0)
                                ? global_pool_get(route_idx, backend_idx) : -1;
                if (pooled_fd >= 0) {
                    nh->backend_fd = pooled_fd;
                    nh->flags |= CONN_FLAG_BACKEND_POOLED;
                    uring_install_fd(&w->uring, (unsigned)FIXED_FD_BACKEND(w, new_cid), pooled_fd);
                    log_debug("accept_pool", "conn=%u reused backend fd=%d",
                        (unsigned)new_cid, pooled_fd);
                } else {
                    /* Async connect — CONNECT completion arms RECV_CLIENT */
                    const struct backend_config *bcfg = &w->cfg->routes[route_idx].backends[backend_idx];
                    nh->backend_fd = begin_async_connect(w, bcfg, new_cid);
                    if (nh->backend_fd >= 0)
                        uring_install_fd(&w->uring, (unsigned)FIXED_FD_BACKEND(w, new_cid), nh->backend_fd);
                    if (nh->backend_fd < 0) {
                        const char *r502 =
                            "HTTP/1.1 502 Bad Gateway\r\n"
                            "Content-Length: 11\r\nConnection: close\r\n\r\nBad Gateway";
                        send(client_fd, r502, strlen(r502), MSG_NOSIGNAL);
                        close(client_fd);
                        conn_free(&w->pool, new_cid);
                        return;
                    }
                    nh->flags |= CONN_FLAG_BACKEND_CONNECTING;
                    nh->state = CONN_STATE_BACKEND_CONNECT;
                    nh->last_active_tsc = rdtsc();
                    w->accepted++;
                    /* RECV_CLIENT will be armed by VORTEX_OP_CONNECT handler */
                    return;
                }
            }
        }

        if (nh->backend_fd < 0) {
            const char *r502 =
                "HTTP/1.1 502 Bad Gateway\r\n"
                "Content-Length: 11\r\nConnection: close\r\n\r\nBad Gateway";
            send(client_fd, r502, strlen(r502), MSG_NOSIGNAL);
            close(client_fd);
            conn_free(&w->pool, new_cid);
            return;
        }

        nh->state = CONN_STATE_PROXYING;
        nh->last_active_tsc = rdtsc();
        w->accepted++;

        /* Backend came from pool — arm RECV_CLIENT immediately */
        struct io_uring_sqe *s1 = io_uring_get_sqe(&w->uring.ring);
        if (!s1) { conn_close(w, new_cid, true); return; }
        PREP_RECV(w, s1, client_fd, FIXED_FD_CLIENT(w, new_cid),
            conn_recv_buf(&w->pool, new_cid), nh->recv_window, 0, new_cid);
        s1->user_data = URING_UD_ENCODE(VORTEX_OP_RECV_CLIENT, new_cid);
        log_debug("accept_arm", "conn=%u client_fd=%d backend_fd=%d (pooled)",
            (unsigned)new_cid, client_fd, nh->backend_fd);
        uring_submit(&w->uring);
        return;
    }

#ifdef VORTEX_PHASE_TLS
    if (op == VORTEX_OP_TLS_DONE) {
        /* Re-arm pipe read for the next result before processing this one */
        struct io_uring_sqe *rpsqe = io_uring_get_sqe(&w->uring.ring);
        if (rpsqe) {
            io_uring_prep_read(rpsqe, w->tls_done_pipe_rd,
                               w->tls_pipe_buf, sizeof(w->tls_pipe_buf), 0);
            rpsqe->user_data = URING_UD_ENCODE(VORTEX_OP_TLS_DONE, 0);
        }
        uring_submit(&w->uring);

        if (cqe->res != (int)sizeof(struct tls_handshake_result)) {
            /* Partial or error read — nothing we can do, pipe stays armed */
            return;
        }

        struct tls_handshake_result res;
        memcpy(&res, w->tls_pipe_buf, sizeof(res));
        uint32_t hcid = res.cid;

        if (hcid >= w->pool.capacity) return;
        struct conn_hot *th = conn_hot(&w->pool, hcid);
        if (th->state == CONN_STATE_FREE) return;

        if (!res.ok) {
            close(res.client_fd);
            conn_free(&w->pool, hcid);
            return;
        }

        /* Record TLS version stats */
        if (res.tls_version == TLS1_3_VERSION) w->tls13_count++;
        else w->tls12_count++;

        if (res.ktls_tx && res.ktls_rx) {
            th->flags |= CONN_FLAG_KTLS_TX | CONN_FLAG_KTLS_RX;
            th->ssl    = NULL;
            w->ktls_count++;
        } else {
            th->ssl = res.ssl;
        }

#ifdef VORTEX_H2
        /* If client negotiated h2 via ALPN, hand off to the H2 session */
        if (res.h2_negotiated) {
            th->flags |= CONN_FLAG_HTTP2;
            th->state  = CONN_STATE_PROXYING;
            th->route_idx = (uint16_t)(res.tls_route_idx >= 0 ? res.tls_route_idx : 0);
            th->last_active_tsc = rdtsc();
            w->accepted++;

            if (h2_session_init(w, hcid) != 0) {
                close(res.client_fd);
                conn_free(&w->pool, hcid);
                return;
            }

            /* Arm first RECV_CLIENT for H2 frame data */
            struct io_uring_sqe *h2sq = io_uring_get_sqe(&w->uring.ring);
            if (!h2sq) { conn_close(w, hcid, true); return; }
            io_uring_prep_recv(h2sq, res.client_fd,
                conn_recv_buf(&w->pool, hcid), w->pool.buf_size, 0);
            h2sq->user_data = URING_UD_H2_ENCODE(VORTEX_OP_H2_RECV_CLIENT, 0, hcid);
            uring_submit(&w->uring);
            return;
        }
#endif

        /* Route selection (same logic as post-TLS in handle_accept) */
        int tls_route_idx = res.tls_route_idx;
        int route_idx = tls_route_idx;
        if (w->cfg->route_count > 0 && route_idx < w->cfg->route_count) {
            int backend_idx = select_available_backend(w, route_idx, 0);
            if (backend_idx < 0) {
                static const char r503[] =
                    "HTTP/1.1 503 Service Unavailable\r\n"
                    "Content-Length: 19\r\nRetry-After: 5\r\nConnection: close\r\n\r\n"
                    "Service Unavailable";
                send(res.client_fd, r503, sizeof(r503) - 1, MSG_NOSIGNAL);
                close(res.client_fd);
                conn_free(&w->pool, hcid);
                return;
            }
            const char *addr = router_backend_addr(&w->router, route_idx, backend_idx);
            th->route_idx   = (uint16_t)route_idx;
            th->backend_idx = (uint16_t)backend_idx;

            if (addr) {
                int cfg_pool = w->cfg->routes[route_idx].backends[backend_idx].pool_size;
                int pooled_fd = (cfg_pool > 0)
                                ? global_pool_get(route_idx, backend_idx) : -1;
                if (pooled_fd >= 0) {
                    th->backend_fd = pooled_fd;
                    th->flags |= CONN_FLAG_BACKEND_POOLED;
                    uring_install_fd(&w->uring, (unsigned)FIXED_FD_BACKEND(w, hcid), pooled_fd);
                } else {
                    const struct backend_config *bcfg =
                        &w->cfg->routes[route_idx].backends[backend_idx];
                    th->backend_fd = begin_async_connect(w, bcfg, hcid);
                    if (th->backend_fd >= 0)
                        uring_install_fd(&w->uring, (unsigned)FIXED_FD_BACKEND(w, hcid),
                                         th->backend_fd);
                    if (th->backend_fd < 0) {
                        const char *r502 =
                            "HTTP/1.1 502 Bad Gateway\r\n"
                            "Content-Length: 11\r\nConnection: close\r\n\r\nBad Gateway";
                        send(res.client_fd, r502, strlen(r502), MSG_NOSIGNAL);
                        close(res.client_fd);
                        conn_free(&w->pool, hcid);
                        return;
                    }
                    th->flags |= CONN_FLAG_BACKEND_CONNECTING;
                    th->state = CONN_STATE_BACKEND_CONNECT;
                    th->last_active_tsc = rdtsc();
                    w->accepted++;
                    return; /* RECV_CLIENT armed by VORTEX_OP_CONNECT handler */
                }
            }
        }

        if (th->backend_fd < 0) {
            const char *r502 =
                "HTTP/1.1 502 Bad Gateway\r\n"
                "Content-Length: 11\r\nConnection: close\r\n\r\nBad Gateway";
            send(res.client_fd, r502, strlen(r502), MSG_NOSIGNAL);
            close(res.client_fd);
            conn_free(&w->pool, hcid);
            return;
        }

        th->state = CONN_STATE_PROXYING;
        th->last_active_tsc = rdtsc();
        w->accepted++;

        struct io_uring_sqe *ts1 = io_uring_get_sqe(&w->uring.ring);
        if (!ts1) { conn_close(w, hcid, true); return; }
        PREP_RECV(w, ts1, res.client_fd, FIXED_FD_CLIENT(w, hcid),
            conn_recv_buf(&w->pool, hcid), th->recv_window, 0, hcid);
        ts1->user_data = URING_UD_ENCODE(VORTEX_OP_RECV_CLIENT, hcid);
        uring_submit(&w->uring);
        return;
    }
#endif

#ifdef VORTEX_H2
    /* H2 backend ops encode (slot << 12) | cid in the lower 32 bits —
     * extract the real cid with URING_UD_H2_CID before the pool capacity check. */
    if (op == VORTEX_OP_H2_CONNECT || op == VORTEX_OP_H2_SEND_BACKEND ||
        op == VORTEX_OP_H2_RECV_BACKEND) {
        uint32_t h2_cid  = URING_UD_H2_CID(cqe->user_data);
        uint32_t h2_slot = URING_UD_H2_SLOT(cqe->user_data);
        if (h2_cid >= w->pool.capacity) return;
        struct conn_hot *hh = conn_hot(&w->pool, h2_cid);
        if (hh->state == CONN_STATE_FREE) return;
        if (op == VORTEX_OP_H2_CONNECT)
            h2_on_backend_connect(w, h2_cid, h2_slot, cqe->res);
        else if (op == VORTEX_OP_H2_SEND_BACKEND)
            h2_on_backend_send(w, h2_cid, h2_slot, cqe->res);
        else
            h2_on_backend_recv(w, h2_cid, h2_slot, cqe->res);
        return;
    }
#endif

    /* For all other ops, validate cid */
    if (cid >= w->pool.capacity) return;
    struct conn_hot *h = conn_hot(&w->pool, cid);
    if (h->state == CONN_STATE_FREE) return;

    if (cqe->res < 0) {
        /* EIO on kTLS = TLS close_notify or alert — treat as normal close */
        bool is_error = true;
        if (cqe->res == -ECONNRESET || cqe->res == -EPIPE ||
            cqe->res == -EBADF     || cqe->res == -ECANCELED ||
            cqe->res == -EIO) {
            is_error = false; /* expected close conditions */
        } else {
            log_debug("proxy_err", "conn=%u op=%u err=%s", cid, op, strerror(-cqe->res));
        }
        conn_close(w, cid, is_error);
        return;
    }

    switch (op) {
    case VORTEX_OP_RECV_CLIENT: {
        int n = cqe->res;
        log_debug("recv_client", "conn=%u n=%d", cid, n);
        if (n == 0) { conn_close(w, cid, false); break; } /* Client EOF */
        RECV_WINDOW_GROW(h, n, w->pool.buf_size);
        h->bytes_in += (uint32_t)n;

        /* Reconnect to backend if previous response consumed the connection */
        if (h->backend_fd < 0) {
            int ri = h->route_idx;
            /* Re-select backend respecting circuit breaker state */
            int bi = select_available_backend(w, ri, 0);
            if (bi < 0) {
                static const char r503[] =
                    "HTTP/1.1 503 Service Unavailable\r\n"
                    "Content-Length: 19\r\nRetry-After: 5\r\nConnection: close\r\n\r\n"
                    "Service Unavailable";
                send(h->client_fd, r503, sizeof(r503) - 1, MSG_NOSIGNAL);
                conn_close(w, cid, false);
                break;
            }
            h->backend_idx = (uint16_t)bi;
            const char *addr = router_backend_addr(&w->router, ri, bi);
            if (!addr) {
                const char *r502 =
                    "HTTP/1.1 502 Bad Gateway\r\n"
                    "Content-Length: 11\r\nConnection: close\r\n\r\nBad Gateway";
                send(h->client_fd, r502, strlen(r502), MSG_NOSIGNAL);
                conn_close(w, cid, false);
                break;
            }
            /* Prefer the sticky backend fd pinned from the previous request.
             * This avoids pool operations (uring_install_fd/remove_fd) on every
             * request for long-lived client connections. */
            int cfg_pool = w->cfg->routes[ri].backends[bi].pool_size;
            if (h->backend_fd >= 0 && h->backend_idx == (uint16_t)bi) {
                /* Reuse existing connection — already installed in fixed slot */
                log_debug("backend_reuse", "conn=%u fd=%d", cid, h->backend_fd);
            } else {
                /* Release any fd for a different backend (route switch) */
                if (h->backend_fd >= 0) {
                    int old_ps = w->cfg->routes[h->route_idx].backends[h->backend_idx].pool_size;
                    uring_remove_fd(&w->uring, (unsigned)FIXED_FD_BACKEND(w, cid));
                    if (old_ps > 0)
                        global_pool_put(h->route_idx, h->backend_idx, h->backend_fd, old_ps);
                    else
                        close(h->backend_fd);
                    h->backend_fd = -1;
                }
                /* Try global pool, then async connect */
                int pfd = (cfg_pool > 0) ? global_pool_get(ri, bi) : -1;
                if (pfd >= 0) {
                    h->backend_fd = pfd;
                    h->flags |= CONN_FLAG_BACKEND_POOLED;
                    uring_install_fd(&w->uring, (unsigned)FIXED_FD_BACKEND(w, cid), pfd);
                } else {
                    /* Async reconnect: data already in recv_buf — save it and
                     * arm CONNECT; the CONNECT handler will re-arm RECV_CLIENT
                     * which will trigger resend of the buffered request.
                     * We pass n as hint via send_buf_len so CONNECT can forward it. */
                    h->send_buf_len = (uint32_t)n;  /* stash the byte count */
                    const struct backend_config *bcfg2 = &w->cfg->routes[ri].backends[bi];
                    h->backend_fd = begin_async_connect(w, bcfg2, cid);
                    if (h->backend_fd >= 0)
                        uring_install_fd(&w->uring, (unsigned)FIXED_FD_BACKEND(w, cid), h->backend_fd);
                    if (h->backend_fd < 0) {
                        const char *r502 =
                            "HTTP/1.1 502 Bad Gateway\r\n"
                            "Content-Length: 11\r\nConnection: close\r\n\r\nBad Gateway";
                        send(h->client_fd, r502, strlen(r502), MSG_NOSIGNAL);
                        conn_close(w, cid, false);
                        break;
                    }
                    h->flags |= CONN_FLAG_BACKEND_CONNECTING;
                    h->state = CONN_STATE_BACKEND_CONNECT;
                    /* Do not fall through — wait for CONNECT completion */
                    break;
                }
            }
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
                        "Connection: keep-alive\r\n\r\n";
                    struct io_uring_sqe *sqe429  = io_uring_get_sqe(&w->uring.ring);
                    struct io_uring_sqe *sqe429r = io_uring_get_sqe(&w->uring.ring);
                    if (!sqe429 || !sqe429r) { conn_close(w, cid, false); break; }
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
                    break;
                }
                w->route_rl[ri].tokens--;
            }
        }

        /* Basic Auth check */
        {
            const struct route_config *rc = &w->cfg->routes[h->route_idx];
            if (!auth_check_request(&rc->auth, conn_recv_buf(&w->pool, cid), n)) {
                /* Send 401 and re-arm for next request */
                static const char r401[] =
                    "HTTP/1.1 401 Unauthorized\r\n"
                    "WWW-Authenticate: Basic realm=\"vortex\"\r\n"
                    "Content-Length: 0\r\n"
                    "Connection: keep-alive\r\n\r\n";
                struct io_uring_sqe *sqe401 = io_uring_get_sqe(&w->uring.ring);
                struct io_uring_sqe *sqe401r = io_uring_get_sqe(&w->uring.ring);
                if (!sqe401 || !sqe401r) { conn_close(w, cid, false); break; }
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
                break;
            }
        }

        /* Detect WebSocket upgrade request */
        {
            const uint8_t *rbuf = conn_recv_buf(&w->pool, cid);
            if (memmem(rbuf, (size_t)n, "Upgrade: websocket", 18) != NULL ||
                memmem(rbuf, (size_t)n, "upgrade: websocket", 18) != NULL) {
                h->flags |= CONN_FLAG_WEBSOCKET_ACTIVE;
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
        if (w->cache.index) {
            char method[16], url[512];
            const uint8_t *rbuf = conn_recv_buf(&w->pool, cid);
            if (parse_http_request_line(rbuf, n,
                                        method, sizeof(method),
                                        url, sizeof(url)) == 0
                && strcmp(method, "GET") == 0) {

                char cache_key[640];
                make_cache_key(rbuf, (size_t)n, url, cache_key, sizeof(cache_key));
                struct cache_index_entry *ce = cache_lookup(&w->cache, cache_key, strlen(cache_key));
                if (ce && cache_entry_valid(ce)) {
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
                             (unsigned long long)ce->body_etag);

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
                            log_debug("cache_304", "conn=%u url=%s", cid, url);
                            break;
                        }
                    }

                    /* Full cache HIT — serve stored response + inject ETag / X-Cache */
                    const uint8_t *resp = cache_response_ptr(&w->cache, ce);
                    if (resp) {
                        /* Extra headers to splice before the final \r\n\r\n */
                        char extra[128];
                        int extra_len = snprintf(extra, sizeof(extra),
                            "ETag: \"%s\"\r\nX-Cache: HIT\r\n", etag_str);

                        uint32_t stored_total = ce->header_len + ce->body_len;
                        size_t serve_len = stored_total + (size_t)extra_len;
                        uint8_t *sbuf = conn_send_buf(&w->pool, cid);

                        if (serve_len <= w->pool.buf_size && ce->header_len >= 4) {
                            /* Copy headers minus the blank-line terminator (\r\n).
                             * The last header's own \r\n stays so extra headers
                             * splice in cleanly without merging onto the same line. */
                            size_t hdr_body = ce->header_len - 2;
                            memcpy(sbuf, resp, hdr_body);
                            memcpy(sbuf + hdr_body, extra, (size_t)extra_len);
                            memcpy(sbuf + hdr_body + extra_len, "\r\n", 2);
                            memcpy(sbuf + ce->header_len + extra_len,
                                   resp + ce->header_len, ce->body_len);

                            struct io_uring_sqe *sqe = io_uring_get_sqe(&w->uring.ring);
                            if (sqe) {
                                h->send_buf_off = 0;
                                h->send_buf_len = (uint32_t)serve_len;
                                h->flags &= ~CONN_FLAG_STREAMING_BACKEND;
                                PREP_SEND(w, sqe, h->client_fd, FIXED_FD_CLIENT(w, cid),
                                    sbuf, serve_len, MSG_NOSIGNAL, SEND_IDX_SEND(w, cid));
                                sqe->user_data = URING_UD_ENCODE(VORTEX_OP_SEND_CLIENT, cid);
                                uring_submit(&w->uring);
                                log_debug("cache_hit", "conn=%u url=%s", cid, url);
                                break;
                            }
                        }
                        /* Fall through to backend if response too large or no sqe */
                    }
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

            /* ---- Strip Accept-Encoding ----
             * We handle compression ourselves; tell the backend to send plain
             * so we can inspect, cache, and compress on the way out. */
            {
                uint8_t *ae = (uint8_t *)memmem(rbuf, (size_t)fwd_n, "\r\nAccept-Encoding:", 18);
                if (!ae)
                    ae = (uint8_t *)memmem(rbuf, (size_t)fwd_n, "\r\naccept-encoding:", 18);
                if (ae) {
                    uint8_t *line_end = (uint8_t *)FIND_CRLF(ae + 2,
                        (size_t)(rbuf + fwd_n - ae - 2));
                    if (line_end) {
                        line_end += 2;
                        size_t remove = (size_t)(line_end - ae - 2);
                        memmove(ae + 2, ae + 2 + remove,
                            (size_t)(rbuf + fwd_n - (ae + 2 + remove)));
                        fwd_n -= (int)remove;
                    }
                }
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
            if (!is_ws) {
                bool use_ka = (h->flags & CONN_FLAG_BACKEND_POOLED) != 0
                              || (w->cfg->routes[h->route_idx]
                                     .backends[h->backend_idx].pool_size > 0);
                const char *conn_val = use_ka ? "keep-alive" : "close";
                size_t      conn_val_len = use_ka ? 10 : 5;

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
                    /* No Connection header — inject one */
                    const char *eol0 = (const char *)FIND_CRLF(rbuf, (size_t)fwd_n);
                    if (eol0) {
                        size_t le = (size_t)(eol0 - (const char *)rbuf) + 2;
                        char inj0[32];
                        int il0 = snprintf(inj0, sizeof(inj0),
                            "Connection: %s\r\n", conn_val);
                        if (fwd_n + il0 <= (int)w->pool.buf_size) {
                            memmove(rbuf + le + il0, rbuf + le, (size_t)fwd_n - le);
                            memcpy(rbuf + le, inj0, (size_t)il0);
                            fwd_n += il0;
                        }
                    }
                }

                /* Reset per-response body tracking for this request */
                if (use_ka) {
                    struct conn_cold *cold = conn_cold_ptr(&w->pool, cid);
                    cold->backend_content_length = 0;
                    cold->backend_body_recv      = 0;
                }
            }

            /* ---- Inject proxy headers after request line ----
             * X-Forwarded-Proto, X-Forwarded-For, X-Real-IP, X-Api-Key */
            const char *eol = (const char *)FIND_CRLF(rbuf, (size_t)fwd_n);
            if (eol) {
                size_t line_end = (size_t)(eol - (const char *)rbuf) + 2;

                /* Build inject block */
                char inj[640];
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

                /* X-Api-Key if configured */
                if (rc_fwd->x_api_key[0])
                    inj_len += snprintf(inj + inj_len, sizeof(inj) - (size_t)inj_len,
                        "X-Api-Key: %s\r\n", rc_fwd->x_api_key);

                /* Backend Basic Auth credentials if configured — inject after
                 * the proxy-level Authorization header has been stripped. */
                if (rc_fwd->backend_credentials[0]) {
                    static const char b64tab[] =
                        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                    const char *src = rc_fwd->backend_credentials;
                    size_t slen = strlen(src);
                    char b64[512];
                    size_t bi = 0;
                    for (size_t si = 0; si < slen && bi + 4 < sizeof(b64); si += 3) {
                        unsigned int v  = (unsigned char)src[si] << 16;
                        if (si+1 < slen) v |= (unsigned char)src[si+1] << 8;
                        if (si+2 < slen) v |= (unsigned char)src[si+2];
                        b64[bi++] = b64tab[(v >> 18) & 0x3f];
                        b64[bi++] = b64tab[(v >> 12) & 0x3f];
                        b64[bi++] = (si+1 < slen) ? b64tab[(v >> 6) & 0x3f] : '=';
                        b64[bi++] = (si+2 < slen) ? b64tab[v & 0x3f] : '=';
                    }
                    b64[bi] = '\0';
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
        struct io_uring_sqe *sqe = io_uring_get_sqe(&w->uring.ring);
        if (!sqe) { conn_close(w, cid, true); break; }
        PREP_SEND(w, sqe, h->backend_fd, FIXED_FD_BACKEND(w, cid),
            conn_recv_buf(&w->pool, cid), fwd_n, MSG_NOSIGNAL, SEND_IDX_RECV(w, cid));
        sqe->user_data = URING_UD_ENCODE(VORTEX_OP_SEND_BACKEND, cid);
        uring_submit(&w->uring);
        break;
    }

    case VORTEX_OP_SEND_BACKEND: {
        int n = cqe->res;
        log_debug("send_backend", "conn=%u n=%d", cid, n);
        if (n < 0) { conn_close(w, cid, true); break; }
        /* All client data forwarded — arm deadline then wait for backend response */
        backend_deadline_set(w, cid, w->cfg->routes[h->route_idx].backend_timeout_ms);
        struct io_uring_sqe *sqe = io_uring_get_sqe(&w->uring.ring);
        if (!sqe) { conn_close(w, cid, true); break; }
        PREP_RECV(w, sqe, h->backend_fd, FIXED_FD_BACKEND(w, cid),
            conn_send_buf(&w->pool, cid), h->recv_window, 0, SEND_IDX_SEND(w, cid));
        sqe->user_data = URING_UD_ENCODE(VORTEX_OP_RECV_BACKEND, cid);
        uring_submit(&w->uring);
        break;
    }

    case VORTEX_OP_RECV_BACKEND: {
        int n = cqe->res;
        log_debug("recv_backend", "conn=%u n=%d", cid, n);
        if (n > 0) {
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
                static const char r502[] =
                    "HTTP/1.1 502 Bad Gateway\r\n"
                    "Content-Length: 11\r\nConnection: close\r\n\r\nBad Gateway";
                send(h->client_fd, r502, sizeof(r502) - 1, MSG_NOSIGNAL);
                conn_close(w, cid, false);
                break;
            }
            /* Normal EOF — backend finished streaming response */
            h->flags &= ~CONN_FLAG_STREAMING_BACKEND;
            /* Backend closed the connection — never return to pool */
            if (h->backend_fd >= 0) {
                uring_remove_fd(&w->uring, (unsigned)FIXED_FD_BACKEND(w, cid));
                close(h->backend_fd); h->backend_fd = -1;
            }
            h->flags &= ~CONN_FLAG_BACKEND_POOLED;
            /* Keep client alive for next request */
            struct io_uring_sqe *sqe = io_uring_get_sqe(&w->uring.ring);
            if (!sqe) { conn_close(w, cid, false); break; }
            PREP_RECV(w, sqe, h->client_fd, FIXED_FD_CLIENT(w, cid),
                conn_recv_buf(&w->pool, cid), h->recv_window, 0, cid);
            sqe->user_data = URING_UD_ENCODE(VORTEX_OP_RECV_CLIENT, cid);
            uring_submit(&w->uring);
            break;
        }
        /* First response byte received — cancel the backend deadline */
        conn_cold_ptr(&w->pool, cid)->backend_deadline_ns = 0;
        h->flags |= CONN_FLAG_STREAMING_BACKEND;
        h->bytes_out += (uint32_t)n;

        /* Track body bytes for keep-alive pool return */
        {
            int _ri = h->route_idx, _bi = h->backend_idx;
            int _ps = w->cfg->routes[_ri].backends[_bi].pool_size;
            if (_ps > 0) {
                struct conn_cold *cold = conn_cold_ptr(&w->pool, cid);
                /* Parse Content-Length from the first response chunk */
                if (cold->backend_content_length == 0 && n > 12) {
                    const uint8_t *sbuf2 = conn_send_buf(&w->pool, cid);
                    const char *clh = (const char *)memmem(sbuf2, (size_t)n,
                                                            "\r\nContent-Length:", 17);
                    if (!clh) clh = (const char *)memmem(sbuf2, (size_t)n,
                                                           "\r\ncontent-length:", 17);
                    if (clh) {
                        const char *cv = clh + 17;
                        while (*cv == ' ') cv++;
                        cold->backend_content_length = (uint32_t)atol(cv);
                    }
                }
                /* Count body bytes (after \r\n\r\n header terminator) */
                if (cold->backend_content_length > 0) {
                    const uint8_t *sbuf2 = conn_send_buf(&w->pool, cid);
                    const char *hend = (const char *)FIND_HDR_END(sbuf2, (size_t)n);
                    if (hend) {
                        size_t body_in_chunk = (size_t)n - (size_t)(hend + 4 - (const char *)sbuf2);
                        cold->backend_body_recv += (uint32_t)body_in_chunk;
                    } else {
                        cold->backend_body_recv += (uint32_t)n;
                    }
                }
            }
        }

        /* Chunked TE reassembly: accumulate body on follow-up recvs */
        if ((h->flags & CONN_FLAG_CACHING) &&
            (n < 5 || memcmp(conn_send_buf(&w->pool, cid), "HTTP/", 5) != 0)) {
            struct conn_cold *cold = conn_cold_ptr(&w->pool, cid);
            if (cold->chunk_buf) {
                bool final = chunked_decode_append(cold,
                    conn_send_buf(&w->pool, cid), (size_t)n);
                if (final) {
                    cache_chunked_store(w, cid, h, cold);
                    h->flags &= ~CONN_FLAG_CACHING;
                }
            }
        }

        /* WebSocket 101 upgrade — switch to io_uring relay mode.
         * Forward the 101 response synchronously (small, bounded), then arm
         * two concurrent io_uring read chains (one per direction) and return.
         * The connection stays alive in the pool; conn_close() will clean up. */
        if ((h->flags & CONN_FLAG_WEBSOCKET_ACTIVE) && n > 12 &&
            memcmp(conn_send_buf(&w->pool, cid), "HTTP/1.1 101", 12) == 0) {
            send(h->client_fd, conn_send_buf(&w->pool, cid), (size_t)n, MSG_NOSIGNAL);

            /* Arm both recv directions simultaneously. */
            struct io_uring_sqe *ws_c = io_uring_get_sqe(&w->uring.ring);
            struct io_uring_sqe *ws_b = io_uring_get_sqe(&w->uring.ring);
            if (!ws_c || !ws_b) { conn_close(w, cid, false); break; }

            /* client → backend direction: recv into recv_buf */
            PREP_RECV(w, ws_c, h->client_fd, FIXED_FD_CLIENT(w, cid),
                conn_recv_buf(&w->pool, cid), w->pool.buf_size, 0, SEND_IDX_RECV(w, cid));
            ws_c->user_data = URING_UD_ENCODE(VORTEX_OP_RECV_CLIENT_WS, cid);

            /* backend → client direction: recv into send_buf */
            PREP_RECV(w, ws_b, h->backend_fd, FIXED_FD_BACKEND(w, cid),
                conn_send_buf(&w->pool, cid), w->pool.buf_size, 0, SEND_IDX_SEND(w, cid));
            ws_b->user_data = URING_UD_ENCODE(VORTEX_OP_RECV_BACKEND_WS, cid);

            uring_submit(&w->uring);
            break;
        }

        /* Response header rewrites — only on the first chunk (starts with "HTTP/") */
        if (n > 7 && memcmp(conn_send_buf(&w->pool, cid), "HTTP/", 5) == 0) {
            uint8_t *sbuf = conn_send_buf(&w->pool, cid);

            /* Locate end of headers */
            uint8_t *hdr_end = (uint8_t *)FIND_HDR_END(sbuf, (size_t)n);
            size_t hdr_len = hdr_end ? (size_t)(hdr_end - sbuf) + 4 : (size_t)n;

            /* ---- Replace/inject Server header ----
             * Uses cfg->server_header (configurable); empty string = pass through. */
            if (w->cfg->server_header[0]) {
                const char *new_srv = w->cfg->server_header;
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
                    int cc_val_len;
                    if (ttl >= 3600) {
                        cc_val_len = snprintf(cc_val, sizeof(cc_val),
                            "public, max-age=%u, immutable", ttl);
                    } else {
                        cc_val_len = snprintf(cc_val, sizeof(cc_val),
                            "public, max-age=%u", ttl);
                    }

                    /* Find existing Cache-Control header */
                    uint8_t *cch = (uint8_t *)memmem(sbuf, hdr_len, "\r\nCache-Control:", 16);
                    if (!cch)
                        cch = (uint8_t *)memmem(sbuf, hdr_len, "\r\ncache-control:", 16);

                    if (cch) {
                        if (ttl >= 3600) {
                            /* Replace value in-place */
                            uint8_t *vs = cch + 16;
                            while (vs < sbuf + hdr_len && (*vs == ' ' || *vs == '\t')) vs++;
                            uint8_t *ve = (uint8_t *)FIND_CRLF(vs,
                                (size_t)(sbuf + hdr_len - vs));
                            if (ve) {
                                size_t old_len = (size_t)(ve - vs);
                                int delta = cc_val_len - (int)old_len;
                                if (n + delta <= (int)w->pool.buf_size && n + delta > 0) {
                                    memmove(vs + cc_val_len, ve, (size_t)(sbuf + n - ve));
                                    memcpy(vs, cc_val, (size_t)cc_val_len);
                                    n += delta;
                                    hdr_end = (uint8_t *)FIND_HDR_END(sbuf, (size_t)n);
                                    hdr_len = hdr_end ? (size_t)(hdr_end - sbuf) + 4 : (size_t)n;
                                }
                            }
                        }
                        /* else ttl==60 and header present: leave it alone */
                    } else {
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

            /* ---- Inject Alt-Svc to advertise HTTP/3 ---- */
#ifdef VORTEX_QUIC
            if (hdr_end) {
                const char *altsvc = "\r\nAlt-Svc: h3=\":443\"; ma=86400";
                int as_len = 30; /* strlen of above */
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

            /* ---- Replace Connection: close → keep-alive ---- */
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
                    /* No Connection header — inject one (24 bytes: \r\nConnection: keep-alive) */
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

            /* ---- Cache store: after all rewrites so stored headers are clean ---- */
            if (w->cache.index) {
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

                                /* Skip chunked responses — we only have the first
                                 * segment and would serve a truncated body from cache. */
                                bool is_chunked =
                                    memmem(resp2, hl2, "\r\nTransfer-Encoding: chunked", 28) ||
                                    memmem(resp2, hl2, "\r\ntransfer-encoding: chunked", 28);

                                /* Only cache if Content-Length matches received bytes
                                 * (guarantees the full body is in this one recv). */
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
                                    cache_store(&w->cache, cc_key2, strlen(cc_key2),
                                        (uint16_t)status2, ttl2,
                                        resp2, hl2, resp2 + hl2, bl2);
                                    log_debug("cache_store",
                                        "conn=%u url=%s ttl=%u body=%zu",
                                        cid, cc_key2, ttl2, bl2);
                                } else if (is_chunked && !(h->flags & CONN_FLAG_CACHING)) {
                                    /* Chunked TE: begin multi-recv reassembly.
                                     * Save rewritten headers + decode body bytes
                                     * in this first recv; continue on RECV_BACKEND. */
                                    struct conn_cold *cold2 = conn_cold_ptr(&w->pool, cid);
                                    uint32_t hlen2 = (uint32_t)hl2;
                                    uint32_t init_cap = hlen2 + 65536;
                                    cold2->chunk_buf = malloc(init_cap);
                                    if (cold2->chunk_buf) {
                                        cold2->chunk_buf_cap  = init_cap;
                                        cold2->chunk_hdr_len  = hlen2;
                                        cold2->chunk_body_len = 0;
                                        cold2->chunk_remaining = 0;
                                        cold2->chunk_skip_crlf = false;
                                        cold2->chunk_ttl = ttl2;
                                        make_cache_key(req2, (size_t)w->pool.buf_size,
                                                       cc_url2,
                                                       cold2->chunk_url,
                                                       sizeof(cold2->chunk_url));
                                        /* Copy rewritten response headers verbatim */
                                        memcpy(cold2->chunk_buf, resp2, hlen2);
                                        h->flags |= CONN_FLAG_CACHING;
                                        /* Decode any body bytes in this recv */
                                        if (bl2 > 0) {
                                            bool fin2 = chunked_decode_append(cold2,
                                                resp2 + hlen2, bl2);
                                            if (fin2) {
                                                cache_chunked_store(w, cid, h, cold2);
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

        /* ---- Record compressibility for splice gating ----
         * Only on the first response chunk (starts with "HTTP/").  Subsequent
         * chunks contain raw body bytes with no headers — scanning them would
         * always find no Content-Type, resetting ct_compressible to 0 and
         * incorrectly enabling splice for compressible types (HTML, JSON, JS).
         * ct_compressible defaults to 0 in conn_hot; we only set it to 1 here
         * when we positively identify a compressible Content-Type. */
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
                /* No Content-Type — treat as non-compressible (safe for splice) */
                h->ct_compressible = 0;
            }
        }

        /* ---- Brotli / gzip compression ----
         * Only on complete single-chunk responses (Content-Length present and
         * matching) with a compressible Content-Type.  Prefer brotli (br) when
         * the client supports it — typically 15-25% smaller than gzip at the
         * same CPU cost.  recv_buf is free at this point (client request already
         * forwarded) and used as scratch.  Cache store above saved uncompressed. */
        if ((h->flags & (CONN_FLAG_CLIENT_BR | CONN_FLAG_CLIENT_GZIP)) && n > 0) {
            uint8_t *sbuf_gz = conn_send_buf(&w->pool, cid);
            const uint8_t *hend_gz = (const uint8_t *)FIND_HDR_END(sbuf_gz, (size_t)n);
            if (hend_gz) {
                size_t hdr_end_off = (size_t)(hend_gz - sbuf_gz);
                size_t body_off    = hdr_end_off + 4; /* past \r\n\r\n */
                size_t body_len    = (size_t)n - body_off;

                /* Verify Content-Length matches body in buffer (complete response) */
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

                /* Check Content-Type is compressible and not already encoded */
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
                            /* Pick algorithm: prefer brotli, fall back to gzip */
                            bool use_br = (h->flags & CONN_FLAG_CLIENT_BR) != 0;
                            uint8_t *scratch = conn_recv_buf(&w->pool, cid);
                            size_t clen = use_br
                                ? brotli_compress(sbuf_gz + body_off, body_len,
                                                  scratch, w->pool.buf_size)
                                : gzip_compress(sbuf_gz + body_off, body_len,
                                                scratch, w->pool.buf_size);
                            /* Fall back to gzip if brotli failed or didn't shrink */
                            if (use_br && (clen == 0 || clen >= body_len)) {
                                use_br = false;
                                clen = gzip_compress(sbuf_gz + body_off, body_len,
                                                     scratch, w->pool.buf_size);
                            }

                            /* Only proceed if compression reduced size */
                            if (clen > 0 && clen < body_len) {
                                /* 1. Update Content-Length in-place */
                                uint8_t *clh3 = (uint8_t *)memmem(
                                    sbuf_gz, hdr_end_off + 4, "\r\nContent-Length:", 17);
                                if (!clh3) clh3 = (uint8_t *)memmem(
                                    sbuf_gz, hdr_end_off + 4, "\r\ncontent-length:", 17);
                                if (clh3) {
                                    uint8_t *vs = clh3 + 17;
                                    while (*vs == ' ') vs++;
                                    uint8_t *ve = (uint8_t *)FIND_CRLF(vs,
                                        (size_t)(sbuf_gz + hdr_end_off - vs));
                                    if (ve) {
                                        char new_cl[20];
                                        int ncl = snprintf(new_cl, sizeof(new_cl), "%zu", clen);
                                        int delta = ncl - (int)(ve - vs);
                                        memmove(vs + ncl, ve,
                                            (size_t)(sbuf_gz + hdr_end_off + 4 - ve));
                                        memcpy(vs, new_cl, (size_t)ncl);
                                        hdr_end_off = (size_t)((int)hdr_end_off + delta);
                                    }
                                }

                                /* 2. Insert Content-Encoding header before \r\n\r\n */
                                const char *ce_hdr = use_br
                                    ? "\r\nContent-Encoding: br"
                                    : "\r\nContent-Encoding: gzip";
                                int ce_len = use_br ? 22 : 24;
                                memmove(sbuf_gz + hdr_end_off + ce_len,
                                        sbuf_gz + hdr_end_off, 4);
                                memcpy(sbuf_gz + hdr_end_off, ce_hdr, (size_t)ce_len);
                                size_t new_body_off = hdr_end_off + (size_t)ce_len + 4;

                                /* 3. Copy compressed body after headers */
                                if (new_body_off + clen <= w->pool.buf_size) {
                                    memcpy(sbuf_gz + new_body_off, scratch, clen);
                                    n = (int)(new_body_off + clen);
                                    log_debug("compress", "conn=%u %s %zu→%zu bytes",
                                              cid, use_br ? "br" : "gzip", body_len, clen);
                                }
                            }
                        }
                    }
                }
            }
        }

        /* Forward backend data to client */
        h->send_buf_off = 0;
        h->send_buf_len = (uint32_t)n;
        struct io_uring_sqe *sqe = io_uring_get_sqe(&w->uring.ring);
        if (!sqe) { conn_close(w, cid, true); break; }
        if (w->uring.bufs_registered && !(h->flags & CONN_FLAG_KTLS_TX)) {
            /* Zero-copy: kernel reads directly from pinned registered buffer.
             * send_zc is incompatible with kTLS TX (like splice) — the kernel
             * cannot handle zero-copy sends through the kTLS record layer.
             * Two CQEs: completion (bytes transferred) + notification (buffer released).
             * We arm next recv only after the notification — see SEND_CLIENT_ZC handler. */
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
        break;
    }

    case VORTEX_OP_SEND_CLIENT: {
        int sent = cqe->res;
        log_debug("send_client", "conn=%u sent=%d", cid, sent);
        if (sent < 0) { conn_close(w, cid, true); break; }
        h->send_buf_off += (uint32_t)sent;

        if (h->send_buf_off < h->send_buf_len) {
            /* Partial send (kTLS record boundary) — flush remaining bytes */
            struct io_uring_sqe *sqe = io_uring_get_sqe(&w->uring.ring);
            if (!sqe) { conn_close(w, cid, true); break; }
            PREP_SEND(w, sqe, h->client_fd, FIXED_FD_CLIENT(w, cid),
                conn_send_buf(&w->pool, cid) + h->send_buf_off,
                h->send_buf_len - h->send_buf_off, MSG_NOSIGNAL, SEND_IDX_SEND(w, cid));
            sqe->user_data = URING_UD_ENCODE(VORTEX_OP_SEND_CLIENT, cid);
            uring_submit(&w->uring);
            break;
        }

        /* Full chunk sent */
        h->send_buf_off = 0;
        h->send_buf_len = 0;

        /* Check if a poolable backend response is now complete.
         * When it is, keep the fd installed in the fixed slot (sticky backend):
         * the same client connection will reuse it for its next request with
         * zero pool operations.  We only release the fd to the global pool when
         * the client connection itself closes (see conn_close). */
        if (h->flags & CONN_FLAG_STREAMING_BACKEND) {
            int ri = h->route_idx, bi = h->backend_idx;
            int ps = w->cfg->routes[ri].backends[bi].pool_size;
            if (ps > 0) {
                struct conn_cold *cold = conn_cold_ptr(&w->pool, cid);
                if (cold->backend_content_length > 0 &&
                    cold->backend_body_recv >= cold->backend_content_length) {
                    /* Full response forwarded — mark backend idle, keep fd pinned */
                    h->flags &= ~(CONN_FLAG_STREAMING_BACKEND | CONN_FLAG_BACKEND_POOLED);
                    cold->backend_content_length = 0;
                    cold->backend_body_recv      = 0;
                    log_debug("backend_sticky", "conn=%u route=%d backend=%d fd=%d",
                        cid, ri, bi, h->backend_fd);
                }
            }
        }

        if (h->flags & CONN_FLAG_STREAMING_BACKEND) {
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
                break;
            }
            /* Still reading backend response — get next chunk */
            struct io_uring_sqe *sqe = io_uring_get_sqe(&w->uring.ring);
            if (!sqe) { conn_close(w, cid, true); break; }
            PREP_RECV(w, sqe, h->backend_fd, FIXED_FD_BACKEND(w, cid),
                conn_send_buf(&w->pool, cid), h->recv_window, 0, SEND_IDX_SEND(w, cid));
            sqe->user_data = URING_UD_ENCODE(VORTEX_OP_RECV_BACKEND, cid);
            uring_submit(&w->uring);
        } else {
            /* Response complete (cache hit, single chunk, or pool return) — next request */
            struct io_uring_sqe *sqe = io_uring_get_sqe(&w->uring.ring);
            if (!sqe) { conn_close(w, cid, true); break; }
            PREP_RECV(w, sqe, h->client_fd, FIXED_FD_CLIENT(w, cid),
                conn_recv_buf(&w->pool, cid), h->recv_window, 0, cid);
            sqe->user_data = URING_UD_ENCODE(VORTEX_OP_RECV_CLIENT, cid);
            uring_submit(&w->uring);
        }
        break;
    }

    case VORTEX_OP_SEND_CLIENT_LINKED: {
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
            break;
        }
        h->send_buf_off += (uint32_t)sent;
        if (h->send_buf_off < h->send_buf_len) {
            /* Partial send — flush remainder; pre-armed recv is still in flight */
            struct io_uring_sqe *sqe = io_uring_get_sqe(&w->uring.ring);
            if (!sqe) { conn_close(w, cid, true); break; }
            PREP_SEND(w, sqe, h->client_fd, FIXED_FD_CLIENT(w, cid),
                conn_send_buf(&w->pool, cid) + h->send_buf_off,
                h->send_buf_len - h->send_buf_off, MSG_NOSIGNAL, SEND_IDX_SEND(w, cid));
            sqe->user_data = URING_UD_ENCODE(VORTEX_OP_SEND_CLIENT, cid);
            uring_submit(&w->uring);
        }
        /* Full send: recv already queued by kernel — nothing else to submit */
        h->send_buf_off = 0;
        h->send_buf_len = 0;
        break;
    }

    case VORTEX_OP_SPLICE_BACKEND: {
        /* Kernel spliced n bytes from backend_fd into splice_pipe[1] */
        int n = cqe->res;
        log_debug("splice_backend", "conn=%u n=%d", cid, n);
        if (n < 0) { conn_close(w, cid, true); break; }
        if (n == 0) {
            /* Backend EOF — done streaming */
            h->flags &= ~(CONN_FLAG_STREAMING_BACKEND | CONN_FLAG_SPLICE_MODE);
            if (h->backend_fd >= 0) {
                uring_remove_fd(&w->uring, (unsigned)FIXED_FD_BACKEND(w, cid));
                close(h->backend_fd); h->backend_fd = -1;
            }
            h->flags &= ~CONN_FLAG_BACKEND_POOLED;
            struct io_uring_sqe *sqe = io_uring_get_sqe(&w->uring.ring);
            if (!sqe) { conn_close(w, cid, false); break; }
            PREP_RECV(w, sqe, h->client_fd, FIXED_FD_CLIENT(w, cid),
                conn_recv_buf(&w->pool, cid), h->recv_window, 0, cid);
            sqe->user_data = URING_UD_ENCODE(VORTEX_OP_RECV_CLIENT, cid);
            uring_submit(&w->uring);
            break;
        }
        /* Bytes are in the pipe — splice pipe[0] → client_fd */
        h->bytes_out += (uint32_t)n;
        struct conn_cold *cold = conn_cold_ptr(&w->pool, cid);
        struct io_uring_sqe *sqe = io_uring_get_sqe(&w->uring.ring);
        if (!sqe) { conn_close(w, cid, true); break; }
        io_uring_prep_splice(sqe, cold->splice_pipe[0], -1,
                             h->client_fd, -1,
                             (unsigned int)n, SPLICE_F_MOVE);
        sqe->user_data = URING_UD_ENCODE(VORTEX_OP_SPLICE_CLIENT, cid);
        uring_submit(&w->uring);
        break;
    }

    case VORTEX_OP_SPLICE_CLIENT: {
        /* Kernel spliced bytes from pipe → client_fd */
        int sent = cqe->res;
        log_debug("splice_client", "conn=%u sent=%d", cid, sent);
        if (sent < 0) { conn_close(w, cid, true); break; }
        /* Loop: splice next chunk from backend into pipe */
        if (h->flags & CONN_FLAG_STREAMING_BACKEND) {
            struct conn_cold *cold = conn_cold_ptr(&w->pool, cid);
            struct io_uring_sqe *sqe = io_uring_get_sqe(&w->uring.ring);
            if (!sqe) { conn_close(w, cid, true); break; }
            io_uring_prep_splice(sqe, h->backend_fd, -1,
                                 cold->splice_pipe[1], -1,
                                 (unsigned int)(1u << 20), SPLICE_F_MOVE);
            sqe->user_data = URING_UD_ENCODE(VORTEX_OP_SPLICE_BACKEND, cid);
            uring_submit(&w->uring);
        } else {
            /* Streaming flag cleared elsewhere (shouldn't normally reach here) */
            struct io_uring_sqe *sqe = io_uring_get_sqe(&w->uring.ring);
            if (!sqe) { conn_close(w, cid, false); break; }
            PREP_RECV(w, sqe, h->client_fd, FIXED_FD_CLIENT(w, cid),
                conn_recv_buf(&w->pool, cid), h->recv_window, 0, cid);
            sqe->user_data = URING_UD_ENCODE(VORTEX_OP_RECV_CLIENT, cid);
            uring_submit(&w->uring);
        }
        break;
    }

    case VORTEX_OP_CONNECT: {
        /* Async backend connect completed */
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
            const char *r502 =
                "HTTP/1.1 502 Bad Gateway\r\n"
                "Content-Length: 11\r\nConnection: close\r\n\r\nBad Gateway";
            send(h->client_fd, r502, strlen(r502), MSG_NOSIGNAL);
            conn_close(w, cid, false);
            break;
        }
        log_debug("connect_cqe", "conn=%u backend_fd=%d connected", cid, h->backend_fd);

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

            /* Rewrite Connection: keep-alive → close so the backend signals
             * response completion with EOF, allowing RECV_CLIENT to re-arm. */
            {
                uint8_t *ch = (uint8_t *)memmem(rbuf, (size_t)fwd_n, "\r\nConnection:", 13);
                if (!ch)
                    ch = (uint8_t *)memmem(rbuf, (size_t)fwd_n, "\r\nconnection:", 13);
                if (ch) {
                    uint8_t *vs = ch + 13;
                    while (vs < rbuf + fwd_n && (*vs == ' ' || *vs == '\t')) vs++;
                    uint8_t *ve = (uint8_t *)FIND_CRLF(vs,
                        (size_t)(rbuf + fwd_n - vs));
                    if (ve && ve > vs) {
                        size_t old_len = (size_t)(ve - vs);
                        int delta = 5 - (int)old_len; /* "close" = 5 bytes */
                        if (fwd_n + delta <= (int)w->pool.buf_size && fwd_n + delta > 0) {
                            memmove(vs + 5, ve, (size_t)(rbuf + fwd_n - ve));
                            memcpy(vs, "close", 5);
                            fwd_n += delta;
                        }
                    }
                } else {
                    /* No Connection header — inject one after the request line */
                    const char *eol0 = (const char *)FIND_CRLF(rbuf, (size_t)fwd_n);
                    if (eol0 && fwd_n + 19 <= (int)w->pool.buf_size) {
                        size_t le = (size_t)(eol0 - (const char *)rbuf) + 2;
                        memmove(rbuf + le + 19, rbuf + le, (size_t)fwd_n - le);
                        memcpy(rbuf + le, "Connection: close\r\n", 19);
                        fwd_n += 19;
                    }
                }
            }

            struct io_uring_sqe *sqe_s = io_uring_get_sqe(&w->uring.ring);
            if (!sqe_s) { conn_close(w, cid, true); break; }
            PREP_SEND(w, sqe_s, h->backend_fd, FIXED_FD_BACKEND(w, cid),
                rbuf, (size_t)fwd_n, MSG_NOSIGNAL, SEND_IDX_RECV(w, cid));
            sqe_s->user_data = URING_UD_ENCODE(VORTEX_OP_SEND_BACKEND, cid);
        } else {
            /* Initial connect: arm RECV_CLIENT to get the first request */
            struct io_uring_sqe *sqe_c = io_uring_get_sqe(&w->uring.ring);
            if (!sqe_c) { conn_close(w, cid, true); break; }
            PREP_RECV(w, sqe_c, h->client_fd, FIXED_FD_CLIENT(w, cid),
                conn_recv_buf(&w->pool, cid), h->recv_window, 0, cid);
            sqe_c->user_data = URING_UD_ENCODE(VORTEX_OP_RECV_CLIENT, cid);
        }
        uring_submit(&w->uring);
        break;
    }

    /* --- WebSocket relay: client → backend direction ---
     *
     * Recv completed: n bytes of client data sit in recv_buf.
     * Queue an async send to the backend; the buffer must not be reused
     * until SEND_BACKEND_WS fires, so RECV_CLIENT_WS is re-armed there. */
    case VORTEX_OP_RECV_CLIENT_WS: {
        int n = cqe->res;
        if (n <= 0) { conn_close(w, cid, false); break; }
        struct io_uring_sqe *sqe_ws_c = io_uring_get_sqe(&w->uring.ring);
        if (!sqe_ws_c) { conn_close(w, cid, false); break; }
        PREP_SEND(w, sqe_ws_c, h->backend_fd, FIXED_FD_BACKEND(w, cid),
            conn_recv_buf(&w->pool, cid), (size_t)n, MSG_NOSIGNAL, SEND_IDX_RECV(w, cid));
        sqe_ws_c->user_data = URING_UD_ENCODE(VORTEX_OP_SEND_BACKEND_WS, cid);
        uring_submit(&w->uring);
        break;
    }

    /* Send to backend completed — recv_buf is free; re-arm the client recv. */
    case VORTEX_OP_SEND_BACKEND_WS: {
        if (cqe->res <= 0) { conn_close(w, cid, false); break; }
        struct io_uring_sqe *sqe_ws_c = io_uring_get_sqe(&w->uring.ring);
        if (!sqe_ws_c) { conn_close(w, cid, false); break; }
        PREP_RECV(w, sqe_ws_c, h->client_fd, FIXED_FD_CLIENT(w, cid),
            conn_recv_buf(&w->pool, cid), w->pool.buf_size, 0, SEND_IDX_RECV(w, cid));
        sqe_ws_c->user_data = URING_UD_ENCODE(VORTEX_OP_RECV_CLIENT_WS, cid);
        uring_submit(&w->uring);
        break;
    }

    /* --- WebSocket relay: backend → client direction ---
     *
     * Recv completed: n bytes of backend data sit in send_buf.
     * Queue an async send to the client; re-arm RECV_BACKEND_WS in SEND_CLIENT_WS. */
    case VORTEX_OP_RECV_BACKEND_WS: {
        int n = cqe->res;
        if (n <= 0) { conn_close(w, cid, false); break; }
        struct io_uring_sqe *sqe_ws_b = io_uring_get_sqe(&w->uring.ring);
        if (!sqe_ws_b) { conn_close(w, cid, false); break; }
        PREP_SEND(w, sqe_ws_b, h->client_fd, FIXED_FD_CLIENT(w, cid),
            conn_send_buf(&w->pool, cid), (size_t)n, MSG_NOSIGNAL, SEND_IDX_SEND(w, cid));
        sqe_ws_b->user_data = URING_UD_ENCODE(VORTEX_OP_SEND_CLIENT_WS, cid);
        uring_submit(&w->uring);
        break;
    }

    /* Send to client completed — send_buf is free; re-arm the backend recv. */
    case VORTEX_OP_SEND_CLIENT_WS: {
        if (cqe->res <= 0) { conn_close(w, cid, false); break; }
        struct io_uring_sqe *sqe_ws_b = io_uring_get_sqe(&w->uring.ring);
        if (!sqe_ws_b) { conn_close(w, cid, false); break; }
        PREP_RECV(w, sqe_ws_b, h->backend_fd, FIXED_FD_BACKEND(w, cid),
            conn_send_buf(&w->pool, cid), w->pool.buf_size, 0, SEND_IDX_SEND(w, cid));
        sqe_ws_b->user_data = URING_UD_ENCODE(VORTEX_OP_RECV_BACKEND_WS, cid);
        uring_submit(&w->uring);
        break;
    }

    case VORTEX_OP_SEND_CLIENT_ZC: {
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
                struct io_uring_sqe *sqe = io_uring_get_sqe(&w->uring.ring);
                if (!sqe) { conn_close(w, cid, true); break; }
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
            break;
        }

        /* Completion CQE */
        int zc_sent = cqe->res;
        if (zc_sent <= 0) { conn_close(w, cid, true); break; }
        h->bytes_out += (uint32_t)zc_sent;
        /* Note: do NOT arm next recv here — wait for the NOTIF CQE */
        break;
    }

#ifdef VORTEX_H2
    case VORTEX_OP_H2_RECV_CLIENT: {
        h2_on_recv(w, cid, cqe->res);
        break;
    }
    case VORTEX_OP_H2_SEND_CLIENT: {
        h2_on_send_client(w, cid, cqe->res);
        break;
    }
#endif

    default: break;
    }
}
