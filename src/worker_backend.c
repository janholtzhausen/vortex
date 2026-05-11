#define _GNU_SOURCE
/*
 * worker_backend.c — circuit breaker state, backend selection, and async
 * TCP connect for the vortex worker event loop.
 *
 * Functions here are called from handle_proxy_data (worker_proxy.c) at the
 * point where a client request needs routing to an upstream server.
 */
#include "worker_internal.h"

#ifdef VORTEX_PHASE_TLS
#include <picotls.h>
#include <poll.h>
#include <stdlib.h>

static uint32_t backend_timeout_ms_for(struct worker *w, uint32_t cid)
{
    struct conn_hot *h = conn_hot(&w->pool, cid);
    uint32_t tmo_ms = w->cfg->routes[h->route_idx].backend_timeout_ms;
    return tmo_ms ? tmo_ms : 30000;
}

static const char *backend_server_name(const struct backend_config *bcfg, char *fallback,
                                       size_t fallback_sz)
{
    if (bcfg->sni[0]) return bcfg->sni;

    const char *addr = bcfg->address;
    const char *colon = strrchr(addr, ':');
    size_t host_len = colon ? (size_t)(colon - addr) : strlen(addr);
    if (host_len >= fallback_sz) host_len = fallback_sz - 1;
    memcpy(fallback, addr, host_len);
    fallback[host_len] = '\0';
    return fallback;
}
#endif

bool backend_uses_tls(struct worker *w, uint32_t cid)
{
    struct conn_hot *h = conn_hot(&w->pool, cid);
    return (h->flags & CONN_FLAG_BACKEND_TLS) != 0;
}

int backend_tls_handshake(struct worker *w, const struct backend_config *bcfg, uint32_t cid)
{
#ifdef VORTEX_PHASE_TLS
    struct conn_hot *h = conn_hot(&w->pool, cid);
    struct conn_cold *cold = conn_cold_ptr(&w->pool, cid);
    char sni_buf[256];
    const char *server_name;
    uint32_t timeout_ms;

    if (!bcfg->tls) return 0;
    if (!w->backend_tls_client_ctx || h->backend_fd < 0) return -1;

    server_name = backend_server_name(bcfg, sni_buf, sizeof(sni_buf));
    timeout_ms = backend_timeout_ms_for(w, cid);

    struct tls_session_ticket *resume = NULL;
    if (h->route_idx < VORTEX_MAX_ROUTES && h->backend_idx < VORTEX_MAX_BACKENDS)
        resume = w->backend_tls_sessions[h->route_idx][h->backend_idx];

    struct tls_session_ticket *new_ticket = NULL;
    ptls_t *ptls = tls_backend_connect(w->backend_tls_client_ctx, h->backend_fd, server_name,
                                       timeout_ms, resume, &new_ticket);
    if (!ptls) return -1;

    if (new_ticket && h->route_idx < VORTEX_MAX_ROUTES && h->backend_idx < VORTEX_MAX_BACKENDS) {
        free(w->backend_tls_sessions[h->route_idx][h->backend_idx]);
        w->backend_tls_sessions[h->route_idx][h->backend_idx] = new_ticket;
    } else {
        free(new_ticket);
    }

    cold->backend_ssl = ptls;
    h->flags |= CONN_FLAG_BACKEND_TLS;
    h->flags &= ~CONN_FLAG_BACKEND_POOLED;
    return 0;
#else
    (void)w;
    (void)bcfg;
    (void)cid;
    return -1;
#endif
}

int backend_tls_send_all(struct worker *w, uint32_t cid, const uint8_t *buf, size_t len)
{
#ifdef VORTEX_PHASE_TLS
    struct conn_hot *h = conn_hot(&w->pool, cid);
    struct conn_cold *cold = conn_cold_ptr(&w->pool, cid);
    ptls_t *ptls = (ptls_t *)cold->backend_ssl;

    if (!ptls) return -1;

    /* ptls_send encrypts and writes to a buffer; we then write to socket */
    uint8_t wbuf_small[16384];
    ptls_buffer_t wbuf;
    ptls_buffer_init(&wbuf, wbuf_small, sizeof(wbuf_small));

    int ret = ptls_send(ptls, &wbuf, buf, len);
    if (ret != 0) {
        ptls_buffer_dispose(&wbuf);
        log_warn("backend_tls_send", "conn=%u ptls_send failed ret=%d", cid, ret);
        return -1;
    }

    /* Backend fd is non-blocking.  Never poll() here — this runs in the worker
     * io_uring event loop.  On EAGAIN, queue remaining encrypted bytes and arm a
     * VORTEX_OP_BACKEND_TLS_DRAIN POLLOUT so the event loop resumes when writable.
     * Returns: (int)len = fully sent; 0 = queued (POLLOUT armed, do NOT arm
     * RECV_BACKEND yet); -1 = fatal error (close connection). */
    size_t off = 0;
    while (off < wbuf.off) {
        ssize_t n = write(h->backend_fd, wbuf.base + off, wbuf.off - off);
        if (n > 0) {
            off += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            size_t rem = wbuf.off - off;
            uint8_t *saved = malloc(rem);
            if (!saved) {
                ptls_buffer_dispose(&wbuf);
                log_warn("backend_tls_send", "conn=%u OOM queueing %zu pending bytes", cid, rem);
                return -1;
            }
            memcpy(saved, wbuf.base + off, rem);
            ptls_buffer_dispose(&wbuf);
            free(cold->backend_tls_pending);
            cold->backend_tls_pending = saved;
            cold->backend_tls_pending_len = (uint32_t)rem;
            cold->backend_tls_pending_off = 0;
            h->flags |= CONN_FLAG_BACKEND_TLS_SEND_PENDING;
            struct io_uring_sqe *sqe = io_uring_get_sqe(&w->uring.ring);
            if (!sqe) {
                free(cold->backend_tls_pending);
                cold->backend_tls_pending = NULL;
                h->flags &= ~CONN_FLAG_BACKEND_TLS_SEND_PENDING;
                return -1;
            }
            io_uring_prep_poll_add(sqe, h->backend_fd, POLLOUT);
            sqe->user_data = URING_UD_ENCODE(VORTEX_OP_BACKEND_TLS_DRAIN, cid);
            uring_submit(&w->uring);
            log_debug("backend_tls_send", "conn=%u EAGAIN — queued %zu bytes, POLLOUT armed", cid,
                      rem);
            return 0;
        }
        ptls_buffer_dispose(&wbuf);
        log_warn("backend_tls_send", "conn=%u write failed: %s", cid, strerror(errno));
        return -1;
    }
    ptls_buffer_dispose(&wbuf);
    return (int)len;
#else
    (void)w;
    (void)cid;
    (void)buf;
    (void)len;
    return -1;
#endif
}

int backend_tls_recv_some(struct worker *w, uint32_t cid, uint8_t *buf, size_t len)
{
#ifdef VORTEX_PHASE_TLS
    struct conn_hot *h = conn_hot(&w->pool, cid);
    struct conn_cold *cold = conn_cold_ptr(&w->pool, cid);
    ptls_t *ptls = (ptls_t *)cold->backend_ssl;

    if (!ptls) return -1;

    /* Read encrypted data from the backend socket */
    uint8_t ibuf[16384];
    ssize_t nr = recv(h->backend_fd, ibuf, sizeof(ibuf), 0);
    if (nr < 0) {
        if (errno == EINTR || errno == EAGAIN) return 0;
        return -1;
    }
    if (nr == 0) return 0; /* EOF */

    /* Decrypt via picotls */
    ptls_buffer_t plainbuf;
    uint8_t plainbuf_small[16384];
    ptls_buffer_init(&plainbuf, plainbuf_small, sizeof(plainbuf_small));

    size_t consumed = (size_t)nr;
    int ret = ptls_receive(ptls, &plainbuf, ibuf, &consumed);
    if (ret != 0 && ret != PTLS_ERROR_IN_PROGRESS) {
        ptls_buffer_dispose(&plainbuf);
        log_warn("backend_tls_recv", "conn=%u ptls_receive failed ret=%d", cid, ret);
        return -1;
    }

    size_t out_len = plainbuf.off < len ? plainbuf.off : len;
    if (out_len > 0) memcpy(buf, plainbuf.base, out_len);
    ptls_buffer_dispose(&plainbuf);
    return (int)out_len;
#else
    (void)w;
    (void)cid;
    (void)buf;
    (void)len;
    return -1;
#endif
}

/* Circuit breaker functions are now in router.c (global, shared across workers). */

/*
 * Select an available (non-open-circuit) backend for the given route.
 * Tries the LB-selected backend first, then walks other backends.
 * Returns backend index, or -1 if every backend's circuit is open.
 * When a circuit whose timeout has elapsed is selected, it acts as a
 * HALF_OPEN probe: the next connect result will reset or re-open it.
 */
int select_available_backend(struct worker *w, int ri, uint32_t client_ip)
{
    const struct route_config *rc = &w->cfg->routes[ri];
    int n = rc->backend_count;
    if (n == 0) return -1;

    struct timespec _cb_ts;
    clock_gettime(CLOCK_MONOTONIC_COARSE, &_cb_ts);
    uint64_t now_ns = (uint64_t)_cb_ts.tv_sec * 1000000000ULL + _cb_ts.tv_nsec;

    int primary = router_select_backend(&w->router, ri, client_ip);
    for (int i = 0; i < n; i++) {
        int bi = (primary + i) % n;
        if (!cb_is_open_global(ri, bi, now_ns)) return bi;
    }
    return -1; /* all backends open — caller sends 503 */
}

/* Set backend response deadline for a connection.
 * timeout_ms = 0 → use BACKEND_DEFAULT_TIMEOUT_MS. */
void backend_deadline_set(struct worker *w, uint32_t cid, uint32_t timeout_ms)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);
    uint64_t now_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
    uint64_t ms = timeout_ms ? timeout_ms : BACKEND_DEFAULT_TIMEOUT_MS;
    conn_cold_ptr(&w->pool, cid)->backend_deadline_ns = now_ns + ms * 1000000ULL;
}

/* ------------------------------------------------------------------ */
/* Async backend connect via io_uring CONNECT                          */
/* ------------------------------------------------------------------ */

/*
 * Resolve addr_str ("host:port"), create a non-blocking socket, store the
 * resolved address in conn_cold for use when CONNECT completes, and issue
 * an io_uring CONNECT sqe.  Returns the new fd on success, -1 on error.
 * The caller must NOT read from or write to the fd until VORTEX_OP_CONNECT
 * completes on the io_uring ring.
 */
int begin_async_connect(struct worker *w, const struct backend_config *bcfg, uint32_t cid)
{
    struct conn_cold *cold = conn_cold_ptr(&w->pool, cid);

    if (bcfg->resolved_addrlen > 0) {
        /* Fast path: use pre-resolved address — no blocking DNS call */
        memcpy(&cold->backend_addr, &bcfg->resolved_addr, bcfg->resolved_addrlen);
        cold->backend_addrlen = bcfg->resolved_addrlen;
    } else {
        /* Fallback: address not pre-resolved (parse error at startup?), resolve now */
        const char *addr_str = bcfg->address;
        char host[256], port_str[16];
        const char *colon = strrchr(addr_str, ':');
        if (!colon) return -1;
        size_t hlen = (size_t)(colon - addr_str);
        if (hlen >= sizeof(host)) return -1;
        memcpy(host, addr_str, hlen);
        host[hlen] = '\0';
        snprintf(port_str, sizeof(port_str), "%s", colon + 1);

        struct addrinfo hints = {
            .ai_family = AF_UNSPEC,
            .ai_socktype = SOCK_STREAM,
            .ai_flags = AI_ADDRCONFIG,
        };
        struct addrinfo *res = NULL;
        if (getaddrinfo(host, port_str, &hints, &res) != 0) {
            log_error("async_connect", "getaddrinfo(%s) failed: %s", addr_str, strerror(errno));
            return -1;
        }
        bool got = false;
        for (int pass = 0; pass < 2 && !got; pass++) {
            int family = (pass == 0) ? AF_INET : AF_UNSPEC;
            for (struct addrinfo *rp = res; rp; rp = rp->ai_next) {
                if (family != AF_UNSPEC && rp->ai_family != family) continue;
                if (rp->ai_addrlen <= sizeof(cold->backend_addr)) {
                    memcpy(&cold->backend_addr, rp->ai_addr, rp->ai_addrlen);
                    cold->backend_addrlen = (socklen_t)rp->ai_addrlen;
                    got = true;
                    break;
                }
            }
        }
        freeaddrinfo(res);
        if (!got) {
            log_error("async_connect", "no usable addr for %s", addr_str);
            return -1;
        }
    }

    int fd = socket(cold->backend_addr.ss_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0) {
        log_error("async_connect", "socket() failed: %s", strerror(errno));
        return -1;
    }

    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    /* ACK backend data immediately — backend is LAN/loopback so delayed ACK
     * (40 ms) would needlessly throttle throughput on short responses. */
    setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &one, sizeof(one));
    /* Same NOTSENT_LOWAT as the client side — keeps per-connection kernel
     * send buffer pressure at one chunk rather than growing unbounded. */
    int lowat = WORKER_BUF_SIZE;
    setsockopt(fd, IPPROTO_TCP, TCP_NOTSENT_LOWAT, &lowat, sizeof(lowat));

    /* TCP_USER_TIMEOUT — kernel drops connection when data is unACKed for
     * longer than backend_timeout_ms.  Without this the default retransmit
     * window is ~15 min, turning a dead backend into a silent hang. */
    struct conn_hot *_ch = conn_hot(&w->pool, cid);
    int ri = _ch->route_idx;
    uint32_t tmo_ms = w->cfg->routes[ri].backend_timeout_ms;
    if (tmo_ms == 0) tmo_ms = 30000; /* match default deadline */
    setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &tmo_ms, sizeof(tmo_ms));

    /* SO_KEEPALIVE — detect silently-dead backends on pooled connections.
     * Keepalive probes start after 5 s idle, repeat every 5 s, abandon
     * after 3 missed probes (total ~20 s to declare a pooled conn dead). */
    if (bcfg->pool_size > 0) {
        setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
        int idle = 5, intvl = 5, cnt = 3;
        setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
        setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
        setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt));
    }

    /* TCP congestion control — per-route override, then global, then kernel default */
    const char *cc = w->cfg->routes[ri].congestion_control[0]
                         ? w->cfg->routes[ri].congestion_control
                         : w->cfg->congestion_control;
    if (cc[0]) setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, cc, (socklen_t)strlen(cc));

    /* Issue async CONNECT — returns EINPROGRESS immediately */
    struct io_uring_sqe *sqe = io_uring_get_sqe(&w->uring.ring);
    if (!sqe) {
        close(fd);
        return -1;
    }
    io_uring_prep_connect(sqe, fd, (struct sockaddr *)&cold->backend_addr, cold->backend_addrlen);
    sqe->user_data = URING_UD_ENCODE(VORTEX_OP_CONNECT, cid);
    uring_submit(&w->uring);

    /* Arm deadline covering both connect and first response byte */
    struct conn_hot *_h = conn_hot(&w->pool, cid);
    backend_deadline_set(w, cid, w->cfg->routes[_h->route_idx].backend_timeout_ms);
    log_debug("async_connect", "conn=%u fd=%d -> %s (CONNECT in flight)", cid, fd, bcfg->address);
    return fd;
}
