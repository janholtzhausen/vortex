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
#include <openssl/err.h>
#include <openssl/x509v3.h>

static void log_backend_ssl_errors(const char *tag)
{
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        log_error(tag, "OpenSSL: %s", buf);
    }
}

static uint32_t backend_timeout_ms_for(struct worker *w, uint32_t cid)
{
    struct conn_hot *h = conn_hot(&w->pool, cid);
    uint32_t tmo_ms = w->cfg->routes[h->route_idx].backend_timeout_ms;
    return tmo_ms ? tmo_ms : 30000;
}

static int backend_ssl_wait(int fd, bool want_read, uint32_t timeout_ms)
{
    fd_set rset, wset;
    struct timeval tv;

    FD_ZERO(&rset);
    FD_ZERO(&wset);
    if (want_read)
        FD_SET(fd, &rset);
    else
        FD_SET(fd, &wset);

    tv.tv_sec = (int)(timeout_ms / 1000);
    tv.tv_usec = (int)((timeout_ms % 1000) * 1000);
    return select(fd + 1, want_read ? &rset : NULL, want_read ? NULL : &wset,
                  NULL, &tv);
}

static const char *backend_server_name(const struct backend_config *bcfg,
                                       char *fallback, size_t fallback_sz)
{
    if (bcfg->sni[0])
        return bcfg->sni;

    const char *addr = bcfg->address;
    const char *colon = strrchr(addr, ':');
    size_t host_len = colon ? (size_t)(colon - addr) : strlen(addr);
    if (host_len >= fallback_sz)
        host_len = fallback_sz - 1;
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

int backend_tls_handshake(struct worker *w, const struct backend_config *bcfg,
                          uint32_t cid)
{
#ifdef VORTEX_PHASE_TLS
    struct conn_hot *h = conn_hot(&w->pool, cid);
    struct conn_cold *cold = conn_cold_ptr(&w->pool, cid);
    SSL *ssl;
    char sni_buf[256];
    const char *server_name;
    uint32_t timeout_ms;

    if (!bcfg->tls)
        return 0;
    if (!w->backend_tls_client_ctx || h->backend_fd < 0)
        return -1;

    ssl = SSL_new(w->backend_tls_client_ctx);
    if (!ssl) {
        log_backend_ssl_errors("backend_tls_new");
        return -1;
    }
    if (SSL_set_fd(ssl, h->backend_fd) != 1) {
        log_backend_ssl_errors("backend_tls_set_fd");
        SSL_free(ssl);
        return -1;
    }

    server_name = backend_server_name(bcfg, sni_buf, sizeof(sni_buf));
    if (server_name[0]) {
        SSL_set_tlsext_host_name(ssl, server_name);
        if (bcfg->verify_peer || !bcfg->verify_peer_set) {
            X509_VERIFY_PARAM *param = SSL_get0_param(ssl);
            if (X509_VERIFY_PARAM_set1_host(param, server_name, 0) != 1) {
                log_backend_ssl_errors("backend_tls_set_host");
                SSL_free(ssl);
                return -1;
            }
        }
    }

    SSL_set_verify(ssl,
        (bcfg->verify_peer || !bcfg->verify_peer_set) ? SSL_VERIFY_PEER : SSL_VERIFY_NONE,
        NULL);

    timeout_ms = backend_timeout_ms_for(w, cid);
    ERR_clear_error();
    for (;;) {
        int ret = SSL_connect(ssl);
        if (ret == 1)
            break;
        {
            int err = SSL_get_error(ssl, ret);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                int sel = backend_ssl_wait(h->backend_fd, err == SSL_ERROR_WANT_READ, timeout_ms);
                if (sel > 0)
                    continue;
                log_warn("backend_tls_handshake",
                         "conn=%u fd=%d wait timeout/error during SSL_connect", cid, h->backend_fd);
            } else {
                log_backend_ssl_errors("backend_tls_handshake");
            }
        }
        SSL_free(ssl);
        return -1;
    }

    if ((bcfg->verify_peer || !bcfg->verify_peer_set) &&
        SSL_get_verify_result(ssl) != X509_V_OK) {
        log_warn("backend_tls_handshake", "conn=%u certificate verification failed", cid);
        SSL_free(ssl);
        return -1;
    }

    cold->backend_ssl = ssl;
    h->flags |= CONN_FLAG_BACKEND_TLS;
    h->flags &= ~CONN_FLAG_BACKEND_POOLED;
    return 0;
#else
    (void)w; (void)bcfg; (void)cid;
    return -1;
#endif
}

int backend_tls_send_all(struct worker *w, uint32_t cid, const uint8_t *buf, size_t len)
{
#ifdef VORTEX_PHASE_TLS
    struct conn_hot *h = conn_hot(&w->pool, cid);
    struct conn_cold *cold = conn_cold_ptr(&w->pool, cid);
    SSL *ssl = (SSL *)cold->backend_ssl;
    uint32_t timeout_ms = backend_timeout_ms_for(w, cid);
    size_t off = 0;

    if (!ssl)
        return -1;

    while (off < len) {
        int ret;
        ERR_clear_error();
        ret = SSL_write(ssl, buf + off, (int)(len - off));
        if (ret > 0) {
            off += (size_t)ret;
            continue;
        }
        {
            int err = SSL_get_error(ssl, ret);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                int sel = backend_ssl_wait(h->backend_fd, err == SSL_ERROR_WANT_READ, timeout_ms);
                if (sel > 0)
                    continue;
                log_warn("backend_tls_send", "conn=%u fd=%d wait timeout/error", cid, h->backend_fd);
            } else {
                log_backend_ssl_errors("backend_tls_send");
            }
        }
        return -1;
    }
    return (int)off;
#else
    (void)w; (void)cid; (void)buf; (void)len;
    return -1;
#endif
}

int backend_tls_recv_some(struct worker *w, uint32_t cid, uint8_t *buf, size_t len)
{
#ifdef VORTEX_PHASE_TLS
    struct conn_hot *h = conn_hot(&w->pool, cid);
    struct conn_cold *cold = conn_cold_ptr(&w->pool, cid);
    SSL *ssl = (SSL *)cold->backend_ssl;
    uint32_t timeout_ms = backend_timeout_ms_for(w, cid);

    if (!ssl)
        return -1;

    for (;;) {
        int ret;
        ERR_clear_error();
        ret = SSL_read(ssl, buf, (int)len);
        if (ret > 0)
            return ret;
        if (ret == 0) {
            int err = SSL_get_error(ssl, ret);
            if (err == SSL_ERROR_ZERO_RETURN)
                return 0;
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                int sel = backend_ssl_wait(h->backend_fd, err == SSL_ERROR_WANT_READ, timeout_ms);
                if (sel > 0)
                    continue;
                log_warn("backend_tls_recv", "conn=%u fd=%d wait timeout/error", cid, h->backend_fd);
            } else {
                log_backend_ssl_errors("backend_tls_recv");
            }
            return -1;
        }
        {
            int err = SSL_get_error(ssl, ret);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                int sel = backend_ssl_wait(h->backend_fd, err == SSL_ERROR_WANT_READ, timeout_ms);
                if (sel > 0)
                    continue;
                log_warn("backend_tls_recv", "conn=%u fd=%d wait timeout/error", cid, h->backend_fd);
            } else {
                log_backend_ssl_errors("backend_tls_recv");
            }
        }
        return -1;
    }
#else
    (void)w; (void)cid; (void)buf; (void)len;
    return -1;
#endif
}

/* ------------------------------------------------------------------ */
/* Circuit breaker helpers                                             */
/* ------------------------------------------------------------------ */

bool cb_is_open(struct worker *w, int ri, int bi, uint64_t now_ns)
{
    uint64_t until = w->backend_cb[ri][bi].open_until_ns;
    return until != 0 && now_ns < until;
}

void cb_record_failure(struct worker *w, int ri, int bi, uint64_t now_ns,
                       uint32_t cfg_threshold, uint32_t cfg_open_ms)
{
    uint32_t threshold = cfg_threshold ? cfg_threshold : CB_DEFAULT_THRESHOLD;
    uint64_t open_ms   = cfg_open_ms   ? cfg_open_ms   : CB_DEFAULT_OPEN_MS;
    uint32_t count = ++w->backend_cb[ri][bi].fail_count;
    if (count >= threshold) {
        w->backend_cb[ri][bi].open_until_ns = now_ns + open_ms * 1000000ULL;
        log_warn("circuit_breaker",
            "route=%d backend=%d OPEN after %u consecutive failures (retry in %llums)",
            ri, bi, count, (unsigned long long)open_ms);
    }
}

void cb_record_success(struct worker *w, int ri, int bi)
{
    if (w->backend_cb[ri][bi].fail_count > 0 ||
        w->backend_cb[ri][bi].open_until_ns != 0) {
        log_info("circuit_breaker", "route=%d backend=%d CLOSED (probe succeeded)", ri, bi);
    }
    w->backend_cb[ri][bi].fail_count    = 0;
    w->backend_cb[ri][bi].open_until_ns = 0;
}

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
        if (!cb_is_open(w, ri, bi, now_ns))
            return bi;
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
int begin_async_connect(struct worker *w, const struct backend_config *bcfg,
                        uint32_t cid)
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
                if (family != AF_UNSPEC && rp->ai_family != family)
                    continue;
                if (rp->ai_addrlen <= sizeof(cold->backend_addr)) {
                    memcpy(&cold->backend_addr, rp->ai_addr, rp->ai_addrlen);
                    cold->backend_addrlen = (socklen_t)rp->ai_addrlen;
                    got = true;
                    break;
                }
            }
        }
        freeaddrinfo(res);
        if (!got) { log_error("async_connect", "no usable addr for %s", addr_str); return -1; }
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
        setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE,  &idle,  sizeof(idle));
        setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
        setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT,   &cnt,   sizeof(cnt));
    }

    /* TCP congestion control — per-route override, then global, then kernel default */
    const char *cc = w->cfg->routes[ri].congestion_control[0]
                     ? w->cfg->routes[ri].congestion_control
                     : w->cfg->congestion_control;
    if (cc[0])
        setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, cc, (socklen_t)strlen(cc));

    /* Issue async CONNECT — returns EINPROGRESS immediately */
    struct io_uring_sqe *sqe = io_uring_get_sqe(&w->uring.ring);
    if (!sqe) { close(fd); return -1; }
    io_uring_prep_connect(sqe, fd,
        (struct sockaddr *)&cold->backend_addr, cold->backend_addrlen);
    sqe->user_data = URING_UD_ENCODE(VORTEX_OP_CONNECT, cid);
    uring_submit(&w->uring);

    /* Arm deadline covering both connect and first response byte */
    struct conn_hot *_h = conn_hot(&w->pool, cid);
    backend_deadline_set(w, cid, w->cfg->routes[_h->route_idx].backend_timeout_ms);
    log_debug("async_connect", "conn=%u fd=%d -> %s (CONNECT in flight)", cid, fd, bcfg->address);
    return fd;
}
