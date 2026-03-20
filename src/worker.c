#include "worker.h"
#include "log.h"
#include "util.h"
#include "auth.h"
#include "bpf_loader.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <linux/time_types.h>

#ifdef VORTEX_PHASE_TLS
#include "tls.h"
#include <openssl/ssl.h>
#endif

/*
 * Peek at the raw TLS ClientHello and extract the SNI hostname.
 * Uses MSG_PEEK so the data remains unconsumed in the socket buffer.
 * Returns 1 if SNI found and written to `out`, 0 otherwise.
 */
static int peek_client_hello_sni(int fd, char *out, size_t out_max)
{
    uint8_t buf[1024];
    ssize_t n = recv(fd, buf, sizeof(buf), MSG_PEEK | MSG_DONTWAIT);
    if (n < 5) return 0;

    /* TLS record: ContentType=22 (handshake), legacy_version(2), length(2) */
    if (buf[0] != 0x16) return 0;
    uint16_t rec_len = ((uint16_t)buf[3] << 8) | buf[4];
    if (n < (ssize_t)(5 + rec_len)) return 0;

    /* Handshake header: type=1 (ClientHello), length(3) */
    const uint8_t *p = buf + 5;
    const uint8_t *end = buf + 5 + rec_len;
    if (p >= end || p[0] != 0x01) return 0;
    p += 4; /* skip type(1) + length(3) */

    /* client_version(2) + random(32) */
    if (p + 34 > end) return 0;
    p += 34;

    /* session_id: length(1) + data */
    if (p + 1 > end) return 0;
    p += 1 + p[0];

    /* cipher_suites: length(2) + data */
    if (p + 2 > end) return 0;
    p += 2 + (((uint16_t)p[0] << 8) | p[1]);

    /* compression_methods: length(1) + data */
    if (p + 1 > end) return 0;
    p += 1 + p[0];

    /* extensions: total_length(2) + list */
    if (p + 2 > end) return 0;
    uint16_t ext_total = ((uint16_t)p[0] << 8) | p[1];
    p += 2;
    const uint8_t *ext_end = p + ext_total;
    if (ext_end > end) return 0;

    while (p + 4 <= ext_end) {
        uint16_t ext_type = ((uint16_t)p[0] << 8) | p[1];
        uint16_t ext_len  = ((uint16_t)p[2] << 8) | p[3];
        p += 4;
        if (p + ext_len > ext_end) return 0;

        if (ext_type == 0x0000) { /* server_name */
            /* server_name_list: list_len(2) | entry_type(1)=0 | name_len(2) | name */
            const uint8_t *s = p;
            if (s + 5 > p + ext_len) return 0;
            if (s[2] != 0x00) return 0; /* not host_name type */
            uint16_t name_len = ((uint16_t)s[3] << 8) | s[4];
            s += 5;
            if (s + name_len > p + ext_len) return 0;
            if (name_len >= (uint16_t)out_max) name_len = (uint16_t)(out_max - 1);
            memcpy(out, s, name_len);
            out[name_len] = '\0';
            return 1;
        }
        p += ext_len;
    }
    return 0;
}

/*
 * Tarpit a connection: shrink our TCP receive window to 1 byte so the
 * remote end stalls trying to send data. Send /dev/urandom garbage immediately
 * so scanners get a confusing non-TLS response. Log the client IP.
 * The fd is stored in a FIFO; when the tarpit is full the oldest is evicted.
 */
static void tarpit_conn(struct worker *w, int fd)
{
    /* Clamp receive window to 1 — attacker can only send 1 byte at a time */
    int clamp = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_WINDOW_CLAMP, &clamp, sizeof(clamp));

    /* Log the offender's IP address */
    {
        struct sockaddr_storage ss;
        socklen_t slen = sizeof(ss);
        if (getpeername(fd, (struct sockaddr *)&ss, &slen) == 0) {
            char ipstr[64] = {0};
            if (ss.ss_family == AF_INET)
                inet_ntop(AF_INET,
                    &((struct sockaddr_in *)&ss)->sin_addr, ipstr, sizeof(ipstr));
            else
                inet_ntop(AF_INET6,
                    &((struct sockaddr_in6 *)&ss)->sin6_addr, ipstr, sizeof(ipstr));

            log_info("tarpit", "fd=%d ip=%s total=%llu",
                fd, ipstr, (unsigned long long)(w->tarpit_total + 1));

            if (w->tarpit_log) {
                time_t now = time(NULL);
                struct tm tm;
                gmtime_r(&now, &tm);
                fprintf(w->tarpit_log,
                    "%04d-%02d-%02dT%02d:%02d:%02dZ %s\n",
                    tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                    tm.tm_hour, tm.tm_min, tm.tm_sec, ipstr);
                fflush(w->tarpit_log);
            }
        }
    }

    /* Send an immediate burst of garbage — scanner gets garbage, not silence */
    if (w->urandom_fd >= 0) {
        uint8_t noise[256];
        ssize_t r = read(w->urandom_fd, noise, sizeof(noise));
        if (r > 0) send(fd, noise, (size_t)r, MSG_NOSIGNAL | MSG_DONTWAIT);
    }

    uint32_t slot = (w->tarpit_head + w->tarpit_count) % WORKER_TARPIT_MAX;
    if (w->tarpit_count == WORKER_TARPIT_MAX) {
        /* Evict oldest — move its IP into the XDP blocklist for 60 minutes */
        int evict_fd = w->tarpit_fds[w->tarpit_head];
        if (evict_fd >= 0) {
            struct sockaddr_storage evict_ss;
            socklen_t evict_len = sizeof(evict_ss);
            if (getpeername(evict_fd, (struct sockaddr *)&evict_ss, &evict_len) == 0 &&
                evict_ss.ss_family == AF_INET) {
                uint32_t ip_host =
                    ntohl(((struct sockaddr_in *)&evict_ss)->sin_addr.s_addr);
                if (bpf_blocklist_add(ip_host) == 0 &&
                    w->blocked_count < WORKER_BLOCKED_MAX) {
                    struct blocked_entry *be =
                        &w->blocked_list[w->blocked_tail];
                    be->ip_host   = ip_host;
                    be->expire_at = time(NULL) + WORKER_BLOCK_TTL_SECS;
                    w->blocked_tail =
                        (w->blocked_tail + 1) % WORKER_BLOCKED_MAX;
                    w->blocked_count++;
                    char evict_ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &((struct sockaddr_in *)&evict_ss)->sin_addr,
                              evict_ip, sizeof(evict_ip));
                    log_info("tarpit_block", "ip=%s blocked for %ds",
                             evict_ip, WORKER_BLOCK_TTL_SECS);
                }
            }
            close(evict_fd);
        }
        w->tarpit_fds[w->tarpit_head] = fd;
        w->tarpit_head = (w->tarpit_head + 1) % WORKER_TARPIT_MAX;
    } else {
        w->tarpit_fds[slot] = fd;
        w->tarpit_count++;
    }
    w->tarpit_total++;
}

/* ------------------------------------------------------------------ */
/* Backend connection pool helpers                                     */
/* ------------------------------------------------------------------ */

static int backend_pool_get(struct worker *w, int ri, int bi)
{
    if (ri < 0 || ri >= VORTEX_MAX_ROUTES) return -1;
    if (bi < 0 || bi >= VORTEX_MAX_BACKENDS) return -1;
    struct backend_fd_pool *p = &w->backend_pool[ri][bi];
    if (p->count == 0) return -1;
    int fd = p->fds[--p->count];
    log_debug("backend_pool_get", "route=%d backend=%d fd=%d remaining=%u",
        ri, bi, fd, p->count);
    return fd;
}

static void backend_pool_put(struct worker *w, int ri, int bi, int fd,
                             int configured_pool_size)
{
    if (ri < 0 || ri >= VORTEX_MAX_ROUTES) { close(fd); return; }
    if (bi < 0 || bi >= VORTEX_MAX_BACKENDS) { close(fd); return; }
    struct backend_fd_pool *p = &w->backend_pool[ri][bi];

    int slots = configured_pool_size < BACKEND_POOL_SLOTS
                ? configured_pool_size : BACKEND_POOL_SLOTS;

    if ((int)p->count < slots) {
        p->fds[p->count++] = fd;
        log_debug("backend_pool_put", "route=%d backend=%d fd=%d pool=%u",
            ri, bi, fd, p->count);
    } else {
        close(fd); /* pool full — discard */
    }
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
static int begin_async_connect(struct worker *w, const char *addr_str,
                               uint32_t cid)
{
    char host[256];
    char port_str[16];

    const char *colon = strrchr(addr_str, ':');
    if (!colon) return -1;

    size_t hlen = (size_t)(colon - addr_str);
    if (hlen >= sizeof(host)) return -1;
    memcpy(host, addr_str, hlen);
    host[hlen] = '\0';
    strncpy(port_str, colon + 1, sizeof(port_str) - 1);

    struct addrinfo hints = {
        .ai_family   = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
    };
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        log_error("async_connect", "getaddrinfo(%s) failed: %s",
            addr_str, strerror(errno));
        return -1;
    }

    int fd = -1;
    struct addrinfo *chosen = NULL;
    for (struct addrinfo *rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype | SOCK_NONBLOCK, rp->ai_protocol);
        if (fd < 0) continue;
        chosen = rp;
        break;
    }

    if (fd < 0) {
        freeaddrinfo(res);
        log_error("async_connect", "socket() failed for %s: %s", addr_str, strerror(errno));
        return -1;
    }

    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    /* Store resolved address in conn_cold for the CONNECT completion handler */
    struct conn_cold *cold = conn_cold_ptr(&w->pool, cid);
    if (chosen->ai_addrlen <= sizeof(cold->backend_addr)) {
        memcpy(&cold->backend_addr, chosen->ai_addr, chosen->ai_addrlen);
        cold->backend_addrlen = chosen->ai_addrlen;
    }

    freeaddrinfo(res);

    /* Issue async CONNECT — returns EINPROGRESS immediately */
    struct io_uring_sqe *sqe = io_uring_get_sqe(&w->uring.ring);
    if (!sqe) { close(fd); return -1; }
    io_uring_prep_connect(sqe, fd,
        (struct sockaddr *)&cold->backend_addr, cold->backend_addrlen);
    sqe->user_data = URING_UD_ENCODE(VORTEX_OP_CONNECT, cid);
    uring_submit(&w->uring);

    log_debug("async_connect", "conn=%u fd=%d -> %s (CONNECT in flight)", cid, fd, addr_str);
    return fd;
}

struct ws_relay_fds {
    int client_fd;
    int backend_fd;
};

static void *ws_relay_thread(void *arg)
{
    struct ws_relay_fds *fds = arg;
    int cfd = fds->client_fd, bfd = fds->backend_fd;
    free(fds);

    char buf[65536];
    fd_set rfds;

    while (1) {
        FD_ZERO(&rfds);
        FD_SET(cfd, &rfds);
        FD_SET(bfd, &rfds);
        int maxfd = (cfd > bfd ? cfd : bfd) + 1;

        struct timeval tv = {.tv_sec = 60, .tv_usec = 0};
        int r = select(maxfd, &rfds, NULL, NULL, &tv);
        if (r <= 0) break;

        if (FD_ISSET(cfd, &rfds)) {
            int n = (int)recv(cfd, buf, sizeof(buf), 0);
            if (n <= 0) break;
            if (send(bfd, buf, (size_t)n, MSG_NOSIGNAL) < 0) break;
        }
        if (FD_ISSET(bfd, &rfds)) {
            int n = (int)recv(bfd, buf, sizeof(buf), 0);
            if (n <= 0) break;
            if (send(cfd, buf, (size_t)n, MSG_NOSIGNAL) < 0) break;
        }
    }
    close(cfd);
    close(bfd);
    return NULL;
}

static void conn_close(struct worker *w, uint32_t cid, bool is_error)
{
    struct conn_hot *h = conn_hot(&w->pool, cid);
    if (h->state == CONN_STATE_FREE) return;
#ifdef VORTEX_PHASE_TLS
    if (h->ssl) { tls_ssl_free((SSL *)h->ssl); h->ssl = NULL; }
#endif
    if (h->client_fd  >= 0) { close(h->client_fd);  h->client_fd  = -1; }
    if (h->backend_fd >= 0) { close(h->backend_fd); h->backend_fd = -1; }
    conn_free(&w->pool, cid);
    if (is_error) w->errors++; else w->completed++;
}

/* Extract method and URL from HTTP/1.x request line.
 * Returns 0 on success, -1 if not a parseable HTTP request. */
static int parse_http_request_line(const uint8_t *buf, int len,
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

/* Core proxy handler — called for each io_uring completion */
static void handle_proxy_data(struct worker *w, struct io_uring_cqe *cqe)
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

            char sni[256] = {0};
            SSL *ssl = tls_accept(w->tls, client_fd, &tls_route_idx, sni, sizeof(sni));
            if (!ssl) {
                close(client_fd);
                conn_free(&w->pool, new_cid);
                return;
            }

            /* Track TLS version before potentially freeing ssl */
            {
                int ver = SSL_version(ssl);
                if (ver == TLS1_3_VERSION) w->tls13_count++;
                else                       w->tls12_count++;
            }

            if (tls_ktls_tx_active(ssl) && tls_ktls_rx_active(ssl)) {
                /* kTLS active — kernel handles crypto, raw io_uring send/recv works */
                nh->flags |= CONN_FLAG_KTLS_TX | CONN_FLAG_KTLS_RX;
                tls_ssl_free(ssl); /* SSL* no longer needed */
                nh->ssl = NULL;
                w->ktls_count++;
                log_debug("ktls_active", "conn=%u sni=%s", (unsigned)new_cid, sni);
            } else {
                /* No kTLS — store SSL* for SSL_read/SSL_write data path */
                nh->ssl = ssl;
                log_debug("ktls_fallback", "conn=%u sni=%s", (unsigned)new_cid, sni);
            }

            /* Re-set fd to blocking now that handshake is done (io_uring works on blocking fds) */
            int flags = fcntl(client_fd, F_GETFL);
            fcntl(client_fd, F_SETFL, flags & ~O_NONBLOCK);
        }
#endif

        /* Route selection: TLS SNI route takes priority */
        int route_idx = tls_route_idx;
        if (w->cfg->route_count > 0 && route_idx < w->cfg->route_count) {
            int backend_idx = router_select_backend(&w->router, route_idx, 0);
            const char *addr = router_backend_addr(&w->router, route_idx, backend_idx);
            nh->route_idx   = (uint16_t)route_idx;
            nh->backend_idx = (uint16_t)backend_idx;

            if (addr) {
                /* Try idle pool first */
                int cfg_pool = w->cfg->routes[route_idx].backends[backend_idx].pool_size;
                int pooled_fd = (cfg_pool > 0)
                                ? backend_pool_get(w, route_idx, backend_idx) : -1;
                if (pooled_fd >= 0) {
                    nh->backend_fd = pooled_fd;
                    nh->flags |= CONN_FLAG_BACKEND_POOLED;
                    log_debug("accept_pool", "conn=%u reused backend fd=%d",
                        (unsigned)new_cid, pooled_fd);
                } else {
                    /* Async connect — CONNECT completion arms RECV_CLIENT */
                    nh->backend_fd = begin_async_connect(w, addr, new_cid);
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
        io_uring_prep_recv(s1, client_fd,
            conn_recv_buf(&w->pool, new_cid), w->pool.buf_size, 0);
        s1->user_data = URING_UD_ENCODE(VORTEX_OP_RECV_CLIENT, new_cid);
        log_debug("accept_arm", "conn=%u client_fd=%d backend_fd=%d (pooled)",
            (unsigned)new_cid, client_fd, nh->backend_fd);
        uring_submit(&w->uring);
        return;
    }

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
        h->bytes_in += (uint32_t)n;

        /* Reconnect to backend if previous response consumed the connection */
        if (h->backend_fd < 0) {
            int ri = h->route_idx, bi = h->backend_idx;
            const char *addr = router_backend_addr(&w->router, ri, bi);
            if (!addr) {
                const char *r502 =
                    "HTTP/1.1 502 Bad Gateway\r\n"
                    "Content-Length: 11\r\nConnection: close\r\n\r\nBad Gateway";
                send(h->client_fd, r502, strlen(r502), MSG_NOSIGNAL);
                conn_close(w, cid, false);
                break;
            }
            /* Try pool first */
            int cfg_pool = w->cfg->routes[ri].backends[bi].pool_size;
            int pfd = (cfg_pool > 0) ? backend_pool_get(w, ri, bi) : -1;
            if (pfd >= 0) {
                h->backend_fd = pfd;
                h->flags |= CONN_FLAG_BACKEND_POOLED;
            } else {
                /* Async reconnect: data already in recv_buf — save it and
                 * arm CONNECT; the CONNECT handler will re-arm RECV_CLIENT
                 * which will trigger resend of the buffered request.
                 * We pass n as hint via send_buf_len so CONNECT can forward it. */
                h->send_buf_len = (uint32_t)n;  /* stash the byte count */
                h->backend_fd = begin_async_connect(w, addr, cid);
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
                if (!sqe401) { conn_close(w, cid, false); break; }
                /* Copy 401 to send buf */
                uint8_t *sbuf = conn_send_buf(&w->pool, cid);
                size_t r401_len = sizeof(r401) - 1;
                memcpy(sbuf, r401, r401_len);
                io_uring_prep_send(sqe401, h->client_fd, sbuf, r401_len, MSG_NOSIGNAL);
                sqe401->user_data = URING_UD_ENCODE(VORTEX_OP_SEND_CLIENT, cid);
                /* Clear streaming flag so SEND_CLIENT goes back to RECV_CLIENT */
                h->flags &= ~CONN_FLAG_STREAMING_BACKEND;
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

        /* Cache check: only for GET requests */
        if (w->cache.index) {
            char method[16], url[512];
            const uint8_t *rbuf = conn_recv_buf(&w->pool, cid);
            if (parse_http_request_line(rbuf, n,
                                        method, sizeof(method),
                                        url, sizeof(url)) == 0
                && strcmp(method, "GET") == 0) {

                struct cache_index_entry *ce = cache_lookup(&w->cache, url, strlen(url));
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
                        struct io_uring_sqe *sqe = io_uring_get_sqe(&w->uring.ring);
                        if (sqe) {
                            h->send_buf_off = 0;
                            h->send_buf_len = (uint32_t)r304_len;
                            io_uring_prep_send(sqe, h->client_fd, sbuf,
                                               (size_t)r304_len, MSG_NOSIGNAL);
                            sqe->user_data = URING_UD_ENCODE(VORTEX_OP_SEND_CLIENT, cid);
                            /* Clear streaming so SEND_CLIENT goes back to RECV_CLIENT */
                            h->flags &= ~CONN_FLAG_STREAMING_BACKEND;
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
                            /* Copy headers minus trailing \r\n\r\n */
                            size_t hdr_body = ce->header_len - 4;
                            memcpy(sbuf, resp, hdr_body);
                            memcpy(sbuf + hdr_body, extra, (size_t)extra_len);
                            memcpy(sbuf + hdr_body + extra_len, "\r\n\r\n", 4);
                            memcpy(sbuf + ce->header_len + extra_len,
                                   resp + ce->header_len, ce->body_len);

                            struct io_uring_sqe *sqe = io_uring_get_sqe(&w->uring.ring);
                            if (sqe) {
                                h->send_buf_off = 0;
                                h->send_buf_len = (uint32_t)serve_len;
                                h->flags &= ~CONN_FLAG_STREAMING_BACKEND;
                                io_uring_prep_send(sqe, h->client_fd, sbuf,
                                                   serve_len, MSG_NOSIGNAL);
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

            /* ---- Strip Authorization header ----
             * The proxy consumed it for its own auth check; never forward
             * our proxy credentials to the backend. */
            {
                uint8_t *ah = (uint8_t *)memmem(rbuf, (size_t)fwd_n, "\r\nAuthorization:", 16);
                if (!ah)
                    ah = (uint8_t *)memmem(rbuf, (size_t)fwd_n, "\r\nauthorization:", 16);
                if (ah) {
                    uint8_t *line_end = (uint8_t *)memmem(ah + 2,
                        (size_t)(rbuf + fwd_n - ah - 2), "\r\n", 2);
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
                    uint8_t *ve = (uint8_t *)memmem(vs, (size_t)(rbuf + fwd_n - vs), "\r\n", 2);
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
                    const char *eol0 = (const char *)memmem(rbuf, (size_t)fwd_n, "\r\n", 2);
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
            const char *eol = (const char *)memmem(rbuf, (size_t)fwd_n, "\r\n", 2);
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
        io_uring_prep_send(sqe, h->backend_fd, conn_recv_buf(&w->pool, cid), fwd_n, MSG_NOSIGNAL);
        sqe->user_data = URING_UD_ENCODE(VORTEX_OP_SEND_BACKEND, cid);
        uring_submit(&w->uring);
        break;
    }

    case VORTEX_OP_SEND_BACKEND: {
        int n = cqe->res;
        log_debug("send_backend", "conn=%u n=%d", cid, n);
        if (n < 0) { conn_close(w, cid, true); break; }
        /* All client data forwarded — now wait for backend response */
        struct io_uring_sqe *sqe = io_uring_get_sqe(&w->uring.ring);
        if (!sqe) { conn_close(w, cid, true); break; }
        io_uring_prep_recv(sqe, h->backend_fd, conn_send_buf(&w->pool, cid),
            w->pool.buf_size, 0);
        sqe->user_data = URING_UD_ENCODE(VORTEX_OP_RECV_BACKEND, cid);
        uring_submit(&w->uring);
        break;
    }

    case VORTEX_OP_RECV_BACKEND: {
        int n = cqe->res;
        log_debug("recv_backend", "conn=%u n=%d", cid, n);
        if (n == 0) {
            /* Backend EOF — done streaming this response */
            h->flags &= ~CONN_FLAG_STREAMING_BACKEND;
            /* Backend closed the connection — never return to pool */
            if (h->backend_fd >= 0) { close(h->backend_fd); h->backend_fd = -1; }
            h->flags &= ~CONN_FLAG_BACKEND_POOLED;
            /* Keep client alive for next request */
            struct io_uring_sqe *sqe = io_uring_get_sqe(&w->uring.ring);
            if (!sqe) { conn_close(w, cid, false); break; }
            io_uring_prep_recv(sqe, h->client_fd, conn_recv_buf(&w->pool, cid),
                w->pool.buf_size, 0);
            sqe->user_data = URING_UD_ENCODE(VORTEX_OP_RECV_CLIENT, cid);
            uring_submit(&w->uring);
            break;
        }
        h->flags |= CONN_FLAG_STREAMING_BACKEND;
        h->bytes_out += (uint32_t)n;

        /* Track body bytes for keep-alive pool return */
        if (h->flags & CONN_FLAG_BACKEND_POOLED) {
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
                const char *hend = (const char *)memmem(sbuf2, (size_t)n, "\r\n\r\n", 4);
                if (hend) {
                    size_t body_in_chunk = (size_t)n - (size_t)(hend + 4 - (const char *)sbuf2);
                    cold->backend_body_recv += (uint32_t)body_in_chunk;
                } else {
                    cold->backend_body_recv += (uint32_t)n;
                }
            }
        }

        /* Check for WebSocket 101 upgrade response */
        if ((h->flags & CONN_FLAG_WEBSOCKET_ACTIVE) && n > 12 &&
            memcmp(conn_send_buf(&w->pool, cid), "HTTP/1.1 101", 12) == 0) {
            /* Send 101 to client synchronously, then hand off to relay thread */
            send(h->client_fd, conn_send_buf(&w->pool, cid), (size_t)n, MSG_NOSIGNAL);

            /* Hand off fds to relay thread */
            struct ws_relay_fds *relay = malloc(sizeof(*relay));
            if (relay) {
                relay->client_fd  = h->client_fd;
                relay->backend_fd = h->backend_fd;
                h->client_fd  = -1;  /* prevent conn_close from closing them */
                h->backend_fd = -1;
                pthread_t t;
                pthread_attr_t attr;
                pthread_attr_init(&attr);
                pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
                pthread_create(&t, &attr, ws_relay_thread, relay);
                pthread_attr_destroy(&attr);
            }
            conn_close(w, cid, false);
            break;
        }

        /* Response header rewrites — only on the first chunk (starts with "HTTP/") */
        if (n > 7 && memcmp(conn_send_buf(&w->pool, cid), "HTTP/", 5) == 0) {
            uint8_t *sbuf = conn_send_buf(&w->pool, cid);

            /* Locate end of headers */
            uint8_t *hdr_end = (uint8_t *)memmem(sbuf, (size_t)n, "\r\n\r\n", 4);
            size_t hdr_len = hdr_end ? (size_t)(hdr_end - sbuf) + 4 : (size_t)n;

            /* ---- Replace Server header with CSWS/OpenVMS identity ----
             * VSI Secure Web Server for OpenVMS — obscures true server stack. */
            {
                const char *new_srv = "CSWS/2.4.62 OpenVMS/V9.2-2 (Alpha)";
                size_t new_srv_len  = strlen(new_srv);
                uint8_t *sh = (uint8_t *)memmem(sbuf, hdr_len, "\r\nServer:", 9);
                if (!sh) sh = (uint8_t *)memmem(sbuf, hdr_len, "\r\nserver:", 9);
                if (sh) {
                    uint8_t *vs = sh + 9;
                    while (vs < sbuf + hdr_len && (*vs == ' ' || *vs == '\t')) vs++;
                    uint8_t *ve = (uint8_t *)memmem(vs,
                        (size_t)(sbuf + hdr_len - vs), "\r\n", 2);
                    if (ve) {
                        size_t old_len = (size_t)(ve - vs);
                        int delta = (int)new_srv_len - (int)old_len;
                        if (n + delta <= (int)w->pool.buf_size && n + delta > 0) {
                            memmove(vs + new_srv_len, ve, (size_t)(sbuf + n - ve));
                            memcpy(vs, new_srv, new_srv_len);
                            n += delta;
                            hdr_end = (uint8_t *)memmem(sbuf, (size_t)n, "\r\n\r\n", 4);
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
                        hdr_end = (uint8_t *)memmem(sbuf, (size_t)n, "\r\n\r\n", 4);
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
                            uint8_t *ve = (uint8_t *)memmem(vs,
                                (size_t)(sbuf + hdr_len - vs), "\r\n", 2);
                            if (ve) {
                                size_t old_len = (size_t)(ve - vs);
                                int delta = cc_val_len - (int)old_len;
                                if (n + delta <= (int)w->pool.buf_size && n + delta > 0) {
                                    memmove(vs + cc_val_len, ve, (size_t)(sbuf + n - ve));
                                    memcpy(vs, cc_val, (size_t)cc_val_len);
                                    n += delta;
                                    hdr_end = (uint8_t *)memmem(sbuf, (size_t)n, "\r\n\r\n", 4);
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
                            hdr_end = (uint8_t *)memmem(sbuf, (size_t)n, "\r\n\r\n", 4);
                            hdr_len = hdr_end ? (size_t)(hdr_end - sbuf) + 4 : (size_t)n;
                        }
                    }

                    /* For static assets: also strip Pragma header (no-cache from Kestrel) */
                    if (ttl >= 3600 && hdr_end) {
                        uint8_t *ph = (uint8_t *)memmem(sbuf, hdr_len, "\r\nPragma:", 9);
                        if (!ph)
                            ph = (uint8_t *)memmem(sbuf, hdr_len, "\r\npragma:", 9);
                        if (ph) {
                            uint8_t *pe = (uint8_t *)memmem(ph + 2,
                                (size_t)(sbuf + n - ph - 2), "\r\n", 2);
                            if (pe) {
                                pe += 2; /* point past the line's \r\n */
                                size_t remove = (size_t)(pe - (ph + 2));
                                memmove(ph + 2, ph + 2 + remove,
                                    (size_t)(sbuf + n - (ph + 2 + remove)));
                                n -= (int)remove;
                                hdr_end = (uint8_t *)memmem(sbuf, (size_t)n, "\r\n\r\n", 4);
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
                    hdr_end = (uint8_t *)memmem(sbuf, (size_t)n, "\r\n\r\n", 4);
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
                    uint8_t *ve = (uint8_t *)memmem(vs,
                        (size_t)(sbuf + hdr_len - vs), "\r\n", 2);
                    if (ve && ve > vs) {
                        const char *kl = "keep-alive";
                        size_t kl_len = 10;
                        size_t old_len = (size_t)(ve - vs);
                        int delta = (int)kl_len - (int)old_len;
                        if (n + delta <= (int)w->pool.buf_size && n + delta > 0) {
                            memmove(vs + kl_len, ve, (size_t)(sbuf + n - ve));
                            memcpy(vs, kl, kl_len);
                            n += delta;
                            hdr_end = (uint8_t *)memmem(sbuf, (size_t)n, "\r\n\r\n", 4);
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
                        hdr_end = (uint8_t *)memmem(sbuf, (size_t)n, "\r\n\r\n", 4);
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
                            const char *he2 = (const char *)memmem(
                                resp2, (size_t)n, "\r\n\r\n", 4);
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
                                    cache_store(&w->cache, cc_url2, strlen(cc_url2),
                                        (uint16_t)status2, ttl2,
                                        resp2, hl2, resp2 + hl2, bl2);
                                    log_debug("cache_store",
                                        "conn=%u url=%s ttl=%u body=%zu",
                                        cid, cc_url2, ttl2, bl2);
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
        io_uring_prep_send(sqe, h->client_fd, conn_send_buf(&w->pool, cid), (size_t)n, MSG_NOSIGNAL);
        sqe->user_data = URING_UD_ENCODE(VORTEX_OP_SEND_CLIENT, cid);
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
            io_uring_prep_send(sqe, h->client_fd,
                conn_send_buf(&w->pool, cid) + h->send_buf_off,
                h->send_buf_len - h->send_buf_off, MSG_NOSIGNAL);
            sqe->user_data = URING_UD_ENCODE(VORTEX_OP_SEND_CLIENT, cid);
            uring_submit(&w->uring);
            break;
        }

        /* Full chunk sent */
        h->send_buf_off = 0;
        h->send_buf_len = 0;

        /* Check if a pooled backend response is now complete */
        if ((h->flags & CONN_FLAG_BACKEND_POOLED) &&
            (h->flags & CONN_FLAG_STREAMING_BACKEND)) {
            struct conn_cold *cold = conn_cold_ptr(&w->pool, cid);
            if (cold->backend_content_length > 0 &&
                cold->backend_body_recv >= cold->backend_content_length) {
                /* Full response received and forwarded — return fd to pool */
                int ri = h->route_idx, bi = h->backend_idx;
                int ps = w->cfg->routes[ri].backends[bi].pool_size;
                backend_pool_put(w, ri, bi, h->backend_fd, ps);
                h->backend_fd = -1;
                h->flags &= ~(CONN_FLAG_STREAMING_BACKEND | CONN_FLAG_BACKEND_POOLED);
                cold->backend_content_length = 0;
                cold->backend_body_recv      = 0;
                log_debug("pool_return", "conn=%u route=%d backend=%d", cid, ri, bi);
            }
        }

        struct io_uring_sqe *sqe = io_uring_get_sqe(&w->uring.ring);
        if (!sqe) { conn_close(w, cid, true); break; }
        if (h->flags & CONN_FLAG_STREAMING_BACKEND) {
            /* Still reading backend response — get next chunk */
            io_uring_prep_recv(sqe, h->backend_fd, conn_send_buf(&w->pool, cid),
                w->pool.buf_size, 0);
            sqe->user_data = URING_UD_ENCODE(VORTEX_OP_RECV_BACKEND, cid);
        } else {
            /* Response complete (cache hit, single chunk, or pool return) — next request */
            io_uring_prep_recv(sqe, h->client_fd, conn_recv_buf(&w->pool, cid),
                w->pool.buf_size, 0);
            sqe->user_data = URING_UD_ENCODE(VORTEX_OP_RECV_CLIENT, cid);
        }
        uring_submit(&w->uring);
        break;
    }

    case VORTEX_OP_CONNECT: {
        /* Async backend connect completed */
        h->flags &= ~CONN_FLAG_BACKEND_CONNECTING;
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
        /* Now arm RECV_CLIENT to wait for the HTTP request */
        struct io_uring_sqe *sqe_c = io_uring_get_sqe(&w->uring.ring);
        if (!sqe_c) { conn_close(w, cid, true); break; }
        io_uring_prep_recv(sqe_c, h->client_fd,
            conn_recv_buf(&w->pool, cid), w->pool.buf_size, 0);
        sqe_c->user_data = URING_UD_ENCODE(VORTEX_OP_RECV_CLIENT, cid);
        uring_submit(&w->uring);
        break;
    }

    case VORTEX_OP_RECV_CLIENT_WS: {
        int n = cqe->res;
        if (n <= 0) { conn_close(w, cid, false); break; }
        /* Forward client WebSocket data to backend */
        if (send(h->backend_fd, conn_recv_buf(&w->pool, cid), (size_t)n, MSG_NOSIGNAL) < 0) {
            conn_close(w, cid, false); break;
        }
        /* Re-arm for next client WebSocket frame */
        struct io_uring_sqe *sqe_ws_c = io_uring_get_sqe(&w->uring.ring);
        if (!sqe_ws_c) { conn_close(w, cid, false); break; }
        io_uring_prep_recv(sqe_ws_c, h->client_fd, conn_recv_buf(&w->pool, cid),
            w->pool.buf_size, 0);
        sqe_ws_c->user_data = URING_UD_ENCODE(VORTEX_OP_RECV_CLIENT_WS, cid);
        uring_submit(&w->uring);
        break;
    }

    case VORTEX_OP_RECV_BACKEND_WS: {
        int n = cqe->res;
        if (n <= 0) { conn_close(w, cid, false); break; }
        /* Forward backend WebSocket data to client */
        if (send(h->client_fd, conn_send_buf(&w->pool, cid), (size_t)n, MSG_NOSIGNAL) < 0) {
            conn_close(w, cid, false); break;
        }
        /* Re-arm for next backend WebSocket frame */
        struct io_uring_sqe *sqe_ws_b = io_uring_get_sqe(&w->uring.ring);
        if (!sqe_ws_b) { conn_close(w, cid, false); break; }
        io_uring_prep_recv(sqe_ws_b, h->backend_fd, conn_send_buf(&w->pool, cid),
            w->pool.buf_size, 0);
        sqe_ws_b->user_data = URING_UD_ENCODE(VORTEX_OP_RECV_BACKEND_WS, cid);
        uring_submit(&w->uring);
        break;
    }

    default: break;
    }
}

static void *worker_thread(void *arg)
{
    struct worker *w = (struct worker *)arg;
    log_info("worker_start", "id=%d", w->worker_id);

    /* Init io_uring in this thread (required for SINGLE_ISSUER / COOP_TASKRUN) */
    if (uring_init(&w->uring, WORKER_URING_DEPTH, false) != 0) {
        log_error("worker_thread", "uring_init failed");
        return NULL;
    }

    /* Queue the multishot accept — cid=0 means accept op */
    struct io_uring_sqe *asqe = io_uring_get_sqe(&w->uring.ring);
    if (!asqe) {
        log_error("worker_thread", "get_sqe for accept failed");
        uring_destroy(&w->uring);
        return NULL;
    }
    io_uring_prep_multishot_accept(asqe, w->listen_fd, NULL, NULL, 0);
    asqe->user_data = URING_UD_ENCODE(VORTEX_OP_ACCEPT, 0);
    uring_submit(&w->uring);

    while (!w->stop) {
        struct io_uring_cqe *cqe;
        unsigned head;
        unsigned count = 0;

        /* Wait up to 1s so we can check stop flag for graceful shutdown */
        struct __kernel_timespec ts = { .tv_sec = 1, .tv_nsec = 0 };
        int ret = io_uring_wait_cqe_timeout(&w->uring.ring, &cqe, &ts);
        if (ret == -ETIME) {
            /* Periodic: drip more urandom garbage into tarpitted connections */
            if (w->urandom_fd >= 0 && w->tarpit_count > 0) {
                uint8_t noise[64];
                if (read(w->urandom_fd, noise, sizeof(noise)) == (ssize_t)sizeof(noise)) {
                    for (uint32_t ti = 0; ti < w->tarpit_count; ti++) {
                        int slot = (int)((w->tarpit_head + ti) % WORKER_TARPIT_MAX);
                        int tfd  = w->tarpit_fds[slot];
                        if (tfd < 0) continue;
                        if (send(tfd, noise, sizeof(noise),
                                 MSG_NOSIGNAL | MSG_DONTWAIT) < 0) {
                            close(tfd);
                            w->tarpit_fds[slot] = -1;
                        }
                    }
                }
            }
            /* Periodic: expire blocklist entries whose TTL has elapsed */
            if (w->blocked_count > 0) {
                time_t now_t = time(NULL);
                while (w->blocked_count > 0) {
                    struct blocked_entry *be =
                        &w->blocked_list[w->blocked_head];
                    if (be->expire_at > now_t) break;
                    bpf_blocklist_remove(be->ip_host);
                    w->blocked_head =
                        (w->blocked_head + 1) % WORKER_BLOCKED_MAX;
                    w->blocked_count--;
                }
            }
            continue;
        }
        if (ret < 0) {
            if (ret == -EINTR) continue;
            log_error("worker_loop", "io_uring_wait_cqe_timeout: %s", strerror(-ret));
            break;
        }

        /* Process all available completions */
        io_uring_for_each_cqe(&w->uring.ring, head, cqe) {
            handle_proxy_data(w, cqe);
            count++;
            (void)head;
        }
        io_uring_cq_advance(&w->uring.ring, count);
    }

    log_info("worker_stop", "id=%d accepted=%llu completed=%llu errors=%llu",
        w->worker_id,
        (unsigned long long)w->accepted,
        (unsigned long long)w->completed,
        (unsigned long long)w->errors);
    uring_destroy(&w->uring);
    return NULL;
}

int worker_create_listener(const char *addr, uint16_t port, int backlog)
{
    struct sockaddr_in sa = {
        .sin_family = AF_INET,
        .sin_port   = htons(port),
    };
    if (inet_pton(AF_INET, addr, &sa.sin_addr) <= 0) {
        sa.sin_addr.s_addr = INADDR_ANY;
    }

    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0) {
        log_error("create_listener", "socket: %s", strerror(errno));
        return -1;
    }

    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));

    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        log_error("create_listener", "bind %s:%d: %s", addr, port, strerror(errno));
        close(fd);
        return -1;
    }

    if (listen(fd, backlog) < 0) {
        log_error("create_listener", "listen: %s", strerror(errno));
        close(fd);
        return -1;
    }

    log_info("listener_ready", "addr=%s port=%d fd=%d", addr, port, fd);
    return fd;
}

int worker_init(struct worker *w, int id, int listen_fd,
                struct vortex_config *cfg, struct tls_ctx *tls)
{
    memset(w, 0, sizeof(*w));
    w->worker_id = id;
    w->listen_fd = listen_fd;
    w->cfg       = cfg;
#ifdef VORTEX_PHASE_TLS
    w->tls       = tls;
#else
    (void)tls;
#endif

    /* io_uring is initialized inside the worker thread for SINGLE_ISSUER compat */

    for (int i = 0; i < WORKER_TARPIT_MAX; i++) w->tarpit_fds[i] = -1;

    /* Initialise backend pool fd arrays to -1 */
    for (int ri = 0; ri < VORTEX_MAX_ROUTES; ri++)
        for (int bi = 0; bi < VORTEX_MAX_BACKENDS; bi++)
            for (int pi = 0; pi < BACKEND_POOL_SLOTS; pi++)
                w->backend_pool[ri][bi].fds[pi] = -1;

    /* Open /dev/urandom for tarpit noise */
    w->urandom_fd = open("/dev/urandom", O_RDONLY | O_NONBLOCK);
    if (w->urandom_fd < 0)
        log_warn("worker_init", "cannot open /dev/urandom: %s", strerror(errno));

    /* Open tarpit log */
    w->tarpit_log = fopen("/var/log/vortex/tarpit.log", "a");
    if (!w->tarpit_log)
        log_warn("worker_init", "cannot open tarpit log: %s", strerror(errno));

    if (conn_pool_init(&w->pool, WORKER_MAX_CONNS, WORKER_BUF_SIZE) != 0) {
        return -1;
    }

    if (router_init(&w->router, cfg) != 0) {
        conn_pool_destroy(&w->pool);
        return -1;
    }

    /* Init response cache if enabled */
    if (cfg->cache.enabled) {
        uint32_t entries = cfg->cache.index_entries > 0 ?
            cfg->cache.index_entries : 16384;
        size_t slab_bytes = cfg->cache.slab_size_bytes > 0 ?
            cfg->cache.slab_size_bytes : (64ULL * 1024 * 1024);
        size_t disk_bytes = (size_t)cfg->cache.disk_slab_size_bytes;
        const char *disk_path = cfg->cache.disk_cache_path[0] ?
            cfg->cache.disk_cache_path : NULL;
        if (cache_init(&w->cache, entries, slab_bytes,
                       cfg->cache.use_hugepages, disk_path, disk_bytes) != 0) {
            log_warn("worker_init", "cache init failed — running without cache");
        }
    }

    return 0;
}

int worker_start(struct worker *w)
{
    return pthread_create(&w->thread, NULL, worker_thread, w);
}

void worker_stop(struct worker *w)
{
    w->stop = 1;
}

void worker_join(struct worker *w)
{
    pthread_join(w->thread, NULL);
}

void worker_destroy(struct worker *w)
{
    /* Close any held tarpit connections */
    for (uint32_t i = 0; i < w->tarpit_count; i++) {
        int idx = (int)((w->tarpit_head + i) % WORKER_TARPIT_MAX);
        if (w->tarpit_fds[idx] >= 0) { close(w->tarpit_fds[idx]); w->tarpit_fds[idx] = -1; }
    }
    if (w->tarpit_total)
        log_info("tarpit_stats", "worker=%d total=%llu active=%u blocked=%u",
            w->worker_id, (unsigned long long)w->tarpit_total,
            w->tarpit_count, w->blocked_count);

    /* Close all idle pooled backend connections */
    for (int ri = 0; ri < VORTEX_MAX_ROUTES; ri++) {
        for (int bi = 0; bi < VORTEX_MAX_BACKENDS; bi++) {
            struct backend_fd_pool *p = &w->backend_pool[ri][bi];
            for (uint32_t pi = 0; pi < p->count; pi++) {
                if (p->fds[pi] >= 0) close(p->fds[pi]);
            }
            p->count = 0;
        }
    }

    /* Remove any still-live blocklist entries so they don't persist across restarts */
    for (uint32_t i = 0; i < w->blocked_count; i++) {
        uint32_t bi = (w->blocked_head + i) % WORKER_BLOCKED_MAX;
        bpf_blocklist_remove(w->blocked_list[bi].ip_host);
    }

    if (w->urandom_fd >= 0) { close(w->urandom_fd); w->urandom_fd = -1; }
    if (w->tarpit_log)  { fclose(w->tarpit_log); w->tarpit_log = NULL; }

    router_destroy(&w->router);
    conn_pool_destroy(&w->pool);
    if (w->cache.index) {
        log_info("cache_stats", "worker=%d hits=%llu misses=%llu stores=%llu evictions=%llu",
            w->worker_id,
            (unsigned long long)w->cache.hits,
            (unsigned long long)w->cache.misses,
            (unsigned long long)w->cache.stores,
            (unsigned long long)w->cache.evictions);
        cache_destroy(&w->cache);
    }
    /* uring is destroyed inside the worker thread */
}
