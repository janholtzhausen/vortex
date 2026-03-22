#define _GNU_SOURCE
/*
 * worker_accept.c — TLS ClientHello SNI peek, tarpit handling, and connection
 * teardown for the vortex worker event loop.
 *
 * tarpit_conn() and peek_client_hello_sni() are called from the VORTEX_OP_ACCEPT
 * handler in handle_proxy_data (worker_proxy.c).  conn_close() is called from
 * every error path throughout the worker subsystem.
 */
#include "worker_internal.h"
#ifdef VORTEX_H2
#include "h2.h"
#endif

/*
 * Peek at the raw TLS ClientHello and extract the SNI hostname.
 * Uses MSG_PEEK so the data remains unconsumed in the socket buffer.
 * Returns 1 if SNI found and written to `out`, 0 otherwise.
 */
int peek_client_hello_sni(int fd, char *out, size_t out_max)
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
void tarpit_conn(struct worker *w, int fd)
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

void conn_close(struct worker *w, uint32_t cid, bool is_error)
{
    struct conn_hot *h = conn_hot(&w->pool, cid);
    if (h->state == CONN_STATE_FREE) return;
#ifdef VORTEX_PHASE_TLS
    if (h->ssl) { tls_ssl_free((SSL *)h->ssl); h->ssl = NULL; }
#endif
#ifdef VORTEX_H2
    {
        struct conn_cold *cc = conn_cold_ptr(&w->pool, cid);
        if (cc->h2) { h2_session_free(cc->h2); cc->h2 = NULL; }
    }
#endif
    if (h->client_fd  >= 0) {
        uring_remove_fd(&w->uring, (unsigned)FIXED_FD_CLIENT(w, cid));
        close(h->client_fd);  h->client_fd  = -1;
    }
    if (h->backend_fd >= 0) {
        uring_remove_fd(&w->uring, (unsigned)FIXED_FD_BACKEND(w, cid));
        /* On a clean close with an idle (non-streaming) backend, return the fd
         * to the global pool for reuse by future connections. */
        if (!is_error && !(h->flags & CONN_FLAG_STREAMING_BACKEND)) {
            int ri = h->route_idx, bi = h->backend_idx;
            int ps = (ri >= 0 && ri < VORTEX_MAX_ROUTES &&
                      bi >= 0 && bi < VORTEX_MAX_BACKENDS)
                     ? w->cfg->routes[ri].backends[bi].pool_size : 0;
            if (ps > 0) {
                global_pool_put(ri, bi, h->backend_fd, ps);
                h->backend_fd = -1;
            }
        }
        if (h->backend_fd >= 0) {
            close(h->backend_fd); h->backend_fd = -1;
        }
    }
    conn_free(&w->pool, cid);
    if (is_error) w->errors++; else w->completed++;
}
