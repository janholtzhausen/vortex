#define _GNU_SOURCE
/*
 * worker_cache.c — cache key construction, chunked Transfer-Encoding
 * reassembly, cache store after chunked responses, and splice-mode setup
 * for the vortex worker event loop.
 *
 * Functions here are called from handle_proxy_data (worker_proxy.c) during
 * the RECV_BACKEND and RECV_CLIENT processing paths.
 */
#include "worker_internal.h"

/*
 * Build a cache key of the form "host|url" to avoid cross-host collisions.
 * host is extracted from the raw HTTP request buffer.
 */
void make_cache_key(const uint8_t *req_buf, size_t req_len,
                    const char *url, char *key, size_t key_cap)
{
    char host[128] = {0};
    const uint8_t *hh = (const uint8_t *)memmem(req_buf, req_len, "\r\nHost:", 7);
    if (!hh) hh = (const uint8_t *)memmem(req_buf, req_len, "\r\nhost:", 7);
    if (hh) {
        const uint8_t *hs = hh + 7;
        while (hs < req_buf + req_len && (*hs == ' ' || *hs == '\t')) hs++;
        const uint8_t *he = hs;
        while (he < req_buf + req_len && *he != '\r' && *he != '\n') he++;
        size_t hl = (size_t)(he - hs);
        if (hl >= sizeof(host)) hl = sizeof(host) - 1;
        memcpy(host, hs, hl);
    }
    snprintf(key, key_cap, "%s|%s", host, url);
}

/*
 * Append decoded chunked body bytes from data[0..len) to cold->chunk_buf.
 * chunk_buf layout: headers occupy [0..chunk_hdr_len), decoded body follows.
 * Maintains cold->chunk_remaining and cold->chunk_skip_crlf across calls.
 * Returns true when the terminal chunk (size 0) is detected.
 * Stops accumulating (but returns false) if CHUNK_MAX_BODY is exceeded or
 * on allocation failure — the partial data is simply not cached.
 */
bool chunked_decode_append(struct conn_cold *cold,
                           const uint8_t *data, size_t len)
{
    const uint8_t *p   = data;
    const uint8_t *end = data + len;

    while (p < end) {
        /* Consume the trailing \r\n that follows each chunk's data */
        if (cold->chunk_skip_crlf) {
            if (p + 2 > end) break; /* split across recvs — wait */
            if (p[0] == '\r' && p[1] == '\n') p += 2;
            cold->chunk_skip_crlf = false;
        }

        if (cold->chunk_remaining == 0) {
            /* Expecting: <hex-size>[;ext]\r\n */
            const uint8_t *crlf = memmem(p, (size_t)(end - p), "\r\n", 2);
            if (!crlf) break; /* incomplete size line — wait for more data */
            size_t hex_len = (size_t)(crlf - p);
            if (hex_len == 0 || hex_len > 8) break; /* malformed */
            char hex[9] = {0};
            /* Copy up to optional semicolon (chunk extensions) */
            size_t hl = hex_len;
            for (size_t i = 0; i < hex_len; i++) { if (p[i] == ';') { hl = i; break; } }
            memcpy(hex, p, hl);
            uint32_t chunk_size = (uint32_t)strtoul(hex, NULL, 16);
            p = crlf + 2;
            if (chunk_size == 0) return true; /* terminal chunk */
            cold->chunk_remaining = chunk_size;
        }

        /* Copy body bytes into chunk_buf (after the saved headers) */
        uint32_t avail    = (uint32_t)(end - p);
        uint32_t to_copy  = avail < cold->chunk_remaining ? avail : cold->chunk_remaining;
        uint32_t buf_used = cold->chunk_hdr_len + cold->chunk_body_len;

        if (buf_used + to_copy <= CHUNK_MAX_BODY + cold->chunk_hdr_len) {
            if (buf_used + to_copy > cold->chunk_buf_cap) {
                uint32_t new_cap = cold->chunk_buf_cap ? cold->chunk_buf_cap * 2 : 131072;
                while (new_cap < buf_used + to_copy) new_cap *= 2;
                if (new_cap > cold->chunk_hdr_len + CHUNK_MAX_BODY)
                    new_cap = cold->chunk_hdr_len + CHUNK_MAX_BODY;
                uint8_t *nb = realloc(cold->chunk_buf, new_cap);
                if (nb) { cold->chunk_buf = nb; cold->chunk_buf_cap = new_cap; }
                else { to_copy = 0; } /* alloc failed — skip bytes, give up caching */
            }
            if (cold->chunk_buf && to_copy > 0) {
                memcpy(cold->chunk_buf + buf_used, p, to_copy);
                cold->chunk_body_len += to_copy;
            }
        }

        p                    += to_copy;
        cold->chunk_remaining -= to_copy;
        if (cold->chunk_remaining == 0)
            cold->chunk_skip_crlf = true;
    }
    return false;
}

/*
 * Build cache-ready headers (TE:chunked removed, Content-Length added)
 * into scratch[0..scratch_cap), then call cache_store.
 * Frees cold->chunk_buf and resets all chunk_* fields.
 */
void cache_chunked_store(struct worker *w, uint32_t cid,
                         struct conn_hot *h, struct conn_cold *cold)
{
    if (!cold->chunk_buf || cold->chunk_body_len == 0 || !w->cache || !w->cache->index)
        goto cleanup;

    /* Scratch = recv_buf (client recv is idle during backend streaming) */
    uint8_t *scratch     = conn_recv_buf(&w->pool, cid);
    size_t   scratch_cap = w->pool.buf_size;
    const uint8_t *src   = cold->chunk_buf;
    size_t   slen        = cold->chunk_hdr_len;
    size_t   out         = 0;

    /* Copy headers, removing Transfer-Encoding and Content-Length lines */
    const uint8_t *p2 = src, *src_end = src + slen;
    while (p2 < src_end) {
        /* Find end of current header line */
        const uint8_t *eol = memmem(p2, (size_t)(src_end - p2), "\r\n", 2);
        if (!eol) { /* copy remainder */
            size_t rem = (size_t)(src_end - p2);
            if (out + rem <= scratch_cap) { memcpy(scratch + out, p2, rem); out += rem; }
            break;
        }
        size_t line_len = (size_t)(eol - p2) + 2; /* including \r\n */

        /* Skip Transfer-Encoding and Content-Length header lines */
        bool skip = ((line_len >= 20 &&
                      (memcmp(p2, "Transfer-Encoding:", 18) == 0 ||
                       memcmp(p2, "transfer-encoding:", 18) == 0)) ||
                     (line_len >= 16 &&
                      (memcmp(p2, "Content-Length:", 15) == 0 ||
                       memcmp(p2, "content-length:", 15) == 0)));
        if (!skip && out + line_len <= scratch_cap) {
            memcpy(scratch + out, p2, line_len);
            out += line_len;
        }
        p2 = eol + 2;

        /* Stop at blank line (\r\n\r\n — eol == p2 - 2 means blank line coming) */
        if (eol[0] == '\r' && eol[1] == '\n' && p2 < src_end &&
            p2[0] == '\r' && p2[1] == '\n') {
            /* p2 is the final \r\n\r\n — we haven't copied it yet */
            break;
        }
    }

    /* Append Content-Length and blank line */
    char cl_hdr[48];
    int cl_len = snprintf(cl_hdr, sizeof(cl_hdr),
                          "Content-Length: %u\r\n\r\n", cold->chunk_body_len);
    if (out + (size_t)cl_len <= scratch_cap) {
        memcpy(scratch + out, cl_hdr, (size_t)cl_len);
        out += (size_t)cl_len;
    } else goto cleanup;

    cache_store(w->cache, cold->chunk_url, strlen(cold->chunk_url),
                200, cold->chunk_ttl,
                scratch, out,
                cold->chunk_buf + cold->chunk_hdr_len, cold->chunk_body_len);
    log_debug("cache_chunked", "conn=%u url=%s body=%u ttl=%u",
              cid, cold->chunk_url, cold->chunk_body_len, cold->chunk_ttl);
    (void)h;

cleanup:
    free(cold->chunk_buf);
    cold->chunk_buf      = NULL;
    cold->chunk_buf_cap  = 0;
    cold->chunk_hdr_len  = 0;
    cold->chunk_body_len = 0;
    cold->chunk_remaining = 0;
    cold->chunk_skip_crlf = false;
}

/*
 * Switch a streaming connection into zero-copy splice mode.
 * Creates a pipe (if not already open), increases its buffer to 512 KB,
 * then submits a SPLICE_BACKEND SQE: backend_fd → pipe[1].
 * Falls back to the normal RECV_BACKEND path if pipe creation fails.
 */
void begin_splice(struct worker *w, uint32_t cid, struct conn_hot *h)
{
    struct conn_cold *cold = conn_cold_ptr(&w->pool, cid);

    if (cold->splice_pipe[0] < 0) {
        if (pipe2(cold->splice_pipe, O_NONBLOCK | O_CLOEXEC) < 0) {
            /* Fallback: normal recv/send */
            struct io_uring_sqe *sqe = io_uring_get_sqe(&w->uring.ring);
            if (!sqe) { conn_close(w, cid, true); return; }
            PREP_RECV(w, sqe, h->backend_fd, FIXED_FD_BACKEND(w, cid),
                conn_send_buf(&w->pool, cid),
                h->recv_window, 0, SEND_IDX_SEND(w, cid));
            sqe->user_data = URING_UD_ENCODE(VORTEX_OP_RECV_BACKEND, cid);
            uring_submit(&w->uring);
            return;
        }
        /* 512 KB pipe buffer — reduces kernel round-trips for large bodies */
        fcntl(cold->splice_pipe[1], F_SETPIPE_SZ, 512 * 1024);
    }

    h->flags |= CONN_FLAG_SPLICE_MODE;
    struct io_uring_sqe *sqe = io_uring_get_sqe(&w->uring.ring);
    if (!sqe) { conn_close(w, cid, true); return; }
    /* Splice up to 1 MB at a time from backend socket into pipe.
     * SPLICE_F_MOVE: hint kernel to avoid data copies where possible. */
    io_uring_prep_splice(sqe, h->backend_fd, -1,
                         cold->splice_pipe[1], -1,
                         (unsigned int)(1u << 20), SPLICE_F_MOVE);
    sqe->user_data = URING_UD_ENCODE(VORTEX_OP_SPLICE_BACKEND, cid);
    uring_submit(&w->uring);
}
