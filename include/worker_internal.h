#pragma once
/*
 * worker_internal.h — shared macros and forward declarations for the worker
 * subsystem.  Included by every worker_*.c translation unit.  NOT part of
 * the public worker API (use worker.h for that).
 */

#define _GNU_SOURCE   /* memmem, pipe2, etc. */

/* All standard/system headers needed by any worker_*.c file */
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/time_types.h>
#include <sys/uio.h>
#include <zlib.h>
#include <brotli/encode.h>
#include <liburing.h>

#include "worker.h"
#include "conn.h"
#include "uring.h"
#include "log.h"
#include "router.h"
#include "cache.h"
#include "pool.h"
#include "config.h"
#include "bpf_loader.h"
#include "util.h"
#include "auth.h"
#include "simd.h"
#ifdef VORTEX_PHASE_TLS
#include "tls.h"
#include "tls_pool.h"
#include <openssl/ssl.h>
#endif

/* Route all memmem calls through the AVX2-accelerated vx_memmem */
#define memmem(h,hl,n,nl) vx_memmem((h),(hl),(n),(nl))
/* Specialized finders — faster than memmem for the two hottest patterns */
#define FIND_CRLF(buf,len)    vx_find_crlf((const uint8_t *)(buf),(size_t)(len))
#define FIND_HDR_END(buf,len) vx_find_hdr_end((const uint8_t *)(buf),(size_t)(len))

/* Dynamic recv window: double on full read, cap at buf_size.
 * Called after every RECV_CLIENT / RECV_BACKEND completion. */
#define RECV_WINDOW_GROW(h, n, buf_size) do { \
    if ((size_t)(n) >= (h)->recv_window && (h)->recv_window < (uint16_t)(buf_size)) { \
        uint32_t next = (uint32_t)(h)->recv_window * 2; \
        (h)->recv_window = (uint16_t)(next < (buf_size) ? next : (buf_size)); \
    } \
} while (0)

/* Minimum body size (bytes) for compression to be worthwhile */
#define COMPRESS_MIN_BODY 512

/* Base64-encode src (len bytes) into dst (must hold ceil(len/3)*4 + 1 bytes).
 * Returns the number of characters written (excluding NUL). */
static inline size_t b64_encode(const char *src, size_t slen, char *dst, size_t dsz)
{
    static const char tab[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t di = 0;
    for (size_t si = 0; si < slen && di + 4 < dsz; si += 3) {
        unsigned int v  = (unsigned char)src[si] << 16;
        if (si+1 < slen) v |= (unsigned char)src[si+1] << 8;
        if (si+2 < slen) v |= (unsigned char)src[si+2];
        dst[di++] = tab[(v >> 18) & 0x3f];
        dst[di++] = tab[(v >> 12) & 0x3f];
        dst[di++] = (si+1 < slen) ? tab[(v >> 6) & 0x3f] : '=';
        dst[di++] = (si+2 < slen) ? tab[v & 0x3f] : '=';
    }
    dst[di] = '\0';
    return di;
}

/*
 * Fixed-buffer I/O helpers.
 * recv_buf[cid] is registered at index cid.
 * send_buf[cid] is registered at index (pool.capacity + cid).
 *
 * liburing 2.5 (Ubuntu 24.04) has io_uring_prep_read_fixed /
 * io_uring_prep_write_fixed which map to IORING_OP_READ_FIXED /
 * IORING_OP_WRITE_FIXED.  These use registered (pinned) buffers and work
 * on any fd, including TCP sockets and kTLS fds.  Offset is 0 (ignored by
 * the kernel for streaming sockets).
 *
 * Falls back to standard prep_recv/prep_send if registration failed.
 * MSG_NOSIGNAL is not needed for WRITE_FIXED because main() installs
 * SIG_IGN for SIGPIPE.
 *
 * When fixed files are registered (IOSQE_FIXED_FILE), the fd field of the
 * SQE is a slot index rather than a real fd — eliminating fdget/fdput on
 * every operation.  slot is FIXED_FD_CLIENT/BACKEND(w,cid).
 */
#define PREP_RECV(w, sqe, fd, slot, buf, len, _io_flags, buf_idx) do { \
    int _pfd = ((w)->uring.files_registered) ? (slot) : (fd); \
    if ((w)->uring.bufs_registered) \
        io_uring_prep_read_fixed((sqe), _pfd, (buf), (unsigned)(len), 0, (buf_idx)); \
    else \
        io_uring_prep_recv((sqe), _pfd, (buf), (len), (_io_flags)); \
    if ((w)->uring.files_registered) (sqe)->flags |= IOSQE_FIXED_FILE; \
} while (0)

#define PREP_SEND(w, sqe, fd, slot, buf, len, _io_flags, buf_idx) do { \
    int _pfd = ((w)->uring.files_registered) ? (slot) : (fd); \
    if ((w)->uring.bufs_registered) \
        io_uring_prep_write_fixed((sqe), _pfd, (buf), (unsigned)(len), 0, (buf_idx)); \
    else \
        io_uring_prep_send((sqe), _pfd, (buf), (len), (_io_flags)); \
    if ((w)->uring.files_registered) (sqe)->flags |= IOSQE_FIXED_FILE; \
} while (0)

/* Fixed buffer index for a connection's recv_buf */
#define SEND_IDX_RECV(w, cid)  ((int)(cid))
/* Fixed buffer index for a connection's send_buf */
#define SEND_IDX_SEND(w, cid)  ((int)((w)->pool.capacity + (cid)))

/* Fixed file table layout:
 *   slot 0           — server listen fd
 *   slots [1..cap]   — client_fd for connection cid
 *   slots [cap+1..2*cap] — backend_fd for connection cid */
#define FIXED_FD_SERVER         0
#define FIXED_FD_CLIENT(w, cid)  ((int)(1 + (cid)))
#define FIXED_FD_BACKEND(w, cid) ((int)(1 + (w)->pool.capacity + (cid)))

/* Maximum body size to accumulate for chunked TE caching (4 MB) */
#define CHUNK_MAX_BODY (4u * 1024u * 1024u)

/* Circuit breaker defaults */
#define CB_DEFAULT_THRESHOLD       3
#define CB_DEFAULT_OPEN_MS         10000ULL
#define BACKEND_DEFAULT_TIMEOUT_MS 30000ULL

/* ---- Forward declarations for cross-module internal functions ---- */
/* These are NOT static — they have internal linkage within the worker subsystem */

/* worker_compress.c */
size_t gzip_compress(const uint8_t *src, size_t src_len, uint8_t *dst, size_t dst_max);
size_t brotli_compress(const uint8_t *src, size_t src_len, uint8_t *dst, size_t dst_max);
bool   is_compressible_type(const uint8_t *ct_val, size_t ct_len);

/* worker_accept.c */
int  peek_client_hello_sni(int fd, char *out, size_t out_max);
void tarpit_conn(struct worker *w, int fd);
void conn_close(struct worker *w, uint32_t cid, bool is_error);

/* worker_backend.c */
bool cb_is_open(struct worker *w, int ri, int bi, uint64_t now_ns);
void cb_record_failure(struct worker *w, int ri, int bi, uint64_t now_ns,
                       uint32_t cfg_threshold, uint32_t cfg_open_ms);
void cb_record_success(struct worker *w, int ri, int bi);
int  select_available_backend(struct worker *w, int ri, uint32_t client_ip);
void backend_deadline_set(struct worker *w, uint32_t cid, uint32_t timeout_ms);
int  begin_async_connect(struct worker *w, const struct backend_config *bcfg, uint32_t cid);

/* worker_cache.c */
void make_cache_key(const uint8_t *req_buf, size_t req_len,
                    const char *url, char *key, size_t key_cap);
bool chunked_decode_append(struct conn_cold *cold,
                           const uint8_t *data, size_t len);
void cache_chunked_store(struct worker *w, uint32_t cid,
                         struct conn_hot *h, struct conn_cold *cold);
void begin_splice(struct worker *w, uint32_t cid, struct conn_hot *h);

/* worker_proxy.c */
int  parse_http_request_line(const uint8_t *buf, int len,
                             char *method_out, size_t method_max,
                             char *url_out, size_t url_max);
void handle_proxy_data(struct worker *w, struct io_uring_cqe *cqe);
