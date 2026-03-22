#pragma once
/*
 * h2.h — HTTP/2 frontend session and stream types for vortex.
 *
 * One h2_session is heap-allocated per HTTP/2 client connection, pointed to
 * by conn_cold.h2 (NULL for HTTP/1.1 connections).  Each concurrent HTTP/2
 * stream gets a slot in sess->streams[]; H2_STREAM_SLOTS bounds the
 * per-connection concurrency (also advertised in SETTINGS).
 *
 * Data flow:
 *  Client --(HTTP/2 TLS)--> vortex (nghttp2 session) --(HTTP/1.1)--> backend
 *
 * Backend connections are plain TCP per-stream (not registered fixed files).
 * Sending to the HTTP/2 client is serialized via send_in_flight: only one
 * io_uring SEND (VORTEX_OP_H2_SEND_CLIENT) is outstanding at a time.
 */

#include <nghttp2/nghttp2.h>
#include <stdint.h>
#include <stdbool.h>

/* Per-connection stream concurrency limit */
#define H2_MAX_STREAMS       32
#define H2_STREAM_SLOTS      32

/* Initial output buffer for nghttp2_session_mem_send → io_uring SEND */
#define H2_SEND_BUF_SIZE     (32 * 1024)

/* Backend receive buffer per stream */
#define H2_STREAM_RECV_CAP   (256 * 1024)

/* Maximum accumulated backend response (body + headers).
 * The current H2 path buffers the full backend response before submission, and
 * modern frontend bundles can exceed 4 MiB. */
#define H2_RESP_MAX          (16 * 1024 * 1024)

typedef enum {
    H2_STREAM_FREE = 0,
    H2_STREAM_OPEN,          /* HEADERS received, backend not connected */
    H2_STREAM_CONNECTING,    /* async backend TCP connect in flight */
    H2_STREAM_SENDING_REQ,   /* sending HTTP/1.1 request to backend */
    H2_STREAM_WAITING_RESP,  /* request sent, awaiting backend response */
    H2_STREAM_STREAMING,     /* receiving backend response, sending to client */
    H2_STREAM_CLOSING,       /* RST or error */
} h2_stream_state_t;

/*
 * State for one HTTP/2 stream.  Streams share the parent h2_session.
 * Backend is connected separately per stream (plain TCP, not fixed-file).
 */
struct h2_stream {
    int32_t           stream_id;   /* nghttp2 stream ID; 0 = free slot */
    h2_stream_state_t state;
    int               backend_fd;  /* -1 = not connected */

    /* Request pseudo-headers (from HEADERS frame) */
    char  method[16];
    char  path[2048];
    char  authority[256];
    char  scheme[16];

    /* Regular (non-pseudo) request headers for HTTP/1.1 forward */
    uint8_t  req_hdr_buf[4096];
    uint32_t req_hdr_len;

    /* Request body (for POST / PUT) */
    uint8_t *req_body;
    uint32_t req_body_len;
    uint32_t req_body_cap;
    bool     req_complete;   /* END_STREAM received from client */

    /* Backend response accumulation buffer (heap) */
    uint8_t *resp_buf;
    uint32_t resp_buf_len;
    uint32_t resp_buf_cap;
    bool     resp_headers_done; /* \r\n\r\n found in resp_buf */
    uint32_t resp_hdr_end;      /* byte offset of end of headers (past \r\n\r\n) */
    bool     backend_eof;       /* backend closed connection */
    bool     resp_submitted;    /* nghttp2_submit_response2 called */
    uint32_t resp_body_sent;    /* bytes already given to nghttp2 data provider */

    /* Partial HTTP/1.1 request send tracking */
    uint32_t req_send_off;      /* bytes of assembled request already sent */

    /* Assembled HTTP/1.1 request (heap) */
    uint8_t *req_http11;
    uint32_t req_http11_len;

    uint8_t  slot;              /* index in h2_session.streams[] */
    uint32_t cid;               /* parent connection id */
};

/*
 * Per-connection HTTP/2 session state.
 * Allocated on first H2 request; freed in conn_close().
 */
struct h2_session {
    nghttp2_session *ngh2;
    struct h2_stream streams[H2_STREAM_SLOTS];
    uint32_t         active_streams;

    /* Serialised client send queue — nghttp2 output buffered here */
    uint8_t         *send_buf;    /* heap, grows as needed */
    uint32_t         send_buf_cap;
    uint32_t         send_buf_len;
    uint32_t         send_buf_off;
    bool             send_in_flight;

    struct worker   *w;           /* owning worker (for io_uring access) */
    uint32_t         cid;
};

/* Forward declaration (full type in worker.h) */
struct worker;

/* Lifecycle */
int  h2_session_init(struct worker *w, uint32_t cid);
void h2_session_free(struct h2_session *sess);

/* Called from VORTEX_OP_H2_RECV_CLIENT completion */
void h2_on_recv(struct worker *w, uint32_t cid, int n);

/* Called from VORTEX_OP_H2_SEND_CLIENT completion */
void h2_on_send_client(struct worker *w, uint32_t cid, int sent);

/* Called from VORTEX_OP_H2_CONNECT completion */
void h2_on_backend_connect(struct worker *w, uint32_t cid, uint32_t slot, int res);

/* Called from VORTEX_OP_H2_SEND_BACKEND completion */
void h2_on_backend_send(struct worker *w, uint32_t cid, uint32_t slot, int sent);

/* Called from VORTEX_OP_H2_RECV_BACKEND completion */
void h2_on_backend_recv(struct worker *w, uint32_t cid, uint32_t slot, int n);
