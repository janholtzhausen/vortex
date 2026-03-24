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

/* Per-connection stream concurrency limit.
 * Browser UIs can burst well past 32 concurrent requests on one H2 session
 * once images, JS chunks, API calls, and SignalR setup overlap. Keep the
 * advertised max and local slot count aligned to avoid refusing streams
 * during normal page load. */
#define H2_MAX_STREAMS       128
#define H2_STREAM_SLOTS      128

/* gRPC backend (h2c) header/trailer storage limits */
#define H2_GRPC_MAX_HDRS      32
#define H2_GRPC_MAX_TRAILERS  16
#define H2_GRPC_HDR_NAME_MAX  64
#define H2_GRPC_HDR_VAL_MAX   256

struct h2_grpc_hdr {
    char name [H2_GRPC_HDR_NAME_MAX];
    char value[H2_GRPC_HDR_VAL_MAX];
};

/*
 * State for the backend h2c leg of a gRPC stream.
 * Heap-allocated via h2_stream.grpc; freed in h2_stream_cleanup.
 *
 * nghttp2 is used as a client against the backend — it handles H2 preface,
 * SETTINGS exchange, HPACK, and frame framing.  We feed raw bytes received
 * from the backend into nghttp2_session_mem_recv and drain nghttp2 output
 * (SETTINGS_ACK, WINDOW_UPDATE, etc.) back to the backend via io_uring.
 */
struct h2_grpc_backend {
    nghttp2_session  *ngh2;         /* nghttp2 client session */
    struct h2_session *sess;        /* parent frontend session */
    int32_t           stream_id;    /* nghttp2 client stream ID (always 1) */

    /* Pending bytes to send to backend (nghttp2 client output) */
    uint8_t  *send_buf;
    uint32_t  send_len;
    uint32_t  send_cap;
    bool      send_in_flight;

    /* Per-recv scratch buffer for raw bytes from backend */
    uint8_t   recv_buf[16384];

    /* Request body offset for the nghttp2 data-provider callback */
    uint32_t  req_body_sent;

    /* Response headers received from backend HEADERS frame */
    struct h2_grpc_hdr resp_hdrs[H2_GRPC_MAX_HDRS];
    int                resp_nhdrs;
    int                resp_status;   /* numeric HTTP status from :status */
    bool               resp_hdrs_done;

    /* Trailers received from backend trailing HEADERS frame (END_STREAM) */
    struct h2_grpc_hdr trailers[H2_GRPC_MAX_TRAILERS];
    int                ntrailers;
    bool               trailers_done;
};

/* Initial output buffer for nghttp2_session_mem_send → io_uring SEND */
#define H2_SEND_BUF_SIZE     (32 * 1024)

/* Backend receive buffer per stream */
#define H2_STREAM_RECV_CAP   (256 * 1024)

/* Maximum accumulated backend response for the *buffered* path
 * (Transfer-Encoding: chunked responses that cannot be streamed).
 * Non-chunked responses are streamed and have no fixed size cap. */
#define H2_RESP_MAX          (64 * 1024 * 1024)

/* Streaming backpressure: stop reading from backend when this many body bytes
 * are pending in resp_buf but not yet consumed by the nghttp2 data provider.
 * Limits per-stream memory to ~2 × this value (one window of unread + one recv). */
#define H2_STREAM_BUF_MAX    (1 * 1024 * 1024)

typedef enum {
    H2_STREAM_FREE = 0,
    H2_STREAM_OPEN,          /* HEADERS received, backend not connected */
    H2_STREAM_CONNECTING,    /* async backend TCP connect in flight */
    H2_STREAM_SENDING_REQ,   /* sending HTTP/1.1 request to backend */
    H2_STREAM_WAITING_RESP,  /* request sent, awaiting backend response */
    H2_STREAM_STREAMING,     /* receiving backend response, sending to client */
    H2_STREAM_GRPC_ACTIVE,   /* h2c backend active, exchanging gRPC frames */
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
    bool     req_too_large;
    bool     auth_ok;
    bool     auth_seen;

    /* Backend response accumulation buffer (heap) */
    uint8_t *resp_buf;
    uint32_t resp_buf_len;
    uint32_t resp_buf_cap;
    bool     resp_headers_done; /* \r\n\r\n found in resp_buf */
    uint32_t resp_hdr_end;      /* byte offset of end of headers (past \r\n\r\n) */
    bool     backend_eof;       /* backend closed connection */
    bool     resp_submitted;    /* nghttp2_submit_response called */
    uint32_t resp_body_sent;    /* bytes already given to nghttp2 data provider */

    /* Streaming (non-chunked) path: response submitted as soon as headers
     * arrive; body bytes fed incrementally via NGHTTP2_ERR_DEFERRED. */
    bool     is_chunked_resp;      /* Transfer-Encoding: chunked → use buffered path */
    bool     prefer_buffered_resp; /* fonts/images stay on the buffered path */
    bool     backend_recv_paused;  /* recv not re-armed; resume after client drains */

    /* Partial HTTP/1.1 request send tracking */
    uint32_t req_send_off;      /* bytes of assembled request already sent */

    /* Assembled HTTP/1.1 request (heap) */
    uint8_t *req_http11;
    uint32_t req_http11_len;

    uint8_t  slot;              /* index in h2_session.streams[] */
    uint32_t cid;               /* parent connection id */

    /* gRPC proxying (h2c backend).  Non-NULL only when is_grpc = true. */
    bool                   is_grpc;
    struct h2_grpc_backend *grpc;
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

/* Called from VORTEX_OP_H2_RECV_CLIENT completion.
 * data/buf_id: ring buffer assigned by the kernel (NULL/0 when no recv_ring).
 * multishot_active: true when IORING_CQE_F_MORE is set (SQE still armed). */
void h2_on_recv(struct worker *w, uint32_t cid, int n,
                const uint8_t *data, uint16_t buf_id, bool multishot_active);

/* Called from VORTEX_OP_H2_SEND_CLIENT completion */
void h2_on_send_client(struct worker *w, uint32_t cid, int sent);

/* Called from VORTEX_OP_H2_CONNECT completion */
void h2_on_backend_connect(struct worker *w, uint32_t cid, uint32_t slot, int res);

/* Called from VORTEX_OP_H2_SEND_BACKEND completion */
void h2_on_backend_send(struct worker *w, uint32_t cid, uint32_t slot, int sent);

/* Called from VORTEX_OP_H2_RECV_BACKEND completion */
void h2_on_backend_recv(struct worker *w, uint32_t cid, uint32_t slot, int n);

/* Called from VORTEX_OP_H2_GRPC_SEND_BACKEND completion */
void h2_on_grpc_backend_send(struct worker *w, uint32_t cid, uint32_t slot, int sent);

/* Called from VORTEX_OP_H2_GRPC_RECV_BACKEND completion */
void h2_on_grpc_backend_recv(struct worker *w, uint32_t cid, uint32_t slot, int n);
