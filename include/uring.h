#pragma once

#include <liburing.h>
#include <stdint.h>
#include <stdbool.h>

/* Operation types — stored in sqe->user_data (upper bits) */
#define VORTEX_OP_ACCEPT         1
#define VORTEX_OP_RECV_CLIENT    2   /* recv from client → forward to backend */
#define VORTEX_OP_SEND_BACKEND   3   /* send to backend (client data) */
#define VORTEX_OP_RECV_BACKEND   4   /* recv from backend → forward to client */
#define VORTEX_OP_SEND_CLIENT    5   /* send to client (backend data) */
#define VORTEX_OP_CONNECT        6
#define VORTEX_OP_CLOSE          7
#define VORTEX_OP_TIMEOUT        8
#define VORTEX_OP_RECV_CLIENT_WS   9   /* websocket passthrough recv from client */
#define VORTEX_OP_RECV_BACKEND_WS  10  /* websocket passthrough recv from backend */
#define VORTEX_OP_SEND_CLIENT_LINKED 11 /* send to client + pre-armed RECV_CLIENT linked */
#define VORTEX_OP_SPLICE_BACKEND     12 /* splice backend_fd → pipe (zero-copy recv) */
#define VORTEX_OP_SPLICE_CLIENT      13 /* splice pipe → client_fd (zero-copy send) */
#define VORTEX_OP_TLS_DONE           14 /* tls_pool result pipe became readable */
#define VORTEX_OP_SEND_BACKEND_WS    15 /* send client WS frame to backend (after RECV_CLIENT_WS) */
#define VORTEX_OP_SEND_CLIENT_WS     16 /* send backend WS frame to client (after RECV_BACKEND_WS) */
/* Legacy aliases */
#define VORTEX_OP_RECV  VORTEX_OP_RECV_CLIENT
#define VORTEX_OP_SEND  VORTEX_OP_SEND_BACKEND

/* Encode op + conn_id into user_data */
#define URING_UD_ENCODE(op, id)   (((uint64_t)(op) << 32) | (uint32_t)(id))
#define URING_UD_OP(ud)           ((uint32_t)((ud) >> 32))
#define URING_UD_ID(ud)           ((uint32_t)((ud) & 0xFFFFFFFF))

struct uring_ctx {
    struct io_uring  ring;
    unsigned int     sq_entries;
    unsigned int     cq_entries;
    bool             sqpoll;          /* SQPOLL mode */
    bool             bufs_registered; /* io_uring fixed buffers registered */
    bool             files_registered;/* io_uring fixed files registered */
    unsigned int     file_slots;      /* total fixed file slots */
};

int  uring_init(struct uring_ctx *ctx, unsigned int entries, bool sqpoll);
void uring_destroy(struct uring_ctx *ctx);

/* Register fixed buffers for zero-copy pinned I/O.
 * iovecs[0..n-1] describe the buffers; must remain valid for the ring's lifetime.
 * On success, sets ctx->bufs_registered = true and returns 0. */
int  uring_register_bufs(struct uring_ctx *ctx, struct iovec *iovecs, uint32_t n);

/* Register a sparse fixed file table of nslots entries.
 * Eliminates fdget/fdput on every SQE that sets IOSQE_FIXED_FILE.
 * On success, sets ctx->files_registered = true and returns 0. */
int  uring_register_files_sparse(struct uring_ctx *ctx, unsigned int nslots);

/* Install / remove an fd in the fixed file table at the given slot.
 * uring_remove_fd installs -1 (kernel sentinel for "empty slot"). */
int  uring_install_fd(struct uring_ctx *ctx, unsigned int slot, int fd);
int  uring_remove_fd(struct uring_ctx *ctx, unsigned int slot);

/* Submit all pending SQEs */
int uring_submit(struct uring_ctx *ctx);

/* Wait for at least min_events completions, process up to max_events.
 * Returns number processed, or -1 on error. */
int uring_wait(struct uring_ctx *ctx, unsigned int min_events);

/* SQE helpers — return 0 on success, -EBUSY if SQ full */
int uring_prep_accept(struct uring_ctx *ctx, int server_fd, uint32_t conn_id);
int uring_prep_recv(struct uring_ctx *ctx, int fd, void *buf, size_t len, uint32_t conn_id);
int uring_prep_send(struct uring_ctx *ctx, int fd, const void *buf, size_t len, uint32_t conn_id);
int uring_prep_connect(struct uring_ctx *ctx, int fd, struct sockaddr *addr, socklen_t addrlen, uint32_t conn_id);
int uring_prep_close(struct uring_ctx *ctx, int fd, uint32_t conn_id);
int uring_prep_timeout(struct uring_ctx *ctx, struct __kernel_timespec *ts, uint32_t conn_id);
