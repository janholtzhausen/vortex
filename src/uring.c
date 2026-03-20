#include "uring.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

int uring_init(struct uring_ctx *ctx, unsigned int entries, bool sqpoll)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->sq_entries = entries;
    ctx->cq_entries = entries * 2;
    ctx->sqpoll     = sqpoll;

    struct io_uring_params params = { 0 };
    params.flags = IORING_SETUP_COOP_TASKRUN | IORING_SETUP_SINGLE_ISSUER;
    params.cq_entries = ctx->cq_entries;
    params.flags |= IORING_SETUP_CQSIZE;

    if (sqpoll) {
        params.flags |= IORING_SETUP_SQPOLL;
        params.sq_thread_idle = 2000; /* ms */
        log_info("uring_init", "SQPOLL mode enabled");
    }

    int ret = io_uring_queue_init_params(entries, &ctx->ring, &params);
    if (ret < 0) {
        /* Try without CQSIZE if unsupported */
        params.flags &= ~IORING_SETUP_CQSIZE;
        params.cq_entries = 0;
        ret = io_uring_queue_init_params(entries, &ctx->ring, &params);
    }
    if (ret < 0) {
        log_error("uring_init", "io_uring_queue_init_params failed: %s", strerror(-ret));
        return ret;
    }

    log_info("uring_init", "sq_entries=%u cq_entries=%u sqpoll=%d",
        entries, ctx->cq_entries, sqpoll);
    return 0;
}

void uring_destroy(struct uring_ctx *ctx)
{
    io_uring_queue_exit(&ctx->ring);
}

int uring_submit(struct uring_ctx *ctx)
{
    int ret = io_uring_submit(&ctx->ring);
    if (ret < 0) {
        log_error("uring_submit", "failed: %s", strerror(-ret));
        return ret;
    }
    return ret;
}

int uring_wait(struct uring_ctx *ctx, unsigned int min_events)
{
    struct io_uring_cqe *cqe;
    unsigned int count = 0;

    /* Block until at least min_events completions */
    int ret = io_uring_wait_cqe_nr(&ctx->ring, &cqe, min_events);
    if (ret < 0) {
        if (ret == -EINTR) return 0;
        log_error("uring_wait", "io_uring_wait_cqe_nr: %s", strerror(-ret));
        return ret;
    }

    /* Drain all available completions */
    unsigned head;
    io_uring_for_each_cqe(&ctx->ring, head, cqe) {
        count++;
    }
    io_uring_cq_advance(&ctx->ring, count);
    return (int)count;
}

int uring_prep_accept(struct uring_ctx *ctx, int server_fd, uint32_t conn_id)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    if (!sqe) return -EBUSY;
    io_uring_prep_multishot_accept(sqe, server_fd, NULL, NULL, 0);
    sqe->user_data = URING_UD_ENCODE(VORTEX_OP_ACCEPT, conn_id);
    return 0;
}

int uring_prep_recv(struct uring_ctx *ctx, int fd, void *buf, size_t len, uint32_t conn_id)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    if (!sqe) return -EBUSY;
    io_uring_prep_recv(sqe, fd, buf, len, 0);
    sqe->user_data = URING_UD_ENCODE(VORTEX_OP_RECV, conn_id);
    return 0;
}

int uring_prep_send(struct uring_ctx *ctx, int fd, const void *buf, size_t len, uint32_t conn_id)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    if (!sqe) return -EBUSY;
    io_uring_prep_send(sqe, fd, buf, len, 0);
    sqe->user_data = URING_UD_ENCODE(VORTEX_OP_SEND, conn_id);
    return 0;
}

int uring_prep_connect(struct uring_ctx *ctx, int fd,
                       struct sockaddr *addr, socklen_t addrlen,
                       uint32_t conn_id)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    if (!sqe) return -EBUSY;
    io_uring_prep_connect(sqe, fd, addr, addrlen);
    sqe->user_data = URING_UD_ENCODE(VORTEX_OP_CONNECT, conn_id);
    return 0;
}

int uring_prep_close(struct uring_ctx *ctx, int fd, uint32_t conn_id)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    if (!sqe) return -EBUSY;
    io_uring_prep_close(sqe, fd);
    sqe->user_data = URING_UD_ENCODE(VORTEX_OP_CLOSE, conn_id);
    return 0;
}

int uring_prep_timeout(struct uring_ctx *ctx, struct __kernel_timespec *ts,
                       uint32_t conn_id)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    if (!sqe) return -EBUSY;
    io_uring_prep_timeout(sqe, ts, 0, 0);
    sqe->user_data = URING_UD_ENCODE(VORTEX_OP_TIMEOUT, conn_id);
    return 0;
}
