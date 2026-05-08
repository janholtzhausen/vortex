# ADR-001: io_uring for async I/O

**Status:** Accepted  
**Date:** 2024

## Context

A high-performance reverse proxy needs to handle thousands of concurrent connections without per-connection thread overhead. Options considered: blocking threads, epoll, io_uring.

## Decision

Use `io_uring` (Linux 5.1+) as sole async I/O mechanism. One ring per worker thread. Multishot accept. Fixed-buffer and fixed-file registration for zero-copy paths.

## Rationale

- **Zero syscall per packet** on the data path when SQPOLL is enabled (kernel polls SQ without needing a syscall from userspace)
- **Multishot accept** issues one SQE and gets unlimited CQEs — no re-arm overhead per connection
- **Fixed buffers** (`IORING_OP_READ_FIXED` / `IORING_OP_WRITE_FIXED`) pin buffer pages once at startup, eliminating per-operation page pinning
- **Fixed files** eliminate `fdget/fdput` on every I/O operation by using slot indices instead of real fds
- **Batched submission** amortises syscall cost across multiple operations per loop iteration

## Alternatives Rejected

- **epoll + threads**: context-switch overhead at scale; thundering herd on accept; no zero-copy path
- **epoll + one thread**: single core limit; no parallelism for CPU-bound work (compression, auth)
- **kqueue (BSD)**: Linux-only deployment target

## Consequences

- Minimum kernel: 5.19 (for full fixed-file + multishot + IORING_OP_CONNECT support used here)
- Worker thread is a run-to-completion event loop — any blocking call (DNS, TLS handshake for backends) stalls all connections on that worker. Mitigated by offloading TLS to `tls_pool` and DNS resolution at startup.
- kTLS TX and `send_zc` / `begin_splice` are gated on `!CONN_FLAG_KTLS_TX` — kernel 6.8 incompatibility; do not remove these guards.
