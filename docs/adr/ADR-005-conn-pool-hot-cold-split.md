# ADR-005: Connection Pool with Hot/Cold Struct Split

**Status:** Accepted  
**Date:** 2024

## Context

Each worker manages up to N concurrent connections. Connection state access patterns differ significantly between frequently-accessed per-event fields and rarely-accessed per-connection metadata.

## Decision

Split connection state into two arrays:

- `conn_hot[]`: 64-byte cache-line-aligned array of frequently accessed fields (`state`, `flags`, `client_fd`, `backend_fd`, `recv_window`, `route_idx`, `backend_idx`). One entry per connection slot.
- `conn_cold[]`: heap-allocated array of large, rarely-accessed fields (`backend_ssl`, `h2`, `chunk_buf`, `backend_addr`, `backend_deadline_ns`, `splice_pipe`).

Buffer slabs are contiguous mmap regions, one per direction, sliced per-connection. Registered with io_uring as fixed buffers at startup.

## Rationale

- **Cache efficiency**: the io_uring event loop processes CQEs sequentially. For each CQE, only `conn_hot[cid]` is accessed for routing decisions. With 64-byte alignment, each hot entry fits one cache line — typical batch of 32 CQEs touches at most 32 cache lines.
- **Fixed-buffer registration**: contiguous slab layout is required for `io_uring_register_buffers()`. The kernel pins the entire slab once; per-operation page pinning is eliminated.
- **Free list**: O(1) alloc/free via stack-based `free_list[]`. No malloc per connection.
- **Ownership invariant**: `conn_free()` asserts (logs warning) if `backend_ssl` or `h2` are non-NULL at free time — these must be freed by `conn_close()` before `conn_free()`.

## Consequences

- `sizeof(struct vortex_config)` is 3.1 MB — never stack-allocate. Tests use file-scope static globals; `main.c` uses a file-scope static `g_cfg`.
- `conn_cold` is accessed via pointer dereference from `conn_hot`'s sibling index — one extra indirection, justified by cold-path access pattern.
- Connection pool capacity is fixed at startup (`VORTEX_MAX_CONNS`). Under extreme load, new connections are rejected (logged, client gets RST) rather than dynamically growing the pool — avoids malloc latency on the hot path.
