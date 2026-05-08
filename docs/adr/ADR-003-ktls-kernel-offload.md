# ADR-003: kTLS Kernel TLS Offload

**Status:** Accepted  
**Date:** 2024

## Context

After TLS handshake, symmetric encryption/decryption (AES-GCM, ChaCha20-Poly1305) can run either in userspace via picotls record layer, or in the kernel via the TLS ULP (kTLS, Linux 4.13+).

## Decision

After picotls handshake, extract traffic keys via `ptls_get_traffic_keys()`, install into kernel via `setsockopt(SOL_TCP, TCP_ULP, "tls")` + `setsockopt(SOL_TLS, TLS_TX/TLS_RX)`, then free the `ptls_t*` context. io_uring then operates directly on the fd with plaintext I/O — the kernel handles AEAD on every `send`/`recv`.

## Return Value Convention

`tls_accept()` returns `NULL` on **both** kTLS success and handshake failure. Callers distinguish via the `*ktls_tx_out` output parameter:
- `NULL` + `*ktls_tx_out = true` → kTLS installed, kernel owns crypto
- `NULL` + `*ktls_tx_out = false` → handshake failed
- Non-NULL → non-kTLS fallback, caller holds `ptls_t*`

## Rationale

- **Zero-copy I/O**: with kTLS RX, `recv()` returns plaintext directly into user buffers — no intermediate copy for decryption
- **CPU offload**: on NIC hardware with TLS offload (e.g., Mellanox ConnectX-5+), kTLS TX can be hardware-accelerated
- **io_uring compatibility**: io_uring operations work on the kTLS fd without modification. Without kTLS, picotls `ptls_send`/`ptls_receive` would need to wrap every I/O call.
- **Sequence number accuracy**: TX sequence number after the handshake is typically 1 (server sent NewSessionTicket using epoch-3, seq=0). `ptls_get_traffic_keys()` returns the post-handshake seq correctly.

## Constraints

- `splice` and `send_zc` are incompatible with kTLS TX on kernel 6.8 (`EIO` instead of `EINVAL`). Both are gated on `!CONN_FLAG_KTLS_TX`. Do not remove these guards.
- kTLS RX: `EIO` from `recv()` on a kTLS fd means `close_notify` or TLS alert (treated as clean close in the worker state machine).
- ChaCha20-Poly1305 IV layout differs from AES-GCM: full 12-byte IV copied directly rather than salt+iv split. `install_ktls_direction` handles both.

## Alternatives Rejected

- **Userspace TLS only**: every io_uring recv/send would require a picotls encrypt/decrypt step. At 40 Gbps line rate, AES-NI in userspace is competitive but adds memory copies and per-operation lock contention on the picotls context.
- **OpenSSL kTLS**: OpenSSL 3.x supports kTLS but requires linking OpenSSL. See ADR-002.

## Consequences

- On kernels without `tls` module loaded or without AES-NI, falls back to userspace picotls path transparently. `tls->ktls_available` is probed at startup via `/proc/net/tls_stat`.
- Non-kTLS path restores socket to original flags after handshake; non-kTLS backend send/recv uses poll-on-EAGAIN loop bounded by `backend_timeout_ms`.
