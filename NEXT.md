# Next

## Correctness / stability

- **Wildcard hostname matching** — routing is currently exact + case-insensitive. `*.example.com`
  routes require implementing a suffix-match pass in `router.c` before exact lookup.
- **Config reload — topology changes** — SIGHUP rejects backend count/order changes; a full
  live-reload of route+backend topology without restart would require a RCU-style swap of the
  route table pointer.
- **WebSocket relay back-pressure** — currently one in-flight recv/send chain per direction;
  deep proxy-side queuing for high-latency WS peers not implemented.

## Performance

- **io_uring fixed-file / registered buffers** — `IORING_OP_READ_FIXED` / `IORING_OP_WRITE_FIXED`
  with pre-registered fds and buffers would reduce per-syscall overhead further.
- **least_conn accuracy** — active-count per backend is approximate across workers; a shared
  atomic or lock-free counter would make it exact.
- **Zero-copy splice for non-kTLS paths** — `send_zc` / `splice` are already gated on
  `!CONN_FLAG_KTLS_TX`; adding a splice fast-path for plain-HTTP backends would reduce copies.

## Features

- **Wildcard SAN / multi-domain certs** — ACME currently issues per-hostname certs; adding
  multi-SAN order support would reduce cert count for vhosts on the same domain.
- **Additional DNS-01 providers** — Cloudflare is the only implementation; Route53 / Gandi /
  Hetzner would cover common setups.
- **HTTP/3 stable build** — ngtcp2/nghttp3 conditional compile works but is not included in the
  default `.deb` build; a `WITH_HTTP3=1` build variant would make it distributable.
- **Prometheus histogram metrics** — request latency and backend response time histograms would
  make SLO alerting practical.

## Quality

- Address remaining clang-tidy implicit-widening warnings in `src/auth.c` BlockMix/ROMix with
  explicit `(size_t)` casts throughout (low risk, cosmetic).
- Expand unit test coverage: `test_router.c` covers route lookup but not LB algorithm selection;
  `test_cache.c` does not cover disk-backed slab or CRC verification paths.
- Add a `clang-tidy` CMake target so `make tidy` runs the full check pass without manual
  invocation.
