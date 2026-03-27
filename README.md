# Vortex

A high-performance, kernel-assisted reverse proxy and TLS terminator written in C.

Vortex is built for extreme throughput on Linux using modern kernel interfaces: XDP/eBPF for sub-microsecond packet filtering, io_uring for async I/O, kTLS for kernel-offloaded TLS crypto, and HTTP/3 via QUIC. It targets bare-metal deployments where latency and throughput matter more than operational simplicity.

---

## Feature Summary

### Core Proxy
- **io_uring async I/O** — multishot accept, zero-syscall-per-packet data path
- **Per-CPU worker threads** — one io_uring ring per thread, auto-scales to CPU count (max 64)
- **SNI-based routing** — TLS Server Name Indication routes connections to named backends before the full handshake completes
- **Wildcard hostname matching** — planned but not yet implemented; current matching is exact (case-insensitive)
- **Load balancing** — round-robin, weighted round-robin (honors per-backend `weight`), least-connections, IP-hash
- **HTTP/1.1 keep-alive** — backends with `pool_size > 0` are kept alive and returned to the shared origin pool after each complete response; non-pooled backends are forced closed
- **HTTPS backend TLS offload** — origin `SSL_connect` runs in the shared TLS pool instead of blocking the io_uring worker thread
- **HTTPS backend session reuse** — repeated TLS-origin connections reuse cached client TLS sessions per worker/backend when the origin supports resumption
- **HTTPS backend pooling** — pooled `https://` origins reuse both the TCP socket and live `SSL*` session across client connections when the origin keeps the connection alive
- **Optional compression offload** — gzip/brotli response compression can run in a dedicated thread pool instead of blocking the io_uring worker thread
- **WebSocket passthrough** — detects `Upgrade: websocket` and `101 Switching Protocols`; switches to paired io_uring recv/send chains for full-duplex streaming
- **HTTP/2 and HTTP/3** — HTTP/3 via ngtcp2 + nghttp3 (conditional compile); `Alt-Svc: h3=":443"` injected into HTTP/1.x responses to advertise QUIC

### TLS (OpenSSL 4.0)
- TLS 1.2 and 1.3, configurable minimum/maximum versions and cipher suites
- **kTLS offload** — after handshake, kernel handles symmetric crypto; io_uring operates on plaintext via the socket directly
- **SNI-multiplexed certificates** — one listener, unlimited virtual hosts
- **Session tickets** with configurable timeout and rotation interval
- Per-route certificate providers: static files, ACME HTTP-01, ACME DNS-01

### Certificate Management (ACME)
- Automatic certificate issuance and renewal via Let's Encrypt (or any ACME v2 CA)
- **HTTP-01 challenge** — built-in challenge server on port 80
- **DNS-01 challenge** — Cloudflare DNS provider supported; pluggable `dns_provider` interface for others
- Renewal background thread checks every hour; renews N days before expiry (default 30)
- Hot-reload of static certs on SIGHUP without restart

### XDP/eBPF Acceleration
- XDP program attached in native mode (falls back to SKB/generic mode automatically)
- **IP blocklist** — kernel-space drop before packet reaches userspace; loaded from file on startup and SIGHUP reload
- **Per-IP token-bucket rate limiting** — applied to new connection SYNs; configurable RPS and burst; LRU map auto-evicts stale entries
- **Stateful L4 TCP connection tracking** — fully stateful state machine in XDP:
  - SYN → creates `CT_SYN_SENT` entry (after rate limit check)
  - ACK (client completing handshake) → advances to `CT_ESTABLISHED`
  - FIN → `CT_FIN_WAIT`, then `CT_CLOSING`
  - RST → deletes CT entry, always passes
  - Non-SYN with no CT entry → **XDP_DROP** (drops ACK scans, spoofed packets, mid-stream injection attempts)
  - Idle timeouts: 30 s (SYN), 120 s (ESTABLISHED), 30 s (FIN)
  - Map capacity: 128 K connections (LRU_HASH, auto-evicts)
- BPF maps pinned under `/sys/fs/bpf/vortex` for external inspection
- Per-CPU metrics: `rx_packets`, `rx_bytes`, `passed`, `dropped_ratelimit`, `dropped_blocklist`, `dropped_invalid`, `dropped_conntrack`

### Tarpit (Honeypot)
- Connections with unrecognised SNI are tarpitted instead of rejected
- TCP receive window clamped to 1 byte — scanner stalls attempting to send
- 256 bytes of `/dev/urandom` noise sent immediately — confuses protocol fingerprinting
- Periodic drip of additional noise (every 1 s) keeps the connection alive
- When the tarpit FIFO is full (configurable), the oldest IP is **automatically added to the XDP blocklist** for `WORKER_BLOCK_TTL_SECS` (60 minutes), then removed when the TTL expires
- All tarpitted IPs logged to `/var/log/vortex/tarpit.log` with timestamps

### Response Caching
- Per-worker in-memory cache (RAM slab, optionally disk-backed via file-backed mmap)
- 64-byte cache index entries, one per cache line; hugepage-backed index for TLB efficiency
- LRU eviction; per-URL TTL selection based on path/extension patterns
- **ETag support** — body xxhash64 stored as ETag; `If-None-Match` → 304 Not Modified
- `X-Cache: HIT` header injected on cache hits
- URL-pattern-driven Cache-Control rewrite:
  - Static assets (images, fonts, bundles): `public, max-age=N, immutable`
  - Dynamic content: `public, max-age=60` injected if backend sent nothing
  - API endpoints (`/api/*`): Cache-Control left untouched
  - `Pragma: no-cache` stripped from responses for static assets
- Full one-buffer responses are cached immediately; chunked responses use a bounded reassembly path and are cached only after full decode
- RAM slab defaults to 30% of system RAM (floor 64 MB, cap 4 GB); optional disk slab

### HTTP Header Rewrites
- **Inbound (client → backend)**:
  - `X-Real-IP` and `X-Forwarded-For` injected from actual client socket address
  - `X-Api-Key` injected per route (if configured)
  - `Authorization` header stripped (proxy consumed it; never forwarded to backend)
  - `Connection` rewritten to `close` for HTTP, passed through for WebSocket upgrades
- **Outbound (backend → client)**:
  - `Server` header replaced with `CSWS/2.4.62 OpenVMS/V9.2-2 (Alpha)` — obscures backend stack identity
  - `Connection` rewritten to `keep-alive`
  - `Alt-Svc: h3=":443"; ma=86400` injected when HTTP/3 is compiled in

### HTTP Basic Auth
- Per-route hashed verifier list, either inline under `users:` or loaded from `auth.file`
- Verifier format: `username:$scrypt$ln=...,r=...,p=...$salt_b64$hash_b64`
- Startup fails if `auth.enabled: true` is set without at least one verifier
- 401 response with `WWW-Authenticate: Basic realm="vortex"`
- `Authorization` header stripped before forwarding to backend

Generate verifiers with:

```bash
python3 tools/vortex-passwd.py admin
```

### Observability
- **Prometheus metrics** on a separate HTTP server (default `127.0.0.1:9090/metrics`)
  - Per-worker: accepted connections, completed, errors, TLS version counts, kTLS count, bytes in/out
  - Cache: hits, misses, stores, evictions
  - XDP: all drop/pass counters aggregated from per-CPU BPF array
  - TLS cert expiry timestamps per hostname (`vortex_cert_expiry_seconds`)
- **Live dashboard** on a separate HTTP server (default `127.0.0.1:9091`) with a WebSocket-fed status view for routes, cache, TLS, tarpit, and XDP state
- **Structured JSON logging** (or plain text via config) — all log events are key=value pairs
- Log levels: `debug`, `info`, `warn`, `error`
- XDP metrics logged every second at `debug` level in the main loop

### Operations
- Foreground by default; `systemd` should supervise the process directly
- `-d` enables background daemonisation for non-`systemd` use
- PID file written only in daemon mode to `/run/vortex.pid` (configurable)
- **SIGHUP** — hot-reload config, refresh XDP blocklist and rate-limit config, re-read static certs from disk; route/backend topology changes are rejected and require a restart
- **SIGTERM / SIGINT** — graceful shutdown: stops workers, closes connections, detaches XDP, removes PID file
- `-t` — test config and exit
- `-v` — force debug logging
- `-X` — disable XDP (run without BPF acceleration)
- `-T` — disable TLS (plain HTTP only)
- `-b <path>` — path to BPF object file (default: must be supplied alongside `-b`)
- Environment variable expansion in config values: `${VAR}` and `$VAR`

## Architecture

```
                              ┌──────────────────────────────────┐
NIC ──► XDP program ──────►  │  blocklist drop                  │
        (kernel space)        │  conntrack state machine         │
                              │  SYN rate limiting               │
                              └────────────┬─────────────────────┘
                                           │ XDP_PASS
                                           ▼
                              ┌──────────────────────────────────┐
                              │  Listening socket (SO_REUSEPORT) │
                              └─────┬──────────────────────┬─────┘
                                    │                      │
                          ┌─────────▼──────┐    ┌──────────▼─────┐
                          │  Worker 0      │    │  Worker N      │   (one per CPU)
                          │  io_uring ring │    │  io_uring ring │
                          │  ┌───────────┐ │    │                │
                          │  │multishot  │ │    │                │
                          │  │accept     │ │    │                │
                          │  └─────┬─────┘ │    │                │
                          │        │        │    │                │
                          │  ┌─────▼─────┐ │    │                │
                          │  │TLS accept │ │    │                │
                          │  │(SNI peek) │ │    │                │
                          │  └─────┬─────┘ │    │                │
                          │        │ tarpit?│    │                │
                          │  ┌─────▼─────┐ │    │                │
                          │  │route/LB   │ │    │                │
                          │  └─────┬─────┘ │    │                │
                          │        │        │    │                │
                          │  ┌─────▼──────────────────────────┐ │
                          │  │ io_uring data path             │ │
                          │  │  RECV_CLIENT → SEND_BACKEND    │ │
                          │  │  RECV_BACKEND → SEND_CLIENT    │ │
                          │  │  cache lookup / store          │ │
                          │  │  header rewrite                │ │
                          │  └────────────────────────────────┘ │
                          └────────────────────────────────────┘

Separate threads:
  - Metrics HTTP server (Prometheus scrape endpoint)
  - ACME renewal thread (checks every hour)
  - WebSocket relay threads (spawned on 101 upgrade, detached)
  - QUIC server thread (HTTP/3, when compiled)
```

### Connection State Machine (XDP)

```
               SYN (rate-limit OK)
[no entry] ─────────────────────► CT_SYN_SENT
                                       │
                              ACK from client
                                       │
                                       ▼
                                CT_ESTABLISHED ◄──── data packets (ACK)
                                       │
                                  FIN seen
                                       │
                                       ▼
                                 CT_FIN_WAIT
                                       │
                               second FIN seen
                                       │
                                       ▼
                                  CT_CLOSING
                                  (LRU evicts)

RST at any state → delete entry, XDP_PASS
Non-SYN with no entry → XDP_DROP (dropped_conntrack++)
Idle timeout exceeded → delete entry, XDP_DROP (dropped_conntrack++)
```

### io_uring Connection State Machine (userspace)

```
ACCEPT ──► [TLS handshake] ──► RECV_CLIENT
                                    │
                           (cache hit?) ──► SEND_CLIENT ──► RECV_CLIENT
                                    │
                                    ▼
                              SEND_BACKEND
                                    │
                                    ▼
                              RECV_BACKEND ──► SEND_CLIENT
                                    │                │
                              (streaming?)          done
                                    │
                              RECV_BACKEND (next chunk)
```

---

## Build

### Prerequisites

| Dependency | Package | Notes |
|---|---|---|
| CMake 3.20+ | `cmake` | |
| clang | `clang` | BPF compiler |
| libbpf | `libbpf-dev` | eBPF/XDP |
| liburing | `liburing-dev` | io_uring |
| libyaml | `libyaml-dev` | config parsing |
| bpftool | `linux-tools-common` | vmlinux.h generation |
| OpenSSL 4.0 | build from source | TLS (optional but recommended) |
| ngtcp2 1.16 | build from source | HTTP/3 (optional) |
| nghttp3 1.8 | build from source | HTTP/3 (optional) |

OpenSSL 4.0 is expected at `/opt/openssl-4.0`. ngtcp2 and nghttp3 build dirs
are expected at `/tmp/ngtcp2-1.16-build` and `/tmp/nghttp3-build`.

### Debug build

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j$(nproc)
```

Debug builds enable AddressSanitizer and UBSan.

### Release build (Zen 3 optimised)

```sh
cmake -B build-release -DCMAKE_BUILD_TYPE=Release
cmake --build build-release -j$(nproc)
```

### Run tests

```sh
cmake --build build --target test_config test_cache test_log
ctest --test-dir build/tests
```

### Custom paths

```sh
cmake -B build \
  -DOPENSSL_ROOT_DIR=/opt/openssl-4.0 \
  -DNGTCP2_BUILD_DIR=/opt/ngtcp2/build \
  -DNGHTTP3_BUILD_DIR=/opt/nghttp3/build
```

### Build outputs

| File | Description |
|---|---|
| `build/vortex` | Debug executable |
| `build-release/vortex` | Release executable |
| `build-release/vortex_xdp.bpf.o` | Compiled BPF/XDP object (load with `-b`) |

---

## Deployment

### Building a .deb package

`tools/build_deb.sh` produces a self-contained Debian package that bundles the
OpenSSL 4.0 shared libraries so the target machine does not need them pre-installed.

```sh
tools/build_deb.sh 0.2.0        # produces vortex_0.2.0_amd64.deb
```

### Installing on a fresh machine

```sh
# Install runtime dependencies (all available in standard Debian/Ubuntu repos)
sudo apt-get install -y libbpf1 liburing2 libyaml-0-2

# Install the package
sudo dpkg -i vortex_0.2.0_amd64.deb
```

The postinst script will:
- Create `/var/log/vortex` and `/etc/vortex`
- Copy `vortex.example.yaml` to `/etc/vortex/vortex.yaml` if no config exists yet
- Run `ldconfig` and `systemctl daemon-reload`

Edit `/etc/vortex/vortex.yaml`, then:

```sh
sudo systemctl enable --now vortex
```

### Upgrading

```sh
sudo dpkg -i vortex_<new-version>_amd64.deb
sudo systemctl restart vortex
```

`dpkg -i` over an existing install is safe — it will not overwrite
`/etc/vortex/vortex.yaml` if it already exists.

---

## Running

```sh
# Foreground, debug logging, custom config and BPF object
sudo ./build-release/vortex -v \
  -c /etc/vortex/vortex.yaml \
  -b ./build-release/vortex_xdp.bpf.o

# Legacy daemon mode outside systemd
sudo ./build-release/vortex -d \
  -c /etc/vortex/vortex.yaml \
  -b ./build-release/vortex_xdp.bpf.o

# Test config validity
./build-release/vortex -t -c /etc/vortex/vortex.yaml

# Reload config (blocklist, rate limits, static certs)
sudo systemctl reload vortex

# Graceful shutdown
sudo systemctl stop vortex
```

**Root is required** to attach XDP programs and create BPF maps. Running without
`-b` or without the network interface configured skips XDP silently. `-X`
disables XDP explicitly. `-T` disables TLS.

---

## Configuration Reference

```yaml
global:
  workers: auto            # Number of worker threads (default: auto = nproc)
  compress_pool_threads: 0 # 0 = synchronous compression in worker thread; 2-4 recommended for offload
  bind_address: "0.0.0.0"
  bind_port: 443
  http_port: 80            # Used by ACME HTTP-01 challenge server
  interface: "eth0"        # Network interface for XDP attachment
  log_level: "info"        # debug | info | warn | error
  log_format: "json"       # json | text
  pid_file: "/run/vortex.pid"

tls:
  min_version: "1.2"       # "1.2" or "1.3"
  max_version: "1.3"
  ciphersuites: "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384"
  session_timeout: 3600          # TLS session cache lifetime (seconds)
  session_ticket_rotation: 3600  # Rotate session ticket keys every N seconds
  ktls: true               # Enable kernel TLS offload (requires kernel 4.13+)

xdp:
  mode: "auto"             # auto | native | skb
  blocklist_file: "/etc/vortex/blocklist.txt"  # One IPv4 per line, # comments
  rate_limit:
    enabled: true
    requests_per_second: 1000   # New connections per second per source IP
    burst: 2000                 # Initial token bucket fill (allows initial burst)

cache:
  enabled: true
  index_entries: 16384     # Number of URL slots (power of 2 recommended)
  slab_size_mb: 64         # RAM slab size; default = 30% of system RAM
  default_ttl: 300         # Default TTL in seconds
  use_hugepages: true      # Use 2 MB hugepages for the index
  disk_cache_path: ""      # Path for disk-backed slab (empty = RAM only)
  disk_slab_size_mb: 0     # 0 = auto (50% of free space)

acme:
  enabled: false
  email: "admin@example.com"
  directory_url: "https://acme-v02.api.letsencrypt.org/directory"
  account_key_path: "/etc/vortex/acme-account.key"
  storage_path: "/etc/vortex/certs/"
  renewal_days_before_expiry: 30
  preferred_challenge: "http-01"   # http-01 | dns-01
  dns_provider: "cloudflare"       # Required for dns-01
  dns_provider_config:
    api_token: "${CF_API_TOKEN}"   # Environment variable expansion supported

metrics:
  enabled: true
  bind_address: "127.0.0.1"
  port: 9090
  path: "/metrics"

routes:
  - hostname: "api.example.com"   # Exact match (case-insensitive)
    load_balancing: "round_robin" # round_robin | weighted_round_robin | least_conn | ip_hash
    cert_provider: "static_file"  # static_file | acme_http01 | acme_dns01
    cert_path: "/etc/ssl/api.crt"
    key_path: "/etc/ssl/api.key"
    x_api_key: ""                 # If set, injected as X-Api-Key to backend
    backends:
      - address: "10.0.0.1:8080"
        weight: 3
        pool_size: 0
      - address: "10.0.0.2:8080"
        weight: 1
    cache:
      enabled: true
      ttl: 60
    auth:
      enabled: false
      file: "/etc/vortex/auth/api-users.auth"
      users:
        - "alice:$scrypt$ln=15,r=8,p=1$AQIDBAUGBwgJCgsMDQ4PEA==$1b98GT+mgzwTa+tOSyi5AORw9EiZ0XG3ILt27KXWTzc="
```

### Environment variable expansion

Config values support `${VAR}` and `$VAR` substitution at load time:
```yaml
  api_token: "${CF_API_TOKEN}"
  cert_path: "${CERT_DIR}/fullchain.pem"
```

---

## Prometheus Metrics

All metrics are exposed at `http://127.0.0.1:9090/metrics` (configurable).

| Metric | Description |
|---|---|
| `vortex_connections_accepted_total` | Total accepted connections per worker |
| `vortex_connections_completed_total` | Total completed connections per worker |
| `vortex_connections_errors_total` | Total errored connections per worker |
| `vortex_bytes_in_total` | Bytes received from clients |
| `vortex_bytes_out_total` | Bytes sent to clients |
| `vortex_tls12_total` | TLS 1.2 handshakes |
| `vortex_tls13_total` | TLS 1.3 handshakes |
| `vortex_ktls_total` | Connections using kTLS offload |
| `vortex_cache_hits_total` | Cache hits |
| `vortex_cache_misses_total` | Cache misses |
| `vortex_cache_stores_total` | Cache entries written |
| `vortex_cache_evictions_total` | Cache entries evicted (LRU) |
| `vortex_tls_pool_queue_depth` | Pending TLS handshakes in the shared handshake queue |
| `vortex_tls_pool_active_handshakes` | TLS handshakes currently executing |
| `vortex_tls_pool_submitted_total` | Handshakes submitted to the TLS pool |
| `vortex_tls_pool_completed_total` | Successful TLS handshakes completed by the pool |
| `vortex_tls_pool_failed_total` | TLS handshakes that failed in the pool |
| `vortex_tls_pool_dropped_total` | Handshakes dropped because the TLS pool queue was full |
| `vortex_compress_pool_queue_depth` | Pending compression jobs in the shared compression queue |
| `vortex_compress_pool_active_jobs` | Compression jobs currently executing |
| `vortex_compress_pool_submitted_total` | Compression jobs submitted to the compression pool |
| `vortex_compress_pool_completed_total` | Compression jobs completed successfully |
| `vortex_compress_pool_failed_total` | Compression jobs that failed or were not beneficial |
| `vortex_compress_pool_dropped_total` | Compression jobs dropped because the pool queue was full |
| `vortex_xdp_rx_packets_total` | Packets seen by XDP |
| `vortex_xdp_rx_bytes_total` | Bytes seen by XDP |
| `vortex_xdp_passed_total` | Packets passed to kernel stack |
| `vortex_xdp_dropped_ratelimit_total` | SYNs dropped by rate limiter |
| `vortex_xdp_dropped_blocklist_total` | Packets dropped by IP blocklist |
| `vortex_xdp_dropped_conntrack_total` | Packets dropped by conntrack (invalid state) |
| `vortex_xdp_dropped_invalid_total` | Malformed/unparseable frames |
| `vortex_cert_expiry_seconds` | TLS cert not-after timestamp (Unix) per hostname |

---

## Security Features

### XDP Layer (kernel space)
- **IP blocklist** — drop packets from known-bad IPs before they consume any CPU
- **Connection-rate limiting** — token bucket per source IP, applied to SYN packets only
- **Stateful TCP conntrack** — non-SYN packets with no matching state are dropped; prevents ACK scans, spoofed mid-stream injection, and half-open attacks
- **Conntrack timeouts** — stale entries expire (30 s SYN, 120 s idle, 30 s FIN)

### Application Layer
- **Tarpit** — unrecognised SNI connections are held open with a 1-byte TCP window; `/dev/urandom` noise confuses scanners; persistent offenders escalate to the XDP blocklist automatically
- **Blocklist TTL** — IPs added by tarpit escalation expire after 60 minutes; removed cleanly on shutdown
- **Authorization header stripping** — proxy credentials are never forwarded to backends
- **Server header masquerade** — backend identity hidden behind `CSWS/2.4.62 OpenVMS/V9.2-2 (Alpha)` to mislead automated vulnerability scanners
- **HTTP Basic Auth** — per-route credential enforcement at the proxy level
- **SNI pre-check** — TLS ClientHello is peeked before the full handshake; unrecognised SNI → tarpit without handshake cost

---

## Implementation Notes

### Phase history

The codebase was developed in phases; `VORTEX_PHASE=7` is the current build target:

| Phase | Feature |
|---|---|
| 1 | Config parser (YAML), structured logging, unit tests |
| 2 | io_uring workers, connection pool, SNI routing |
| 3 | TLS termination (OpenSSL 4.0), kTLS offload |
| 4 | Response caching (RAM+disk), header rewrites, Basic Auth |
| 5 | XDP/eBPF: IP blocklist, per-IP rate limiting |
| 6 | ACME cert management, Prometheus metrics |
| 7 | HTTP/3 via ngtcp2+nghttp3, Alt-Svc advertisement |

**Features added beyond the original phase plan:**
- Tarpit mode with automatic XDP blocklist escalation
- WebSocket passthrough (detect Upgrade, relay thread)
- Connection-rate limiting applied SYN-only (not per-packet)
- Cache ETag support with If-None-Match / 304 responses
- Cache-Control rewrite + Pragma stripping based on URL patterns
- Partial send handling in io_uring (kTLS record boundary flush)
- Authorization header stripping before backend forward
- Server header masquerade
- X-Api-Key injection per route
- Wildcard hostname matching planned; current routing is exact and case-insensitive
- Environment variable expansion in config
- Config hot-reload on SIGHUP (blocklist, rate limits, static certs)
- Foreground-by-default runtime with optional `-d` daemon mode
- PID file management in daemon mode
- `-X` / `-T` runtime flags to disable XDP / TLS
- DNS-01 ACME challenge with Cloudflare provider
- TLS cert expiry in Prometheus metrics
- **Stateful L4 TCP connection tracking in XDP** (CT_SYN_SENT → CT_ESTABLISHED → CT_FIN_WAIT → CT_CLOSING)

### BPF maps

All maps pinned under `/sys/fs/bpf/vortex/`:

| Map | Type | Key | Value | Purpose |
|---|---|---|---|---|
| `rate_limit_map` | LRU_HASH (64K) | src IPv4 | token bucket entry | SYN rate limiting |
| `blocklist_map` | HASH (10K) | src IPv4 | u8 flag | IP blocklist |
| `metrics_map` | PERCPU_ARRAY (1) | 0 | `vortex_metrics` | per-CPU counters |
| `rate_config_map` | ARRAY (1) | 0 | `rate_config` | global rate limit config |
| `conn_track_map` | LRU_HASH (128K) | `conn_tuple` (5-tuple) | `conn_state` | TCP state machine |

### kTLS fast path

When OpenSSL negotiates kTLS (`SSL_CTX_set_options` with `SSL_OP_ENABLE_KTLS`):
1. After the handshake, symmetric keys are installed into the kernel via `setsockopt(SOL_TLS)`
2. `SSL_sendfile` / normal `send` on the socket triggers kernel-side AES-GCM
3. The `SSL*` object is freed; io_uring operates directly on the fd
4. `CONN_FLAG_KTLS_TX` and `CONN_FLAG_KTLS_RX` flags track which directions are offloaded
5. `EIO` on a kTLS recv is treated as `close_notify` / TLS alert (normal close path)

When kTLS is not available (negotiated cipher not supported, older kernel), the SSL* object is kept and `SSL_read`/`SSL_write` are used via the standard OpenSSL data path.

### Cache URL patterns

`cache_ttl_for_url()` selects TTL by URL path/extension:
- `/api/*`, `/auth/*`, `/login*` → TTL 0 (do not cache)
- `*.html`, `*.json` → TTL 60 s
- `*.css`, `*.js`, `*.woff2`, `*.png`, `*.jpg`, `*.svg`, `*.ico` → TTL 86400 s (1 day), `immutable`
- Everything else → default TTL from config (default 300 s)

---

## Known Limitations

- **IPv4 only** in the XDP program — IPv6 packets are passed without filtering or conntrack
- **Load balancer — least_conn** uses process-wide active backend counters and is approximate across workers/threads rather than globally serialized
- **Backend connections** are synchronous blocking connects (set non-blocking after connect); async io_uring CONNECT is planned
- **Backend TLS** (`https://` origins) offloads `SSL_connect` to the shared TLS pool, but `SSL_write`/`SSL_read` still run synchronously in the worker thread after the handshake completes. A slow or unresponsive HTTPS backend during request or response I/O can still stall all connections on that worker until the operation completes or times out. Set `backend_timeout_ms` to a low value (for example `5000`) for TLS backend routes to limit the blast radius. Pooled TLS backends reuse the live origin socket and `SSL*` state across requests when the response is framing-safe to return to the pool; repeated fresh connections also reuse cached client TLS sessions when the origin permits resumption.
- **Backend TLS verification** is enabled by default. Per backend, set `verify_peer: false` or `insecure_skip_verify: true` to ignore certificate-chain and hostname validity checks for that origin.
- **Single-segment caching** — full one-buffer responses are cached immediately; chunked responses use a bounded reassembly path and are cached only after full decode
- **WebSocket relay** uses one in-flight io_uring recv/send chain per direction and relies on socket backpressure rather than deep proxy-side queues
- **Config reload** rejects route/backend topology changes on SIGHUP; changing route order, backend order, or backend counts still requires a restart

---

## Development

### Code layout

```
src/        Core proxy engine
  main.c    Entry point, signal handling, lifecycle
  worker.c  io_uring event loop, proxy data path, tarpit, header rewrites
  conn.c/h  Connection pool (hot/cold split, cache-line aligned)
  router.c  SNI route lookup, backend selection (LB algorithms)
  tls.c     OpenSSL 4.0 TLS context, accept, kTLS install, cert rotation
  cache.c   Response cache (RAM+disk slab, LRU index, ETag)
  auth.c    HTTP Basic Auth
  metrics.c Prometheus HTTP server
  log.c     Structured JSON/text logger
  config.c  YAML config parser with env-var expansion
  bpf_loader.c  libbpf wrapper: load, attach, map accessors
  uring.c   io_uring helpers (init, submit, timeout)
  quic.c    HTTP/3 server (ngtcp2 + nghttp3, conditional)
  util.h    xxhash64, rdtsc

bpf/
  vortex_xdp.bpf.c  XDP kernel program
  maps.h             Shared struct definitions (BPF + userspace)
  vortex_xdp.h       Shared constants (ports, pin paths, map names)
  vmlinux.h          BTF type definitions (generated from running kernel)

cert/
  cert_provider.h    Provider interface
  static_file.c      Load cert+key from PEM files
  acme_client.c      ACME v2 client (JWK, JWS, account/order lifecycle)
  acme_http01.c      HTTP-01 challenge server
  acme_dns01.c       DNS-01 challenge orchestration
  dns_cloudflare.c   Cloudflare DNS API provider

tests/
  test_config.c
  test_cache.c
  test_log.c

tools/
  gen_vmlinux.sh     Regenerate bpf/vmlinux.h from running kernel
  bench.sh           wrk/hey benchmark runner
  test_phase6.sh     Integration tests for Phase 6 features
  test_phase7.sh     Integration tests for Phase 7 (HTTP/3)
  test_xdp.sh        XDP map inspection and drop counter validation
```

### Adding a new cert provider

Implement `struct cert_provider_ops` from `cert/cert_provider.h` and register
it in `main.c` alongside the existing static/ACME providers.

### Adding a new DNS provider for DNS-01

Implement `struct dns_provider_ops` from `cert/dns_provider.h` and add a
selection branch in `cert_manager_init()` in `main.c`.

---

## Acknowledgements

Vortex is original software but is built on the shoulders of several excellent open-source libraries. Their authors deserve full credit.

### Libraries used

| Project | Version | License | Role in Vortex |
|---------|---------|---------|----------------|
| **[libbpf](https://github.com/libbpf/libbpf)** | system | LGPL-2.1 / BSD-2-Clause | Loads and manages the XDP/eBPF kernel programs; provides BPF map accessors and the skeleton API |
| **[liburing](https://github.com/axboe/liburing)** | system | LGPL-2.1 | All async I/O: multishot accept, send/recv, async backend connect, timeouts |
| **[libyaml](https://github.com/yaml/libyaml)** | system | MIT | Parses `vortex.yaml` configuration files |
| **[OpenSSL 4.0](https://github.com/openssl/openssl)** | 4.0 | Apache 2.0 | TLS 1.2/1.3 handshake, kTLS kernel offload, ACME HTTPS requests, ECDSA key generation |
| **[ngtcp2](https://github.com/ngtcp2/ngtcp2)** | 1.16.0 | MIT | QUIC transport protocol (HTTP/3) |
| **[nghttp3](https://github.com/ngtcp2/nghttp3)** | 1.8.0 | MIT | HTTP/3 application layer over QUIC |

### Kernel interfaces

- **XDP (eXpress Data Path)** — in-kernel packet processing framework, part of the Linux kernel (GPL-2.0).  
  The BPF program at `bpf/vortex_xdp.bpf.c` runs inside the kernel and is licensed GPL-2.0 as required.
- **io_uring** — Linux kernel async I/O subsystem (GPL-2.0). Vortex uses the userspace `liburing` wrapper.
- **kTLS** — Kernel TLS offload (Linux 4.13+, GPL-2.0). After TLS handshake, the kernel handles symmetric crypto.
- **`bpf/vmlinux.h`** — auto-generated from the running kernel's BTF type information via `bpftool btf dump`. Reflects the kernel's own type definitions and is covered by the kernel's GPL-2.0 license.

### License compatibility

Vortex itself is released under the **GNU General Public License v3.0 (GPLv3)**. All dependencies are compatible:

- MIT, BSD-2-Clause — permissive, compatible with GPLv3.
- LGPL-2.1 — compatible with GPLv3 when linked dynamically (libbpf, liburing, libyaml are system shared libraries).
- Apache 2.0 (OpenSSL 4.0) — compatible with GPLv3 per the FSF's clarification.
- GPL-2.0 (kernel BPF program, vmlinux.h) — the XDP program is a separate kernel-space component; it is explicitly GPL-2.0 as required by the kernel's module ABI.

Commercial entities wishing to use Vortex without complying with the GPLv3 (for example, in a proprietary product) must obtain a separate commercial licence from the author.
