# Security Audit — Vortex Reverse Proxy (007 STRIDE/PASTA Mode)

**Date:** 2026-05-08  
**Version:** v1.0.14  
**Framework:** STRIDE + PASTA  
**Scope:** Full codebase — src/, cert/, bpf/, include/, config/

---

## 1. Attack Surface Map

### Trust Boundaries

```
[Internet]
    │
    ▼ Ethernet frames
[XDP/eBPF kernel program]  ← blocklist, rate-limit, conntrack
    │ XDP_PASS
    ▼ sk_buff
[Linux TCP stack]
    │ accept()
    ▼ client_fd
[vortex worker (io_uring)]  ← TLS termination, HTTP parsing, routing
    │
    ├─ [Backend server]  ← TCP connect, optional TLS
    ├─ [Prometheus scrape]  127.0.0.1:9090  (no auth)
    └─ [Dashboard WebSocket]  127.0.0.1:9091  (no auth)

[Config file]  ←  env var expansion, YAML parsing
    │
    └─ [ACME CA / Cloudflare API]  ←  ACME renewal thread
```

### Entry Points

| Entry | Data | Trust |
|---|---|---|
| TLS ClientHello | SNI, cipher list | Untrusted |
| HTTP request headers | Method, URL, headers, body | Untrusted |
| HTTP response from backend | Status, headers, body, chunked encoding | Semi-trusted |
| Config YAML | All config fields, env var references | Trusted (operator) |
| Blocklist file | IPv4 addresses, one per line | Trusted (operator) |
| BPF maps at `/sys/fs/bpf/vortex/` | Rate config, blocklist entries | Trusted (root only) |
| ACME server responses | JSON, certificate DER, nonces | Semi-trusted |
| DNS API (Cloudflare) | JSON | Semi-trusted |

---

## 2. STRIDE Threat Model

### S — Spoofing

| # | Finding | Severity | Mitigation |
|---|---|---|---|
| S1 | Backend cert verification is `NULL` by default in `tls_create_client_ctx` — `verify_certificate` callback not implemented | HIGH | Per-backend `verify_peer: true` config exists but backend cert chain validation is unimplemented (TODO in tls.c:1010). Attacker on the network path can MITM backend TLS connections. |
| S2 | kTLS session keys extracted from picotls and installed in kernel — if `/proc/PID/mem` readable by attacker, keys could be extracted | LOW | Mitigated by privilege drop (`run_as_user`) and `PR_SET_NO_NEW_PRIVS`. Keys are zeroed from userspace buffers immediately after `setsockopt`. |

### T — Tampering

| # | Finding | Severity | Mitigation |
|---|---|---|---|
| T1 | BPF maps pinned at `/sys/fs/bpf/vortex/` — writable by any process with `CAP_BPF` or root | MEDIUM | Mitigated: privilege drop at startup. After `setuid`, vortex cannot write BPF maps itself; pinned maps accessible to root only. |
| T2 | Config file not authenticated — if writable by non-root, attacker can inject routes/backends | MEDIUM | Operator responsibility. `vortex -t` validates config before apply. No runtime config write path. |
| T3 | Backend HTTP responses: chunked decoder accepts bare `\n` as chunk separator | LOW | Fixed in v1.0.14 — bare LF accepted but protocol errors abort caching. Cache corruption path eliminated. |

### R — Repudiation

| # | Finding | Severity | Mitigation |
|---|---|---|---|
| R1 | No per-request access log — only error/warn events logged | MEDIUM | Structured JSON logging exists but access logging (method, URL, client IP, status, bytes) is not implemented. Tarpit IPs are logged. |
| R2 | No request ID / correlation ID injected into forwarded headers | LOW | `X-Real-IP` and `X-Forwarded-For` are injected. No `X-Request-ID` or `Traceparent`. |

### I — Information Disclosure

| # | Finding | Severity | Mitigation |
|---|---|---|---|
| I1 | Prometheus metrics (`:9090/metrics`) has no authentication | MEDIUM | Default bind: `127.0.0.1`. SSRF from a backend service or same-host app could reach it. Recommendation: add optional bearer token or mTLS. |
| I2 | Dashboard WebSocket (`:9091`) has no authentication | MEDIUM | Same as I1. Exposes route names, backend addresses, cache stats, tarpit IPs, TLS cert expiry timestamps. |
| I3 | `tls_gen_self_signed()` writes cert/key PEM to `/tmp/vortex-cert-XXXXXX.pem` via `mkstemps` | LOW | Files are created with mode 0600 (default umask). Deleted after use. Race window is small. Dev/testing only — not called from `main.c`. |
| I4 | Backend `Server:` header is spoofed globally (`CSWS/2.4.62 OpenVMS`) | INFO | Intentional obfuscation. Configurable per-route. |

### D — Denial of Service

| # | Finding | Severity | Mitigation |
|---|---|---|---|
| D1 | chunked body accumulation: 4 MB per connection (`CHUNK_MAX_BODY`) | MEDIUM | At 1024 connections, worst case 4 GB RAM. Mitigated by `max_request_body_bytes` (default 8 MB) limiting request bodies, but response chunked bodies for caching have a separate 4 MB limit per-connection. |
| D2 | TLS handshake pool queue: if full, drops with `503`. Queue depth is bounded. | LOW | Correct behavior. `vortex_tls_pool_dropped_total` metric tracks drops. |
| D3 | ACME renewal failure silently continues — cert expires if CA is unreachable | MEDIUM | Renewal thread logs errors but does not alert. `vortex_cert_expiry_seconds` metric enables external Prometheus alerting. |
| D4 | IPv6 rate limiting: token bucket per /128 source address. Attacker with a /48 prefix (65K addresses) bypasses rate limiting | MEDIUM | No per-prefix aggregation. Mitigation: blocklist the offending prefix at the OS/firewall level. |

### E — Elevation of Privilege

| # | Finding | Severity | Mitigation |
|---|---|---|---|
| E1 | `tls_gen_self_signed()` previously used `execvp("openssl", ...)` — PATH-relative lookup | MEDIUM | **Fixed in v1.0.14**: now uses absolute path (`/usr/bin/openssl` or `/usr/local/bin/openssl`) + CN sanitization. CWE-426 mitigated. |
| E2 | Request smuggling: dual `Transfer-Encoding` + `Content-Length` rejected with 400 | OK | Implemented in HTTP/1.1 parser. |
| E3 | `PR_SET_NO_NEW_PRIVS` set after privilege drop — prevents setuid exec escalation | OK | Implemented in `main.c`. |
| E4 | PID file created with `O_EXCL|O_NOFOLLOW` — symlink attack mitigated | OK | Implemented. Stale regular file owned by root is removed and retried. |

---

## 3. PASTA Risk Summary

| Stage | Finding |
|---|---|
| Business objectives | Internet-facing reverse proxy; availability and data confidentiality are critical |
| Technical scope | TLS termination, HTTP parsing, XDP, ACME, metrics, dashboard |
| Attack decomposition | High-value targets: backend connection hijack (S1), metrics/dashboard exposure (I1/I2) |
| Threat analysis | MITM on backend TLS is highest-risk unmitigated threat |
| Vulnerability analysis | Backend cert verification unimplemented; metrics/dashboard unauthenticated |
| Attack modeling | Attacker on backend LAN can intercept backend TLS if `verify_peer` not configured |
| Risk prioritization | Backend cert verification (S1) is the only unmitigated HIGH finding |

---

## 4. Findings Table

| # | Severity | Component | Finding | Fixed in |
|---|---|---|---|---|
| S1 | **HIGH** | tls.c | Backend TLS cert verification unimplemented | Open |
| D4 | **MEDIUM** | XDP | IPv6 /128 rate limiting bypassable with /48 prefix | Open |
| I1 | **MEDIUM** | metrics.c | Prometheus endpoint unauthenticated | Open |
| I2 | **MEDIUM** | dashboard.c | Dashboard endpoint unauthenticated | Open |
| D3 | **MEDIUM** | main.c | ACME renewal failure not alerted | Open |
| R1 | **MEDIUM** | worker_proxy.c | No per-request access log | Open |
| T2 | **MEDIUM** | config.c | Config file integrity not verified | Open (operator) |
| E1 | **MEDIUM** | tls.c | execvp PATH-relative openssl lookup | **Fixed v1.0.14** |
| T3 | **LOW** | worker_cache.c | Chunked decoder protocol error handling | **Fixed v1.0.14** |
| D1 | **MEDIUM** | worker_cache.c | 4 MB chunked accumulation × connections | Open |
| I3 | **LOW** | tls.c | Temp cert/key files in /tmp | Open (dev-only) |
| R2 | **LOW** | worker_proxy.c | No request correlation ID | Open |

---

## 5. Recommended Fixes (Open Items)

### S1 — Backend TLS cert verification (HIGH)

Implement `verify_certificate` callback in `tls_create_client_ctx()`. Per-backend `verify_peer: true` is already parsed but has no effect. Use picotls's certificate chain verification API against the system CA store.

### I1/I2 — Metrics/Dashboard auth (MEDIUM)

Add optional bearer token authentication for both endpoints:
```yaml
metrics:
  auth_token: "${METRICS_TOKEN}"  # empty = no auth (localhost-only default)
dashboard:
  auth_token: "${DASHBOARD_TOKEN}"
```

### R1 — Access logging (MEDIUM)

Add a structured access log line per completed request:
```json
{"time":"...","client":"1.2.3.4","method":"GET","url":"/","status":200,"bytes":1234,"route":"api.example.com","duration_ms":12}
```

---

## 6. Security Score (007 Scoring Model)

| Domain | Weight | Score | Notes |
|---|---|---|---|
| Secrets & Credentials | 20% | 88 | API tokens zeroed post-init; no hardcoded secrets; gitleaks clean |
| Input Validation | 15% | 75 | Header limits, request smuggling blocked; chunked decoder fixed; URL length enforced |
| Auth & Authorization | 15% | 70 | Client auth via HTTP Basic + scrypt; metrics/dashboard unauthenticated |
| Data Protection | 15% | 80 | kTLS; HSTS injected; PIE/full-RELRO; key material wiped immediately |
| Resilience | 10% | 85 | Circuit breaker; rate limiting; tarpit; request body limits; TLS pool drop |
| Monitoring | 10% | 72 | Prometheus metrics; structured logging; no access log; no alerting on cert expiry |
| Supply Chain | 10% | 90 | No npm/pip/cargo; picotls/micro-ecc vendored; gitleaks + semgrep + trivy clean |
| Compliance | 5% | 80 | OWASP API Top 10 mostly covered; request smuggling mitigated; HSTS; no CORS issues |

**Weighted Score: 80/100**

## 7. Verdict

**APPROVED WITH CAVEATS**

Vortex is production-ready for operator-controlled deployments where:
- Backend TLS routes use `verify_peer: false` only for trusted backends on private networks
- Metrics and dashboard bind to loopback only (default config)
- `run_as_user` is configured for privilege drop

**Block conditions (require fix before internet-facing prod with untrusted backends):**
- S1: Implement backend TLS cert chain verification
