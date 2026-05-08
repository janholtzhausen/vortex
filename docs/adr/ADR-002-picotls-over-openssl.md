# ADR-002: picotls + minicrypto Instead of OpenSSL

**Status:** Accepted  
**Date:** 2024

## Context

TLS termination requires a TLS library. OpenSSL is the default choice; picotls is an alternative with a very different design.

## Decision

Use `picotls` (MIT) with `minicrypto` (pure C, no system crypto dependency) for TLS 1.3 on the server side. Use the same library for backend TLS client connections. ACME certificate management is implemented natively using picotls primitives + micro-ecc.

## Rationale

- **kTLS integration**: picotls exposes `ptls_get_traffic_keys()` after handshake, allowing extraction of HKDF-derived session keys and installation into the kernel TLS ULP (`setsockopt(SOL_TLS, TLS_TX/RX)`). OpenSSL 3.x has a similar API but it is more complex and has changed between versions.
- **Small binary size**: minicrypto is ~50 KB vs OpenSSL ~4 MB. The `.deb` package statically links picotls; no TLS shared library dependency on the target host.
- **Single allocation model**: picotls uses a single `ptls_t*` context per connection, freed after kTLS install. No SSL_CTX reference counting or session cache management needed.
- **License**: MIT is license-compatible with GPLv3. OpenSSL's older versions had a problematic advertising clause.

## Alternatives Rejected

- **OpenSSL**: API stability issues across 1.x/3.x; kTLS key-extraction API changed; larger binary; more attack surface
- **mbedTLS**: No kTLS integration; limited TLS 1.3 cipher suite support at the time of evaluation
- **BoringSSL**: Google-controlled; no stable ABI; no official releases; kTLS support is experimental

## Consequences

- **TLS 1.2 support**: Currently TLS 1.3 only (minicrypto cipher suite list). If TLS 1.2 is required, `min_version: "1.2"` is config-valid but picotls minicrypto does not support TLS 1.2 cipher suites — connections will fail. This is a known gap.
- **Certificate verification for backends**: `tls_create_client_ctx` sets `verify_certificate = NULL`, meaning backend cert chains are not verified by default. Per-backend `verify_peer: true` is intended to enable verification but the callback is not implemented — tracked as TODO in `tls.c:1010`.
- **Self-signed cert generation**: `tls_gen_self_signed()` forks `openssl` binary (absolute path, sanitized CN) as picotls minicrypto does not expose a public key derivation API that would allow building an X.509 cert from scratch. Dev/testing only.
- **ACME**: Entire ACME v2 client including JWK/JWS, P-256 ECDSA, CSR, and X.509 parsing implemented from scratch in `cert/acme_client.c`. No external ACME library dependency.
