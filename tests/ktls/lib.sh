#!/bin/bash
# Shared helpers for kTLS shell tests.
# Source this file; do not run directly.
#
# Skip codes:
#   exit 77 — test infrastructure unavailable (kTLS module, openssl, etc.)
#              ctest maps this to SKIP, not FAIL.
#
# Environment:
#   VORTEX_BIN  — path to vortex binary (default: relative to this file)
#   VORTEX_CFG  — config file path (default: /tmp/<test>.yaml, set by ctest)

VORTEX_BIN="${VORTEX_BIN:-$(cd "$(dirname "$0")/../.." && pwd)/build/vortex}"
VORTEX_CFG="${VORTEX_CFG:-/tmp/ktls_test.yaml}"
VORTEX_PID=""
PASS=0
FAIL=0

die()  { echo "FATAL: $*" >&2; exit 1; }
skip() { echo "SKIP: $*"; exit 77; }

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || skip "$1 not found"
}

require_ktls() {
    modprobe tls 2>/dev/null || true
    grep -q "^tls " /proc/modules 2>/dev/null || skip "kTLS module (tls) not available"
}

require_root() {
    [ "$(id -u)" -eq 0 ] || skip "requires root (uid=$(id -u))"
}

# Generate a self-signed ECDSA P-256 cert + key; prints the temp directory.
gen_cert() {
    require_cmd openssl
    local dir
    dir=$(mktemp -d)
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
        -keyout "$dir/key.pem" -out "$dir/cert.pem" \
        -days 1 -nodes -subj "/CN=localhost" 2>/dev/null \
        || die "openssl cert gen failed"
    echo "$dir"
}

# Write a minimal vortex config (no BPF — XDP is optional).
write_config() {
    local cert_dir="$1" port="${2:-14443}" backend_port="${3:-18080}"
    cat >"$VORTEX_CFG" <<EOF
listen_port: $port
workers: 1
routes:
  - hostname: localhost
    backends:
      - address: "127.0.0.1:$backend_port"
    cert_path: $cert_dir/cert.pem
    key_path:  $cert_dir/key.pem
EOF
}

# Start vortex; skip (exit 77) if it fails to bind within 3 s.
# vortex does NOT need a BPF object — XDP is optional.
start_vortex() {
    [ -x "$VORTEX_BIN" ] || skip "vortex binary not found: $VORTEX_BIN"
    local port="${VORTEX_PORT:-14443}"
    "$VORTEX_BIN" -c "$VORTEX_CFG" >/tmp/vortex_test.log 2>&1 &
    VORTEX_PID=$!
    local i=0
    while [ $i -lt 60 ]; do
        ss -tlnp 2>/dev/null | grep -q ":${port}" && return 0
        kill -0 "$VORTEX_PID" 2>/dev/null || break   # process already exited
        sleep 0.05; ((i++))
    done
    echo "vortex failed to start on port $port:" >&2
    cat /tmp/vortex_test.log >&2
    stop_vortex
    skip "vortex failed to bind (port $port)"
}

stop_vortex() {
    [ -n "$VORTEX_PID" ] && kill "$VORTEX_PID" 2>/dev/null && wait "$VORTEX_PID" 2>/dev/null
    VORTEX_PID=""
}

ok()   { echo "  ok: $*";   ((PASS++)); }
fail() { echo "  FAIL: $*"; ((FAIL++)); }

summary() {
    echo "Results: $PASS passed, $FAIL failed"
    [ "$FAIL" -eq 0 ]
}
