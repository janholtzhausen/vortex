#!/bin/bash
# Shared helpers for kTLS shell tests.
# Source this file; do not run directly.
#
# Requirements:
#   - VORTEX_BIN: path to vortex binary (default: ../../build-release/vortex)
#   - VORTEX_CFG: path to a test config yaml
#   - openssl(1), curl(1), ss(1)
#   - kTLS kernel module (modprobe tls) — skip if missing

VORTEX_BIN="${VORTEX_BIN:-$(dirname "$0")/../../build-release/vortex}"
VORTEX_CFG="${VORTEX_CFG:-$(dirname "$0")/test.yaml}"
VORTEX_PID=""
PASS=0
FAIL=0

die() { echo "FATAL: $*" >&2; exit 1; }

require_ktls() {
    if ! grep -q "^tls " /proc/modules 2>/dev/null; then
        modprobe tls 2>/dev/null || true
        grep -q "^tls " /proc/modules 2>/dev/null || {
            echo "SKIP: kTLS module not available"
            exit 77  # automake skip code
        }
    fi
}

require_root() {
    [ "$(id -u)" -eq 0 ] || { echo "SKIP: requires root"; exit 77; }
}

# Generate a self-signed cert + key into a temp dir, return the dir path
gen_cert() {
    local dir
    dir=$(mktemp -d)
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
        -keyout "$dir/key.pem" -out "$dir/cert.pem" \
        -days 1 -nodes -subj "/CN=localhost" 2>/dev/null
    echo "$dir"
}

# Write a minimal vortex config
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

start_vortex() {
    [ -x "$VORTEX_BIN" ] || die "vortex binary not found: $VORTEX_BIN"
    "$VORTEX_BIN" -c "$VORTEX_CFG" &>/tmp/vortex_test.log &
    VORTEX_PID=$!
    local i=0
    while ! ss -tlnp 2>/dev/null | grep -q ":${VORTEX_PORT:-14443}" && [ $i -lt 30 ]; do
        sleep 0.1; ((i++))
    done
}

stop_vortex() {
    [ -n "$VORTEX_PID" ] && kill "$VORTEX_PID" 2>/dev/null
    VORTEX_PID=""
}

ok() { echo "  ok: $*"; ((PASS++)); }
fail() { echo "  FAIL: $*"; ((FAIL++)); }

summary() {
    echo "Results: $PASS passed, $FAIL failed"
    [ "$FAIL" -eq 0 ]
}
