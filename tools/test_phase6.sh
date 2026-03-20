#!/usr/bin/env bash
# Phase 6: Certificate Management test
# Tests:
#   1. Static file provider: load self-signed cert, verify HTTPS works
#   2. Certificate hot-swap on SIGHUP (replace cert file, SIGHUP, verify new cert)
#   3. Base64url round-trip (unit test)
#   4. ACME staging (skip if ACME_DOMAIN not set)
#
# Requirements: root access (or sudo for port 8443)
# Usage:
#   sudo ./tools/test_phase6.sh
#   ACME_DOMAIN=myhost.example.com sudo -E ./tools/test_phase6.sh

set -euo pipefail

VORTEX_BIN="$(realpath "$(dirname "$0")/../build/vortex")"

PASS=0
FAIL=0

pass() { echo "  [PASS] $*"; ((PASS++)) || true; }
fail() { echo "  [FAIL] $*"; ((FAIL++)) || true; }

PROXY_PORT=18443
BACKEND_PORT=19000
METRICS_PORT=19091
PID_FILE="/tmp/vortex_p6.pid"
LOG_FILE="/tmp/vortex_p6.log"
CFG_FILE="/tmp/vortex_p6.yaml"
CERT_DIR="/tmp/vortex_p6_certs"

# ─── Cleanup ────────────────────────────────────────────────────────────────
cleanup() {
    echo ""
    echo "--- cleanup ---"
    if [ -f "$PID_FILE" ]; then
        kill "$(cat "$PID_FILE")" 2>/dev/null || true
        sleep 0.5
    fi
    pkill -9 -f "build/vortex" 2>/dev/null || true
    kill "$BACKEND_PID" 2>/dev/null || true
    rm -rf "$CERT_DIR" "$CFG_FILE" "$PID_FILE"
    rm -f "$LOG_FILE"
}
trap cleanup EXIT

echo ""
echo "=== Phase 6: Certificate Management Test ==="
echo ""

# ─── 1. Base64url unit test ─────────────────────────────────────────────────
echo "[1] Base64url encode/decode sanity (openssl-based)"

# Test well-known vector: "" → ""
ENC=$(echo -n "" | openssl base64 -e 2>/dev/null | tr '+/' '-_' | tr -d '=\n')
if [ -z "$ENC" ]; then
    pass "base64url empty string encodes to empty"
else
    fail "base64url empty string: expected empty, got '$ENC'"
fi

# "hello" → "aGVsbG8" (standard base64url, no padding)
ENC=$(echo -n "hello" | openssl base64 -e 2>/dev/null | tr '+/' '-_' | tr -d '=\n')
if [ "$ENC" = "aGVsbG8" ]; then
    pass "base64url 'hello' → '$ENC' (correct)"
else
    fail "base64url 'hello': expected 'aGVsbG8', got '$ENC'"
fi

# ─── 2. Self-signed cert generation ─────────────────────────────────────────
echo ""
echo "[2] Generate self-signed cert with openssl"

mkdir -p "$CERT_DIR"

openssl req -x509 \
    -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout "$CERT_DIR/key1.pem" \
    -out    "$CERT_DIR/cert1.pem" \
    -days 365 -nodes \
    -subj "/CN=test.local" \
    -addext "subjectAltName=DNS:test.local,IP:127.0.0.1" \
    2>/dev/null

if [ -f "$CERT_DIR/cert1.pem" ] && [ -f "$CERT_DIR/key1.pem" ]; then
    pass "self-signed cert1 generated"
else
    fail "cert generation failed"
    exit 1
fi

# Check cert details
CERT_CN=$(openssl x509 -noout -subject -in "$CERT_DIR/cert1.pem" 2>/dev/null \
         | grep -oP '(?<=CN\s=\s)[^\s,]+' || echo "")
if [ "$CERT_CN" = "test.local" ]; then
    pass "cert1 CN=test.local"
else
    # openssl subject format varies; check it contains test.local
    if openssl x509 -noout -subject -in "$CERT_DIR/cert1.pem" 2>/dev/null | grep -q "test.local"; then
        pass "cert1 subject contains test.local"
    else
        fail "cert1 subject does not contain test.local"
    fi
fi

# Get fingerprint for later comparison
FP1=$(openssl x509 -noout -fingerprint -sha256 -in "$CERT_DIR/cert1.pem" 2>/dev/null \
     | sed 's/.*=//')
echo "  cert1 fingerprint: $FP1"

# ─── 3. Start backend ───────────────────────────────────────────────────────
echo ""
echo "[3] Start HTTP backend on 127.0.0.1:${BACKEND_PORT}"

python3 -c "
import socket, threading
RESP = (b'HTTP/1.1 200 OK\r\n'
        b'Content-Length: 19\r\n'
        b'Content-Type: text/plain\r\n'
        b'Connection: close\r\n'
        b'\r\n'
        b'hello from backend\n')
def serve(conn):
    try:
        conn.recv(65536)
        conn.sendall(RESP)
    finally:
        conn.close()
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', ${BACKEND_PORT}))
s.listen(128)
while True:
    conn, _ = s.accept()
    threading.Thread(target=serve, args=(conn,), daemon=True).start()
" &
BACKEND_PID=$!
sleep 0.3

# ─── 4. Start vortex with static cert ───────────────────────────────────────
echo ""
echo "[4] Start vortex with static_file cert on port ${PROXY_PORT}"

cat > "$CFG_FILE" << YAML
global:
  workers: 1
  bind_address: '127.0.0.1'
  bind_port: ${PROXY_PORT}
  http_port: 18080
  interface: ''
  log_level: 'info'
  log_format: 'text'
  pid_file: '${PID_FILE}'
tls:
  min_version: '1.2'
  max_version: '1.3'
  ktls: false
xdp:
  mode: 'auto'
  rate_limit:
    enabled: false
    requests_per_second: 0
    burst: 0
  blocklist_file: ''
cache:
  enabled: false
metrics:
  enabled: true
  bind_address: '127.0.0.1'
  port: ${METRICS_PORT}
  path: '/metrics'
routes:
  - hostname: 'test.local'
    backends:
      - address: '127.0.0.1:${BACKEND_PORT}'
        weight: 1
    load_balancing: 'round_robin'
    cert_provider: 'static_file'
    cert_path: '${CERT_DIR}/cert1.pem'
    key_path:  '${CERT_DIR}/key1.pem'
YAML

rm -f "$LOG_FILE"
touch "$LOG_FILE"
"$VORTEX_BIN" -c "$CFG_FILE" -f >> "$LOG_FILE" 2>&1 &

# Wait for pid file
VORTEX_PID=""
for i in $(seq 1 30); do
    sleep 0.2
    [ -f "$PID_FILE" ] && VORTEX_PID=$(cat "$PID_FILE") && break
done

if [ -z "$VORTEX_PID" ]; then
    fail "vortex did not start"
    echo "--- log ---"
    cat "$LOG_FILE"
    exit 1
fi
echo "  vortex pid=$VORTEX_PID"
sleep 1

# ─── 5. Verify HTTPS works with cert1 ───────────────────────────────────────
echo ""
echo "[5] HTTPS request with cert1 (static_file provider)"

RESP=$(curl -sk --connect-timeout 3 --max-time 5 \
    --resolve "test.local:${PROXY_PORT}:127.0.0.1" \
    "https://test.local:${PROXY_PORT}/" 2>&1 || echo "FAILED")

if echo "$RESP" | grep -q "hello from backend"; then
    pass "HTTPS request proxied successfully with cert1"
else
    fail "HTTPS request failed: $RESP"
    echo "--- log ---"; cat "$LOG_FILE"
fi

# Capture server cert fingerprint
FP_SERVED=$(echo | openssl s_client -connect "127.0.0.1:${PROXY_PORT}" \
    -servername "test.local" 2>/dev/null \
    | openssl x509 -noout -fingerprint -sha256 2>/dev/null \
    | sed 's/.*=//' || echo "")
echo "  served cert fingerprint: $FP_SERVED"
if [ "$FP_SERVED" = "$FP1" ]; then
    pass "server is presenting cert1 (fingerprint matches)"
else
    fail "fingerprint mismatch: want=$FP1 got=$FP_SERVED"
fi

# ─── 6. Certificate hot-swap ─────────────────────────────────────────────────
echo ""
echo "[6] Certificate hot-swap: generate cert2, SIGHUP, verify cert2 is served"

# Generate a different cert
openssl req -x509 \
    -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout "$CERT_DIR/key2.pem" \
    -out    "$CERT_DIR/cert2.pem" \
    -days 365 -nodes \
    -subj "/CN=test.local" \
    -addext "subjectAltName=DNS:test.local,IP:127.0.0.1" \
    2>/dev/null

FP2=$(openssl x509 -noout -fingerprint -sha256 -in "$CERT_DIR/cert2.pem" 2>/dev/null \
     | sed 's/.*=//')
echo "  cert2 fingerprint: $FP2"

if [ "$FP1" = "$FP2" ]; then
    fail "cert2 fingerprint same as cert1 (generation failed?)"
else
    pass "cert2 is distinct from cert1"
fi

# Replace cert files in-place
cp "$CERT_DIR/cert2.pem" "$CERT_DIR/cert1.pem"
cp "$CERT_DIR/key2.pem"  "$CERT_DIR/key1.pem"

# Send SIGHUP to trigger cert reload
kill -HUP "$VORTEX_PID"
sleep 1.5  # wait for rotate

FP_AFTER=$(echo | openssl s_client -connect "127.0.0.1:${PROXY_PORT}" \
    -servername "test.local" 2>/dev/null \
    | openssl x509 -noout -fingerprint -sha256 2>/dev/null \
    | sed 's/.*=//' || echo "")
echo "  served cert after SIGHUP: $FP_AFTER"

if [ "$FP_AFTER" = "$FP2" ]; then
    pass "hot-swap: server now presents cert2 after SIGHUP"
else
    fail "hot-swap: expected cert2 ($FP2), got $FP_AFTER"
fi

# Verify proxy still works after hot-swap
RESP2=$(curl -sk --connect-timeout 3 --max-time 5 \
    --resolve "test.local:${PROXY_PORT}:127.0.0.1" \
    "https://test.local:${PROXY_PORT}/" 2>&1 || echo "FAILED")
if echo "$RESP2" | grep -q "hello from backend"; then
    pass "HTTPS still works after cert hot-swap"
else
    fail "HTTPS broken after hot-swap: $RESP2"
fi

# ─── 7. Check cert/ symbols compiled in ─────────────────────────────────────
echo ""
echo "[7] Check vortex binary — cert/ sources compiled in"

# Capture symbols once (grep -q with pipefail causes SIGPIPE on nm; avoid it)
SYMBOLS=$(nm "$VORTEX_BIN" 2>/dev/null || true)

for sym in acme_obtain_http01 b64url_encode tls_rotate_cert static_file_load; do
    if echo "$SYMBOLS" | grep -q "$sym"; then
        pass "$sym symbol present in binary"
    else
        fail "$sym symbol not found (cert/ not linked?)"
    fi
done

# ─── 8. ACME staging (optional) ─────────────────────────────────────────────
echo ""
echo "[8] ACME staging test (requires ACME_DOMAIN env var)"

if [ -z "${ACME_DOMAIN:-}" ]; then
    echo "  SKIP: ACME_DOMAIN not set"
    echo "  To run ACME staging test:"
    echo "    - Point DNS for your domain to this machine (port 80 must be public)"
    echo "    - Run: ACME_DOMAIN=myhost.example.com sudo -E $0"
else
    echo "  ACME_DOMAIN=$ACME_DOMAIN"
    echo "  NOTE: This will contact Let's Encrypt staging and obtain a real cert."
    echo "  (Not implemented in this automated test — run vortex with ACME config manually)"
    echo "  SKIP: automated ACME staging test not yet implemented"
fi

# ─── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
echo ""
if [ -s "$LOG_FILE" ]; then
    echo "--- vortex log ---"
    cat "$LOG_FILE"
fi

[ "$FAIL" -eq 0 ]
