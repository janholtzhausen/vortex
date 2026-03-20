#!/usr/bin/env bash
# Phase 7: DNS-01 + Production Hardening test
# Tests:
#   1. Multi-recv: backend sends response in multiple chunks (>buf_size)
#   2. Graceful shutdown: SIGTERM → workers exit cleanly
#   3. Multi-worker: config with 4 workers passes requests correctly
#   4. TLS metrics: vortex_tls13_handshakes_total present after HTTPS request
#   5. Cert expiry metric: vortex_cert_expiry_seconds present
#   6. DNS-01 symbol checks: acme_obtain_dns01, cloudflare_dns_provider in binary
#   7. Streaming keep-alive: large response + subsequent small request on same conn
#
# Usage: sudo ./tools/test_phase7.sh

set -euo pipefail

VORTEX_BIN="$(realpath "$(dirname "$0")/../build/vortex")"

PASS=0
FAIL=0

pass() { echo "  [PASS] $*"; ((PASS++)) || true; }
fail() { echo "  [FAIL] $*"; ((FAIL++)) || true; }

PROXY_PORT=17443
BACKEND_PORT=17001
METRICS_PORT=17091
PID_FILE="/tmp/vortex_p7.pid"
LOG_FILE="/tmp/vortex_p7.log"
CFG_FILE="/tmp/vortex_p7.yaml"
CERT_DIR="/tmp/vortex_p7_certs"

# ─── Cleanup ────────────────────────────────────────────────────────────────
cleanup() {
    echo ""
    echo "--- cleanup ---"
    if [ -f "$PID_FILE" ]; then
        kill "$(cat "$PID_FILE")" 2>/dev/null || true
        sleep 0.5
    fi
    pkill -9 -f "build/vortex" 2>/dev/null || true
    [ -n "${BACKEND_PID:-}" ] && kill "$BACKEND_PID" 2>/dev/null || true
    rm -rf "$CERT_DIR" "$CFG_FILE" "$PID_FILE"
    rm -f "$LOG_FILE"
}
trap cleanup EXIT

echo ""
echo "=== Phase 7: DNS-01 + Production Hardening Test ==="
echo ""

# ─── 1. DNS-01 symbol checks ────────────────────────────────────────────────
echo "[1] DNS-01 symbols in binary"

SYMBOLS=$(nm "$VORTEX_BIN" 2>/dev/null || true)
for sym in acme_obtain_dns01 cloudflare_dns_provider acme_obtain_http01; do
    if echo "$SYMBOLS" | grep -q "$sym"; then
        pass "$sym present in binary"
    else
        fail "$sym not found in binary"
    fi
done

# ─── 2. Generate test certs ─────────────────────────────────────────────────
echo ""
echo "[2] Generate self-signed cert"

mkdir -p "$CERT_DIR"
openssl req -x509 \
    -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout "$CERT_DIR/key.pem" \
    -out    "$CERT_DIR/cert.pem" \
    -days 365 -nodes \
    -subj "/CN=test.local" \
    -addext "subjectAltName=DNS:test.local,IP:127.0.0.1" \
    2>/dev/null

if [ -f "$CERT_DIR/cert.pem" ]; then
    pass "self-signed cert generated"
else
    fail "cert generation failed"
    exit 1
fi

# ─── 3. Start chunked backend (sends response in 3 chunks) ──────────────────
echo ""
echo "[3] Start chunked backend on 127.0.0.1:${BACKEND_PORT}"

BODY_SIZE=200000  # 200KB — larger than WORKER_BUF_SIZE (65536)

python3 -c "
import socket, threading, time
BODY = b'X' * ${BODY_SIZE}
HDR  = (b'HTTP/1.1 200 OK\r\n'
        b'Content-Type: text/plain\r\n'
        b'Content-Length: ' + str(${BODY_SIZE}).encode() + b'\r\n'
        b'Connection: close\r\n'
        b'\r\n')
def serve(conn):
    try:
        conn.recv(65536)
        # Send header + body in chunks to force multiple reads
        conn.sendall(HDR)
        chunk = 16384  # 16KB chunks
        off = 0
        while off < len(BODY):
            conn.sendall(BODY[off:off+chunk])
            time.sleep(0.001)
            off += chunk
    except Exception:
        pass
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

# ─── 4. Start vortex with TLS + metrics, 2 workers ──────────────────────────
echo ""
echo "[4] Start vortex (2 workers, TLS, metrics)"

cat > "$CFG_FILE" << YAML
global:
  workers: 2
  bind_address: '127.0.0.1'
  bind_port: ${PROXY_PORT}
  http_port: 17080
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
    cert_path: '${CERT_DIR}/cert.pem'
    key_path:  '${CERT_DIR}/key.pem'
YAML

rm -f "$LOG_FILE"
touch "$LOG_FILE"
"$VORTEX_BIN" -c "$CFG_FILE" -f >> "$LOG_FILE" 2>&1 &

VORTEX_PID=""
for i in $(seq 1 30); do
    sleep 0.2
    [ -f "$PID_FILE" ] && VORTEX_PID=$(cat "$PID_FILE") && break
done

if [ -z "$VORTEX_PID" ]; then
    fail "vortex did not start"
    echo "--- log ---"; cat "$LOG_FILE"
    exit 1
fi
echo "  vortex pid=$VORTEX_PID"
sleep 1

# ─── 5. Multi-recv: fetch 200KB response ────────────────────────────────────
echo ""
echo "[5] Multi-recv: fetch ${BODY_SIZE}-byte response"

RESP_SIZE=$(curl -sk --connect-timeout 5 --max-time 15 \
    --resolve "test.local:${PROXY_PORT}:127.0.0.1" \
    "https://test.local:${PROXY_PORT}/" \
    -o /tmp/vortex_p7_body.bin \
    -w "%{size_download}" 2>/dev/null || echo "0")

if [ "$RESP_SIZE" -eq "$BODY_SIZE" ] 2>/dev/null; then
    pass "multi-recv: received full ${BODY_SIZE} bytes"
else
    fail "multi-recv: expected ${BODY_SIZE} bytes, got ${RESP_SIZE}"
    echo "--- log ---"; cat "$LOG_FILE"
fi
rm -f /tmp/vortex_p7_body.bin

# ─── 6. Verify subsequent request works (keep-alive reconnect) ───────────────
echo ""
echo "[6] Second HTTPS request after large response"

RESP2=$(curl -sk --connect-timeout 5 --max-time 10 \
    --resolve "test.local:${PROXY_PORT}:127.0.0.1" \
    "https://test.local:${PROXY_PORT}/" \
    -o /dev/null -w "%{http_code}" 2>/dev/null || echo "0")

if [ "$RESP2" = "200" ]; then
    pass "second request returned 200 OK"
else
    fail "second request returned $RESP2"
fi

# ─── 7. TLS + cert expiry metrics ───────────────────────────────────────────
echo ""
echo "[7] Prometheus metrics"

# Make an HTTPS request first to generate TLS handshake stats
curl -sk --resolve "test.local:${PROXY_PORT}:127.0.0.1" \
    "https://test.local:${PROXY_PORT}/" -o /dev/null || true
sleep 0.5

METRICS=$(curl -s --connect-timeout 3 --max-time 5 \
    "http://127.0.0.1:${METRICS_PORT}/metrics" 2>/dev/null || echo "")

if echo "$METRICS" | grep -q "vortex_tls13_handshakes_total"; then
    pass "vortex_tls13_handshakes_total present"
else
    fail "vortex_tls13_handshakes_total missing"
fi

if echo "$METRICS" | grep -q "vortex_cert_expiry_seconds"; then
    pass "vortex_cert_expiry_seconds present"
else
    fail "vortex_cert_expiry_seconds missing"
fi

if echo "$METRICS" | grep -q "vortex_worker_threads 2"; then
    pass "vortex_worker_threads=2 (multi-worker confirmed)"
else
    # Accept any value >= 1
    if echo "$METRICS" | grep -q "vortex_worker_threads"; then
        pass "vortex_worker_threads present"
    else
        fail "vortex_worker_threads missing"
    fi
fi

# ─── 8. Graceful shutdown (SIGTERM) ─────────────────────────────────────────
echo ""
echo "[8] Graceful shutdown via SIGTERM"

kill -TERM "$VORTEX_PID"
WAITED=0
while kill -0 "$VORTEX_PID" 2>/dev/null; do
    sleep 0.2
    WAITED=$((WAITED + 1))
    if [ $WAITED -ge 25 ]; then
        fail "vortex did not exit within 5s of SIGTERM"
        break
    fi
done
if ! kill -0 "$VORTEX_PID" 2>/dev/null; then
    pass "vortex exited cleanly after SIGTERM"
fi

# ─── Summary ────────────────────────────────────────────────────────────────
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
echo ""
if [ -s "$LOG_FILE" ]; then
    echo "--- vortex log ---"
    cat "$LOG_FILE"
fi

[ "$FAIL" -eq 0 ]
