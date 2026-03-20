#!/usr/bin/env bash
# Phase 5 XDP filtering test — rate limiting + IP blocklist
# Uses an isolated veth pair + network namespace; does NOT touch real NICs.
# Must be run as root (or with sudo).

set -euo pipefail

VORTEX_BIN="$(realpath "$(dirname "$0")/../build/vortex")"
BPF_OBJ="$(realpath   "$(dirname "$0")/../build/vortex_xdp.bpf.o")"

# Kill any stale processes and wipe old state before we begin
pkill -9 -f "build/vortex" 2>/dev/null || true
fuser -k 18000/tcp 2>/dev/null || true
fuser -k 18080/tcp 2>/dev/null || true
fuser -k 19090/tcp 2>/dev/null || true
sleep 0.5
rm -rf /sys/fs/bpf/vortex 2>/dev/null || true
ip netns del vortex_xdp_test 2>/dev/null || true
ip link del vxdp_host        2>/dev/null || true

TEST_NS="vortex_xdp_test"
VETH_HOST="vxdp_host"
VETH_NS="vxdp_ns"
HOST_IP="10.99.1.1"
NS_IP="10.99.1.2"

BACKEND_PORT=18000
PROXY_PORT=18080

BLOCKLIST_FILE="/tmp/vortex_xdp_blocklist.txt"
CFG_FILE="/tmp/vortex_xdp.yaml"
PID_FILE="/tmp/vortex_xdp.pid"
LOG_FILE="/tmp/vortex_xdp.log"

PASS=0
FAIL=0

pass() { echo "  [PASS] $*"; ((PASS++)) || true; }
fail() { echo "  [FAIL] $*"; ((FAIL++)) || true; }

# ─── Helpers ────────────────────────────────────────────────────────────────
map_key_count() {
    local pinned="$1"
    # bpftool dumps JSON: count '"key":' occurrences
    local n
    n=$(bpftool map dump pinned "$pinned" 2>/dev/null | grep -c '"key":' || true)
    echo "${n:-0}"
}

get_prometheus_metric() {
    local name="$1"
    local val
    val=$(curl -s http://127.0.0.1:19090/metrics 2>/dev/null \
        | grep "^${name} " | awk '{print int($2)}')
    echo "${val:-0}"
}

# ─── Cleanup ────────────────────────────────────────────────────────────────
cleanup() {
    echo ""
    echo "--- cleanup ---"
    if [ -f "$PID_FILE" ]; then
        kill "$(cat "$PID_FILE")" 2>/dev/null || true
        sleep 0.8
    fi
    kill "$BACKEND_PID" 2>/dev/null || true
    ip netns del "$TEST_NS"    2>/dev/null || true
    ip link del "$VETH_HOST"   2>/dev/null || true
    rm -f "$BLOCKLIST_FILE" "$CFG_FILE" "$PID_FILE" "$LOG_FILE"
    rm -rf /sys/fs/bpf/vortex  2>/dev/null || true
}
trap cleanup EXIT

echo ""
echo "=== Phase 5: XDP Filtering Test ==="
echo ""

# ─── 1. Network setup ───────────────────────────────────────────────────────
echo "[1] Setting up veth pair + network namespace"
ip netns add "$TEST_NS"
ip link add "$VETH_HOST" type veth peer name "$VETH_NS"
ip link set "$VETH_NS" netns "$TEST_NS"
ip addr add "${HOST_IP}/30" dev "$VETH_HOST"
ip link set "$VETH_HOST" up
ip netns exec "$TEST_NS" ip addr add "${NS_IP}/30" dev "$VETH_NS"
ip netns exec "$TEST_NS" ip link set "$VETH_NS" up
ip netns exec "$TEST_NS" ip link set lo up
echo "  veth: $VETH_HOST ($HOST_IP) <-> $VETH_NS ($NS_IP) [ns=$TEST_NS]"

# ─── 2. Backend ─────────────────────────────────────────────────────────────
echo "[2] Starting HTTP backend on ${HOST_IP}:${BACKEND_PORT}"
# Raw socket backend — one sendall() guarantees headers+body arrive in a single
# RECV_BACKEND read at the vortex proxy (single-recv pipeline requirement).
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
        conn.recv(65536)   # read request
        conn.sendall(RESP)
    finally:
        conn.close()
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('${HOST_IP}', ${BACKEND_PORT}))
s.listen(128)
while True:
    conn, _ = s.accept()
    threading.Thread(target=serve, args=(conn,), daemon=True).start()
" &
BACKEND_PID=$!
sleep 0.5

# ─── 3. Config ──────────────────────────────────────────────────────────────
# Use rate_limit=20 rps, burst=40 so a ~100 pkt/s flood quickly empties the bucket
echo "[3] Writing vortex config (rate_limit=20 rps, burst=40)"
touch "$BLOCKLIST_FILE"

printf '%s\n' \
"global:" \
"  workers: 1" \
"  bind_address: '${HOST_IP}'" \
"  bind_port: ${PROXY_PORT}" \
"  http_port: 18081" \
"  interface: '${VETH_HOST}'" \
"  log_level: 'info'" \
"  log_format: 'text'" \
"  pid_file: '${PID_FILE}'" \
"tls:" \
"  min_version: '1.2'" \
"  max_version: '1.3'" \
"  ktls: false" \
"xdp:" \
"  mode: 'auto'" \
"  rate_limit:" \
"    enabled: true" \
"    requests_per_second: 20" \
"    burst: 40" \
"  blocklist_file: '${BLOCKLIST_FILE}'" \
"cache:" \
"  enabled: false" \
"metrics:" \
"  enabled: true" \
"  bind_address: '127.0.0.1'" \
"  port: 19090" \
"  path: '/metrics'" \
"routes:" \
"  - hostname: 'test.local'" \
"    backends:" \
"      - address: '${HOST_IP}:${BACKEND_PORT}'" \
"        weight: 1" \
"    load_balancing: 'round_robin'" \
> "$CFG_FILE"

# ─── 4. Start vortex ────────────────────────────────────────────────────────
echo "[4] Starting vortex (XDP on $VETH_HOST)"
rm -f "$LOG_FILE"
touch "$LOG_FILE"
"$VORTEX_BIN" -c "$CFG_FILE" -f -T -b "$BPF_OBJ" >> "$LOG_FILE" 2>&1 &
VORTEX_BG_PID=$!

# Wait up to 6s for vortex to write its PID file and come up
VORTEX_PID=""
for i in $(seq 1 30); do
    sleep 0.2
    if [ -f "$PID_FILE" ]; then
        VORTEX_PID=$(cat "$PID_FILE")
        if kill -0 "$VORTEX_PID" 2>/dev/null; then break; fi
    fi
    if ! kill -0 "$VORTEX_BG_PID" 2>/dev/null; then
        echo "  vortex exited early — log:"
        cat "$LOG_FILE"
        exit 1
    fi
done

if [ -z "$VORTEX_PID" ]; then
    echo "  vortex did not start — log:"
    cat "$LOG_FILE"
    exit 1
fi
echo "  vortex pid=$VORTEX_PID"

# Give the worker's io_uring accept loop a moment to submit the multishot accept SQE
sleep 2

# Verify XDP attached (SKB mode is fine on veth)
if bpftool net show dev "$VETH_HOST" 2>/dev/null | grep -q "xdp"; then
    echo "  XDP confirmed attached to $VETH_HOST"
elif ip link show "$VETH_HOST" 2>/dev/null | grep -q xdp; then
    echo "  XDP attached (ip link)"
else
    echo "  WARNING: bpftool/ip link did not report XDP — checking BPF pins..."
    ls /sys/fs/bpf/vortex/ 2>/dev/null || echo "  (no pins)"
fi

# ─── 5. Baseline: HTTP proxy works ──────────────────────────────────────────
echo ""
echo "[5] Baseline: HTTP proxy (no filtering active)"

# Connectivity diagnostics
echo "  ping ${HOST_IP} from netns:"
ip netns exec "$TEST_NS" ping -c 1 -W 2 "$HOST_IP" 2>&1 | tail -2 || echo "  ping failed"

echo "  backend reachable (host ns): $(curl -s --connect-timeout 2 --max-time 3 "http://${HOST_IP}:${BACKEND_PORT}/" 2>&1 || echo 'FAILED')"
echo "  proxy reachable (host ns):   $(curl -s --connect-timeout 2 --max-time 3 "http://${HOST_IP}:${PROXY_PORT}/"  2>&1 || echo 'FAILED')"

RESP=$(ip netns exec "$TEST_NS" curl -s --connect-timeout 3 --max-time 5 \
    "http://${HOST_IP}:${PROXY_PORT}/" 2>&1 || echo "FAILED")
if echo "$RESP" | grep -q "hello from backend"; then
    pass "baseline HTTP request proxied successfully (from netns)"
else
    fail "baseline HTTP request failed (from netns): $RESP"
    echo "  --- vortex log ---"
    cat "$LOG_FILE"
fi

# ─── 6. Rate limit test ──────────────────────────────────────────────────────
echo ""
echo "[6] Rate limit: SYN flood from ${NS_IP} → verify XDP drop counter"

RL_BEFORE=$(get_prometheus_metric "vortex_xdp_dropped_ratelimit_total")
echo "  rl_drops before: $RL_BEFORE"

# --faster ≈ 100 pps; 200 pkts × 100 pps ≈ 2s
# burst=40 → first 40 pass, then ~160 are rate-limited
echo "  hping3: 200 SYN packets at ~100 pps to ${HOST_IP}:${PROXY_PORT}..."
ip netns exec "$TEST_NS" hping3 -S -p "$PROXY_PORT" \
    --count 200 --faster "$HOST_IP" >/dev/null 2>&1 || true

sleep 0.5
RL_AFTER=$(get_prometheus_metric "vortex_xdp_dropped_ratelimit_total")
echo "  rl_drops after:  $RL_AFTER"

DELTA_RL=$(( RL_AFTER - RL_BEFORE ))
if [ "$DELTA_RL" -gt 0 ]; then
    pass "rate limiting dropped $DELTA_RL packets"
else
    fail "rate limit drops did not increase (before=$RL_BEFORE after=$RL_AFTER)"
fi

# ─── 7. Cooldown — wait for token bucket to refill ───────────────────────────
echo ""
echo "[7] Waiting 5s for token bucket refill (20 rps × 5s = 100 tokens)"
sleep 5

RESP=$(ip netns exec "$TEST_NS" curl -s --connect-timeout 3 --max-time 5 \
    "http://${HOST_IP}:${PROXY_PORT}/" 2>&1 || echo "FAILED")
if echo "$RESP" | grep -q "hello from backend"; then
    pass "post-flood cooldown: HTTP proxy works again"
else
    fail "post-flood cooldown: request still failing: $RESP"
fi

# ─── 8. Blocklist test ──────────────────────────────────────────────────────
echo ""
echo "[8] Blocklist: add ${NS_IP}, reload via SIGHUP"

BL_BEFORE=$(get_prometheus_metric "vortex_xdp_dropped_blocklist_total")
echo "${NS_IP}" > "$BLOCKLIST_FILE"
kill -HUP "$VORTEX_PID"
sleep 0.5

# Verify map populated
BL_KEYS=$(map_key_count /sys/fs/bpf/vortex/blocklist_map)
if [ "$BL_KEYS" -gt 0 ]; then
    pass "blocklist map has $BL_KEYS entry after SIGHUP"
else
    fail "blocklist map empty after SIGHUP (expected ${NS_IP})"
fi

# Connection from NS_IP should be XDP-dropped (timeout, no response)
RESP=$(ip netns exec "$TEST_NS" curl -s --connect-timeout 2 --max-time 3 \
    "http://${HOST_IP}:${PROXY_PORT}/" 2>&1 || echo "BLOCKED")
if echo "$RESP" | grep -q "hello from backend"; then
    fail "blocklist: request should be blocked but got response"
else
    pass "blocklist: request from ${NS_IP} blocked (no response)"
fi

BL_AFTER=$(get_prometheus_metric "vortex_xdp_dropped_blocklist_total")
DELTA_BL=$(( BL_AFTER - BL_BEFORE ))
if [ "$DELTA_BL" -gt 0 ]; then
    pass "XDP blocklist counter incremented by $DELTA_BL"
else
    fail "XDP blocklist counter did not increase (before=$BL_BEFORE after=$BL_AFTER)"
fi

# ─── 9. Unblock and verify recovery ──────────────────────────────────────────
echo ""
echo "[9] Unblock ${NS_IP}: clear file, SIGHUP, verify recovery"

> "$BLOCKLIST_FILE"
kill -HUP "$VORTEX_PID"
sleep 1

BL_KEYS=$(map_key_count /sys/fs/bpf/vortex/blocklist_map)
if [ "$BL_KEYS" -eq 0 ]; then
    pass "blocklist map cleared after reload"
else
    fail "blocklist map still has $BL_KEYS entries after clearing"
fi

# Wait for token bucket to refill: burst=40 means 2 seconds at 20 rps to fill
sleep 3
RESP=$(ip netns exec "$TEST_NS" curl -s --connect-timeout 3 --max-time 5 \
    "http://${HOST_IP}:${PROXY_PORT}/" 2>&1 || echo "FAILED")
if echo "$RESP" | grep -q "hello from backend"; then
    pass "recovery: request succeeds after unblock"
else
    fail "recovery: request still failing after unblock: $RESP"
    # Debug: check map state
    echo "  blocklist_map:"
    bpftool map dump pinned /sys/fs/bpf/vortex/blocklist_map 2>/dev/null || echo "  (unavailable)"
    echo "  rate_config_map:"
    bpftool map dump pinned /sys/fs/bpf/vortex/rate_config_map 2>/dev/null || echo "  (unavailable)"
fi

# ─── 10. Prometheus metrics ──────────────────────────────────────────────────
echo ""
echo "[10] Prometheus /metrics endpoint"
METRICS=$(curl -s http://127.0.0.1:19090/metrics 2>/dev/null || echo "")
for metric in \
    vortex_xdp_rx_packets_total \
    vortex_xdp_rx_bytes_total \
    vortex_xdp_dropped_ratelimit_total \
    vortex_xdp_dropped_blocklist_total; do
    if echo "$METRICS" | grep -q "^${metric}"; then
        pass "Prometheus: $metric present"
    else
        fail "Prometheus: $metric missing"
    fi
done

# Show final metric values
echo ""
echo "  XDP counters at end of test:"
echo "$METRICS" | grep "^vortex_xdp_" | sed 's/^/    /'

# ─── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
echo ""
if [ -s "$LOG_FILE" ]; then
    echo "--- vortex log ---"
    cat "$LOG_FILE"
fi

[ "$FAIL" -eq 0 ]
