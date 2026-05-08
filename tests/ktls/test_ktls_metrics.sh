#!/bin/bash
# P1: After connections, kTLS Prometheus counters are non-zero and coherent.
set -euo pipefail
source "$(dirname "$0")/lib.sh"
require_ktls
require_root

VORTEX_PORT=14448
METRICS_PORT=9090
cert_dir=$(gen_cert)

# Metrics port needs to be in config
cat >"$VORTEX_CFG" <<EOF
listen_port: $VORTEX_PORT
metrics_port: $METRICS_PORT
workers: 1
routes:
  - hostname: localhost
    backends:
      - address: "127.0.0.1:18085"
    cert_path: $cert_dir/cert.pem
    key_path:  $cert_dir/key.pem
EOF

python3 -c "
import http.server, socketserver
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self): self.send_response(200); self.end_headers(); self.wfile.write(b'ok')
    def log_message(self, *a): pass
s = socketserver.TCPServer(('127.0.0.1', 18085), H); s.serve_forever()
" &
BACKEND_PID=$!
trap "stop_vortex; kill $BACKEND_PID 2>/dev/null; rm -rf $cert_dir" EXIT

start_vortex
sleep 0.5

# Make 5 connections
for i in $(seq 1 5); do
    curl -sk -o /dev/null \
        --resolve "localhost:$VORTEX_PORT:127.0.0.1" \
        "https://localhost:$VORTEX_PORT/" || true
done
sleep 0.2

metrics=$(curl -s "http://127.0.0.1:$METRICS_PORT/metrics" 2>/dev/null || echo "")

if [ -z "$metrics" ]; then
    echo "SKIP: metrics endpoint not reachable"
    exit 77
fi

# kTLS install attempts should be > 0
attempts=$(echo "$metrics" | grep "^vortex_ktls_install_attempts_total " | awk '{print $2}' || echo "0")
[ "${attempts:-0}" -gt 0 ] && \
    ok "ktls_install_attempts_total = $attempts (>0)" || \
    fail "ktls_install_attempts_total = ${attempts:-0} (expected >0)"

# full_ok should be > 0 (kTLS is available on this system)
full_ok=$(echo "$metrics" | grep "^vortex_ktls_install_full_ok_total " | awk '{print $2}' || echo "0")
[ "${full_ok:-0}" -gt 0 ] && \
    ok "ktls_install_full_ok_total = $full_ok (>0)" || \
    fail "ktls_install_full_ok_total = ${full_ok:-0} (expected >0 on kTLS system)"

# attempts >= full_ok
[ "${attempts:-0}" -ge "${full_ok:-0}" ] && \
    ok "attempts($attempts) >= full_ok($full_ok)" || \
    fail "attempts($attempts) < full_ok($full_ok) — impossible"

summary
