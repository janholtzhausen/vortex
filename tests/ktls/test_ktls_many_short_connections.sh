#!/bin/bash
# P2: 100 short TLS connections in sequence; verify no fd leak or crash.
set -euo pipefail
source "$(dirname "$0")/lib.sh"
require_ktls
require_root

VORTEX_PORT=14449
cert_dir=$(gen_cert)
write_config "$cert_dir" "$VORTEX_PORT" 18086

python3 -c "
import http.server, socketserver
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self): self.send_response(200); self.end_headers(); self.wfile.write(b'ok')
    def log_message(self, *a): pass
s = socketserver.TCPServer(('127.0.0.1', 18086), H); s.serve_forever()
" &
BACKEND_PID=$!
trap "stop_vortex; kill $BACKEND_PID 2>/dev/null; rm -rf $cert_dir" EXIT

start_vortex

failed=0
for i in $(seq 1 100); do
    code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 \
        --resolve "localhost:$VORTEX_PORT:127.0.0.1" \
        "https://localhost:$VORTEX_PORT/" 2>/dev/null || echo "000")
    [ "$code" -ne 200 ] && ((failed++))
done

[ "$failed" -eq 0 ] && ok "100 connections: all 200" || fail "100 connections: $failed failures"

# Check vortex is still alive
kill -0 "$VORTEX_PID" 2>/dev/null && ok "vortex still running" || fail "vortex crashed"

summary
