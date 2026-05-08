#!/bin/bash
# P0: Basic HTTP/1.1 request over a kTLS connection succeeds and returns 200.
set -euo pipefail
source "$(dirname "$0")/lib.sh"
require_ktls
require_root

VORTEX_PORT=14443
cert_dir=$(gen_cert)
write_config "$cert_dir" "$VORTEX_PORT" 18080

# Minimal HTTP/1.1 backend
python3 -c "
import http.server, threading, socketserver
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b'ok')
    def log_message(self, *a): pass
s = socketserver.TCPServer(('127.0.0.1', 18080), H); s.serve_forever()
" &
BACKEND_PID=$!
trap "stop_vortex; kill $BACKEND_PID 2>/dev/null; rm -rf $cert_dir" EXIT

start_vortex

http_code=$(curl -sk -o /dev/null -w "%{http_code}" \
    --resolve "localhost:$VORTEX_PORT:127.0.0.1" \
    "https://localhost:$VORTEX_PORT/")

[ "$http_code" -eq 200 ] && ok "HTTP/1.1 basic: got 200" || fail "HTTP/1.1 basic: got $http_code"

summary
