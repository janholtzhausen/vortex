#!/bin/bash
# P2: kTLS send path handles large responses (>1 MB) without truncation.
set -euo pipefail
source "$(dirname "$0")/lib.sh"
require_ktls
require_root

VORTEX_PORT=14450
cert_dir=$(gen_cert)
write_config "$cert_dir" "$VORTEX_PORT" 18087

# Backend serves 2 MB of data
python3 -c "
import http.server, socketserver
DATA = b'x' * (2 * 1024 * 1024)
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Length', str(len(DATA)))
        self.end_headers()
        self.wfile.write(DATA)
    def log_message(self, *a): pass
s = socketserver.TCPServer(('127.0.0.1', 18087), H); s.serve_forever()
" &
BACKEND_PID=$!
trap "stop_vortex; kill $BACKEND_PID 2>/dev/null; rm -rf $cert_dir" EXIT

start_vortex

bytes=$(curl -sk -o /dev/stdout \
    --resolve "localhost:$VORTEX_PORT:127.0.0.1" \
    "https://localhost:$VORTEX_PORT/" 2>/dev/null | wc -c)

[ "$bytes" -eq $((2 * 1024 * 1024)) ] && \
    ok "large response: received $bytes bytes (exact)" || \
    fail "large response: received $bytes bytes (expected 2097152)"

summary
