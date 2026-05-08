#!/bin/bash
# P0: Client sends TLS Finished + first HTTP request in one TCP segment.
# Verify the request is not lost (pending_data path).
set -euo pipefail
source "$(dirname "$0")/lib.sh"
require_ktls
require_root

VORTEX_PORT=14444
cert_dir=$(gen_cert)
write_config "$cert_dir" "$VORTEX_PORT" 18081

python3 -c "
import http.server, socketserver
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path
        self.send_response(200); self.end_headers()
        self.wfile.write(path.encode())
    def log_message(self, *a): pass
s = socketserver.TCPServer(('127.0.0.1', 18081), H); s.serve_forever()
" &
BACKEND_PID=$!
trap "stop_vortex; kill $BACKEND_PID 2>/dev/null; rm -rf $cert_dir" EXIT

start_vortex

# curl uses TLS session resumption on second connection which often bundles data
# First: prime the session
curl -sk -o /dev/null "https://localhost:$VORTEX_PORT/ping" \
    --resolve "localhost:$VORTEX_PORT:127.0.0.1" || true

# Second: reuse session (Finished + request in same segment on fast loopback)
body=$(curl -sk -w "\n%{http_code}" \
    --resolve "localhost:$VORTEX_PORT:127.0.0.1" \
    "https://localhost:$VORTEX_PORT/early_data_check")
status=$(echo "$body" | tail -1)
content=$(echo "$body" | head -1)

[ "$status" -eq 200 ] && ok "early data: got 200" || fail "early data: got $status"
echo "$content" | grep -q "early_data_check" && \
    ok "early data: path preserved" || fail "early data: path not preserved (got: $content)"

summary
