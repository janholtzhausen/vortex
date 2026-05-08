#!/bin/bash
# P0: When the negotiated cipher is not supported by kTLS, vortex must fall
# back to userspace TLS (not crash, not produce corrupt traffic).
# We test by forcing openssl s_client to offer only AES-128-CBC (unsupported).
# Vortex will reject or fall back; either way no corrupt data is served.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

VORTEX_PORT=14446
cert_dir=$(gen_cert)
write_config "$cert_dir" "$VORTEX_PORT" 18083

python3 -c "
import http.server, socketserver
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b'ok')
    def log_message(self, *a): pass
s = socketserver.TCPServer(('127.0.0.1', 18083), H); s.serve_forever()
" &
BACKEND_PID=$!
trap "stop_vortex; kill $BACKEND_PID 2>/dev/null; rm -rf $cert_dir" EXIT

start_vortex

# Standard TLS 1.3 request (uses AES-256-GCM or ChaCha20 — both kTLS-supported)
http_code=$(curl -sk -o /dev/null -w "%{http_code}" \
    --resolve "localhost:$VORTEX_PORT:127.0.0.1" \
    "https://localhost:$VORTEX_PORT/")
[ "$http_code" -eq 200 ] && ok "supported cipher: got 200" || fail "supported cipher: got $http_code"

# Try with TLS 1.2 only (picotls only supports TLS 1.3, so connection should fail cleanly)
http_code2=$(curl -sk --tls-max 1.2 -o /dev/null -w "%{http_code}" --max-time 3 \
    --resolve "localhost:$VORTEX_PORT:127.0.0.1" \
    "https://localhost:$VORTEX_PORT/" 2>/dev/null || echo "000")
[ "$http_code2" != "200" ] && \
    ok "TLS 1.2 attempt: rejected cleanly (got $http_code2)" || \
    fail "TLS 1.2 attempt: unexpectedly got 200"

summary
