#!/bin/bash
# P0: Connection with unrecognised SNI is tarpitted/rejected, not crash-looped.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

VORTEX_PORT=14447
cert_dir=$(gen_cert)
write_config "$cert_dir" "$VORTEX_PORT" 18084

trap "stop_vortex; rm -rf $cert_dir" EXIT
start_vortex

# Wrong SNI — vortex should tarpit or close, not serve data
http_code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 3 \
    --resolve "evil.example.com:$VORTEX_PORT:127.0.0.1" \
    "https://evil.example.com:$VORTEX_PORT/" 2>/dev/null || echo "000")

[ "$http_code" != "200" ] && \
    ok "wrong SNI: rejected (got $http_code)" || \
    fail "wrong SNI: unexpectedly got 200"

# Correct SNI should still work after the bad connection
python3 -c "
import http.server, socketserver
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self): self.send_response(200); self.end_headers(); self.wfile.write(b'ok')
    def log_message(self, *a): pass
s = socketserver.TCPServer(('127.0.0.1', 18084), H); s.serve_forever()
" &
BACKEND_PID=$!
trap "stop_vortex; kill $BACKEND_PID 2>/dev/null; rm -rf $cert_dir" EXIT

sleep 0.2
http_code2=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 \
    --resolve "localhost:$VORTEX_PORT:127.0.0.1" \
    "https://localhost:$VORTEX_PORT/")
[ "$http_code2" -eq 200 ] && ok "good SNI after bad: got 200" || fail "good SNI after bad: got $http_code2"

summary
