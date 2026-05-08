#!/bin/bash
# P0: Force TLS_TX setsockopt to fail; verify connection is closed (FAIL), not
# left in half-kTLS state producing corrupt traffic.
#
# Approach: use LD_PRELOAD to intercept setsockopt and return EINVAL for
# SOL_TLS/TLS_TX on the first call.  Verify vortex closes the connection
# rather than serving plaintext or corrupt data.
set -euo pipefail
source "$(dirname "$0")/lib.sh"
require_ktls
require_root

VORTEX_PORT=14445
cert_dir=$(gen_cert)
write_config "$cert_dir" "$VORTEX_PORT" 18082

# Build the fault-injection shim
cat >/tmp/ktls_tx_fault.c <<'EOF'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <linux/tls.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdatomic.h>

static int(*real_setsockopt)(int,int,int,const void*,unsigned) = NULL;
static _Atomic int injected = 0;

int setsockopt(int fd, int level, int optname, const void *val, unsigned len)
{
    if (!real_setsockopt)
        real_setsockopt = dlsym(RTLD_NEXT, "setsockopt");
    /* Fail the first TLS_TX install */
    if (level == SOL_TLS && optname == TLS_TX) {
        int exp = 0;
        if (atomic_compare_exchange_strong(&injected, &exp, 1)) {
            errno = EINVAL;
            return -1;
        }
    }
    return real_setsockopt(fd, level, optname, val, len);
}
EOF
gcc -shared -fPIC -o /tmp/ktls_tx_fault.so /tmp/ktls_tx_fault.c -ldl 2>/dev/null

python3 -c "
import http.server, socketserver
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b'ok')
    def log_message(self, *a): pass
s = socketserver.TCPServer(('127.0.0.1', 18082), H); s.serve_forever()
" &
BACKEND_PID=$!
trap "stop_vortex; kill $BACKEND_PID 2>/dev/null; rm -rf $cert_dir /tmp/ktls_tx_fault.*" EXIT

LD_PRELOAD=/tmp/ktls_tx_fault.so start_vortex

# First connection should be closed (FAIL from partial kTLS)
http_code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 3 \
    --resolve "localhost:$VORTEX_PORT:127.0.0.1" \
    "https://localhost:$VORTEX_PORT/" 2>/dev/null || echo "000")

# Expect: 000 (connection reset) or 5xx, not 200 with corrupt data
[ "$http_code" != "200" ] && \
    ok "TX fault: connection not served (got $http_code, not 200)" || \
    fail "TX fault: got 200 — half-kTLS may have served data"

# Second connection (fault injected once) should succeed
http_code2=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 \
    --resolve "localhost:$VORTEX_PORT:127.0.0.1" \
    "https://localhost:$VORTEX_PORT/" 2>/dev/null || echo "000")
[ "$http_code2" -eq 200 ] && \
    ok "TX fault: subsequent connection succeeded ($http_code2)" || \
    fail "TX fault: subsequent connection also failed ($http_code2)"

summary
