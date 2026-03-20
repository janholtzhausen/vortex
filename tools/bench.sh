#!/usr/bin/env bash
# Benchmark scripts for vortex
set -euo pipefail

HOST="${1:-localhost}"
PORT="${2:-443}"
DURATION="${3:-30}"

echo "=== vortex benchmark: $HOST:$PORT ==="

if ! command -v wrk &>/dev/null; then
    echo "wrk not found. Install: apt-get install wrk" >&2
    exit 1
fi

echo ""
echo "--- Latency (10 conn, ${DURATION}s) ---"
wrk -t1 -c10 -d${DURATION}s --latency "https://$HOST:$PORT/"

echo ""
echo "--- Throughput (100 conn, ${DURATION}s) ---"
wrk -t1 -c100 -d${DURATION}s "https://$HOST:$PORT/"

echo ""
echo "--- /proc/net/tls_stat ---"
cat /proc/net/tls_stat 2>/dev/null || echo "(kTLS stats not available)"
