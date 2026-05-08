#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${REPO_ROOT}/build-release/vortex"
CFG="${REPO_ROOT}/config/public-benchmark.yaml"
PORT="${PORT:-18080}"
RUNS="${RUNS:-5}"
TMP_DIR="$(mktemp -d /tmp/vortex-public-bench.XXXXXX)"
PID_FILE="${TMP_DIR}/vortex.pid"
LOG_FILE="${TMP_DIR}/vortex.log"
VORTEX_PID=""

cleanup() {
    if [[ -n "${VORTEX_PID}" ]]; then
        kill "${VORTEX_PID}" 2>/dev/null || true
        wait "${VORTEX_PID}" 2>/dev/null || true
    fi
    rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

if [[ ! -x "${BIN}" ]]; then
    echo "missing binary: ${BIN}" >&2
    exit 1
fi

cat <<EOF
Benchmarking public HTTPS origins through a local plain-HTTP Vortex instance.
Routes:
  httpbingo.bench.local -> https://httpbingo.org:443
  wikipedia.bench.local -> https://www.wikipedia.org:443
  hetzner-speed.bench.local -> https://speed.hetzner.de:443

Runs per case: ${RUNS}
Frontend: http://127.0.0.1:${PORT}
EOF

"${BIN}" -T -X -c "${CFG}" >"${LOG_FILE}" 2>&1 &
VORTEX_PID="$!"
echo "${VORTEX_PID}" > "${PID_FILE}"
sleep 1

avg_from_lines() {
    awk 'BEGIN{s=0} {s+=$1} END{if (NR > 0) printf "%.6f\n", s/NR; else print "nan"}'
}

run_case() {
    local name="$1"
    local direct_url="$2"
    local proxied_host="$3"
    local proxied_path="$4"
    local output_mode="$5"

    echo
    echo "== ${name} =="
    echo "-- direct ${direct_url}"
    local direct_totals=()
    for ((i = 1; i <= RUNS; i++)); do
        local total
        total="$(curl -sS -o "${output_mode}" -w '%{time_total}' "${direct_url}")"
        direct_totals+=("${total}")
        echo "run ${i}: total=${total}"
    done
    printf '%s\n' "${direct_totals[@]}" | awk '{print $1}' | {
        read -r avg
        printf 'avg_total=%s\n' "${avg}"
    } < <(printf '%s\n' "${direct_totals[@]}" | avg_from_lines)

    echo "-- proxied http://127.0.0.1:${PORT}${proxied_path} (Host: ${proxied_host})"
    local proxied_totals=()
    for ((i = 1; i <= RUNS; i++)); do
        local total
        total="$(curl -sS -o "${output_mode}" -H "Host: ${proxied_host}" -w '%{time_total}' "http://127.0.0.1:${PORT}${proxied_path}")"
        proxied_totals+=("${total}")
        echo "run ${i}: total=${total}"
    done
    printf '%s\n' "${proxied_totals[@]}" | awk '{print $1}' | {
        read -r avg
        printf 'avg_total=%s\n' "${avg}"
    } < <(printf '%s\n' "${proxied_totals[@]}" | avg_from_lines)
}

run_case "httpbingo-json" "https://httpbingo.org/get" "httpbingo.bench.local" "/get" "/dev/null"
run_case "wikipedia-home" "https://www.wikipedia.org/" "wikipedia.bench.local" "/" "/dev/null"
run_case "hetzner-10mb" "https://speed.hetzner.de/10MB.bin" "hetzner-speed.bench.local" "/10MB.bin" "/dev/null"

echo
echo "vortex log: ${LOG_FILE}"
