#!/usr/bin/env bash
# Generate vmlinux.h from the running kernel's BTF
set -euo pipefail

OUTPUT="${1:-$(dirname "$0")/../bpf/vmlinux.h}"

if ! command -v bpftool &>/dev/null; then
    echo "ERROR: bpftool not found. Install: apt-get install bpftool" >&2
    exit 1
fi

if [ ! -f /sys/kernel/btf/vmlinux ]; then
    echo "ERROR: /sys/kernel/btf/vmlinux not found — kernel BTF not enabled" >&2
    exit 1
fi

echo "Generating vmlinux.h from running kernel $(uname -r)..."
bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$OUTPUT"
echo "Written to: $OUTPUT ($(wc -l < "$OUTPUT") lines)"
