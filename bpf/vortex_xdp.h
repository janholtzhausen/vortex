#pragma once

/* Shared constants between XDP program and userspace */

/* TCP ports we care about */
#define VORTEX_PORT_HTTPS  443
#define VORTEX_PORT_HTTP   80

/* XDP map pin base path */
#define VORTEX_BPF_PIN_DIR  "/sys/fs/bpf/vortex"

/* Map names (must match SEC(".maps") variable names in BPF program) */
#define MAP_NAME_RATE_LIMIT  "rate_limit_map"
#define MAP_NAME_BLOCKLIST   "blocklist_map"
#define MAP_NAME_METRICS     "metrics_map"
#define MAP_NAME_CONNTRACK   "conn_track_map"
