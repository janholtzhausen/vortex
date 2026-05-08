# ADR-004: XDP/eBPF for Packet Filtering

**Status:** Accepted  
**Date:** 2024

## Context

A reverse proxy on an internet-facing host needs protection against SYN floods, IP blocklists, and rate limiting. These can be implemented in userspace (iptables/nftables at kernel netfilter layer) or in XDP (before netfilter, at NIC driver level).

## Decision

Implement packet filtering in an XDP eBPF program (`bpf/vortex_xdp.bpf.c`) attached to the network interface. The XDP program handles:

1. IP blocklist enforcement (window clamp / tarpit for blocked IPs on protected ports)
2. Stateful L4 TCP conntrack (LRU_HASH, 512K entries, protected ports only)
3. Per-source-IP SYN rate limiting (token bucket)
4. Per-CPU metrics

BPF maps are pinned under `/sys/fs/bpf/vortex/` for userspace access (blocklist updates, metrics scraping).

## Rationale

- **Sub-microsecond drop**: XDP runs in the NIC driver before sk_buff allocation. SYN flood packets never reach the kernel TCP stack.
- **Zero kernel-copy**: XDP passes the packet pointer directly; no socket buffer allocated for dropped packets.
- **Port-scoped enforcement**: `protected_ports` config controls which ports get conntrack + rate-limit. SSH, apt, backend health checks on other ports pass through untracked — avoids blocking server-initiated connections.
- **LRU eviction**: BPF_MAP_TYPE_LRU_HASH evicts oldest entries when full, avoiding memory exhaustion from large-scale scans.

## Conntrack Design

- **SYN+RST guard**: SYN flag combined with RST is treated as non-SYN (invalid TCP flag combination, passed to kernel without CT entry).
- **BPF_NOEXIST on SYN**: prevents SYN flood from overwriting ESTABLISHED entries in LRU map.
- **FIN handling**: first FIN → `CT_FIN_WAIT`, second FIN → delete entry (not CT_CLOSING, which relied on LRU eviction). CT_TIMEOUT_FIN_NS (30 s) used for FIN_WAIT state.
- **RST**: always deletes CT entry and passes to kernel.
- **Idle timeouts**: 30 s (SYN), 120 s (ESTABLISHED), 30 s (FIN_WAIT).

## Known Limitations

- **IPv4-only blocklist**: tarpit + blocklist only works for IPv4. IPv6 rate limiting is implemented but IPv6 blocklist file loading is not.
- **Asymmetric paths**: conntrack tracks inbound packets only. On asymmetric routing (different return path) CT state may not advance correctly. In practice, most deployments have symmetric paths.
- **NAT**: clients behind CGNAT share a source IP. Rate limiting affects all clients sharing a NATed IP equally.
- **TCP offload**: some NICs perform TSO/GRO which can merge segments. XDP runs before GRO on most drivers.

## Alternatives Rejected

- **iptables/nftables**: runs at netfilter, after sk_buff allocation. ~5-10x slower than XDP for drop decisions. No per-CPU metrics.
- **tc BPF (clsact)**: similar to XDP but supports both ingress and egress. Not needed here (all decisions are on ingress).
- **Userspace firewall (nfqueue)**: copies packet to userspace per-packet — ~100x overhead vs XDP.
