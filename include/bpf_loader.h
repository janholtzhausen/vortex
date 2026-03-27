#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "../bpf/maps.h"

/* Forward declaration — full definition in config.h */
struct xdp_config;

struct vortex_ip_addr {
    uint8_t family; /* AF_INET / AF_INET6, 0 = unset */
    uint8_t addr[16];
};

int  bpf_loader_init(const char *bpf_obj_path, const char *ifname);
void bpf_loader_detach(void);

/* BPF map accessors — per-IP */
int  bpf_blocklist_add(uint32_t ip_host);
int  bpf_blocklist_remove(uint32_t ip_host);
int  bpf_blocklist_add_addr(const struct vortex_ip_addr *ip);
int  bpf_blocklist_remove_addr(const struct vortex_ip_addr *ip);
int  bpf_rate_limit_set(uint32_t ip_host, uint64_t tokens_per_sec);
int  bpf_metrics_read(struct vortex_metrics *out);

/* Global rate config */
int  bpf_rate_config_set(uint32_t tokens_per_sec, uint32_t burst);

/* Blocklist file loading */
int  bpf_blocklist_clear(void);
int  bpf_blocklist_load_file(const char *path);

/* Apply full XDP config (rate limit + blocklist) — call after init and on reload */
int  bpf_loader_apply_config(const struct xdp_config *xdp);

/* Returns 1 if XDP is loaded and attached */
int  bpf_loader_is_active(void);

/* Conntrack map access */
int  bpf_conntrack_get_fd(void);   /* raw map fd, or -1 if not loaded */
int  bpf_conntrack_count(void);    /* number of active tracked connections, or -1 */
