#include "bpf_loader.h"
#include "config.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define BPF_PIN_DIR  "/sys/fs/bpf/vortex"

static struct bpf_object  *g_obj      = NULL;
static struct bpf_program *g_prog     = NULL;
static struct bpf_link    *g_link     = NULL;
static int                 g_ifindex  = -1;
static int                 g_map_rate_limit_fd  = -1;
static int                 g_map_blocklist_fd   = -1;
static int                 g_map_metrics_fd     = -1;
static int                 g_map_rate_config_fd = -1;
static int                 g_map_conntrack_fd   = -1;
static int                 g_xdp_active         = 0;

/* Suppress verbose libbpf logs unless VORTEX_DEBUG is set */
static int libbpf_print_fn(enum libbpf_print_level level,
                            const char *format, va_list args)
{
#ifndef VORTEX_DEBUG
    if (level == LIBBPF_DEBUG) return 0;
#endif
    return vfprintf(stderr, format, args);
}

/* Ensure BPF filesystem is mounted and pin directory exists */
static int ensure_bpf_fs(void)
{
    struct stat st;
    if (stat("/sys/fs/bpf", &st) != 0) {
        log_error("bpf_fs", "BPF filesystem not mounted at /sys/fs/bpf");
        return -1;
    }
    if (stat(BPF_PIN_DIR, &st) != 0) {
        if (mkdir(BPF_PIN_DIR, 0700) != 0 && errno != EEXIST) {
            log_error("bpf_fs", "mkdir %s failed: %s", BPF_PIN_DIR, strerror(errno));
            return -1;
        }
    }
    return 0;
}

int bpf_loader_init(const char *bpf_obj_path, const char *ifname)
{
    libbpf_set_print(libbpf_print_fn);

    if (ensure_bpf_fs() != 0) return -1;

    /* Resolve interface index */
    g_ifindex = (int)if_nametoindex(ifname);
    if (g_ifindex == 0) {
        log_error("bpf_loader", "interface '%s' not found: %s", ifname, strerror(errno));
        return -1;
    }

    /* Open BPF object */
    struct bpf_object_open_opts opts = {
        .sz = sizeof(opts),
    };
    g_obj = bpf_object__open_file(bpf_obj_path, &opts);
    if (!g_obj) {
        log_error("bpf_loader", "bpf_object__open_file(%s) failed: %s",
            bpf_obj_path, strerror(errno));
        return -1;
    }

    /* Load (verify + load into kernel) */
    int err = bpf_object__load(g_obj);
    if (err) {
        log_error("bpf_loader", "bpf_object__load failed: %s", strerror(-err));
        bpf_object__close(g_obj);
        g_obj = NULL;
        return -1;
    }

    /* Find main XDP program */
    g_prog = bpf_object__find_program_by_name(g_obj, "vortex_xdp_main");
    if (!g_prog) {
        log_error("bpf_loader", "program 'vortex_xdp_main' not found in %s", bpf_obj_path);
        bpf_object__close(g_obj);
        g_obj = NULL;
        return -1;
    }

    /* Try native XDP attach first, fall back to SKB mode */
    unsigned int xdp_flags = XDP_FLAGS_DRV_MODE;
    g_link = bpf_program__attach_xdp(g_prog, g_ifindex);
    if (!g_link) {
        log_warn("bpf_loader",
            "native XDP attach failed on %s, falling back to SKB mode", ifname);
        xdp_flags = XDP_FLAGS_SKB_MODE;

        /* For SKB mode we need to use the older API via netlink */
        int prog_fd = bpf_program__fd(g_prog);
        err = bpf_xdp_attach(g_ifindex, prog_fd, xdp_flags, NULL);
        if (err) {
            log_error("bpf_loader", "XDP SKB attach failed: %s", strerror(-err));
            bpf_object__close(g_obj);
            g_obj = NULL;
            return -1;
        }
        log_info("bpf_loader", "XDP attached in SKB mode on %s", ifname);
    } else {
        log_info("bpf_loader", "XDP attached in native mode on %s", ifname);
    }

    /* Find and pin maps */
    struct bpf_map *map;

    map = bpf_object__find_map_by_name(g_obj, "rate_limit_map");
    if (map) {
        g_map_rate_limit_fd = bpf_map__fd(map);
        char pin_path[256];
        snprintf(pin_path, sizeof(pin_path), BPF_PIN_DIR "/rate_limit_map");
        bpf_map__pin(map, pin_path);
    }

    map = bpf_object__find_map_by_name(g_obj, "blocklist_map");
    if (map) {
        g_map_blocklist_fd = bpf_map__fd(map);
        char pin_path[256];
        snprintf(pin_path, sizeof(pin_path), BPF_PIN_DIR "/blocklist_map");
        bpf_map__pin(map, pin_path);
    }

    map = bpf_object__find_map_by_name(g_obj, "metrics_map");
    if (map) {
        g_map_metrics_fd = bpf_map__fd(map);
        char pin_path[256];
        snprintf(pin_path, sizeof(pin_path), BPF_PIN_DIR "/metrics_map");
        bpf_map__pin(map, pin_path);
    }

    map = bpf_object__find_map_by_name(g_obj, "rate_config_map");
    if (map) {
        g_map_rate_config_fd = bpf_map__fd(map);
        char pin_path[256];
        snprintf(pin_path, sizeof(pin_path), BPF_PIN_DIR "/rate_config_map");
        bpf_map__pin(map, pin_path);
    }

    map = bpf_object__find_map_by_name(g_obj, "conn_track_map");
    if (map) {
        g_map_conntrack_fd = bpf_map__fd(map);
        char pin_path[256];
        snprintf(pin_path, sizeof(pin_path), BPF_PIN_DIR "/conn_track_map");
        bpf_map__pin(map, pin_path);
        log_info("bpf_loader", "conntrack map loaded: max_entries=%u",
            CT_MAP_MAX_ENTRIES);
    } else {
        log_warn("bpf_loader", "conn_track_map not found in BPF object");
    }

    g_xdp_active = 1;
    log_info("bpf_loader", "BPF loader initialised: obj=%s if=%s ifindex=%d",
        bpf_obj_path, ifname, g_ifindex);
    return 0;
}

void bpf_loader_detach(void)
{
    if (!g_xdp_active) return;

    if (g_link) {
        bpf_link__destroy(g_link);
        g_link = NULL;
    } else if (g_ifindex > 0) {
        /* SKB mode — detach via netlink */
        bpf_xdp_detach(g_ifindex, XDP_FLAGS_SKB_MODE, NULL);
    }

    /* Unpin maps */
    char path[256];
    snprintf(path, sizeof(path), BPF_PIN_DIR "/rate_limit_map");  unlink(path);
    snprintf(path, sizeof(path), BPF_PIN_DIR "/blocklist_map");   unlink(path);
    snprintf(path, sizeof(path), BPF_PIN_DIR "/metrics_map");     unlink(path);
    snprintf(path, sizeof(path), BPF_PIN_DIR "/rate_config_map"); unlink(path);
    snprintf(path, sizeof(path), BPF_PIN_DIR "/conn_track_map");  unlink(path);
    rmdir(BPF_PIN_DIR);

    if (g_obj) {
        bpf_object__close(g_obj);
        g_obj = NULL;
    }

    g_xdp_active = 0;
    log_info("bpf_loader", "XDP program detached and maps unpinned");
}

int bpf_blocklist_add(uint32_t ip_host)
{
    if (g_map_blocklist_fd < 0) return -1;
    uint32_t key = htonl(ip_host);
    uint8_t  val = 1;
    return bpf_map_update_elem(g_map_blocklist_fd, &key, &val, BPF_ANY);
}

int bpf_blocklist_remove(uint32_t ip_host)
{
    if (g_map_blocklist_fd < 0) return -1;
    uint32_t key = htonl(ip_host);
    return bpf_map_delete_elem(g_map_blocklist_fd, &key);
}

int bpf_rate_limit_set(uint32_t ip_host, uint64_t tokens_per_sec)
{
    if (g_map_rate_limit_fd < 0) return -1;
    uint32_t key = htonl(ip_host);
    struct rate_limit_entry entry = {
        .tokens         = tokens_per_sec * RATE_SCALE,
        .last_refill_ns = 0,
    };
    return bpf_map_update_elem(g_map_rate_limit_fd, &key, &entry, BPF_ANY);
}

int bpf_metrics_read(struct vortex_metrics *out)
{
    if (g_map_metrics_fd < 0 || !out) return -1;

    memset(out, 0, sizeof(*out));

    /* PERCPU_ARRAY: read all CPUs and aggregate */
    int num_cpus = libbpf_num_possible_cpus();
    if (num_cpus <= 0) num_cpus = 1;

    struct vortex_metrics *per_cpu = calloc(num_cpus, sizeof(*per_cpu));
    if (!per_cpu) return -1;

    uint32_t key = 0;
    int ret = bpf_map_lookup_elem(g_map_metrics_fd, &key, per_cpu);
    if (ret == 0) {
        for (int i = 0; i < num_cpus; i++) {
            out->rx_packets        += per_cpu[i].rx_packets;
            out->rx_bytes          += per_cpu[i].rx_bytes;
            out->dropped_ratelimit += per_cpu[i].dropped_ratelimit;
            out->dropped_blocklist += per_cpu[i].dropped_blocklist;
            out->dropped_invalid   += per_cpu[i].dropped_invalid;
            out->passed            += per_cpu[i].passed;
        }
    }

    free(per_cpu);
    return ret;
}

int bpf_loader_is_active(void)
{
    return g_xdp_active;
}

int bpf_conntrack_get_fd(void)
{
    return g_map_conntrack_fd;
}

int bpf_conntrack_count(void)
{
    if (g_map_conntrack_fd < 0) return -1;

    struct conn_tuple key, next_key;
    int count = 0;
    int ret = bpf_map_get_next_key(g_map_conntrack_fd, NULL, &key);
    while (ret == 0) {
        count++;
        ret = bpf_map_get_next_key(g_map_conntrack_fd, &key, &next_key);
        key = next_key;
    }
    return count;
}

int bpf_rate_config_set(uint32_t tokens_per_sec, uint32_t burst)
{
    if (g_map_rate_config_fd < 0) return -1;
    struct rate_config cfg = {
        .tokens_per_sec = tokens_per_sec,
        .burst          = burst,
    };
    uint32_t key = 0;
    return bpf_map_update_elem(g_map_rate_config_fd, &key, &cfg, BPF_ANY);
}

int bpf_blocklist_clear(void)
{
    if (g_map_blocklist_fd < 0) return 0;

    /* Iterate and delete all keys */
    __be32 key, next_key;
    int ret = bpf_map_get_next_key(g_map_blocklist_fd, NULL, &key);
    while (ret == 0) {
        int next_ret = bpf_map_get_next_key(g_map_blocklist_fd, &key, &next_key);
        bpf_map_delete_elem(g_map_blocklist_fd, &key);
        if (next_ret != 0) break;
        key = next_key;
    }
    return 0;
}

int bpf_blocklist_load_file(const char *path)
{
    if (!path || path[0] == '\0') return 0;

    FILE *f = fopen(path, "r");
    if (!f) {
        log_warn("bpf_blocklist", "cannot open blocklist file %s: %s",
            path, strerror(errno));
        return -1;
    }

    char line[64];
    int count = 0;
    while (fgets(line, sizeof(line), f)) {
        /* Strip leading whitespace */
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        /* Skip comments and blank lines */
        if (*p == '#' || *p == '\0' || *p == '\n' || *p == '\r') continue;
        /* Strip trailing whitespace */
        char *end = p + strlen(p) - 1;
        while (end > p && (*end == '\n' || *end == '\r' || *end == ' ')) {
            *end-- = '\0';
        }

        struct in_addr addr;
        if (inet_aton(p, &addr) == 0) {
            log_warn("bpf_blocklist", "invalid IP in blocklist: '%s'", p);
            continue;
        }
        /* inet_aton fills addr.s_addr in network byte order;
         * bpf_blocklist_add expects host byte order and does htonl internally. */
        if (bpf_blocklist_add(ntohl(addr.s_addr)) == 0)
            count++;
    }
    fclose(f);
    log_info("bpf_blocklist", "loaded %d IPs from %s", count, path);
    return count;
}

int bpf_loader_apply_config(const struct xdp_config *xdp)
{
    if (!g_xdp_active) return 0;

    /* Apply rate limit config */
    uint32_t rps   = (xdp->rate_limit_enabled && xdp->rate_limit_rps > 0)
                     ? xdp->rate_limit_rps   : (uint32_t)DEFAULT_TOKENS_PER_SEC;
    uint32_t burst = (xdp->rate_limit_enabled && xdp->rate_limit_burst > 0)
                     ? xdp->rate_limit_burst : (uint32_t)DEFAULT_BURST_TOKENS;

    if (!xdp->rate_limit_enabled) {
        /* Effectively disable rate limiting with an astronomically high limit */
        rps   = UINT32_MAX;
        burst = UINT32_MAX;
    }

    if (bpf_rate_config_set(rps, burst) == 0) {
        if (xdp->rate_limit_enabled) {
            log_info("xdp_config", "rate limit: %u rps burst=%u", rps, burst);
        } else {
            log_info("xdp_config", "rate limiting disabled");
        }
    }

    /* Reload blocklist */
    bpf_blocklist_clear();
    if (xdp->blocklist_file[0] != '\0') {
        bpf_blocklist_load_file(xdp->blocklist_file);
    }

    return 0;
}
