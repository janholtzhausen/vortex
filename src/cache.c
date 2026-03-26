#include "cache.h"
#include "log.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statvfs.h>

#ifndef MAP_HUGETLB
#define MAP_HUGETLB 0x40000
#endif
#ifndef MAP_HUGE_2MB
#define MAP_HUGE_2MB (21 << MAP_HUGE_SHIFT)
#define MAP_HUGE_SHIFT 26
#endif

static inline uint32_t fnv1a(const char *data, size_t len)
{
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; i++) {
        h ^= (uint8_t)data[i];
        h *= 16777619u;
    }
    return h;
}

/* Try mmap with hugepages, fall back to THP, then regular */
static void *alloc_aligned(size_t size, bool try_hugepages)
{
    void *p = NULL;

    if (try_hugepages) {
        /* Try explicit 2MB hugepages */
        p = mmap(NULL, size,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | MAP_HUGE_2MB,
            -1, 0);
        if (p != MAP_FAILED) {
            log_info("cache_alloc", "hugepage 2MB allocation ok size=%zu", size);
            return p;
        }
        p = NULL;

        /* Try THP hint */
        p = mmap(NULL, size, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p != MAP_FAILED) {
            madvise(p, size, MADV_HUGEPAGE);
            log_info("cache_alloc", "THP hint allocation ok size=%zu", size);
            return p;
        }
        p = NULL;
    }

    /* Regular mmap */
    p = mmap(NULL, size, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        log_error("cache_alloc", "mmap failed: %s", strerror(errno));
        return NULL;
    }
    log_info("cache_alloc", "regular mmap allocation ok size=%zu", size);
    return p;
}

int cache_init(struct cache *c, uint32_t index_entries,
               size_t slab_size, bool try_hugepages,
               const char *disk_path, size_t disk_size)
{
    memset(c, 0, sizeof(*c));
    pthread_mutex_init(&c->lock, NULL);

    /* Round up index_entries to power of 2 */
    if (!IS_POWER_OF_2(index_entries)) {
        uint32_t n = 1;
        while (n < index_entries) n <<= 1;
        index_entries = n;
    }
    c->index_capacity = index_entries;
    c->index_mask     = index_entries - 1;
    c->slab_size      = slab_size;

    size_t index_bytes = index_entries * sizeof(struct cache_index_entry);
    c->index = alloc_aligned(index_bytes, try_hugepages);
    if (!c->index) return -1;
    memset(c->index, 0, index_bytes);

    c->slab = alloc_aligned(slab_size, try_hugepages);
    if (!c->slab) {
        pthread_mutex_destroy(&c->lock);
        munmap(c->index, index_bytes);
        c->index = NULL;
        return -1;
    }

    log_info("cache_init",
        "index_entries=%zu index_bytes=%zu ram_slab=%zu",
        (size_t)index_entries, index_bytes, slab_size);

    /* Optional file-backed disk slab */
    if (disk_path && disk_path[0]) {
        if (disk_size == 0) {
            /* Auto-detect: 50% of free space on the target filesystem */
            struct statvfs st;
            /* statvfs on the parent directory */
            char dir[4096];
            snprintf(dir, sizeof(dir), "%s", disk_path);
            char *slash = strrchr(dir, '/');
            if (slash && slash != dir) *slash = '\0';
            else snprintf(dir, sizeof(dir), "%s", ".");
            if (statvfs(dir, &st) == 0) {
                disk_size = (size_t)st.f_bavail * (size_t)st.f_bsize / 2;
            } else {
                disk_size = 1ULL * 1024 * 1024 * 1024; /* 1 GB fallback */
            }
            /* Floor at 128 MB, cap at 50 GB */
            if (disk_size < 128ULL * 1024 * 1024)
                disk_size = 128ULL * 1024 * 1024;
            if (disk_size > 50ULL * 1024ULL * 1024ULL * 1024ULL)
                disk_size = 50ULL * 1024ULL * 1024ULL * 1024ULL;
        }

        int fd = open(disk_path, O_RDWR | O_CREAT, 0600);
        if (fd >= 0) {
            if (ftruncate(fd, (off_t)disk_size) == 0) {
                void *dm = mmap(NULL, disk_size, PROT_READ | PROT_WRITE,
                                MAP_SHARED, fd, 0);
                if (dm != MAP_FAILED) {
                    c->disk_slab      = dm;
                    c->disk_slab_size = disk_size;
                    log_info("cache_init", "disk_slab path=%s size=%zu",
                             disk_path, disk_size);
                } else {
                    log_warn("cache_init", "disk slab mmap failed: %s", strerror(errno));
                }
            } else {
                log_warn("cache_init", "disk slab ftruncate failed: %s", strerror(errno));
            }
            close(fd);
        } else {
            log_warn("cache_init", "disk slab open(%s) failed: %s", disk_path, strerror(errno));
        }
    }

    return 0;
}

void cache_destroy(struct cache *c)
{
    pthread_mutex_destroy(&c->lock);
    if (c->index) {
        munmap(c->index, c->index_capacity * sizeof(struct cache_index_entry));
    }
    if (c->slab) {
        munmap(c->slab, c->slab_size);
    }
    if (c->disk_slab) {
        msync(c->disk_slab, c->disk_slab_size, MS_SYNC);
        munmap(c->disk_slab, c->disk_slab_size);
    }
    memset(c, 0, sizeof(*c));
}

static struct cache_index_entry *cache_lookup_locked(struct cache *c,
    const char *url, size_t url_len)
{
    uint64_t hash = xxhash64(url, url_len);
    uint32_t confirm = fnv1a(url, url_len);
    size_t   slot = hash & c->index_mask;

    PREFETCH_R(&c->index[slot]);

    for (size_t probe = 0; probe <= c->index_capacity; probe++) {
        struct cache_index_entry *e = &c->index[slot];

        if (!(e->flags & CACHE_FLAG_VALID)) {
            c->misses++;
            return NULL;
        }

        if (e->url_hash == hash) {
            uint8_t klen = (uint8_t)(url_len > 16 ? 16 : url_len);
            if (e->url_key_len != klen || memcmp(e->url_key, url, klen) != 0) {
                c->misses++;
                return NULL;
            }
            if (e->url_hash_confirm != confirm) {
                /* Hash + prefix matched but secondary hash didn't — genuine collision */
                c->misses++;
                return NULL;
            }
            e->last_accessed_ts = (uint32_t)time(NULL);
            e->hit_count = e->hit_count < 0xFF ? e->hit_count + 1 : 0xFF;
            c->hits++;
            return e;
        }

        size_t entry_home = e->url_hash & c->index_mask;
        size_t entry_dist = (slot - entry_home + c->index_capacity) & c->index_mask;
        if (entry_dist < probe) {
            c->misses++;
            return NULL;
        }

        slot = (slot + 1) & c->index_mask;
    }

    c->misses++;
    return NULL;
}

/* Robin Hood hash probing */
struct cache_index_entry *cache_lookup(struct cache *c,
    const char *url, size_t url_len)
{
    pthread_mutex_lock(&c->lock);
    struct cache_index_entry *e = cache_lookup_locked(c, url, url_len);
    pthread_mutex_unlock(&c->lock);
    return e;
}

int cache_store(struct cache *c, const char *url, size_t url_len,
                uint16_t status, uint32_t ttl,
                const uint8_t *headers, size_t header_len,
                const uint8_t *body, size_t body_len)
{
    pthread_mutex_lock(&c->lock);
    size_t total = header_len + body_len;
    if (total == 0) {
        pthread_mutex_unlock(&c->lock);
        return -1;
    }

    /* Compute ETag from body */
    uint64_t etag = (body && body_len > 0) ? xxhash64(body, body_len) : 0;

    /* Try RAM slab first; on overflow try disk slab; finally wrap RAM */
    uint32_t slab_off;
    bool use_disk = false;

    if (total > c->slab_size / 4) {
        /* Too large for RAM slab; try disk slab */
        if (!c->disk_slab || total > c->disk_slab_size / 4) return -1;
        use_disk = true;
    }

    if (!use_disk) {
        if (c->slab_watermark + total > c->slab_size) {
            /* Try overflow to disk slab */
            if (c->disk_slab && c->disk_slab_watermark + total <= c->disk_slab_size) {
                use_disk = true;
            } else {
                /* Wrap RAM slab — invalidate all RAM entries */
                c->slab_watermark = 0;
                for (size_t i = 0; i < c->index_capacity; i++) {
                    if ((c->index[i].flags & CACHE_FLAG_VALID) &&
                        !(c->index[i].slab_offset & CACHE_SLAB_DISK_FLAG)) {
                        c->index[i].flags = 0;
                        c->evictions++;
                    }
                }
            }
        }
    }

    if (use_disk) {
        if (c->disk_slab_watermark + total > c->disk_slab_size) {
            /* Wrap disk slab — invalidate all disk entries */
            c->disk_slab_watermark = 0;
            for (size_t i = 0; i < c->index_capacity; i++) {
                if ((c->index[i].flags & CACHE_FLAG_VALID) &&
                    (c->index[i].slab_offset & CACHE_SLAB_DISK_FLAG)) {
                    c->index[i].flags = 0;
                    c->evictions++;
                }
            }
        }
        slab_off = (uint32_t)c->disk_slab_watermark | CACHE_SLAB_DISK_FLAG;
        if (headers && header_len > 0)
            memcpy(c->disk_slab + c->disk_slab_watermark, headers, header_len);
        if (body && body_len > 0)
            memcpy(c->disk_slab + c->disk_slab_watermark + header_len, body, body_len);
        c->disk_slab_watermark += total;
    } else {
        slab_off = (uint32_t)c->slab_watermark;
        if (headers && header_len > 0)
            memcpy(c->slab + slab_off, headers, header_len);
        if (body && body_len > 0)
            memcpy(c->slab + slab_off + header_len, body, body_len);
        c->slab_watermark += total;
    }

    /* Insert into hash table using Robin Hood */
    uint64_t hash = xxhash64(url, url_len);
    uint32_t confirm = fnv1a(url, url_len);
    size_t   slot = hash & c->index_mask;
    uint32_t now  = (uint32_t)time(NULL);

    uint8_t klen = (uint8_t)(url_len > 16 ? 16 : url_len);
    struct cache_index_entry new_entry = {
        .url_hash         = hash,
        .body_etag        = etag,
        .slab_offset      = slab_off,
        .body_len         = (uint32_t)body_len,
        .header_len       = (uint32_t)header_len,
        .status_code      = status,
        .flags            = CACHE_FLAG_VALID,
        .ttl_seconds      = (uint16_t)(ttl > UINT16_MAX ? UINT16_MAX : ttl),
        .created_ts       = now,
        .last_accessed_ts = now,
        .hit_count        = 0,
        .url_key_len      = klen,
        .url_hash_confirm = confirm,
    };
    memcpy(new_entry.url_key, url, klen);

    int retried = 0;
insert_retry:
    for (size_t probe = 0; probe <= c->index_capacity; probe++) {
        struct cache_index_entry *e = &c->index[slot];

        if (!(e->flags & CACHE_FLAG_VALID)) {
            *e = new_entry;
            c->stores++;
            pthread_mutex_unlock(&c->lock);
            return 0;
        }

        if (e->url_hash == hash) {
            /* Update existing */
            *e = new_entry;
            c->stores++;
            pthread_mutex_unlock(&c->lock);
            return 0;
        }

        /* Robin Hood: steal slot if incumbent has shorter probe distance */
        size_t entry_home = e->url_hash & c->index_mask;
        size_t entry_dist = (slot - entry_home + c->index_capacity) & c->index_mask;
        if (entry_dist < probe) {
            struct cache_index_entry tmp = *e;
            *e = new_entry;
            new_entry = tmp;
            probe = entry_dist;
        }

        slot = (slot + 1) & c->index_mask;
    }

    /* Table full — evict LRU */
    cache_evict_one(c);
    if (!retried) {
        retried = 1;
        slot = hash & c->index_mask;
        goto insert_retry;
    }
    pthread_mutex_unlock(&c->lock);
    return -1;
}

int cache_fetch_copy(struct cache *c, const char *url, size_t url_len,
                     struct cached_response *out)
{
    memset(out, 0, sizeof(*out));
    pthread_mutex_lock(&c->lock);
    struct cache_index_entry *e = cache_lookup_locked(c, url, url_len);
    if (!e || !cache_entry_valid(e)) {
        pthread_mutex_unlock(&c->lock);
        return -1;
    }

    const uint8_t *resp = cache_response_ptr(c, e);
    size_t total = e->header_len + e->body_len;
    out->data = malloc(total);
    if (!out->data) {
        pthread_mutex_unlock(&c->lock);
        return -1;
    }
    memcpy(out->data, resp, total);
    out->header_len = e->header_len;
    out->body_len = e->body_len;
    out->status_code = e->status_code;
    out->body_etag = e->body_etag;
    pthread_mutex_unlock(&c->lock);
    return 0;
}

void cache_cached_response_free(struct cached_response *resp)
{
    free(resp->data);
    memset(resp, 0, sizeof(*resp));
}

const uint8_t *cache_body_ptr(struct cache *c,
    const struct cache_index_entry *entry)
{
    const uint8_t *resp = cache_response_ptr(c, entry);
    return resp ? resp + entry->header_len : NULL;
}

uint32_t cache_ttl_for_url(const char *url)
{
    /* API endpoints: do not cache at proxy level */
    if (strncmp(url, "/api/", 5) == 0 || strncmp(url, "/api?", 5) == 0)
        return 0;

    /* Static assets: cache aggressively for 1 hour */
    const char *ext = strrchr(url, '.');
    if (ext) {
        /* Strip query string from extension */
        char e[16];
        size_t elen = 0;
        for (const char *c = ext; *c && *c != '?' && *c != '#' && elen < 15; c++)
            e[elen++] = *c;
        e[elen] = '\0';
        if (!strcmp(e, ".js")   || !strcmp(e, ".css")  ||
            !strcmp(e, ".woff") || !strcmp(e, ".woff2")||
            !strcmp(e, ".ttf")  || !strcmp(e, ".eot")  ||
            !strcmp(e, ".png")  || !strcmp(e, ".jpg")  ||
            !strcmp(e, ".jpeg") || !strcmp(e, ".svg")  ||
            !strcmp(e, ".ico")  || !strcmp(e, ".gif")  ||
            !strcmp(e, ".webp") || !strcmp(e, ".map")) {
            return 3600;
        }
    }

    /* HTML and other text: 60 seconds */
    return 60;
}

int cache_evict_one(struct cache *c)
{
    uint32_t oldest_ts  = UINT32_MAX;
    size_t   oldest_idx = SIZE_MAX;

    /* Scan for least recently used — O(n) for MVP, acceptable for small tables */
    for (size_t i = 0; i < c->index_capacity; i++) {
        struct cache_index_entry *e = &c->index[i];
        if (!(e->flags & CACHE_FLAG_VALID)) continue;

        /* Frequency-boost: devalue frequently hit entries */
        uint32_t score = e->last_accessed_ts + e->hit_count;
        if (score < oldest_ts) {
            oldest_ts  = score;
            oldest_idx = i;
        }
    }

    if (oldest_idx == SIZE_MAX) return 0;

    c->index[oldest_idx].flags = 0;
    c->evictions++;
    return 1;
}
