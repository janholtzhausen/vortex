#pragma once

#include "util.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <pthread.h>
#include <time.h>

/* Cache entry flags */
#define CACHE_FLAG_VALID       (1 << 0)
#define CACHE_FLAG_STALE       (1 << 1)
#define CACHE_FLAG_REVALIDATING (1 << 2)
#define CACHE_FLAG_COMPRESSED  (1 << 3)

/* Content type enum */
typedef enum {
    CONTENT_OTHER = 0, CONTENT_HTML, CONTENT_JSON,
    CONTENT_CSS, CONTENT_JS, CONTENT_IMAGE,
} content_type_t;

/* Cache index entry — exactly 64 bytes, one cache line */
struct __attribute__((packed, aligned(64))) cache_index_entry {
    uint64_t url_hash;
    uint64_t body_etag;       /* xxhash64 of response body — served as ETag */
    uint32_t slab_offset;
    uint32_t body_len;
    uint32_t header_len;
    uint32_t created_ts;
    uint32_t last_accessed_ts;
    uint32_t ttl_seconds;
    uint16_t status_code;
    uint16_t flags;
    uint16_t hit_count;
    uint8_t  content_type;
    /* Collision guard: first min(key_len,16) bytes of the cache key.
     * Combined with the 64-bit hash this makes a false-positive
     * essentially impossible.  Fills the 17 bytes of tail padding so
     * sizeof stays at 64.  8+8+4+4+4+4+4+4+2+2+2+1+1+16 = 64 */
    uint8_t  url_key_len;     /* bytes stored (0..16) */
    char     url_key[16];     /* first 16 bytes of "host|path" key */
};
_Static_assert(sizeof(struct cache_index_entry) == 64,
    "cache_index_entry must be exactly 64 bytes");

/* High bit of slab_offset distinguishes RAM vs disk slab */
#define CACHE_SLAB_DISK_FLAG (1u << 31)

struct cache {
    pthread_mutex_t lock;
    struct cache_index_entry *index;   /* mmap'd, hugepage-backed if available */
    size_t index_capacity;             /* Power of 2 */
    size_t index_mask;

    uint8_t *slab;                     /* RAM slab (anonymous mmap) */
    size_t   slab_size;
    size_t   slab_watermark;

    uint8_t *disk_slab;                /* Disk slab (file-backed mmap), or NULL */
    size_t   disk_slab_size;
    size_t   disk_slab_watermark;

    /* Stats */
    uint64_t hits;
    uint64_t misses;
    uint64_t evictions;
    uint64_t stores;
};

struct cached_response {
    uint8_t  *data;
    uint32_t  header_len;
    uint32_t  body_len;
    uint16_t  status_code;
    uint64_t  body_etag;
};

/* disk_path: path for file-backed disk slab (NULL or "" = RAM-only).
 * disk_size: 0 = auto (50% of free space on disk_path's filesystem). */
int   cache_init(struct cache *c, uint32_t index_entries,
                 size_t slab_size, bool try_hugepages,
                 const char *disk_path, size_t disk_size);
void  cache_destroy(struct cache *c);

/* Look up a URL. Returns index entry pointer (may be STALE), or NULL on miss.
 * Caller should call __builtin_prefetch before doing other work. */
struct cache_index_entry *cache_lookup(struct cache *c, const char *url,
                                       size_t url_len);

/* Store response. Returns 0 on success. */
int cache_store(struct cache *c, const char *url, size_t url_len,
                uint16_t status, uint32_t ttl,
                const uint8_t *headers, size_t header_len,
                const uint8_t *body, size_t body_len);
int cache_fetch_copy(struct cache *c, const char *url, size_t url_len,
                     struct cached_response *out);
void cache_cached_response_free(struct cached_response *resp);

/* Get pointer to start of full stored response (headers + body) */
static inline const uint8_t *cache_response_ptr(struct cache *c,
    const struct cache_index_entry *entry)
{
    if (!entry || !(entry->flags & CACHE_FLAG_VALID)) return NULL;
    if (entry->slab_offset & CACHE_SLAB_DISK_FLAG) {
        uint32_t off = entry->slab_offset & ~CACHE_SLAB_DISK_FLAG;
        return c->disk_slab ? c->disk_slab + off : NULL;
    }
    return c->slab + entry->slab_offset;
}

/* Get slab pointer for body */
const uint8_t *cache_body_ptr(struct cache *c,
    const struct cache_index_entry *entry);

/* Select TTL for a URL based on path/extension patterns.
 * Returns 0 for URLs that should not be cached (e.g. API endpoints). */
uint32_t cache_ttl_for_url(const char *url);

/* Evict one entry (LRU) — returns 1 if evicted */
int cache_evict_one(struct cache *c);

/* Check if entry is still valid */
static inline bool cache_entry_valid(const struct cache_index_entry *e)
{
    if (!(e->flags & CACHE_FLAG_VALID)) return false;
    uint32_t now = (uint32_t)time(NULL);
    return (now - e->created_ts) < e->ttl_seconds;
}
