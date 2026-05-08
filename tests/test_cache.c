#include "cache.h"
#include "conn.h"
#include "log.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>

/* chunked_decode_append compiled from worker_cache.c — stub unreachable deps */
bool chunked_decode_append(struct conn_cold *cold, const uint8_t *data, size_t len);
/* Stubs for worker_cache.c symbols not needed by chunked_decode_append */
void uring_submit(void *u)
{
    (void)u;
}
void conn_close(void *w, uint32_t cid, bool e)
{
    (void)w;
    (void)cid;
    (void)e;
}

static int g_passed = 0;
static int g_failed = 0;

#define CHECK(cond, msg)                                                                           \
    do {                                                                                           \
        if (cond) {                                                                                \
            g_passed++;                                                                            \
        } else {                                                                                   \
            fprintf(stderr, "FAIL [%s:%d] %s\n", __FILE__, __LINE__, msg);                         \
            g_failed++;                                                                            \
        }                                                                                          \
    } while (0)

#define REQUIRE(cond, msg)                                                                         \
    do {                                                                                           \
        CHECK(cond, msg);                                                                          \
        if (!(cond)) return;                                                                       \
    } while (0)

static void test_init_destroy(void)
{
    struct cache c;
    int r = cache_init(&c, 64, 1024 * 1024, false, NULL, 0, false, false);
    CHECK(r == 0, "cache_init succeeds");
    CHECK(c.index != NULL, "index allocated");
    CHECK(c.slab != NULL, "slab allocated");
    CHECK(c.index_capacity == 64, "capacity is 64");
    cache_destroy(&c);
    CHECK(c.index == NULL, "index freed after destroy");
}

static void test_power_of_two(void)
{
    struct cache c;
    /* Non-power-of-two should be rounded up */
    int r = cache_init(&c, 100, 1024 * 1024, false, NULL, 0, false, false);
    CHECK(r == 0, "init with 100 entries");
    CHECK(c.index_capacity == 128, "rounded up to 128");
    cache_destroy(&c);
}

static void test_miss(void)
{
    struct cache c;
    cache_init(&c, 64, 1024 * 1024, false, NULL, 0, false, false);

    struct cache_index_entry *e = cache_lookup(&c, "/notfound", 9);
    CHECK(e == NULL, "lookup miss returns NULL");
    CHECK(c.misses == 1, "miss counter incremented");
    CHECK(c.hits == 0, "no hits");

    cache_destroy(&c);
}

static void test_store_and_hit(void)
{
    struct cache c;
    cache_init(&c, 64, 1024 * 1024, false, NULL, 0, false, false);

    const char *url = "/api/v1/data";
    const char *body = "hello world";
    const char *hdr = "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n";

    int r = cache_store(&c, url, strlen(url), 200, 300, (const uint8_t *)hdr, strlen(hdr),
                        (const uint8_t *)body, strlen(body));
    CHECK(r == 0, "cache_store succeeds");
    CHECK(c.stores == 1, "store counter incremented");

    struct cache_index_entry *e = cache_lookup(&c, url, strlen(url));
    REQUIRE(e != NULL, "cache_lookup hits");
    CHECK(e->status_code == 200, "status 200");
    CHECK(e->body_len == 11, "body_len correct");
    CHECK(c.hits == 1, "hit counter incremented");

    const uint8_t *body_ptr = cache_body_ptr(&c, e);
    REQUIRE(body_ptr != NULL, "body pointer valid");
    CHECK(memcmp(body_ptr, body, strlen(body)) == 0, "body content matches");

    cache_destroy(&c);
}

static void test_valid_expired(void)
{
    struct cache c;
    cache_init(&c, 64, 1024 * 1024, false, NULL, 0, false, false);

    const char *url = "/short";
    const char *body = "data";

    int r = cache_store(&c, url, strlen(url), 200, 1 /* 1 second TTL */, NULL, 0,
                        (const uint8_t *)body, strlen(body));
    CHECK(r == 0, "store short-lived entry");

    struct cache_index_entry *e = cache_lookup(&c, url, strlen(url));
    CHECK(e != NULL, "lookup succeeds immediately");
    CHECK(cache_entry_valid(e), "entry is valid initially");

    /* Simulate expiry by manipulating created_ts */
    e->created_ts -= 10; /* 10 seconds ago, TTL=1 */
    CHECK(!cache_entry_valid(e), "entry expired after TTL");

    cache_destroy(&c);
}

static void test_multiple_entries(void)
{
    struct cache c;
    cache_init(&c, 64, 2 * 1024 * 1024, false, NULL, 0, false, false);

    /* Store 10 entries */
    char url[64], body[64];
    for (int i = 0; i < 10; i++) {
        snprintf(url, sizeof(url), "/item/%d", i);
        snprintf(body, sizeof(body), "response %d", i);
        int r = cache_store(&c, url, strlen(url), 200, 300, NULL, 0, (const uint8_t *)body,
                            strlen(body));
        CHECK(r == 0, "store entry");
    }

    /* All should be findable */
    int found = 0;
    for (int i = 0; i < 10; i++) {
        snprintf(url, sizeof(url), "/item/%d", i);
        struct cache_index_entry *e = cache_lookup(&c, url, strlen(url));
        if (e) found++;
    }
    CHECK(found == 10, "all 10 entries found");

    /* Miss for non-existent */
    struct cache_index_entry *e = cache_lookup(&c, "/nope", 5);
    CHECK(e == NULL, "non-existent entry is a miss");

    cache_destroy(&c);
}

static void test_update_existing(void)
{
    struct cache c;
    cache_init(&c, 64, 1024 * 1024, false, NULL, 0, false, false);

    const char *url = "/update";
    cache_store(&c, url, strlen(url), 200, 60, NULL, 0, (const uint8_t *)"v1", 2);
    cache_store(&c, url, strlen(url), 200, 60, NULL, 0, (const uint8_t *)"v2", 2);

    struct cache_index_entry *e = cache_lookup(&c, url, strlen(url));
    CHECK(e != NULL, "found after update");
    const uint8_t *bp = cache_body_ptr(&c, e);
    CHECK(bp != NULL && memcmp(bp, "v2", 2) == 0, "body is updated to v2");

    cache_destroy(&c);
}

static void test_evict(void)
{
    struct cache c;
    cache_init(&c, 8, 1024 * 1024, false, NULL, 0, false, false);

    /* Fill to capacity (8 slots with RH probing) */
    char url[32], body[32];
    int stored = 0;
    for (int i = 0; i < 8; i++) {
        snprintf(url, sizeof(url), "/e%d", i);
        snprintf(body, sizeof(body), "b%d", i);
        if (cache_store(&c, url, strlen(url), 200, 300, NULL, 0, (const uint8_t *)body,
                        strlen(body)) == 0) {
            stored++;
        }
    }
    CHECK(stored == 8, "stored 8 entries");

    /* cache_evict_one should remove one */
    int evicted = cache_evict_one(&c);
    CHECK(evicted == 1, "evicted one entry");
    CHECK(c.evictions >= 1, "eviction counter incremented");

    cache_destroy(&c);
}

static void test_slab_wrap(void)
{
    struct cache c;
    /* Very small slab to force wrap */
    cache_init(&c, 64, 4096, false, NULL, 0, false, false);

    /* Store entries until slab wraps */
    char url[32];
    const char *body = "0123456789"; /* 10 bytes */
    for (int i = 0; i < 500; i++) {
        snprintf(url, sizeof(url), "/w%d", i);
        cache_store(&c, url, strlen(url), 200, 300, NULL, 0, (const uint8_t *)body, strlen(body));
    }

    /* Proxy should still work after wrap */
    CHECK(c.slab_watermark < 4096, "slab watermark reset on wrap");
    cache_destroy(&c);
}

static void test_sha256_etag_toggle(void)
{
    struct cache c_xx;
    struct cache c_sha;
    const char *url = "/etag";
    const char *body = "etag-body";

    CHECK(cache_init(&c_xx, 64, 1024 * 1024, false, NULL, 0, false, false) == 0,
          "cache_init xxhash etag");
    CHECK(cache_init(&c_sha, 64, 1024 * 1024, false, NULL, 0, true, false) == 0,
          "cache_init sha256 etag");

    CHECK(cache_store(&c_xx, url, strlen(url), 200, 60, NULL, 0, (const uint8_t *)body,
                      strlen(body)) == 0,
          "store xxhash etag entry");
    CHECK(cache_store(&c_sha, url, strlen(url), 200, 60, NULL, 0, (const uint8_t *)body,
                      strlen(body)) == 0,
          "store sha256 etag entry");

    struct cache_index_entry *e_xx = cache_lookup(&c_xx, url, strlen(url));
    struct cache_index_entry *e_sha = cache_lookup(&c_sha, url, strlen(url));
    REQUIRE(e_xx != NULL && e_sha != NULL, "etag entries stored");
    CHECK(e_xx->body_etag == cache_compute_body_etag(false, (const uint8_t *)body, strlen(body)),
          "xxhash etag matches helper output");
    CHECK(e_sha->body_etag == cache_compute_body_etag(true, (const uint8_t *)body, strlen(body)),
          "sha256 toggle etag matches helper output");

    cache_destroy(&c_xx);
    cache_destroy(&c_sha);
}

static void test_crc_verify_corruption(void)
{
    struct cache c;
    const char *url = "/crc";
    const char *body = "crc-body";
    struct cached_response out;

    CHECK(cache_init(&c, 64, 1024 * 1024, false, NULL, 0, false, true) == 0,
          "cache_init crc verify");
    CHECK(cache_store(&c, url, strlen(url), 200, 60, NULL, 0, (const uint8_t *)body,
                      strlen(body)) == 0,
          "store crc-protected entry");

    struct cache_index_entry *e = cache_lookup(&c, url, strlen(url));
    REQUIRE(e != NULL, "crc entry lookup");
    const uint8_t *bp = cache_body_ptr(&c, e);
    REQUIRE(bp != NULL, "crc body pointer valid");
    ((uint8_t *)bp)[0] ^= 0x01;

    CHECK(cache_fetch_copy(&c, url, strlen(url), &out) == -1,
          "crc mismatch invalidates corrupted entry");
    cache_destroy(&c);
}

/* M-3: chunked oversized chunk must not hang connection slot */
static void test_chunked_oversized(void)
{
    struct conn_cold cold;
    memset(&cold, 0, sizeof(cold));
    cold.chunk_hdr_len = 0;

    /* Craft a chunk-size line claiming 0xFFFFFFFF bytes */
    const uint8_t oversized[] = "ffffffff\r\nXXX";
    bool done = chunked_decode_append(&cold, oversized, sizeof(oversized) - 1);
    CHECK(cold.chunk_remaining == 0, "oversized chunk_remaining capped to 0");
    CHECK(!done, "oversized chunk does not signal terminal");
    free(cold.chunk_buf);
}

/* M-3: normal chunked decode still works */
static void test_chunked_normal(void)
{
    struct conn_cold cold;
    memset(&cold, 0, sizeof(cold));
    cold.chunk_hdr_len = 0;

    const uint8_t data[] = "5\r\nhello\r\n0\r\n\r\n";
    bool done = chunked_decode_append(&cold, data, sizeof(data) - 1);
    CHECK(done, "terminal chunk detected");
    CHECK(cold.chunk_body_len == 5, "body length = 5");
    free(cold.chunk_buf);
}

/* M-5: CLOCK eviction removes exactly one entry */
static void test_clock_eviction(void)
{
    struct cache c;
    CHECK(cache_init(&c, 16, 64 * 1024, false, NULL, 0, false, false) == 0, "cache_init for evict");
    for (int i = 0; i < 16; i++) {
        char url[16];
        snprintf(url, sizeof(url), "/item/%d", i);
        cache_store(&c, url, strlen(url), 200, 300, NULL, 0, (const uint8_t *)"x", 1);
    }
    uint64_t before = c.evictions;
    cache_evict_one(&c);
    CHECK(c.evictions == before + 1, "evict_one increments evictions by 1");
    cache_destroy(&c);
}

/* M-5: clock_hand advances — does not always evict slot 0 */
static void test_clock_hand_advances(void)
{
    struct cache c;
    CHECK(cache_init(&c, 16, 64 * 1024, false, NULL, 0, false, false) == 0,
          "cache_init for clock test");
    for (int i = 0; i < 16; i++) {
        char url[16];
        snprintf(url, sizeof(url), "/item/%d", i);
        cache_store(&c, url, strlen(url), 200, 300, NULL, 0, (const uint8_t *)"x", 1);
    }
    cache_evict_one(&c);
    size_t hand1 = c.clock_hand;
    cache_evict_one(&c);
    CHECK(c.clock_hand != hand1, "clock_hand advances between calls");
    cache_destroy(&c);
}

int main(void)
{
    log_init(LOG_ERROR, LOG_FMT_TEXT, NULL);

    test_init_destroy();
    test_power_of_two();
    test_miss();
    test_store_and_hit();
    test_valid_expired();
    test_multiple_entries();
    test_update_existing();
    test_evict();
    test_slab_wrap();
    test_sha256_etag_toggle();
    test_crc_verify_corruption();
    test_chunked_oversized();
    test_chunked_normal();
    test_clock_eviction();
    test_clock_hand_advances();

    printf("cache tests: %d passed, %d failed\n", g_passed, g_failed);
    return g_failed ? 1 : 0;
}
