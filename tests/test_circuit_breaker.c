#include "router.h"
#include "log.h"

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

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

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/* M-2 T1: failure recorded on ri=0,bi=0 visible globally */
static void test_cb_cross_worker_visibility(void)
{
    memset(&g_backend_cb[0][0], 0, sizeof(g_backend_cb[0][0]));
    cb_record_failure_global(0, 0, now_ns(), 1, 1000);
    CHECK(cb_is_open_global(0, 0, now_ns()), "CB open visible from any caller");
}

/* M-2 T2: threshold=3, circuit opens on 3rd failure */
static void test_cb_threshold(void)
{
    memset(&g_backend_cb[1][0], 0, sizeof(g_backend_cb[1][0]));
    uint64_t now = now_ns();
    cb_record_failure_global(1, 0, now, 3, 1000);
    CHECK(!cb_is_open_global(1, 0, now), "1st failure: CB still closed");
    cb_record_failure_global(1, 0, now, 3, 1000);
    CHECK(!cb_is_open_global(1, 0, now), "2nd failure: CB still closed");
    cb_record_failure_global(1, 0, now, 3, 1000);
    CHECK(cb_is_open_global(1, 0, now), "3rd failure: CB now open");
}

/* M-2 T3: success after open resets state */
static void test_cb_reset_on_success(void)
{
    memset(&g_backend_cb[2][0], 0, sizeof(g_backend_cb[2][0]));
    uint64_t now = now_ns();
    cb_record_failure_global(2, 0, now, 1, 1000);
    CHECK(cb_is_open_global(2, 0, now), "CB open after failure");
    cb_record_success_global(2, 0);
    CHECK(!cb_is_open_global(2, 0, now_ns()), "CB closed after success");
}

/* X-1: half-open probe path — was dead code before fix.
 * Set open_until_ns to a past timestamp so the penalty window has expired;
 * then verify exactly one caller wins the CAS probe slot (returns false =
 * "not open, go ahead") and subsequent callers are blocked (returns true). */
static void test_cb_half_open_probe(void)
{
    memset(&g_backend_cb[3][0], 0, sizeof(g_backend_cb[3][0]));

    /* Manually set circuit open with an already-expired deadline */
    uint64_t past = now_ns() - 1; /* 1 ns in the past — penalty expired */
    atomic_store_explicit(&g_backend_cb[3][0].open_until_ns, past, memory_order_release);
    atomic_store_explicit(&g_backend_cb[3][0].probing, 0, memory_order_relaxed);

    uint64_t future = now_ns() + 1000000000ULL; /* well after the expired deadline */

    /* First caller wins the probe slot → circuit reports "not open" */
    bool first = cb_is_open_global(3, 0, future);
    CHECK(!first, "half-open: first caller wins probe slot (should return false)");

    /* Second caller sees probing=1 → circuit reports "still open" */
    bool second = cb_is_open_global(3, 0, future);
    CHECK(second, "half-open: second caller blocked while probe in flight (should return true)");

    /* Third caller also blocked */
    bool third = cb_is_open_global(3, 0, future);
    CHECK(third, "half-open: third caller also blocked");

    /* After probe succeeds, CB resets and all callers see closed */
    cb_record_success_global(3, 0);
    CHECK(!cb_is_open_global(3, 0, future), "half-open: closed after probe success");
}

int main(void)
{
    log_init(LOG_ERROR, LOG_FMT_TEXT, NULL);

    test_cb_cross_worker_visibility();
    test_cb_threshold();
    test_cb_reset_on_success();
    test_cb_half_open_probe();

    printf("circuit_breaker tests: %d passed, %d failed\n", g_passed, g_failed);
    return g_failed ? 1 : 0;
}
