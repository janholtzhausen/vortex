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

int main(void)
{
    log_init(LOG_ERROR, LOG_FMT_TEXT, NULL);

    test_cb_cross_worker_visibility();
    test_cb_threshold();
    test_cb_reset_on_success();

    printf("circuit_breaker tests: %d passed, %d failed\n", g_passed, g_failed);
    return g_failed ? 1 : 0;
}
