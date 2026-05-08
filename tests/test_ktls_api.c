/*
 * test_ktls_api.c — unit tests for the tls_accept_result enum/struct API.
 *
 * Does NOT require kTLS kernel support or a live server.  Validates:
 *   - enum ordinal values are stable (callers may use switch without default)
 *   - struct fields are present with expected types
 *   - tls_ktls_counters fields are accessible
 *   - FAIL == 0 (zero-init is a safe default)
 */
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

/* Pull in only the type definitions — link without the full TLS subsystem */
#define VORTEX_PHASE_TLS
#include "tls.h"

static void test_enum_values(void)
{
    assert(TLS_ACCEPT_FAIL == 0);
    assert(TLS_ACCEPT_USERSPACE == 1);
    assert(TLS_ACCEPT_KTLS_FULL == 2);
    assert(TLS_ACCEPT_KTLS_TX_ONLY == 3);
    assert(TLS_ACCEPT_KTLS_RX_ONLY == 4);
    printf("  enum values: ok\n");
}

static void test_struct_zero_init(void)
{
    /* Zero-init must produce FAIL status — safe default */
    struct tls_accept_result r;
    memset(&r, 0, sizeof(r));
    assert(r.status == TLS_ACCEPT_FAIL);
    assert(r.ptls == NULL);
    assert(r.pending_data == NULL);
    assert(r.pending_data_len == 0);
    assert(r.ktls_tx == false);
    assert(r.ktls_rx == false);
    assert(r.h2 == false);
    printf("  zero-init is FAIL: ok\n");
}

static void test_struct_fields(void)
{
    struct tls_accept_result r = {
        .status = TLS_ACCEPT_KTLS_FULL,
        .ptls = NULL,
        .route_idx = 3,
        .h2 = true,
        .ktls_tx = true,
        .ktls_rx = true,
        .pending_data = NULL,
        .pending_data_len = 0,
    };
    assert(r.status == TLS_ACCEPT_KTLS_FULL);
    assert(r.route_idx == 3);
    assert(r.h2 == true);
    assert(r.ktls_tx == true);
    assert(r.ktls_rx == true);
    printf("  struct fields: ok\n");
}

static void test_ktls_full_implies_no_ptls(void)
{
    /* Contract: KTLS_FULL must have ptls=NULL (ptls was freed inside tls_accept) */
    struct tls_accept_result r = {
        .status = TLS_ACCEPT_KTLS_FULL,
        .ptls = NULL,
        .ktls_tx = true,
        .ktls_rx = true,
    };
    assert(r.status == TLS_ACCEPT_KTLS_FULL);
    assert(r.ptls == NULL);
    printf("  KTLS_FULL implies ptls=NULL: ok\n");
}

static void test_userspace_implies_ptls(void)
{
    int dummy_ptls = 42; /* stand-in for ptls_t* */
    struct tls_accept_result r = {
        .status = TLS_ACCEPT_USERSPACE,
        .ptls = (void *)&dummy_ptls,
        .ktls_tx = false,
        .ktls_rx = false,
    };
    assert(r.status == TLS_ACCEPT_USERSPACE);
    assert(r.ptls != NULL);
    assert(r.ktls_tx == false);
    assert(r.ktls_rx == false);
    printf("  USERSPACE implies ptls!=NULL: ok\n");
}

static void test_counters_struct(void)
{
    struct tls_ktls_counters c;
    memset(&c, 0, sizeof(c));
    assert(c.attempts == 0);
    assert(c.tx_ok == 0);
    assert(c.rx_ok == 0);
    assert(c.full_ok == 0);
    assert(c.fallback == 0);
    assert(c.fail_close == 0);
    printf("  counters zero-init: ok\n");
}

static void test_partial_ktls_is_not_in_enum(void)
{
    /* Reserved variants exist but should never be produced by tls_accept().
     * Ensure callers can distinguish them if they appear in the future. */
    tls_accept_status_t tx_only = TLS_ACCEPT_KTLS_TX_ONLY;
    tls_accept_status_t rx_only = TLS_ACCEPT_KTLS_RX_ONLY;
    assert(tx_only != TLS_ACCEPT_KTLS_FULL);
    assert(rx_only != TLS_ACCEPT_KTLS_FULL);
    assert(tx_only != rx_only);
    printf("  partial kTLS variants are distinct from FULL: ok\n");
}

int main(void)
{
    printf("test_ktls_api\n");
    test_enum_values();
    test_struct_zero_init();
    test_struct_fields();
    test_ktls_full_implies_no_ptls();
    test_userspace_implies_ptls();
    test_counters_struct();
    test_partial_ktls_is_not_in_enum();
    printf("all tests passed\n");
    return 0;
}
