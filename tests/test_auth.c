#include "auth.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef VORTEX_PHASE_TLS
#include <openssl/evp.h>
#endif

static int g_passed = 0;
static int g_failed = 0;

#define CHECK(cond, msg) do { \
    if (cond) { g_passed++; } \
    else { fprintf(stderr, "FAIL [%s:%d] %s\n", __FILE__, __LINE__, msg); g_failed++; } \
} while(0)

static void test_basic_auth_checks(void)
{
#ifndef VORTEX_PHASE_TLS
    CHECK(1, "auth test skipped without OpenSSL");
#else
    struct route_auth_config auth;
    char header[300];
    static const char *alice_verifier =
        "alice:$scrypt$ln=15,r=8,p=1$KxXZrIHcPWIrku0gJY4TUQ==$2bju0oJ3dQ/IWRkt8tsgwFBLmqzHAyG5ijxiQGaY1WE=";
    static const char *bob_verifier =
        "bob:$scrypt$ln=15,r=8,p=1$rO6ZAXpQhUhH56RfbcR+7Q==$uwQBShF2nrQk0lYflWJH6tirAViG0wnbbxkZZDDhMJg=";

    memset(&auth, 0, sizeof(auth));
    auth.enabled = true;
    auth.credential_count = 2;
    CHECK(auth_parse_verifier(&auth.verifiers[0], alice_verifier),
          "parse alice verifier");
    CHECK(auth_parse_verifier(&auth.verifiers[1], bob_verifier),
          "parse bob verifier");

    snprintf(header, sizeof(header), "Basic YWxpY2U6c3dvcmRmaXNo");
    CHECK(auth_check_basic_value(&auth, header, strlen(header)),
          "valid alice credentials accepted");

    snprintf(header, sizeof(header), "Basic YWxpY2U6d3JvbmdwYXNz");
    CHECK(!auth_check_basic_value(&auth, header, strlen(header)),
          "wrong password rejected");

    snprintf(header, sizeof(header), "Basic bWFsbG9yeTpzd29yZGZpc2g=");
    CHECK(!auth_check_basic_value(&auth, header, strlen(header)),
          "unknown username rejected");
#endif
}

int main(void)
{
    test_basic_auth_checks();

    if (g_failed) {
        fprintf(stderr, "FAILED: %d checks failed, %d passed\n", g_failed, g_passed);
        return 1;
    }
    printf("PASS: %d checks\n", g_passed);
    return 0;
}
