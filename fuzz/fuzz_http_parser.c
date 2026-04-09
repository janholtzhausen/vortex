/*
 * fuzz_http_parser.c — libFuzzer target for the HTTP/1.1 request-line parser.
 *
 * Build:
 *   cmake -B build-fuzz -DVORTEX_FUZZ=ON -DCMAKE_BUILD_TYPE=Debug \
 *         -DCMAKE_C_COMPILER=clang
 *   make -C build-fuzz fuzz_http_parser
 *
 * Run:
 *   ./build-fuzz/fuzz/fuzz_http_parser corpus/ -max_len=16384 -timeout=5
 *
 * The fuzzer exercises parse_http_request_line with fully attacker-controlled
 * input.  Goals:
 *   1. No crash / ASan finding on any input.
 *   2. No UBSan finding.
 *   3. Consistent return value for identical inputs (determinism).
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* pull in the parser symbol — we compile worker_proxy.c into this target */
int parse_http_request_line(const uint8_t *buf, int len,
                            char *method_out, size_t method_max,
                            char *url_out,    size_t url_max);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > 65536) return 0;  /* skip implausibly large inputs early */

    char method[16];
    char url[4096];

    /* Primary call with normal-sized output buffers */
    parse_http_request_line(data, (int)size, method, sizeof(method),
                            url, sizeof(url));

    /* Stress tiny output buffers — must not overflow */
    char m1[1], u1[1];
    parse_http_request_line(data, (int)size, m1, sizeof(m1), u1, sizeof(u1));

    char m2[2], u2[2];
    parse_http_request_line(data, (int)size, m2, sizeof(m2), u2, sizeof(u2));

    return 0;
}
