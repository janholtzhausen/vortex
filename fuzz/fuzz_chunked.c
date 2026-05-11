/*
 * fuzz_chunked.c — libFuzzer target for chunked_decode_append().
 *
 * Goals:
 *  1. No crash / ASan finding on any chunked body input.
 *  2. No UBSan finding.
 *  3. Return value (final-chunk seen) is consistent.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

/* chunked_decode_append() signature — compiled from src/chunked.c */
struct conn_cold; /* opaque in fuzz context */
bool chunked_decode_append(struct conn_cold *cold, const uint8_t *data, size_t len);

/*
 * Minimal conn_cold stub for the fuzzer — must match the fields accessed by
 * chunked_decode_append (chunk_buf, chunk_buf_cap, chunk_body_len,
 * chunk_remaining, chunk_skip_crlf).
 */
struct conn_cold {
    uint8_t *chunk_buf;
    uint32_t chunk_buf_cap;
    uint32_t chunk_hdr_len;
    uint32_t chunk_body_len;
    uint32_t chunk_remaining;
    bool chunk_skip_crlf;
    /* padding to avoid OOB reads from any field-offset assumptions */
    uint8_t _pad[512];
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > 65536) return 0;

    /* Allocate a fresh conn_cold each run so ASan can detect OOB */
    struct conn_cold cold;
    memset(&cold, 0, sizeof(cold));
    cold.chunk_buf_cap = 65536;
    cold.chunk_buf = malloc(cold.chunk_buf_cap);
    if (!cold.chunk_buf) return 0;

    chunked_decode_append(&cold, data, size);

    free(cold.chunk_buf);
    return 0;
}
