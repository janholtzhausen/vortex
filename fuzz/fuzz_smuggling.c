/*
 * fuzz_smuggling.c — libFuzzer target for the HTTP request framing checker.
 *
 * Covers:
 *   - count_header() (case-insensitive header scan)
 *   - request_has_ambiguous_framing() (TE + CL smuggling detection)
 *
 * Goals: no crash / ASan / UBSan finding on any input.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Symbols compiled in from worker_proxy.c via VORTEX_FUZZ_STANDALONE */
bool request_has_ambiguous_framing(const uint8_t *buf, size_t len);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > 65536) return 0;

    /* Primary: smuggling detection */
    request_has_ambiguous_framing(data, size);

    /* Empty / tiny inputs */
    request_has_ambiguous_framing(data, 0);
    if (size >= 1) request_has_ambiguous_framing(data, 1);

    return 0;
}
