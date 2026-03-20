#include "simd.h"

#include <string.h>

#ifdef __AVX2__
#include <immintrin.h>

/* ---------------------------------------------------------------------------
 * AVX2 helpers
 * -------------------------------------------------------------------------*/

/* Find the first occurrence of needle[0..nlen) in hay[0..hlen).
 *
 * Algorithm:
 *   1. Broadcast needle[0] across a 256-bit register.
 *   2. Slide a 32-byte window across the haystack, comparing all 32 bytes
 *      simultaneously with _mm256_cmpeq_epi8.
 *   3. For each candidate position (set bit in the movemask), verify the
 *      full needle with memcmp.
 *   4. Scalar tail for the last < 32 bytes.
 *
 * For needle_len == 1 this degenerates to a fast memchr equivalent.
 * For needle_len == 2 (the "\r\n" case) the confirm cost is one 16-bit
 * compare — essentially free.
 */
static const uint8_t *
memmem_avx2(const uint8_t *hay, size_t hlen,
            const uint8_t *needle, size_t nlen)
{
    if (nlen == 0) return hay;
    if (nlen > hlen) return NULL;

    const __m256i first = _mm256_set1_epi8((char)needle[0]);
    const uint8_t *end  = hay + hlen - nlen + 1; /* one past last valid start */
    const uint8_t *p    = hay;

    for (; p + 32 <= end; p += 32) {
        __m256i block = _mm256_loadu_si256((const __m256i *)p);
        uint32_t mask = (uint32_t)_mm256_movemask_epi8(
                            _mm256_cmpeq_epi8(block, first));
        while (mask) {
            int i = __builtin_ctz(mask);
            if (memcmp(p + i, needle, nlen) == 0)
                return p + i;
            mask &= mask - 1; /* clear lowest set bit */
        }
    }

    /* Scalar tail — at most 31 bytes */
    for (; p < end; p++) {
        if (*p == needle[0] && memcmp(p, needle, nlen) == 0)
            return p;
    }
    return NULL;
}

/* Find "\r\n" using a dual-stream approach:
 *   stream A: 32 bytes at offset 0, match '\r'
 *   stream B: 32 bytes at offset 1, match '\n'
 *   AND the two masks → positions where p[i]=='\r' && p[i+1]=='\n'
 * One pass, no confirm needed. */
static const uint8_t *
find_crlf_avx2(const uint8_t *p, size_t len)
{
    if (len < 2) return NULL;

    const __m256i cr   = _mm256_set1_epi8('\r');
    const __m256i lf   = _mm256_set1_epi8('\n');
    const uint8_t *end = p + len - 1; /* last valid '\r' position */

    for (; p + 32 <= end; p += 32) {
        __m256i a = _mm256_loadu_si256((const __m256i *)p);
        __m256i b = _mm256_loadu_si256((const __m256i *)(p + 1));
        uint32_t mask = (uint32_t)_mm256_movemask_epi8(
                            _mm256_and_si256(
                                _mm256_cmpeq_epi8(a, cr),
                                _mm256_cmpeq_epi8(b, lf)));
        if (mask) return p + __builtin_ctz(mask);
    }

    for (; p < end; p++) {
        if (p[0] == '\r' && p[1] == '\n') return p;
    }
    return NULL;
}

/* Find "\r\n\r\n":
 *   Scan for '\r' with AVX2; for each candidate check the 3 bytes that
 *   follow with a single 32-bit load+compare — no memcmp call. */
static const uint8_t *
find_hdr_end_avx2(const uint8_t *p, size_t len)
{
    if (len < 4) return NULL;

    static const uint8_t pat[4] = {'\r', '\n', '\r', '\n'};
    const __m256i cr   = _mm256_set1_epi8('\r');
    const uint8_t *end = p + len - 3; /* last valid start position */

    for (; p + 32 <= end; p += 32) {
        __m256i block = _mm256_loadu_si256((const __m256i *)p);
        uint32_t mask = (uint32_t)_mm256_movemask_epi8(
                            _mm256_cmpeq_epi8(block, cr));
        while (mask) {
            int i = __builtin_ctz(mask);
            /* Single 32-bit unaligned load to confirm all 4 bytes at once */
            uint32_t word;
            memcpy(&word, p + i, 4);
            uint32_t target;
            memcpy(&target, pat, 4);
            if (word == target) return p + i;
            mask &= mask - 1;
        }
    }

    for (; p < end; p++) {
        if (p[0] == '\r' && p[1] == '\n' && p[2] == '\r' && p[3] == '\n')
            return p;
    }
    return NULL;
}

/* ---------------------------------------------------------------------------
 * Public API (AVX2 path)
 * -------------------------------------------------------------------------*/

const void *vx_memmem(const void *hay, size_t hlen,
                      const void *needle, size_t nlen)
{
    return memmem_avx2(hay, hlen, needle, nlen);
}

const uint8_t *vx_find_crlf(const uint8_t *buf, size_t len)
{
    return find_crlf_avx2(buf, len);
}

const uint8_t *vx_find_hdr_end(const uint8_t *buf, size_t len)
{
    return find_hdr_end_avx2(buf, len);
}

#else  /* !__AVX2__ — scalar fallback */

const void *vx_memmem(const void *hay, size_t hlen,
                      const void *needle, size_t nlen)
{
    return memmem(hay, hlen, needle, nlen);
}

const uint8_t *vx_find_crlf(const uint8_t *buf, size_t len)
{
    if (len < 2) return NULL;
    const uint8_t *p = buf, *end = buf + len - 1;
    for (; p < end; p++) {
        if (p[0] == '\r' && p[1] == '\n') return p;
    }
    return NULL;
}

const uint8_t *vx_find_hdr_end(const uint8_t *buf, size_t len)
{
    if (len < 4) return NULL;
    const uint8_t *r = memmem(buf, len, "\r\n\r\n", 4);
    return r;
}

#endif /* __AVX2__ */
