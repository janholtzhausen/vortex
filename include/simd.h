#pragma once

#include <stddef.h>
#include <stdint.h>

/*
 * SIMD-accelerated string primitives for HTTP header scanning.
 *
 * Built with -march=znver3 (release), so __AVX2__ is always defined and
 * these functions compile to pure AVX2 with no runtime dispatch overhead.
 * Debug builds (no -mavx2) fall back to scalar / libc implementations.
 *
 * All functions match the semantics of their libc equivalents.
 */

/* Drop-in replacement for memmem().
 * Uses AVX2 first-byte broadcast scan + scalar confirm.
 * Faster than glibc memmem for needles ≤ 32 bytes and haystacks ≤ 64 KB
 * because it avoids the PLT call and KMP preprocessing overhead. */
const void *vx_memmem(const void *hay, size_t hlen,
                      const void *needle, size_t nlen);

/* Find first "\r\n" in buf[0..len).  Returns pointer or NULL. */
const uint8_t *vx_find_crlf(const uint8_t *buf, size_t len);

/* Find first "\r\n\r\n" in buf[0..len).  Returns pointer or NULL. */
const uint8_t *vx_find_hdr_end(const uint8_t *buf, size_t len);
