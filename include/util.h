#pragma once

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#ifdef __SSE4_2__
#include <nmmintrin.h>
#endif

/* Branch prediction hints */
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

/* Cache line size */
#define CACHE_LINE_SIZE 64

/* Alignment helpers */
#define ALIGN_UP(x, a)   (((x) + (a) - 1) & ~((a) - 1))
#define ALIGN_DOWN(x, a) ((x) & ~((a) - 1))
#define IS_POWER_OF_2(x) ((x) && !((x) & ((x) - 1)))

/* Container of */
#define container_of(ptr, type, member) \
    ((type *)((char *)(ptr) - offsetof(type, member)))

/* Array size */
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

/* Min/max */
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

/* Prefetch helpers */
#define PREFETCH_R(addr)  __builtin_prefetch((addr), 0, 3)
#define PREFETCH_W(addr)  __builtin_prefetch((addr), 1, 3)
#define PREFETCH_NT(addr) __builtin_prefetch((addr), 0, 0)

/* Compiler barriers */
#define BARRIER()         __asm__ __volatile__("" ::: "memory")
#define READ_ONCE(x)      (*(volatile typeof(x) *)&(x))
#define WRITE_ONCE(x, v)  (*(volatile typeof(x) *)&(x) = (v))

/* rdtsc for high-res timestamps on hot path */
static inline uint64_t rdtsc(void) {
    uint32_t lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

/* xxHash64 — fast non-crypto hash */
static inline uint64_t xxhash64(const void *data, size_t len) {
    const uint64_t PRIME1 = 0x9E3779B185EBCA87ULL;
    const uint64_t PRIME2 = 0xC2B2AE3D27D4EB4FULL;
    const uint64_t PRIME3 = 0x165667B19E3779F9ULL;
    const uint64_t PRIME4 = 0x85EBCA77C2B2AE63ULL;
    const uint64_t PRIME5 = 0x27D4EB2F165667C5ULL;
    const uint64_t seed   = 0;

    const uint8_t *p   = (const uint8_t *)data;
    const uint8_t *end = p + len;
    uint64_t h64;

    if (len >= 32) {
        uint64_t v1 = seed + PRIME1 + PRIME2;
        uint64_t v2 = seed + PRIME2;
        uint64_t v3 = seed;
        uint64_t v4 = seed - PRIME1;

        do {
            uint64_t x;
            memcpy(&x, p, 8); v1 += x * PRIME2; v1 = (v1 << 31 | v1 >> 33) * PRIME1; p += 8;
            memcpy(&x, p, 8); v2 += x * PRIME2; v2 = (v2 << 31 | v2 >> 33) * PRIME1; p += 8;
            memcpy(&x, p, 8); v3 += x * PRIME2; v3 = (v3 << 31 | v3 >> 33) * PRIME1; p += 8;
            memcpy(&x, p, 8); v4 += x * PRIME2; v4 = (v4 << 31 | v4 >> 33) * PRIME1; p += 8;
        } while (p <= end - 32);

        h64 = (v1 << 1 | v1 >> 63) + (v2 << 7 | v2 >> 57) +
              (v3 << 12 | v3 >> 52) + (v4 << 18 | v4 >> 46);
        h64 ^= (v1 * PRIME2); h64 = h64 * PRIME1 + PRIME4;
        h64 ^= (v2 * PRIME2); h64 = h64 * PRIME1 + PRIME4;
        h64 ^= (v3 * PRIME2); h64 = h64 * PRIME1 + PRIME4;
        h64 ^= (v4 * PRIME2); h64 = h64 * PRIME1 + PRIME4;
    } else {
        h64 = seed + PRIME5;
    }

    h64 += (uint64_t)len;

    while (p + 8 <= end) {
        uint64_t x; memcpy(&x, p, 8);
        h64 ^= (x * PRIME2); h64 = (h64 << 31 | h64 >> 33) * PRIME1; h64 = h64 * PRIME1 + PRIME4; p += 8;
    }
    if (p + 4 <= end) {
        uint32_t x; memcpy(&x, p, 4);
        h64 ^= (uint64_t)x * PRIME1; h64 = (h64 << 23 | h64 >> 41) * PRIME2 + PRIME3; p += 4;
    }
    while (p < end) {
        h64 ^= (uint64_t)*p * PRIME5; h64 = (h64 << 11 | h64 >> 53) * PRIME1; p++;
    }

    h64 ^= h64 >> 33; h64 *= PRIME2; h64 ^= h64 >> 29; h64 *= PRIME3; h64 ^= h64 >> 32;
    return h64;
}

static inline uint32_t crc32c_hw(const uint8_t *data, size_t len)
{
#ifdef __SSE4_2__
    uint64_t crc = 0xFFFFFFFFu;
    const uint8_t *p = data;

    while (len >= 8) {
        uint64_t v;
        memcpy(&v, p, sizeof(v));
        crc = _mm_crc32_u64(crc, v);
        p += 8;
        len -= 8;
    }
    while (len--)
        crc = _mm_crc32_u8((uint32_t)crc, *p++);
    return (uint32_t)crc ^ 0xFFFFFFFFu;
#else
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int bit = 0; bit < 8; bit++) {
            uint32_t mask = -(crc & 1u);
            crc = (crc >> 1) ^ (0x82F63B78u & mask);
        }
    }
    return crc ^ 0xFFFFFFFFu;
#endif
}
