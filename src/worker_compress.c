#define _GNU_SOURCE
/*
 * worker_compress.c — gzip and brotli compression helpers for the vortex
 * worker.  Called from handle_proxy_data (worker_proxy.c) when the client
 * advertises Accept-Encoding and the response has a compressible Content-Type.
 */
#include "worker_internal.h"

/*
 * Compress src into dst using gzip framing.
 * Returns compressed length, or 0 on failure / expansion.
 */
size_t gzip_compress(const uint8_t *src, size_t src_len,
                     uint8_t *dst, size_t dst_max)
{
    z_stream zs = {0};
    /* windowBits = 15+16 selects gzip wrapper instead of zlib/deflate */
    if (deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                     15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK)
        return 0;
    zs.next_in   = (Bytef *)src;
    zs.avail_in  = (uInt)src_len;
    zs.next_out  = dst;
    zs.avail_out = (uInt)dst_max;
    int ret = deflate(&zs, Z_FINISH);
    deflateEnd(&zs);
    return (ret == Z_STREAM_END) ? (size_t)zs.total_out : 0;
}

/*
 * Compress src into dst using brotli.
 * Quality 6: nginx default — good ratio, ~2× faster than quality 11.
 * Returns compressed length, or 0 on failure / expansion.
 */
size_t brotli_compress(const uint8_t *src, size_t src_len,
                       uint8_t *dst, size_t dst_max)
{
    size_t out_len = dst_max;
    if (!BrotliEncoderCompress(6, BROTLI_DEFAULT_WINDOW, BROTLI_MODE_TEXT,
                               src_len, src, &out_len, dst))
        return 0;
    return out_len;
}

/*
 * Returns true if Content-Type header value indicates compressible content.
 * ct_val points to the value after "Content-Type: ", ct_len is remaining bytes.
 */
bool is_compressible_type(const uint8_t *ct_val, size_t ct_len)
{
    return (ct_len >= 5  && memcmp(ct_val, "text/",                5) == 0) ||
           (ct_len >= 16 && memcmp(ct_val, "application/json",     16) == 0) ||
           (ct_len >= 22 && memcmp(ct_val, "application/javascript",22) == 0) ||
           (ct_len >= 24 && memcmp(ct_val, "application/x-javascript",24) == 0) ||
           (ct_len >= 15 && memcmp(ct_val, "application/xml", 15) == 0) ||
           (ct_len >= 13 && memcmp(ct_val, "image/svg+xml", 13) == 0);
}
