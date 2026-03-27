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

size_t compress_http_response_parts(uint8_t *headers, size_t header_len,
                                    const uint8_t *body, size_t body_len,
                                    uint8_t *scratch, size_t buf_size,
                                    bool prefer_br, bool *used_brotli,
                                    size_t *compressed_len_out)
{
    if (!headers || !body || !scratch || header_len < 4 || body_len < COMPRESS_MIN_BODY)
        return 0;

    size_t clen = prefer_br
        ? brotli_compress(body, body_len, scratch, buf_size)
        : gzip_compress(body, body_len, scratch, buf_size);
    if (prefer_br && (clen == 0 || clen >= body_len)) {
        prefer_br = false;
        clen = gzip_compress(body, body_len, scratch, buf_size);
    }
    if (clen == 0 || clen >= body_len)
        return 0;

    uint8_t *clh = (uint8_t *)memmem(headers, header_len, "\r\nContent-Length:", 17);
    if (!clh) clh = (uint8_t *)memmem(headers, header_len, "\r\ncontent-length:", 17);
    if (!clh)
        return 0;

    size_t hdr_end_off = header_len - 4;
    uint8_t *vs = clh + 17;
    while (vs < headers + hdr_end_off && (*vs == ' ' || *vs == '\t')) vs++;
    uint8_t *ve = (uint8_t *)FIND_CRLF(vs, (size_t)(headers + hdr_end_off - vs));
    if (!ve)
        return 0;

    char new_cl[20];
    int ncl = snprintf(new_cl, sizeof(new_cl), "%zu", clen);
    int delta = ncl - (int)(ve - vs);
    if (hdr_end_off + 4 + delta >= buf_size)
        return 0;
    memmove(vs + ncl, ve, (size_t)(headers + hdr_end_off + 4 - ve));
    memcpy(vs, new_cl, (size_t)ncl);
    hdr_end_off = (size_t)((int)hdr_end_off + delta);

    const char *ce_hdr = prefer_br
        ? "\r\nContent-Encoding: br"
        : "\r\nContent-Encoding: gzip";
    int ce_len = prefer_br ? 22 : 24;
    size_t new_body_off = hdr_end_off + (size_t)ce_len + 4;
    if (new_body_off + clen > buf_size)
        return 0;

    memmove(headers + hdr_end_off + ce_len, headers + hdr_end_off, 4);
    memcpy(headers + hdr_end_off, ce_hdr, (size_t)ce_len);
    memcpy(headers + new_body_off, scratch, clen);

    if (used_brotli)
        *used_brotli = prefer_br;
    if (compressed_len_out)
        *compressed_len_out = clen;
    return new_body_off + clen;
}
