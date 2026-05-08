#include "chunked.h"
#include "simd.h"

#include <stdlib.h>
#include <string.h>

bool chunked_decode_append(struct conn_cold *cold, const uint8_t *data, size_t len)
{
    const uint8_t *p = data;
    const uint8_t *end = data + len;

    while (p < end) {
        /* Consume the trailing CRLF following each chunk body.
         * Handle split across recvs and servers that send bare LF. */
        if (cold->chunk_skip_crlf) {
            if (p[0] == '\r') {
                if (p + 2 > end) break; /* \n not yet received — wait */
                if (p[1] != '\n') return false; /* protocol error, abort caching */
                p += 2;
            } else if (p[0] == '\n') {
                p += 1; /* bare LF accepted */
            } else {
                return false; /* unexpected byte where CRLF expected */
            }
            cold->chunk_skip_crlf = false;
        }

        if (cold->chunk_remaining == 0) {
            /* Expecting: <hex-size>[;ext]\r\n */
            const uint8_t *crlf = vx_memmem(p, (size_t)(end - p), "\r\n", 2);
            if (!crlf) break; /* incomplete size line — wait for more data */
            size_t hex_len = (size_t)(crlf - p);
            if (hex_len == 0 || hex_len > 8) return false; /* malformed */
            char hex[9] = {0};
            /* Copy up to optional semicolon (chunk extensions) */
            size_t hl = hex_len;
            for (size_t i = 0; i < hex_len; i++) {
                if (p[i] == ';') {
                    hl = i;
                    break;
                }
                if ((p[i] < '0' || p[i] > '9') && (p[i] < 'a' || p[i] > 'f') &&
                    (p[i] < 'A' || p[i] > 'F'))
                    return false; /* non-hex in size field */
            }
            memcpy(hex, p, hl);
            char *endptr;
            unsigned long chunk_size_ul = strtoul(hex, &endptr, 16);
            if (endptr == hex || chunk_size_ul > CHUNK_MAX_BODY) return false;
            uint32_t chunk_size = (uint32_t)chunk_size_ul;
            p = crlf + 2;
            if (chunk_size == 0) return true; /* terminal chunk */
            cold->chunk_remaining = chunk_size;
        }

        /* Copy body bytes into chunk_buf (after the saved headers) */
        uint32_t avail = (uint32_t)(end - p);
        uint32_t to_copy = avail < cold->chunk_remaining ? avail : cold->chunk_remaining;
        uint32_t buf_used = cold->chunk_hdr_len + cold->chunk_body_len;

        if (buf_used + to_copy <= CHUNK_MAX_BODY + cold->chunk_hdr_len) {
            if (buf_used + to_copy > cold->chunk_buf_cap) {
                uint32_t new_cap = cold->chunk_buf_cap ? cold->chunk_buf_cap * 2 : 131072;
                while (new_cap < buf_used + to_copy)
                    new_cap *= 2;
                if (new_cap > cold->chunk_hdr_len + CHUNK_MAX_BODY)
                    new_cap = cold->chunk_hdr_len + CHUNK_MAX_BODY;
                uint8_t *nb = realloc(cold->chunk_buf, new_cap);
                if (nb) {
                    cold->chunk_buf = nb;
                    cold->chunk_buf_cap = new_cap;
                } else {
                    to_copy = 0; /* alloc failed — skip bytes, give up caching */
                }
            }
            if (cold->chunk_buf && to_copy > 0) {
                memcpy(cold->chunk_buf + buf_used, p, to_copy);
                cold->chunk_body_len += to_copy;
            }
        }

        p += to_copy;
        cold->chunk_remaining -= to_copy;
        if (cold->chunk_remaining == 0) cold->chunk_skip_crlf = true;
    }
    return false;
}
