#include "auth.h"
#include <string.h>
#include <stddef.h>
#include <stdbool.h>

static int b64val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1; /* invalid or padding */
}

/* Standard base64 decode. out must be at least (in_len/4)*3+1 bytes.
 * Returns decoded byte count, or -1 on error. */
static int b64_decode(const char *in, size_t in_len, char *out, size_t out_max)
{
    size_t out_pos = 0;
    for (size_t i = 0; i + 3 < in_len; i += 4) {
        int v0 = b64val(in[i]);
        int v1 = b64val(in[i+1]);
        int v2 = in[i+2] == '=' ? 0 : b64val(in[i+2]);
        int v3 = in[i+3] == '=' ? 0 : b64val(in[i+3]);
        if (v0 < 0 || v1 < 0 || v2 < 0 || v3 < 0) return -1;
        if (out_pos < out_max - 1) out[out_pos++] = (char)((v0 << 2) | (v1 >> 4));
        if (in[i+2] != '=' && out_pos < out_max - 1) out[out_pos++] = (char)((v1 << 4) | (v2 >> 2));
        if (in[i+3] != '=' && out_pos < out_max - 1) out[out_pos++] = (char)((v2 << 6) | v3);
    }
    out[out_pos] = '\0';
    return (int)out_pos;
}

bool auth_check_basic_value(const struct route_auth_config *auth,
                            const char *value, size_t value_len)
{
    if (!auth || !auth->enabled) return true; /* auth not configured */
    if (auth->credential_count == 0) return true; /* no users = open */

    const char *v = value;
    const char *value_end = value + value_len;
    while (*v == ' ' || *v == '\t') v++;

    /* Must be "Basic " */
    if ((size_t)(value_end - v) < 6 || strncasecmp(v, "Basic ", 6) != 0) return false;
    v += 6;
    while (v < value_end && *v == ' ') v++;

    /* Find end of token (until \r, \n or end of req) */
    const char *tok_end = v;
    while (tok_end < value_end && *tok_end != '\r' && *tok_end != '\n') tok_end++;
    size_t tok_len = (size_t)(tok_end - v);
    if (tok_len == 0 || tok_len > 512) return false;

    /* Decode base64 */
    char decoded[384]; /* max decoded "user:pass" */
    if (b64_decode(v, tok_len, decoded, sizeof(decoded)) < 0) return false;

    /* Compare against configured credentials */
    for (int i = 0; i < auth->credential_count; i++) {
        if (strcmp(decoded, auth->credentials[i]) == 0) return true;
    }
    return false;
}

bool auth_check_request(const struct route_auth_config *auth,
                        const uint8_t *req, int req_len)
{
    if (!auth || !auth->enabled) return true; /* auth not configured */
    if (auth->credential_count == 0) return true; /* no users = open */

    /* Find "Authorization: Basic " header (case-insensitive for "Authorization") */
    const char *p = (const char *)req;
    int remaining = req_len;
    const char *auth_hdr = NULL;

    while (remaining > 0) {
        const char *eol = (const char *)memchr(p, '\n', (size_t)remaining);
        if (!eol) break;
        size_t line_len = (size_t)(eol - p);
        if (line_len > 14) {
            char tmp[16];
            size_t prefix = line_len < 15 ? line_len : 14;
            memcpy(tmp, p, prefix);
            tmp[prefix] = '\0';
            bool match = true;
            const char *needle = "authorization:";
            for (size_t j = 0; j < 14 && match; j++) {
                char c = tmp[j];
                if (c >= 'A' && c <= 'Z') c += 32;
                if (c != needle[j]) match = false;
            }
            if (match) { auth_hdr = p; break; }
        }
        p = eol + 1;
        remaining -= (int)(line_len + 1);
    }

    if (!auth_hdr) return false;

    const char *v = auth_hdr;
    while (*v && *v != ':') v++;
    if (*v != ':') return false;
    v++;
    return auth_check_basic_value(auth, v, strlen(v));
}
