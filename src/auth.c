#include "auth.h"
#include <stdbool.h>
#include <stddef.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef VORTEX_PHASE_TLS
#include <picotls.h>
#include <picotls/minicrypto.h>
#endif

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

#ifdef VORTEX_PHASE_TLS
static bool auth_parse_u32(const char *s, uint32_t *out)
{
    char *end = NULL;
    unsigned long v = strtoul(s, &end, 10);
    if (!s[0] || !end || *end != '\0' || v > UINT32_MAX)
        return false;
    *out = (uint32_t)v;
    return true;
}

/* Constant-time memory comparison */
static int ct_memcmp(const void *a, const void *b, size_t n)
{
    const uint8_t *pa = (const uint8_t *)a;
    const uint8_t *pb = (const uint8_t *)b;
    unsigned int diff = 0;
    for (size_t i = 0; i < n; i++)
        diff |= pa[i] ^ pb[i];
    return diff != 0;
}

#ifdef VORTEX_PHASE_TLS
/* ---- PBKDF2-SHA256 (RFC 2898) via picotls HMAC-SHA256 ---- */
static void pbkdf2_sha256(const uint8_t *pass, size_t pass_len,
                          const uint8_t *salt, size_t salt_len,
                          uint32_t c,
                          uint8_t *dk, size_t dk_len)
{
    enum { HLEN = 32 }; /* SHA-256 output size */
    uint8_t t[HLEN], u[HLEN];
    uint32_t block_num = 0;

    while (dk_len > 0) {
        block_num++;
        /* U1 = HMAC(pass, salt || block_num_be) */
        uint8_t blk_be[4] = {
            (uint8_t)(block_num >> 24), (uint8_t)(block_num >> 16),
            (uint8_t)(block_num >>  8), (uint8_t)(block_num)
        };
        ptls_hash_context_t *hmac = ptls_hmac_create(&ptls_minicrypto_sha256,
                                                      pass, pass_len);
        hmac->update(hmac, salt, salt_len);
        hmac->update(hmac, blk_be, 4);
        hmac->final(hmac, u, PTLS_HASH_FINAL_MODE_FREE);
        memcpy(t, u, HLEN);

        for (uint32_t i = 1; i < c; i++) {
            ptls_hash_context_t *h2 = ptls_hmac_create(&ptls_minicrypto_sha256,
                                                         pass, pass_len);
            h2->update(h2, u, HLEN);
            h2->final(h2, u, PTLS_HASH_FINAL_MODE_FREE);
            for (int j = 0; j < HLEN; j++) t[j] ^= u[j];
        }

        size_t out_len = dk_len < (size_t)HLEN ? dk_len : (size_t)HLEN;
        memcpy(dk, t, out_len);
        dk     += out_len;
        dk_len -= out_len;
    }
    explicit_bzero(t, sizeof(t));
    explicit_bzero(u, sizeof(u));
}

/* ---- Salsa20/8 core (used by scrypt BlockMix) ---- */
static void salsa20_8(uint32_t *b)
{
    uint32_t x[16];
    memcpy(x, b, 64);
#define R(v,n) (((v) << (n)) | ((v) >> (32 - (n))))
    for (int i = 0; i < 8; i += 2) {
        x[ 4] ^= R(x[ 0]+x[12], 7); x[ 8] ^= R(x[ 4]+x[ 0], 9);
        x[12] ^= R(x[ 8]+x[ 4],13); x[ 0] ^= R(x[12]+x[ 8],18);
        x[ 9] ^= R(x[ 5]+x[ 1], 7); x[13] ^= R(x[ 9]+x[ 5], 9);
        x[ 1] ^= R(x[13]+x[ 9],13); x[ 5] ^= R(x[ 1]+x[13],18);
        x[14] ^= R(x[10]+x[ 6], 7); x[ 2] ^= R(x[14]+x[10], 9);
        x[ 6] ^= R(x[ 2]+x[14],13); x[10] ^= R(x[ 6]+x[ 2],18);
        x[ 3] ^= R(x[15]+x[11], 7); x[ 7] ^= R(x[ 3]+x[15], 9);
        x[11] ^= R(x[ 7]+x[ 3],13); x[15] ^= R(x[11]+x[ 7],18);
        x[ 1] ^= R(x[ 0]+x[ 3], 7); x[ 2] ^= R(x[ 1]+x[ 0], 9);
        x[ 3] ^= R(x[ 2]+x[ 1],13); x[ 0] ^= R(x[ 3]+x[ 2],18);
        x[ 6] ^= R(x[ 5]+x[ 4], 7); x[ 7] ^= R(x[ 6]+x[ 5], 9);
        x[ 4] ^= R(x[ 7]+x[ 6],13); x[ 5] ^= R(x[ 4]+x[ 7],18);
        x[11] ^= R(x[10]+x[ 9], 7); x[ 8] ^= R(x[11]+x[10], 9);
        x[ 9] ^= R(x[ 8]+x[11],13); x[10] ^= R(x[ 9]+x[ 8],18);
        x[12] ^= R(x[15]+x[14], 7); x[13] ^= R(x[12]+x[15], 9);
        x[14] ^= R(x[13]+x[12],13); x[15] ^= R(x[14]+x[13],18);
    }
#undef R
    for (int i = 0; i < 16; i++) b[i] += x[i];
}

/* scrypt BlockMix */
static void block_mix(uint32_t *b, uint32_t *y, uint32_t r)
{
    uint32_t *x = y + 32 * r;
    memcpy(x, b + (2*r - 1) * 16, 64);
    for (uint32_t i = 0; i < 2*r; i++) {
        for (int j = 0; j < 16; j++) x[j] ^= b[i*16 + j];
        salsa20_8(x);
        memcpy(y + (i % 2 == 0 ? i/2 : r + i/2) * 16, x, 64);
    }
    memcpy(b, y, 128 * r);
}

/* scrypt ROMix (RFC 7914 section 4) */
static int romix(uint32_t *b, uint64_t n, uint32_t r)
{
    uint32_t *v = malloc(128 * r * n);
    /* block_mix(x, x+32*r, r) uses (x+32*r)+32*r as scratch → needs 256*r+64 bytes */
    uint32_t *x = malloc(256 * r + 64);
    if (!v || !x) { free(v); free(x); return -1; }

    memcpy(x, b, 128 * r);
    for (uint64_t i = 0; i < n; i++) {
        memcpy(v + i * 32 * r, x, 128 * r);
        block_mix(x, x + 32 * r, r);
    }
    for (uint64_t i = 0; i < n; i++) {
        uint64_t j = ((uint64_t)x[(2*r-1)*16] |
                      ((uint64_t)x[(2*r-1)*16+1] << 32)) & (n - 1);
        for (uint32_t k = 0; k < 32 * r; k++) x[k] ^= v[j * 32 * r + k];
        block_mix(x, x + 32 * r, r);
    }
    memcpy(b, x, 128 * r);
    free(v); free(x);
    return 0;
}

/*
 * scrypt KDF (RFC 7914).
 * N = 1 << log_n (must be power of 2), r, p: standard scrypt parameters.
 * Returns 0 on success.
 */
static int vortex_scrypt(const uint8_t *pass, size_t pass_len,
                          const uint8_t *salt, size_t salt_len,
                          uint64_t N, uint32_t r, uint32_t p,
                          uint8_t *dk, size_t dk_len)
{
    size_t mflen = 128 * r;
    uint8_t *b = malloc(mflen * p);
    if (!b) return -1;

    /* Step 1: B[0..p-1] = PBKDF2-SHA256(pass, salt, 1, mflen * p) */
    pbkdf2_sha256(pass, pass_len, salt, salt_len, 1, b, mflen * p);

    /* Step 2: ROMix each block */
    for (uint32_t i = 0; i < p; i++) {
        if (romix((uint32_t *)(b + i * mflen), N, r) != 0) {
            explicit_bzero(b, mflen * p);
            free(b);
            return -1;
        }
    }

    /* Step 3: DK = PBKDF2-SHA256(pass, B, 1, dk_len) */
    pbkdf2_sha256(pass, pass_len, b, mflen * p, 1, dk, dk_len);

    explicit_bzero(b, mflen * p);
    free(b);
    return 0;
}
#endif /* VORTEX_PHASE_TLS */

static bool auth_verify_password(const struct auth_verifier *verifier,
                                 const char *password)
{
    uint8_t derived[VORTEX_AUTH_MAX_HASH_LEN];
    if (verifier->hash_len == 0 || verifier->hash_len > sizeof(derived))
        return false;
#ifdef VORTEX_PHASE_TLS
    if (vortex_scrypt((const uint8_t *)password, strlen(password),
                      verifier->salt, verifier->salt_len,
                      1ULL << verifier->log_n, verifier->r, verifier->p,
                      derived, verifier->hash_len) != 0) {
        return false;
    }
#else
    (void)verifier; return false;
#endif
    return ct_memcmp(derived, verifier->hash, verifier->hash_len) == 0;
}

static bool auth_username_match_ct(const char *a, const char *b)
{
    size_t la = strlen(a);
    size_t lb = strlen(b);
    size_t n = la > lb ? la : lb;
    unsigned char diff = (unsigned char)(la ^ lb);

    for (size_t i = 0; i < n; i++) {
        unsigned char ca = i < la ? (unsigned char)a[i] : 0;
        unsigned char cb = i < lb ? (unsigned char)b[i] : 0;
        diff |= (unsigned char)(ca ^ cb);
    }
    return diff == 0;
}

static void auth_make_dummy_verifier(struct auth_verifier *dst,
                                     const struct auth_verifier *src)
{
    *dst = *src;
    if (dst->hash_len > 0)
        dst->hash[0] ^= 0xFF;
}
#endif

bool auth_parse_verifier(struct auth_verifier *out, const char *value)
{
    if (!out || !value)
        return false;

    memset(out, 0, sizeof(*out));

#ifndef VORTEX_PHASE_TLS
    (void)value;
    return false;
#else
    char buf[512];
    snprintf(buf, sizeof(buf), "%s", value);

    char *username = strtok(buf, ":");
    char *scheme = strtok(NULL, "$");
    char *params = strtok(NULL, "$");
    char *salt_b64 = strtok(NULL, "$");
    char *hash_b64 = strtok(NULL, "$");
    char *extra = strtok(NULL, "$");

    if (!username || !scheme || !params || !salt_b64 || !hash_b64 || extra)
        return false;
    if (username[0] == '\0' || strlen(username) >= sizeof(out->username))
        return false;
    if (strcmp(scheme, "scrypt") != 0)
        return false;

    uint32_t log_n = 0, r = 0, p = 0;
    char *param_ctx = NULL;
    for (char *tok = strtok_r(params, ",", &param_ctx);
         tok;
         tok = strtok_r(NULL, ",", &param_ctx)) {
        char *eq = strchr(tok, '=');
        if (!eq)
            return false;
        *eq = '\0';
        const char *key = tok;
        const char *val = eq + 1;
        if (strcmp(key, "ln") == 0) {
            if (!auth_parse_u32(val, &log_n))
                return false;
        } else if (strcmp(key, "r") == 0) {
            if (!auth_parse_u32(val, &r))
                return false;
        } else if (strcmp(key, "p") == 0) {
            if (!auth_parse_u32(val, &p))
                return false;
        } else {
            return false;
        }
    }

    if (log_n < 1 || log_n > 20 || r == 0 || p == 0)
        return false;

    char salt_decoded[(VORTEX_AUTH_MAX_SALT_LEN * 4 / 3) + 8];
    char hash_decoded[(VORTEX_AUTH_MAX_HASH_LEN * 4 / 3) + 8];
    int salt_len = b64_decode(salt_b64, strlen(salt_b64),
                              salt_decoded, sizeof(salt_decoded));
    int hash_len = b64_decode(hash_b64, strlen(hash_b64),
                              hash_decoded, sizeof(hash_decoded));
    if (salt_len <= 0 || salt_len > VORTEX_AUTH_MAX_SALT_LEN)
        return false;
    if (hash_len <= 0 || hash_len > VORTEX_AUTH_MAX_HASH_LEN)
        return false;

    snprintf(out->username, sizeof(out->username), "%s", username);
    out->log_n = log_n;
    out->r = r;
    out->p = p;
    out->salt_len = (uint8_t)salt_len;
    out->hash_len = (uint8_t)hash_len;
    memcpy(out->salt, salt_decoded, (size_t)salt_len);
    memcpy(out->hash, hash_decoded, (size_t)hash_len);
    return true;
#endif
}

bool auth_load_verifiers_file(struct route_auth_config *auth,
                              const char *path,
                              const char *route_hostname)
{
    if (!auth || !path || !path[0])
        return false;

    FILE *f = fopen(path, "r");
    if (!f)
        return false;

    char line[512];
    unsigned int lineno = 0;
    while (fgets(line, sizeof(line), f)) {
        lineno++;
        char *p = line;
        while (*p == ' ' || *p == '\t')
            p++;
        if (*p == '#' || *p == '\n' || *p == '\r' || *p == '\0')
            continue;

        char *end = p + strlen(p);
        while (end > p && (end[-1] == '\n' || end[-1] == '\r' ||
                           end[-1] == ' ' || end[-1] == '\t')) {
            *--end = '\0';
        }
        if (*p == '\0')
            continue;
        if (auth->credential_count >= VORTEX_MAX_AUTH_USERS) {
            fclose(f);
            return false;
        }
        if (!auth_parse_verifier(&auth->verifiers[auth->credential_count], p)) {
            fclose(f);
            return false;
        }
        auth->credential_count++;
    }

    if (ferror(f)) {
        fclose(f);
        return false;
    }

    fclose(f);
    (void)route_hostname;
    return true;
}

bool auth_check_basic_value(const struct route_auth_config *auth,
                            const char *value, size_t value_len)
{
    if (!auth || !auth->enabled) return true; /* auth not configured */
    if (auth->credential_count == 0) return false;

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

    char *sep = strchr(decoded, ':');
    if (!sep || sep == decoded)
        return false;
    *sep = '\0';
    const char *username = decoded;
    const char *password = sep + 1;

#ifndef VORTEX_PHASE_TLS
    (void)username;
    (void)password;
    return false;
#else
    const struct auth_verifier *selected = NULL;
    const struct auth_verifier *fallback = &auth->verifiers[0];
    struct auth_verifier dummy;

    for (int i = 0; i < auth->credential_count; i++) {
        const struct auth_verifier *verifier = &auth->verifiers[i];
        if (auth_username_match_ct(username, verifier->username))
            selected = verifier;
    }

    if (!selected) {
        auth_make_dummy_verifier(&dummy, fallback);
        selected = &dummy;
    }
    return auth_verify_password(selected, password);
#endif
}

bool auth_check_request(const struct route_auth_config *auth,
                        const uint8_t *req, int req_len)
{
    if (!auth || !auth->enabled) return true; /* auth not configured */
    if (auth->credential_count == 0) return false;

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
