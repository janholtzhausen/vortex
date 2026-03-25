#include "auth.h"
#include <stdbool.h>
#include <stddef.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef VORTEX_PHASE_TLS
#include <openssl/crypto.h>
#include <openssl/evp.h>
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

static bool auth_verify_password(const struct auth_verifier *verifier,
                                 const char *password)
{
    uint8_t derived[VORTEX_AUTH_MAX_HASH_LEN];
    uint64_t maxmem = 64ULL * 1024ULL * 1024ULL;
    if (verifier->hash_len == 0 || verifier->hash_len > sizeof(derived))
        return false;
    if (EVP_PBE_scrypt(password, strlen(password),
                       verifier->salt, verifier->salt_len,
                       1ULL << verifier->log_n, verifier->r, verifier->p,
                       maxmem, derived, verifier->hash_len) != 1) {
        return false;
    }
    return CRYPTO_memcmp(derived, verifier->hash, verifier->hash_len) == 0;
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
    for (int i = 0; i < auth->credential_count; i++) {
        const struct auth_verifier *verifier = &auth->verifiers[i];
        if (strcmp(username, verifier->username) != 0)
            continue;
        if (auth_verify_password(verifier, password))
            return true;
    }
    return false;
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
