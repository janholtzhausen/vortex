/*
 * dns_cloudflare.c — Cloudflare DNS API v4 provider for ACME DNS-01 challenge.
 *
 * Migrated from OpenSSL BIO to TCP socket + picotls TLS client handshake.
 * Implements the dns_provider_ops vtable.
 */

#include "dns_cloudflare.h"
#include "tls.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>

#ifdef VORTEX_PHASE_TLS

#include <picotls.h>

#define CF_API_HOST "api.cloudflare.com"
#define CF_API_PORT 443

struct cf_ctx {
    char              api_token[512];
    ptls_context_t   *tls_ctx;
};

/* ══════════════════════════════════════════════════════
 *  Minimal HTTPS helper (TCP + picotls)
 * ══════════════════════════════════════════════════════ */

/*
 * Perform a single HTTPS request to api.cloudflare.com.
 *
 * method      — "GET", "POST", "DELETE"
 * url         — full URL, e.g. "https://api.cloudflare.com/client/v4/zones?name=x"
 * auth_token  — Cloudflare Bearer token
 * body        — request body (may be NULL)
 * body_len    — length of body
 * out_body    — on success, heap-allocated NUL-terminated response body (caller frees)
 * out_status  — HTTP status code
 *
 * Returns 0 on success, -1 on error.
 */
static int cf_https_request(struct cf_ctx *ctx,
                             const char *method,
                             const char *url,
                             const char *auth_token,
                             const char *body, size_t body_len,
                             char **out_body, int *out_status)
{
    if (strncmp(url, "https://", 8) != 0) {
        log_error("cf_dns", "non-https URL: %s", url);
        return -1;
    }
    const char *host_start = url + 8;
    const char *slash = strchr(host_start, '/');
    char host[256];
    char path[1024];

    if (slash) {
        size_t hlen = (size_t)(slash - host_start);
        if (hlen >= sizeof(host)) return -1;
        memcpy(host, host_start, hlen);
        host[hlen] = '\0';
        strncpy(path, slash, sizeof(path) - 1);
        path[sizeof(path) - 1] = '\0';
    } else {
        strncpy(host, host_start, sizeof(host) - 1);
        host[sizeof(host) - 1] = '\0';
        strncpy(path, "/", sizeof(path) - 1);
    }

    /* TCP connect */
    struct addrinfo hints, *res0;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char portstr[8];
    snprintf(portstr, sizeof(portstr), "%d", CF_API_PORT);
    if (getaddrinfo(host, portstr, &hints, &res0) != 0) {
        log_error("cf_dns", "getaddrinfo(%s) failed", host);
        return -1;
    }

    int fd = -1;
    for (struct addrinfo *res = res0; res; res = res->ai_next) {
        fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, res->ai_addr, res->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res0);
    if (fd < 0) {
        log_error("cf_dns", "connect to %s:%d failed", host, CF_API_PORT);
        return -1;
    }

    /* TLS handshake */
    ptls_t *ptls = tls_backend_connect(ctx->tls_ctx, fd, host, 10000, NULL, NULL);
    if (!ptls) {
        log_error("cf_dns", "TLS handshake to %s failed", host);
        close(fd);
        return -1;
    }

    /* Build request headers */
    char req_hdr[4096];
    int hdr_len;
    if (body && body_len > 0) {
        hdr_len = snprintf(req_hdr, sizeof(req_hdr),
            "%s %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Authorization: Bearer %s\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: %zu\r\n"
            "Connection: close\r\n"
            "User-Agent: vortex/0.1\r\n"
            "\r\n",
            method, path, host, auth_token, body_len);
    } else {
        hdr_len = snprintf(req_hdr, sizeof(req_hdr),
            "%s %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Authorization: Bearer %s\r\n"
            "Connection: close\r\n"
            "User-Agent: vortex/0.1\r\n"
            "\r\n",
            method, path, host, auth_token);
    }

    /* Send request via picotls */
    {
        uint8_t wbuf_small[4096];
        ptls_buffer_t wbuf;
        ptls_buffer_init(&wbuf, wbuf_small, sizeof(wbuf_small));
        ptls_send(ptls, &wbuf, req_hdr, (size_t)hdr_len);
        if (body && body_len > 0)
            ptls_send(ptls, &wbuf, body, body_len);
        size_t wlen = wbuf.off;
        ssize_t written = write(fd, wbuf.base, wlen);
        ptls_buffer_dispose(&wbuf);
        if (written < 0 || (size_t)written != wlen) {
            log_error("cf_dns", "write to %s failed", host);
            ptls_free(ptls);
            close(fd);
            return -1;
        }
    }

    /* Read full response */
    size_t total = 0, cap = 65536;
    char *rbuf = malloc(cap);
    if (!rbuf) { ptls_free(ptls); close(fd); return -1; }

    for (;;) {
        if (total + 1 >= cap) {
            cap *= 2;
            char *tmp = realloc(rbuf, cap);
            if (!tmp) { free(rbuf); ptls_free(ptls); close(fd); return -1; }
            rbuf = tmp;
        }
        uint8_t ibuf[8192];
        ssize_t nr = recv(fd, ibuf, sizeof(ibuf), 0);
        if (nr < 0 && errno == EINTR) continue;
        if (nr <= 0) break;
        ptls_buffer_t plainbuf;
        uint8_t plainbuf_small[8192];
        ptls_buffer_init(&plainbuf, plainbuf_small, sizeof(plainbuf_small));
        size_t consumed = (size_t)nr;
        int ret = ptls_receive(ptls, &plainbuf, ibuf, &consumed);
        if (ret != 0 && ret != PTLS_ERROR_IN_PROGRESS) {
            ptls_buffer_dispose(&plainbuf);
            break;
        }
        if (plainbuf.off > 0) {
            if (total + plainbuf.off + 1 >= cap) {
                cap = total + plainbuf.off + 65536;
                char *tmp = realloc(rbuf, cap);
                if (!tmp) {
                    ptls_buffer_dispose(&plainbuf);
                    free(rbuf); ptls_free(ptls); close(fd);
                    return -1;
                }
                rbuf = tmp;
            }
            memcpy(rbuf + total, plainbuf.base, plainbuf.off);
            total += plainbuf.off;
        }
        ptls_buffer_dispose(&plainbuf);
    }
    rbuf[total] = '\0';
    ptls_free(ptls);
    close(fd);

    if (total == 0) {
        free(rbuf);
        log_error("cf_dns", "empty response from %s", url);
        return -1;
    }

    /* Parse status line */
    *out_status = 0;
    if (sscanf(rbuf, "HTTP/%*d.%*d %d", out_status) != 1) {
        free(rbuf);
        log_error("cf_dns", "bad HTTP status line");
        return -1;
    }

    /* Find body after \r\n\r\n */
    char *body_start = strstr(rbuf, "\r\n\r\n");
    if (body_start) {
        body_start += 4;
    } else {
        body_start = rbuf + total;
    }
    size_t body_sz = (size_t)(rbuf + total - body_start);

    char *copy = malloc(body_sz + 1);
    if (!copy) { free(rbuf); return -1; }
    memcpy(copy, body_start, body_sz);
    copy[body_sz] = '\0';
    *out_body = copy;

    free(rbuf);
    return 0;
}

/* ══════════════════════════════════════════════════════
 *  JSON helpers (minimal, for Cloudflare API responses)
 * ══════════════════════════════════════════════════════ */

static int cf_json_get_str(const char *json, const char *key,
                            char *out, size_t out_max)
{
    char needle[256];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle);
    if (!p) return -1;
    p += strlen(needle);
    while (*p == ' ' || *p == ':') p++;
    if (*p != '"') return -1;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < out_max) {
        if (*p == '\\') { p++; if (!*p) break; }
        out[i++] = *p++;
    }
    out[i] = '\0';
    return 0;
}

/* ══════════════════════════════════════════════════════
 *  Domain parsing helpers
 * ══════════════════════════════════════════════════════ */

static int get_root_domain(const char *name, char *out, size_t out_max)
{
    const char *p = name;
    if (strncmp(p, "_acme-challenge.", 16) == 0)
        p += 16;

    const char *last_dot = strrchr(p, '.');
    if (!last_dot) {
        strncpy(out, p, out_max - 1);
        out[out_max - 1] = '\0';
        return 0;
    }

    const char *prev_dot = NULL;
    for (const char *q = p; q < last_dot; q++) {
        if (*q == '.') prev_dot = q;
    }

    const char *root_start = prev_dot ? prev_dot + 1 : p;
    size_t rlen = strlen(root_start);
    if (rlen >= out_max) return -1;
    strncpy(out, root_start, out_max - 1);
    out[out_max - 1] = '\0';
    return 0;
}

/* ══════════════════════════════════════════════════════
 *  Provider vtable implementation
 * ══════════════════════════════════════════════════════ */

static int cf_init(void **ctx_out, const char *api_token)
{
    struct cf_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return -1;

    strncpy(ctx->api_token, api_token ? api_token : "",
            sizeof(ctx->api_token) - 1);

    ctx->tls_ctx = tls_create_client_ctx(true);
    if (!ctx->tls_ctx) {
        log_error("cf_dns", "tls_create_client_ctx failed");
        free(ctx);
        return -1;
    }

    *ctx_out = ctx;
    return 0;
}

static int cf_create_txt(void *ctx_ptr, const char *name, const char *value,
                          char *record_id_out, size_t rid_max)
{
    struct cf_ctx *ctx = (struct cf_ctx *)ctx_ptr;

    char domain_root[256];
    if (get_root_domain(name, domain_root, sizeof(domain_root)) < 0) {
        log_error("cf_dns", "failed to parse domain root from %s", name);
        return -1;
    }

    char zone_url[512];
    snprintf(zone_url, sizeof(zone_url),
        "https://api.cloudflare.com/client/v4/zones?name=%s", domain_root);

    char *resp = NULL;
    int status = 0;
    if (cf_https_request(ctx, "GET", zone_url, ctx->api_token,
                         NULL, 0, &resp, &status) < 0) {
        log_error("cf_dns", "zone lookup request failed for %s", domain_root);
        return -1;
    }
    if (status != 200) {
        log_error("cf_dns", "zone lookup returned %d for %s: %s",
                  status, domain_root, resp ? resp : "");
        free(resp);
        return -1;
    }

    char zone_id[128] = "";
    const char *result_arr = strstr(resp ? resp : "", "\"result\"");
    if (result_arr)
        cf_json_get_str(result_arr, "id", zone_id, sizeof(zone_id));
    free(resp); resp = NULL;

    if (zone_id[0] == '\0') {
        log_error("cf_dns", "no zone found for domain %s", domain_root);
        return -1;
    }
    log_info("cf_dns", "zone_id for %s: %s", domain_root, zone_id);

    /* Create the TXT record */
    char create_url[512];
    snprintf(create_url, sizeof(create_url),
        "https://api.cloudflare.com/client/v4/zones/%s/dns_records", zone_id);

    char body[1024];
    snprintf(body, sizeof(body),
        "{\"type\":\"TXT\",\"name\":\"%s\",\"content\":\"%s\",\"ttl\":60}",
        name, value);

    if (cf_https_request(ctx, "POST", create_url, ctx->api_token,
                         body, strlen(body), &resp, &status) < 0) {
        log_error("cf_dns", "create TXT record request failed");
        return -1;
    }
    if (status != 200 && status != 201) {
        log_error("cf_dns", "create TXT record returned %d: %s",
                  status, resp ? resp : "");
        free(resp);
        return -1;
    }

    char record_id[128] = "";
    const char *res_obj = strstr(resp ? resp : "", "\"result\"");
    if (res_obj)
        cf_json_get_str(res_obj, "id", record_id, sizeof(record_id));
    free(resp); resp = NULL;

    if (record_id[0] == '\0') {
        log_error("cf_dns", "no record id in create TXT response");
        return -1;
    }

    int n = snprintf(record_id_out, rid_max, "%s:%s", zone_id, record_id);
    if (n <= 0 || (size_t)n >= rid_max) {
        log_error("cf_dns", "record_id_out buffer too small");
        return -1;
    }

    log_info("cf_dns", "created TXT record %s (zone=%s record=%s)",
             name, zone_id, record_id);
    return 0;
}

static int cf_delete_txt(void *ctx_ptr, const char *zone_id_param,
                          const char *record_id_packed)
{
    struct cf_ctx *ctx = (struct cf_ctx *)ctx_ptr;

    char zone_id[128] = "";
    char record_id[128] = "";

    const char *colon = strchr(record_id_packed, ':');
    if (colon) {
        size_t zlen = (size_t)(colon - record_id_packed);
        if (zlen >= sizeof(zone_id)) return -1;
        memcpy(zone_id, record_id_packed, zlen);
        zone_id[zlen] = '\0';
        strncpy(record_id, colon + 1, sizeof(record_id) - 1);
    } else {
        strncpy(zone_id, zone_id_param ? zone_id_param : "",
                sizeof(zone_id) - 1);
        strncpy(record_id, record_id_packed, sizeof(record_id) - 1);
    }

    if (zone_id[0] == '\0' || record_id[0] == '\0') {
        log_error("cf_dns", "delete_txt: empty zone_id or record_id");
        return -1;
    }

    char del_url[512];
    snprintf(del_url, sizeof(del_url),
        "https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s",
        zone_id, record_id);

    char *resp = NULL;
    int status = 0;
    if (cf_https_request(ctx, "DELETE", del_url, ctx->api_token,
                         NULL, 0, &resp, &status) < 0) {
        log_error("cf_dns", "delete TXT record request failed");
        return -1;
    }
    free(resp);

    if (status != 200) {
        log_error("cf_dns", "delete TXT record returned %d", status);
        return -1;
    }

    log_info("cf_dns", "deleted TXT record %s from zone %s", record_id, zone_id);
    return 0;
}

static void cf_destroy(void *ctx_ptr)
{
    struct cf_ctx *ctx = (struct cf_ctx *)ctx_ptr;
    if (!ctx) return;
    if (ctx->tls_ctx) tls_context_free(ctx->tls_ctx);
    free(ctx);
}

const struct dns_provider_ops cloudflare_dns_provider = {
    .name       = "cloudflare",
    .init       = cf_init,
    .create_txt = cf_create_txt,
    .delete_txt = cf_delete_txt,
    .destroy    = cf_destroy,
};

#else /* !VORTEX_PHASE_TLS */

static int cf_init_stub(void **ctx, const char *api_token)
{ (void)ctx; (void)api_token; return -1; }

static int cf_create_txt_stub(void *ctx, const char *name, const char *value,
                               char *rid, size_t rmax)
{ (void)ctx; (void)name; (void)value; (void)rid; (void)rmax; return -1; }

static int cf_delete_txt_stub(void *ctx, const char *zone_id,
                               const char *record_id)
{ (void)ctx; (void)zone_id; (void)record_id; return -1; }

static void cf_destroy_stub(void *ctx) { (void)ctx; }

const struct dns_provider_ops cloudflare_dns_provider = {
    .name       = "cloudflare",
    .init       = cf_init_stub,
    .create_txt = cf_create_txt_stub,
    .delete_txt = cf_delete_txt_stub,
    .destroy    = cf_destroy_stub,
};

#endif /* VORTEX_PHASE_TLS */
