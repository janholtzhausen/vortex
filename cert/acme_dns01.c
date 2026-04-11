/*
 * acme_dns01.c — ACME DNS-01 challenge provider.
 *
 * Migrated from OpenSSL to picotls minicrypto + micro-ecc:
 *   - HTTPS: reuses https_request() from acme_client.c (TCP + picotls)
 *   - JWS:   reuses make_jws() from acme_client.c
 *   - CSR:   reuses make_csr_der() from acme_client.c
 *   - SHA-256: ptls_minicrypto_sha256
 *
 * Protocol flow:
 *   1. newOrder
 *   2. getAuthz
 *   3. Find dns-01 challenge, compute txt_value = base64url(SHA-256(key_auth))
 *   4. Create TXT record via dns_ops
 *   5. Wait propagation_wait_s for DNS propagation
 *   6. Respond to ACME challenge
 *   7. Poll authz until "valid" (max 120s)
 *   8. Delete TXT record
 *   9. Generate CSR, finalize order, download cert
 *  10. Save cert.pem and key.pem to storage_path/domain/
 */

#include "acme_dns01.h"
#include "acme_internal.h"
#include "dns_cloudflare.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>

#ifdef VORTEX_PHASE_TLS

#include <picotls.h>
#include <picotls/minicrypto.h>
#include <uECC.h>

/* ══════════════════════════════════════════════════════
 *  Local JSON helpers
 * ══════════════════════════════════════════════════════ */

static int dns01_json_get_str(const char *json, const char *key,
                               char *out, size_t out_max)
{
    char needle[256];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle);
    if (!p) return -1;
    p += strlen(needle);
    while (*p == ' ' || *p == ':' || *p == '\t' || *p == '\r' || *p == '\n') p++;
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

static int dns01_json_get_array_first(const char *json, const char *key,
                                       char *out, size_t out_max)
{
    char needle[256];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle);
    if (!p) return -1;
    p += strlen(needle);
    while (*p == ' ' || *p == ':' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p != '[') return -1;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p != '"') return -1;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < out_max) out[i++] = *p++;
    out[i] = '\0';
    return 0;
}

/*
 * Find JSON object in challenges array with "type": "dns-01" and extract
 * "token" and "url".
 */
static int dns01_find_dns01_challenge(const char *json,
                                       char *token, size_t token_max,
                                       char *url,   size_t url_max)
{
    const char *p = json;
    while ((p = strstr(p, "\"type\"")) != NULL) {
        const char *tp = p + 6;
        while (*tp == ' ' || *tp == ':' || *tp == '"') tp++;
        if (strncmp(tp, "dns-01", 6) == 0) {
            /* Backtrack to find the enclosing { */
            const char *bp = p;
            int depth = 0;
            while (bp > json && !(depth == 0 && *bp == '{')) {
                if (*bp == '}') depth++;
                if (*bp == '{') depth--;
                bp--;
            }
            /* Walk forward to find matching } */
            const char *ep = p;
            depth = 0;
            while (*ep) {
                if (*ep == '{') depth++;
                if (*ep == '}') { if (--depth <= 0) break; }
                ep++;
            }
            size_t obj_len = (size_t)(ep - bp) + 1;
            char *obj = malloc(obj_len + 1);
            if (!obj) return -1;
            memcpy(obj, bp, obj_len);
            obj[obj_len] = '\0';
            int r1 = dns01_json_get_str(obj, "token", token, token_max);
            int r2 = dns01_json_get_str(obj, "url",   url,   url_max);
            free(obj);
            if (r1 == 0 && r2 == 0) return 0;
        }
        p++;
    }
    return -1;
}

/* ══════════════════════════════════════════════════════
 *  Nonce / request wrappers
 * ══════════════════════════════════════════════════════ */

static int dns01_get_nonce(struct acme_client *cl,
                            char *nonce, size_t nmax)
{
    int status;
    char loc[8] = "";
    if (https_request(cl, "HEAD", cl->newNonce_url,
                      NULL, NULL, 0,
                      &status, loc, sizeof(loc),
                      nonce, nmax,
                      NULL, NULL) < 0) return -1;
    if (nonce[0] == '\0') {
        log_error("acme_dns01", "no nonce in HEAD response");
        return -1;
    }
    return 0;
}

/* Convenience wrapper: POST with JWS body, capture nonce from response. */
static int dns01_post(struct acme_client *cl,
                      const char *url,
                      const char *payload_json,  /* NULL for POST-as-GET */
                      char *nonce,               /* in: current nonce; out: fresh nonce */
                      size_t nonce_max,
                      char *loc_out, size_t loc_max,
                      int *status_out,
                      char **body_out)
{
    char *jws = make_jws(cl->account_key_priv, cl->account_key_pub,
                         nonce, url,
                         payload_json, cl->account_url,
                         cl->jwk_thumbprint);
    if (!jws) return -1;

    int r = https_request(cl, "POST", url,
                          "application/jose+json",
                          jws, strlen(jws),
                          status_out,
                          loc_out, loc_max,
                          nonce, nonce_max,
                          body_out, NULL);
    free(jws);
    return r;
}

/* ══════════════════════════════════════════════════════
 *  Poll order/authz for a specific status
 * ══════════════════════════════════════════════════════ */

static int dns01_poll_for_status(struct acme_client *cl,
                                  const char *url,
                                  const char *want_status,
                                  int timeout_s)
{
    time_t deadline = time(NULL) + timeout_s;
    for (;;) {
        char nonce[256], loc[8] = "";
        char *body = NULL;
        int status;

        if (dns01_get_nonce(cl, nonce, sizeof(nonce)) < 0) return -1;

        if (dns01_post(cl, url, NULL /* POST-as-GET */,
                       nonce, sizeof(nonce),
                       loc, sizeof(loc),
                       &status, &body) < 0) {
            free(body);
            return -1;
        }

        char obj_status[64] = "";
        dns01_json_get_str(body ? body : "", "status",
                           obj_status, sizeof(obj_status));
        free(body);

        log_debug("acme_dns01", "poll %s → status=%s (want %s)",
                  url, obj_status, want_status);

        if (strcmp(obj_status, want_status) == 0) return 0;
        if (strcmp(obj_status, "invalid")   == 0) {
            log_error("acme_dns01", "order/authz went invalid at %s", url);
            return -1;
        }

        if (time(NULL) >= deadline) {
            log_error("acme_dns01", "timeout polling %s (last status=%s)",
                      url, obj_status);
            return -1;
        }
        sleep(3);
    }
}

/* ══════════════════════════════════════════════════════
 *  Storage helpers
 * ══════════════════════════════════════════════════════ */

static int dns01_ensure_dir(const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0) return S_ISDIR(st.st_mode) ? 0 : -1;
    return mkdir(path, 0700);
}

/* ══════════════════════════════════════════════════════
 *  Main: obtain certificate via DNS-01
 * ══════════════════════════════════════════════════════ */

int acme_obtain_dns01(struct acme_dns01_ctx *dctx,
                       const char *domain,
                       struct cert_result *out)
{
    struct acme_client *cl = &dctx->client;
    char nonce[256], loc[ACME_MAX_URL] = "";
    char *resp = NULL;
    int status;
    int rc = -1;

    /* Track the TXT record for cleanup */
    char txt_record_id[512] = "";
    char txt_name[320]      = "";
    int  txt_created        = 0;

    /* Domain key (raw 32-byte P-256 private key) — cleared on done */
    uint8_t domain_key_priv[32];
    memset(domain_key_priv, 0, sizeof(domain_key_priv));

    /* ── 1. new-order ── */
    if (dns01_get_nonce(cl, nonce, sizeof(nonce)) < 0) goto done;
    {
        char pay[512];
        snprintf(pay, sizeof(pay),
            "{\"identifiers\":[{\"type\":\"dns\",\"value\":\"%s\"}]}", domain);
        if (dns01_post(cl, cl->newOrder_url, pay,
                       nonce, sizeof(nonce),
                       loc, sizeof(loc),
                       &status, &resp) < 0
            || (status != 201 && status != 200)) {
            log_error("acme_dns01", "newOrder returned %d: %s",
                      status, resp ? resp : "");
            goto done;
        }
    }

    char order_url[ACME_MAX_URL];
    strncpy(order_url, loc, sizeof(order_url) - 1);
    order_url[sizeof(order_url) - 1] = '\0';

    char finalize_url[ACME_MAX_URL] = "";
    char authz_url[ACME_MAX_URL]    = "";
    dns01_json_get_str(resp, "finalize", finalize_url, sizeof(finalize_url));
    dns01_json_get_array_first(resp, "authorizations", authz_url, sizeof(authz_url));
    free(resp); resp = NULL;

    if (!finalize_url[0] || !authz_url[0]) {
        log_error("acme_dns01", "order missing finalize or authorizations");
        goto done;
    }

    /* ── 2. Get authorization ── */
    if (dns01_get_nonce(cl, nonce, sizeof(nonce)) < 0) goto done;
    {
        char loc2[8] = "";
        if (dns01_post(cl, authz_url, NULL /* POST-as-GET */,
                       nonce, sizeof(nonce),
                       loc2, sizeof(loc2),
                       &status, &resp) < 0
            || status != 200) {
            log_error("acme_dns01", "get authz returned %d", status);
            goto done;
        }
    }

    char challenge_token[256]        = "";
    char challenge_url[ACME_MAX_URL] = "";
    if (dns01_find_dns01_challenge(resp ? resp : "",
                                   challenge_token, sizeof(challenge_token),
                                   challenge_url,   sizeof(challenge_url)) < 0) {
        log_error("acme_dns01", "no dns-01 challenge in authorization");
        goto done;
    }
    free(resp); resp = NULL;

    /* ── 3. Compute key_auth and TXT value ── */
    char key_auth[512];
    {
        int n = snprintf(key_auth, sizeof(key_auth), "%s.%s",
                         challenge_token, cl->jwk_thumbprint);
        if (n <= 0 || (size_t)n >= sizeof(key_auth)) {
            log_error("acme_dns01", "key_auth buffer overflow");
            goto done;
        }
    }

    /* txt_value = base64url(SHA-256(key_auth)) */
    char txt_value[64] = "";
    {
        ptls_hash_context_t *hctx = ptls_minicrypto_sha256.create();
        if (!hctx) goto done;
        uint8_t digest[PTLS_SHA256_DIGEST_SIZE];
        hctx->update(hctx, key_auth, strlen(key_auth));
        hctx->final(hctx, digest, PTLS_HASH_FINAL_MODE_FREE);
        if (b64url_encode(digest, 32, txt_value, sizeof(txt_value)) < 0) {
            log_error("acme_dns01", "base64url of digest failed");
            goto done;
        }
    }

    /* ── 4. Create TXT record ── */
    snprintf(txt_name, sizeof(txt_name), "_acme-challenge.%s", domain);

    if (dctx->dns_ops->create_txt(dctx->dns_ctx,
                                   txt_name, txt_value,
                                   txt_record_id, sizeof(txt_record_id)) < 0) {
        log_error("acme_dns01", "failed to create TXT record for %s", txt_name);
        goto done;
    }
    txt_created = 1;
    log_info("acme_dns01", "TXT record created: %s = %s", txt_name, txt_value);

    /* ── 5. Wait for DNS propagation ── */
    {
        int wait_s = dctx->propagation_wait_s > 0
                   ? dctx->propagation_wait_s : 90;
        log_info("acme_dns01", "waiting %ds for DNS propagation...", wait_s);
        sleep((unsigned int)wait_s);
    }

    /* ── 6. Respond to challenge ── */
    if (dns01_get_nonce(cl, nonce, sizeof(nonce)) < 0) goto done;
    {
        char loc2[8] = "";
        if (dns01_post(cl, challenge_url, "{}",
                       nonce, sizeof(nonce),
                       loc2, sizeof(loc2),
                       &status, &resp) < 0
            || (status != 200 && status != 202)) {
            log_error("acme_dns01", "respond to challenge returned %d: %s",
                      status, resp ? resp : "");
            goto done;
        }
        free(resp); resp = NULL;
    }
    log_info("acme_dns01", "notified ACME of DNS-01 challenge response");

    /* ── 7. Poll authz until valid (max 120s) ── */
    if (dns01_poll_for_status(cl, authz_url, "valid", 120) < 0) {
        log_error("acme_dns01", "authz did not become valid");
        goto done;
    }
    log_info("acme_dns01", "authz is valid");

    /* ── 8. Delete TXT record ── */
    if (txt_created) {
        dctx->dns_ops->delete_txt(dctx->dns_ctx,
                                   dctx->zone_id[0] ? dctx->zone_id : "",
                                   txt_record_id);
        txt_created = 0;
        log_info("acme_dns01", "TXT record deleted");
    }

    /* ── 9. Generate CSR ── */
    uint8_t *csr_der = NULL;
    size_t csr_len = 0;
    if (make_csr_der(domain, domain_key_priv, &csr_der, &csr_len) < 0) {
        log_error("acme_dns01", "CSR generation failed");
        goto done;
    }

    /* ── 10. Finalize order ── */
    {
        char csr_b64[4096];
        if (b64url_encode(csr_der, csr_len, csr_b64, sizeof(csr_b64)) < 0) {
            free(csr_der);
            log_error("acme_dns01", "base64url encode of CSR failed");
            goto done;
        }
        free(csr_der); csr_der = NULL;

        char pay[5000];
        snprintf(pay, sizeof(pay), "{\"csr\":\"%s\"}", csr_b64);

        if (dns01_get_nonce(cl, nonce, sizeof(nonce)) < 0) goto done;

        char loc2[8] = "";
        if (dns01_post(cl, finalize_url, pay,
                       nonce, sizeof(nonce),
                       loc2, sizeof(loc2),
                       &status, &resp) < 0
            || (status != 200 && status != 201)) {
            log_error("acme_dns01", "finalize returned %d: %s",
                      status, resp ? resp : "");
            goto done;
        }
        free(resp); resp = NULL;
    }

    /* ── 11. Poll order until valid ── */
    if (order_url[0]) {
        if (dns01_poll_for_status(cl, order_url, "valid", 120) < 0) {
            log_error("acme_dns01", "order did not become valid");
            goto done;
        }
    }

    /* ── 12. Re-fetch order to get certificate URL ── */
    {
        if (dns01_get_nonce(cl, nonce, sizeof(nonce)) < 0) goto done;
        char loc2[8] = "";
        if (dns01_post(cl, order_url, NULL /* POST-as-GET */,
                       nonce, sizeof(nonce),
                       loc2, sizeof(loc2),
                       &status, &resp) < 0
            || status != 200) {
            log_error("acme_dns01", "order fetch returned %d", status);
            goto done;
        }
    }

    char cert_url[ACME_MAX_URL] = "";
    dns01_json_get_str(resp ? resp : "", "certificate",
                       cert_url, sizeof(cert_url));
    free(resp); resp = NULL;

    if (!cert_url[0]) {
        log_error("acme_dns01", "no certificate URL in finalized order");
        goto done;
    }

    /* ── 13. Download certificate ── */
    if (dns01_get_nonce(cl, nonce, sizeof(nonce)) < 0) goto done;
    {
        char loc2[8] = "";
        if (dns01_post(cl, cert_url, NULL /* POST-as-GET */,
                       nonce, sizeof(nonce),
                       loc2, sizeof(loc2),
                       &status, &resp) < 0
            || status != 200) {
            log_error("acme_dns01", "cert download returned %d", status);
            goto done;
        }
    }

    /* resp contains the PEM certificate chain */

    /* Encode domain private key as PKCS#8 PEM */
    char key_pem_buf[256];
    if (pkcs8_pem_from_priv(domain_key_priv, key_pem_buf, sizeof(key_pem_buf)) < 0) {
        free(resp);
        log_error("acme_dns01", "failed to encode domain key as PEM");
        goto done;
    }
    char *key_pem = strdup(key_pem_buf);
    if (!key_pem) { free(resp); goto done; }

    /* ── 14. Save cert.pem and key.pem to storage_path/domain/ ── */
    {
        char dom_dir[4096];
        snprintf(dom_dir, sizeof(dom_dir), "%s/%s",
                 cl->storage_path, domain);
        dns01_ensure_dir(cl->storage_path);
        dns01_ensure_dir(dom_dir);

        /* cert.pem */
        char cert_path[4096];
        snprintf(cert_path, sizeof(cert_path), "%s/%s/cert.pem",
                 cl->storage_path, domain);
        FILE *cf = fopen(cert_path, "wb");
        if (cf) { fwrite(resp, 1, strlen(resp), cf); fclose(cf); }

        /* key.pem — mode 0600 */
        char key_path[4096];
        snprintf(key_path, sizeof(key_path), "%s/%s/key.pem",
                 cl->storage_path, domain);
        int kfd = open(key_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (kfd >= 0) {
            FILE *kf = fdopen(kfd, "wb");
            if (kf) { fwrite(key_pem, 1, strlen(key_pem), kf); fclose(kf); }
            else close(kfd);
        }
        log_info("acme_dns01", "certificate saved: %s", cert_path);
    }

    /* Fill result */
    out->cert_pem  = resp; resp = NULL;
    out->key_pem   = key_pem;
    out->not_after = 0;
    {
        size_t der_len = 0;
        uint8_t *der = pem_cert_to_der(out->cert_pem, &der_len);
        if (der) {
            out->not_after = der_cert_not_after(der, der_len);
            free(der);
        }
    }
    rc = 0;

done:
    free(resp);
    memset(domain_key_priv, 0, sizeof(domain_key_priv));

    /* Clean up TXT record if something failed after it was created */
    if (txt_created) {
        log_warn("acme_dns01", "cleaning up TXT record after failure");
        dctx->dns_ops->delete_txt(dctx->dns_ctx,
                                   dctx->zone_id[0] ? dctx->zone_id : "",
                                   txt_record_id);
    }

    return rc;
}

/* ══════════════════════════════════════════════════════
 *  cert_provider_ops vtable implementation
 * ══════════════════════════════════════════════════════ */

static int dns01_provider_init(void **provider_ctx,
                                const struct vortex_config *cfg)
{
    struct acme_dns01_ctx *dctx = calloc(1, sizeof(*dctx));
    if (!dctx) return -1;

    /* Configure the embedded acme_client from cfg->acme */
    const struct acme_config *ac = &cfg->acme;
    strncpy(dctx->client.directory_url,    ac->directory_url,
            sizeof(dctx->client.directory_url) - 1);
    strncpy(dctx->client.account_key_path, ac->account_key_path,
            sizeof(dctx->client.account_key_path) - 1);
    strncpy(dctx->client.storage_path,     ac->storage_path,
            sizeof(dctx->client.storage_path) - 1);
    strncpy(dctx->client.email,            ac->email,
            sizeof(dctx->client.email) - 1);
    dctx->client.renewal_days = ac->renewal_days;

    if (acme_client_init(&dctx->client) < 0) {
        log_error("acme_dns01", "acme_client_init failed");
        free(dctx);
        return -1;
    }

    /* Select DNS provider — currently only Cloudflare is built in */
    if (strcmp(ac->dns_provider, "cloudflare") == 0 ||
        ac->dns_provider[0] == '\0')
    {
        dctx->dns_ops = &cloudflare_dns_provider;
    } else {
        log_error("acme_dns01", "unknown dns_provider: %s", ac->dns_provider);
        acme_client_destroy(&dctx->client);
        free(dctx);
        return -1;
    }

    if (dctx->dns_ops->init(&dctx->dns_ctx, ac->dns_api_token) < 0) {
        log_error("acme_dns01", "dns provider init failed");
        acme_client_destroy(&dctx->client);
        free(dctx);
        return -1;
    }

    dctx->propagation_wait_s = 90;

    *provider_ctx = dctx;
    return 0;
}

static int dns01_provider_obtain(void *provider_ctx, const char *domain,
                                  struct cert_result *out)
{
    return acme_obtain_dns01((struct acme_dns01_ctx *)provider_ctx,
                              domain, out);
}

static int dns01_provider_renew(void *provider_ctx, const char *domain,
                                 struct cert_result *out)
{
    return acme_obtain_dns01((struct acme_dns01_ctx *)provider_ctx,
                              domain, out);
}

static void dns01_provider_free_result(struct cert_result *result)
{
    cert_result_free(result);
}

static void dns01_provider_destroy(void *provider_ctx)
{
    struct acme_dns01_ctx *dctx = (struct acme_dns01_ctx *)provider_ctx;
    if (!dctx) return;
    acme_client_destroy(&dctx->client);
    if (dctx->dns_ops && dctx->dns_ctx)
        dctx->dns_ops->destroy(dctx->dns_ctx);
    free(dctx);
}

const struct cert_provider_ops acme_dns01_provider = {
    .name        = "acme_dns01",
    .init        = dns01_provider_init,
    .obtain      = dns01_provider_obtain,
    .renew       = dns01_provider_renew,
    .free_result = dns01_provider_free_result,
    .destroy     = dns01_provider_destroy,
};

#else /* !VORTEX_PHASE_TLS */

int acme_obtain_dns01(struct acme_dns01_ctx *ctx,
                       const char *domain,
                       struct cert_result *out)
{ (void)ctx; (void)domain; (void)out; return -1; }

static int dns01_provider_init_stub(void **ctx,
                                     const struct vortex_config *cfg)
{ (void)ctx; (void)cfg; return -1; }

static int dns01_provider_obtain_stub(void *ctx, const char *domain,
                                       struct cert_result *out)
{ (void)ctx; (void)domain; (void)out; return -1; }

static int dns01_provider_renew_stub(void *ctx, const char *domain,
                                      struct cert_result *out)
{ (void)ctx; (void)domain; (void)out; return -1; }

static void dns01_provider_free_result_stub(struct cert_result *r)
{ (void)r; }

static void dns01_provider_destroy_stub(void *ctx) { (void)ctx; }

const struct cert_provider_ops acme_dns01_provider = {
    .name        = "acme_dns01",
    .init        = dns01_provider_init_stub,
    .obtain      = dns01_provider_obtain_stub,
    .renew       = dns01_provider_renew_stub,
    .free_result = dns01_provider_free_result_stub,
    .destroy     = dns01_provider_destroy_stub,
};

#endif /* VORTEX_PHASE_TLS */
