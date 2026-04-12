#include "static_file.h"
#include "log.h"
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>


/* Per-route paths stashed in provider_ctx */
struct static_ctx {
    char cert_path[4096];
    char key_path[4096];
};

/* ---- helpers ---- */

static char *read_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        log_error("static_file", "cannot open %s: %s", path, strerror(errno));
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    if (sz <= 0 || sz > 2 * 1024 * 1024) {
        log_error("static_file", "file too large or empty: %s", path);
        fclose(f);
        return NULL;
    }
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return NULL;
    }
    buf[sz] = '\0';
    fclose(f);
    return buf;
}

static time_t pem_not_after(const char *cert_pem)
{
    /* Certificate expiry parsing requires an X.509 library.
     * Until picotls-based cert parsing is implemented, return 0
     * (renewal will fall back to time-based rotation). */
    (void)cert_pem;
    return 0;
}

/* ---- provider interface ---- */

static int sf_init(void **ctx_out, const struct vortex_config *cfg)
{
    /* We allocate one ctx per route; but the provider vtable is global.
     * For the static_file provider we stash paths in the context.
     * The caller is expected to call init once per route and store
     * the returned ctx alongside the route.
     *
     * For simplicity the global cfg is not used here; the route-level
     * cert_path/key_path are passed at obtain time via domain == hostname.
     * We store a pointer to the full config so obtain can find them.
     */
    struct static_ctx *sc = calloc(1, sizeof(*sc));
    if (!sc) return -1;

    /* Find the route whose hostname matches (first route with static cert) */
    for (int i = 0; i < cfg->route_count; i++) {
        const struct route_config *r = &cfg->routes[i];
        if (r->cert_provider == CERT_PROVIDER_STATIC &&
            r->cert_path[0] != '\0') {
            strncpy(sc->cert_path, r->cert_path, sizeof(sc->cert_path) - 1);
            strncpy(sc->key_path,  r->key_path,  sizeof(sc->key_path)  - 1);
            break;
        }
    }

    *ctx_out = sc;
    return 0;
}

static int sf_obtain(void *ctx, const char *domain, struct cert_result *out)
{
    (void)domain;  /* path is in ctx */
    struct static_ctx *sc = ctx;

    if (!sc->cert_path[0]) {
        log_error("static_file", "no cert_path configured");
        return -1;
    }

    out->cert_pem = read_file(sc->cert_path);
    if (!out->cert_pem) return -1;

    out->key_pem = read_file(sc->key_path);
    if (!out->key_pem) {
        free(out->cert_pem);
        out->cert_pem = NULL;
        return -1;
    }

    out->not_after = pem_not_after(out->cert_pem);
    log_info("static_file", "loaded cert=%s not_after=%ld",
        sc->cert_path, (long)out->not_after);
    return 0;
}

static int sf_obtain_for_path(const char *cert_path, const char *key_path,
                               struct cert_result *out)
{
    out->cert_pem = read_file(cert_path);
    if (!out->cert_pem) return -1;

    out->key_pem = read_file(key_path);
    if (!out->key_pem) {
        free(out->cert_pem);
        out->cert_pem = NULL;
        return -1;
    }

    out->not_after = pem_not_after(out->cert_pem);
    return 0;
}

/* Public helper for direct use without the provider vtable */
int static_file_load(const char *cert_path, const char *key_path,
                     struct cert_result *out)
{
    return sf_obtain_for_path(cert_path, key_path, out);
}

static int sf_renew(void *ctx, const char *domain, struct cert_result *out)
{
    /* Re-read the files — caller replaces them externally */
    return sf_obtain(ctx, domain, out);
}

static void sf_free_result(struct cert_result *r)
{
    cert_result_free(r);
}

static void sf_destroy(void *ctx)
{
    free(ctx);
}

const struct cert_provider_ops static_file_provider = {
    .name        = "static_file",
    .init        = sf_init,
    .obtain      = sf_obtain,
    .renew       = sf_renew,
    .free_result = sf_free_result,
    .destroy     = sf_destroy,
};
