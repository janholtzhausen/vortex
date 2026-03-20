#pragma once

#include <time.h>
#include <stdlib.h>
#include "../src/config.h"

/* Heap-allocated cert+key PEM returned by providers */
struct cert_result {
    char    *cert_pem;   /* full chain PEM, null-terminated */
    char    *key_pem;    /* private key PEM, null-terminated */
    time_t   not_after;  /* cert expiry — used to schedule renewal */
};

/* Provider vtable — statically linked */
struct cert_provider_ops {
    const char *name;

    /* One-time init.  *provider_ctx is set on success. */
    int  (*init)(void **provider_ctx, const struct vortex_config *cfg);

    /* Obtain a new certificate for domain.
     * Fills *out; caller must call free_result when done. */
    int  (*obtain)(void *provider_ctx, const char *domain,
                   struct cert_result *out);

    /* Renew an existing certificate (same flow as obtain for most providers). */
    int  (*renew)(void *provider_ctx, const char *domain,
                  struct cert_result *out);

    /* Free heap memory in *result (does NOT free result itself). */
    void (*free_result)(struct cert_result *result);

    /* Destroy provider context and free resources. */
    void (*destroy)(void *provider_ctx);
};

/* Built-in providers */
extern const struct cert_provider_ops static_file_provider;
extern const struct cert_provider_ops acme_http01_provider;

/* Convenience: free cert_result contents (calls the provider's free_result
 * or falls back to free() if provider is NULL). */
static inline void cert_result_free(struct cert_result *r)
{
    if (!r) return;
    free(r->cert_pem);
    free(r->key_pem);
    r->cert_pem = r->key_pem = NULL;
}
