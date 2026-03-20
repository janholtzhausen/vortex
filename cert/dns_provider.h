#pragma once
#include <stddef.h>

/*
 * DNS provider vtable — pluggable API for managing TXT records.
 * Used by DNS-01 ACME challenge to create/delete _acme-challenge records.
 */

struct dns_provider_ops {
    const char *name;

    /* One-time init.  api_token and zone_id may be used or ignored per provider. */
    int  (*init)(void **ctx, const char *api_token);

    /* Create a TXT record.
     *   name:    full DNS name, e.g. "_acme-challenge.example.com"
     *   value:   TXT record content (the base64url SHA-256 key-auth digest)
     *   record_id_out: provider-specific ID for deletion; must be < rid_max bytes.
     * Returns 0 on success, -1 on failure. */
    int  (*create_txt)(void *ctx, const char *name, const char *value,
                       char *record_id_out, size_t rid_max);

    /* Delete a previously created TXT record by its provider ID. */
    int  (*delete_txt)(void *ctx, const char *zone_id, const char *record_id);

    /* Destroy context. */
    void (*destroy)(void *ctx);
};

/* Built-in providers */
extern const struct dns_provider_ops cloudflare_dns_provider;
