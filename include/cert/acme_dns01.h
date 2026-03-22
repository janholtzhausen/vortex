#pragma once

#include "cert_provider.h"
#include "dns_provider.h"
#include "acme_client.h"

/*
 * ACME DNS-01 challenge provider.
 *
 * Uses a dns_provider_ops vtable to create and delete TXT records.
 * Waits 90 seconds for DNS propagation before notifying ACME.
 */

extern const struct cert_provider_ops acme_dns01_provider;

struct acme_dns01_ctx {
    struct acme_client         client;
    const struct dns_provider_ops *dns_ops;
    void                      *dns_ctx;
    char                       zone_id[256];
    int                        propagation_wait_s;  /* default 90 */
};

/* Obtain a cert for domain via DNS-01.  dns_ops/dns_ctx must be set on ctx. */
int acme_obtain_dns01(struct acme_dns01_ctx *ctx,
                      const char *domain,
                      struct cert_result *out);
