#pragma once
#include "dns_provider.h"

/*
 * Cloudflare DNS API v4 provider.
 *
 * Requires:
 *   api_token  — Cloudflare API token with DNS:Edit permission
 *
 * The zone is looked up automatically from the domain name.
 *
 * Set via acme config:
 *   dns_provider: "cloudflare"
 *   dns_api_token: "your-cf-token"
 */

extern const struct dns_provider_ops cloudflare_dns_provider;
