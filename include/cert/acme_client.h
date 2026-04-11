#pragma once

#include "cert_provider.h"
#include "acme_http01.h"

#include <stdint.h>

/*
 * ACME client — RFC 8555 implementation.
 *
 * Supports HTTP-01 challenge only (Phase 6).
 * DNS-01 added in Phase 7.
 *
 * Crypto backend: picotls minicrypto + micro-ecc (no OpenSSL).
 */

#define ACME_MAX_URL 512

struct acme_client {
    /* Configuration (set before acme_client_init) */
    char   directory_url[ACME_MAX_URL];
    char   account_key_path[4096];
    char   storage_path[4096];
    char   email[256];
    int    renewal_days;

#ifdef VORTEX_PHASE_TLS
    void   *https_ctx;              /* ptls_context_t* for ACME HTTPS calls */
    uint8_t account_key_priv[32];   /* raw P-256 private key */
    uint8_t account_key_pub[64];    /* raw P-256 public key X||Y */
#endif

    /* ACME directory endpoints (fetched at init) */
    char newNonce_url[ACME_MAX_URL];
    char newAccount_url[ACME_MAX_URL];
    char newOrder_url[ACME_MAX_URL];

    /* Account URL (kid) obtained after account registration */
    char account_url[ACME_MAX_URL];

    /* JWK thumbprint (for key-auth = token + "." + thumbprint) */
    char jwk_thumbprint[64];  /* base64url-encoded SHA-256 */

    /* HTTP-01 challenge server (not owned by this struct) */
    struct acme_http01_server *http01_srv;
};

/*
 * Initialise ACME client:
 *   - Load or generate ECDSA P-256 account key from account_key_path
 *   - Fetch ACME directory
 *   - Register/locate account
 */
int  acme_client_init(struct acme_client *cl);
void acme_client_destroy(struct acme_client *cl);

/*
 * Obtain a new certificate for domain via HTTP-01.
 * http01_srv must already be started and listening.
 * On success, fills *out (caller calls cert_result_free when done).
 */
int  acme_obtain_http01(struct acme_client *cl,
                         const char *domain,
                         struct acme_http01_server *http01_srv,
                         struct cert_result *out);

/*
 * Check whether the stored cert for domain needs renewal.
 * Returns 1 if renewal is needed (within renewal_days of expiry).
 */
int  acme_needs_renewal(const char *storage_path, const char *domain,
                        int renewal_days);

/*
 * Compute the key-authorization string for a challenge token:
 *   key_auth = token + "." + base64url(SHA-256(JWK))
 */
int  acme_key_auth(const char *token, const char *thumbprint,
                   char *out, size_t out_max);

/*
 * Base64url encode/decode (no padding, RFC 4648 §5).
 * encode: returns number of chars written (excl. NUL), or -1 on error.
 * decode: returns number of bytes decoded, or -1 on error.
 */
int  b64url_encode(const unsigned char *in, size_t in_len,
                   char *out, size_t out_max);
int  b64url_decode(const char *in, size_t in_len,
                   unsigned char *out, size_t out_max);
