#pragma once
/*
 * acme_internal.h — internal helpers shared between acme_client.c and
 *                   acme_dns01.c / dns_cloudflare.c.
 *
 * NOT part of the public API.  Do not include from outside cert/.
 */

#include "acme_client.h"

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#ifdef VORTEX_PHASE_TLS

/*
 * HTTPS request via TCP + picotls TLS handshake.
 * Reuses cl->https_ctx (ptls_context_t *).
 * Returns 0 on success, -1 on error.
 * *resp_out is heap-allocated; caller must free.
 */
int https_request(struct acme_client *cl,
                  const char *method,
                  const char *url,
                  const char *content_type,   /* NULL → "application/jose+json" */
                  const char *body,
                  size_t body_len,
                  int   *status_out,
                  char  *location_out, size_t loc_max,
                  char  *nonce_out,    size_t nonce_max,
                  char **resp_out,     size_t *resp_len_out);

/*
 * Build a JWS-signed request body (RFC 7515 / RFC 8555).
 * kid != NULL && kid[0] → use kid header; else embed JWK (newAccount).
 * thumbprint may be NULL (only needed for newAccount JWK).
 * Returns heap-allocated JSON string or NULL on error.  Caller must free.
 */
char *make_jws(const uint8_t *priv32, const uint8_t *pub64,
               const char *nonce,
               const char *url,
               const char *payload_json,
               const char *kid,
               const char *thumbprint);

/*
 * Encode a raw 32-byte P-256 private key as PKCS#8 PEM
 * ("-----BEGIN PRIVATE KEY-----" ... "-----END PRIVATE KEY-----").
 * Returns 0 on success, -1 if out_max is too small.
 */
int pkcs8_pem_from_priv(const uint8_t priv[32], char *out, size_t out_max);

/*
 * Build a PKCS#10 CSR for a fresh ECDSA P-256 key with CN=domain and
 * SAN=DNS:domain.
 *   priv_out   — receives the 32-byte raw private key of the new domain key
 *   *csr_out   — heap-allocated DER blob (caller must free)
 *   *csr_len   — length of DER blob
 * Returns 0 on success, -1 on error.
 */
int make_csr_der(const char *domain,
                 uint8_t priv_out[32],
                 uint8_t **csr_out, size_t *csr_len);

/*
 * Decode the first "-----BEGIN CERTIFICATE-----" block from PEM → DER.
 * Returns heap-allocated DER (caller must free), or NULL on error.
 * *der_len_out is set to the DER length.
 */
uint8_t *pem_cert_to_der(const char *pem, size_t *der_len_out);

/*
 * Extract the notAfter date from a DER-encoded X.509 certificate.
 * Returns the Unix timestamp, or 0 on parse error.
 */
time_t der_cert_not_after(const uint8_t *der, size_t der_len);

#endif /* VORTEX_PHASE_TLS */
