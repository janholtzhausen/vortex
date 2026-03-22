#pragma once

#include "cert_provider.h"

/*
 * Static file provider — reads cert_path and key_path from the route config
 * that was provided at init time.  Suitable for certs managed externally
 * (e.g. certbot, manual deployment).
 *
 * obtain/renew simply re-read the files; the caller is responsible for
 * ensuring new files are in place before calling renew.
 */

extern const struct cert_provider_ops static_file_provider;

/* Convenience: load cert+key PEM directly from file paths.
 * Caller calls cert_result_free() when done. */
int static_file_load(const char *cert_path, const char *key_path,
                     struct cert_result *out);
