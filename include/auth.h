#pragma once
#include "config.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Returns true if the HTTP request passes Basic Auth for the route,
 * or if auth is not enabled. */
bool auth_parse_verifier(struct auth_verifier *out, const char *value);
bool auth_load_verifiers_file(struct route_auth_config *auth,
                              const char *path,
                              const char *route_hostname);
bool auth_check_basic_value(const struct route_auth_config *auth,
                            const char *value, size_t value_len);
bool auth_check_request(const struct route_auth_config *auth,
                        const uint8_t *req, int req_len);
