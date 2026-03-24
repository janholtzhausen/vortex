#pragma once

#ifdef VORTEX_QUIC

#include "cache.h"
#include "config.h"
#include "tls.h"
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <netinet/in.h>

/* Maximum concurrent QUIC connections per server instance */
#define QUIC_MAX_CONNS   512
/* Maximum concurrent streams per connection */
#define QUIC_MAX_STREAMS 64
/* Response buffer ceiling per stream: 4 MB */
#define QUIC_RESP_MAX    (4 * 1024 * 1024)

struct quic_server;

/*
 * quic_server_init: create UDP socket, SSL_CTX for QUIC, populate state.
 * tls is the existing TCP TLS context (used to borrow the SSL_CTX route certs).
 * Returns 0 on success, -1 on failure.
 */
int  quic_server_init(struct quic_server **out,
                      struct tls_ctx *tls,
                      struct cache *cache,
                      struct vortex_config *cfg,
                      const char *bind_addr,
                      uint16_t port);

/* Start the QUIC event-loop thread */
int  quic_server_start(struct quic_server *qs);

/* Signal stop and wait for thread */
void quic_server_stop(struct quic_server *qs);
void quic_server_join(struct quic_server *qs);
void quic_server_destroy(struct quic_server *qs);

#endif /* VORTEX_QUIC */
