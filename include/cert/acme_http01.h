#pragma once

#include <stdint.h>
#include <pthread.h>

/*
 * ACME HTTP-01 challenge responder.
 *
 * Listens on a plain TCP port (typically 80 / http_port) in a background
 * thread.  Serves a single active challenge token at a time.  All other
 * requests receive a 301 redirect to https.
 */

struct acme_http01_server {
    int      listen_fd;
    int      port;
    int      stop_pipe[2];     /* write 1 byte to [1] to stop the thread */

    /* Current challenge (protected by challenge_lock) */
    pthread_mutex_t challenge_lock;
    char challenge_token[256]; /* empty = no active challenge */
    char challenge_keyauth[512];

    pthread_t thread;
    int       running;
};

/* Bind + start background accept thread.  Returns 0 on success. */
int  acme_http01_start(struct acme_http01_server *srv, int port);

/* Set active challenge.  Thread-safe; can be called from any thread. */
void acme_http01_set_challenge(struct acme_http01_server *srv,
                                const char *token,
                                const char *key_auth);

/* Clear active challenge after it has been validated. */
void acme_http01_clear_challenge(struct acme_http01_server *srv);

/* Stop the server and free resources. */
void acme_http01_stop(struct acme_http01_server *srv);
