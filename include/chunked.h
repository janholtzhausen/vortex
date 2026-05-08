#pragma once
#include "conn.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Maximum body size to accumulate for chunked TE caching (4 MB). */
#define CHUNK_MAX_BODY (4u * 1024u * 1024u)

/*
 * Append decoded chunked-transfer body bytes to cold->chunk_buf.
 * Returns true when the terminal zero-size chunk is seen.
 * Returns false on protocol error or size cap exceeded — caller discards.
 * No worker or io_uring deps; safe to test standalone.
 */
bool chunked_decode_append(struct conn_cold *cold, const uint8_t *data, size_t len);
