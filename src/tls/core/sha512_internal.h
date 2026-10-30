/**
 * @file sha512_internal.h
 * @brief Internal interface to the shared SHA-512 compression/buffering core.
 *
 * SHA-384 and SHA-512 use the same compression function, block size and
 * message-length encoding. sha512.c owns that core; sha384.c supplies the
 * SHA-384 IV and truncates the output to 48 bytes.
 */

#ifndef tls_sha512_internal_h
#define tls_sha512_internal_h

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The context is a tls_sha512_context (or the layout-compatible
 * tls_sha384_context). The core accesses it through an internal may_alias
 * view, so either pointer type may be passed. */
bool tls_sha512_core_init(void *ctx, const uint64_t iv[8]);
void tls_sha512_core_update(void *ctx, const uint8_t *data, size_t len);
void tls_sha512_core_digest(void *ctx, uint8_t *digest, size_t digest_len);

#endif
