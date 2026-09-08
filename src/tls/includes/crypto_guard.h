/**
 * @file crypto_guard.h
 * @author Anthony Cagliano
 * @brief Provides device specific side-channel mitigations.
 * @license: GNU GPL v3.0
 */

#ifndef TLS_CRYPTO_GUARD_H
#define TLS_CRYPTO_GUARD_H

#include <stdint.h>

/* C-callable wrappers for crypto side-channel hardening. */
void tls_crypto_guard_enable(void);
void tls_crypto_guard_disable(void);

#endif
