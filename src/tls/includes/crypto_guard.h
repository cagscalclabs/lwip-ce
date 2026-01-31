#ifndef TLS_CRYPTO_GUARD_H
#define TLS_CRYPTO_GUARD_H

#include <stdint.h>

/* C-callable wrappers for crypto side-channel hardening. */
void tls_crypto_guard_start(void);
void tls_crypto_guard_stop(void);

#endif
