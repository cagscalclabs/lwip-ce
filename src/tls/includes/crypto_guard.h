#ifndef TLS_CRYPTO_GUARD_H
#define TLS_CRYPTO_GUARD_H

#include <stdint.h>

/* C-callable wrappers for crypto side-channel hardening. */
uint8_t tls_crypto_enter(void);
void tls_crypto_exit(uint8_t state);
void tls_crypto_erase_stack(void);

#endif
