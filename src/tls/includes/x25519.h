#ifndef X25519_X25519_H
#define X25519_X25519_H

#include <stdbool.h>
#include <stdint.h>

/**
 * @brief X25519 scalar multiplication (compute shared secret)
 *
 * @param shared_secret Output shared secret (32 bytes, little-endian)
 * @param my_private    Our private scalar (32 bytes, will be clamped internally)
 * @param their_public  Peer's public key point (32 bytes, u-coordinate)
 * @param yield_fn      Optional: callback for cooperative multitasking (may be NULL)
 * @param yield_data    Optional: context passed to yield_fn (may be NULL)
 * @return true on success, false on error (e.g., low-order point)
 */
extern bool tls_x25519_secret(
    uint8_t shared_secret[32],
    const uint8_t my_private[32],
    const uint8_t their_public[32],
    void (*yield_fn)(void*),
    void* yield_data
);

/**
 * @brief Generate X25519 public key from private key
 *
 * @param public_key  Output public key (32 bytes, u-coordinate)
 * @param private_key Input private scalar (32 bytes, will be clamped internally)
 * @param yield_fn    Optional: callback for cooperative multitasking (may be NULL)
 * @param yield_data  Optional: context passed to yield_fn (may be NULL)
 */
extern bool tls_x25519_publickey(
    uint8_t public_key[32],
    const uint8_t private_key[32],
    void (*yield_fn)(void*),
    void* yield_data
);

#endif //X25519_X25519_H