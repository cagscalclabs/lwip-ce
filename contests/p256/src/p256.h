#ifndef CONTEST_P256_H
#define CONTEST_P256_H

#include <stdbool.h>
#include <stdint.h>

/*
 * P-256 (secp256r1) contest interface.
 *
 * All coordinates and scalars are big-endian, 32 bytes.
 * Uncompressed public keys are 65 bytes: 0x04 || X || Y.
 *
 * Implement the four functions below.
 */

/**
 * @brief Generate a P-256 public key from a private scalar.
 *
 * Computes Q = d * G where G is the P-256 base point.
 *
 * @param public_key  Output: 65-byte uncompressed point (0x04 || X || Y)
 * @param private_key Input: 32-byte private scalar, big-endian
 * @return true on success, false if private_key is zero or >= n
 */
bool tls_p256_publickey(
    uint8_t public_key[65],
    const uint8_t private_key[32]
);

/**
 * @brief Compute ECDHE shared secret (X coordinate of d * Q_peer).
 *
 * @param shared_secret  Output: 32-byte X coordinate, big-endian
 * @param private_key    Our private scalar (32 bytes, big-endian)
 * @param peer_public    Peer's uncompressed public key (65 bytes)
 * @return true on success, false on invalid input or point-at-infinity result
 */
bool tls_p256_secret(
    uint8_t shared_secret[32],
    const uint8_t private_key[32],
    const uint8_t peer_public[65]
);

/**
 * @brief Sign a message hash with ECDSA over P-256.
 *
 * Produces a deterministic signature (RFC 6979) or random-k signature.
 * The signature is encoded as r || s, each 32 bytes big-endian (64 bytes total).
 *
 * @param sig         Output: 64-byte signature (r || s)
 * @param msg_hash    32-byte SHA-256 hash of the message
 * @param private_key 32-byte private scalar
 * @return true on success
 */
bool tls_p256_sign(
    uint8_t sig[64],
    const uint8_t msg_hash[32],
    const uint8_t private_key[32]
);

/**
 * @brief Verify an ECDSA signature over P-256.
 *
 * @param sig         64-byte signature (r || s, big-endian)
 * @param msg_hash    32-byte SHA-256 hash of the signed message
 * @param public_key  65-byte uncompressed public key (0x04 || X || Y)
 * @return true if signature is valid, false otherwise
 */
bool tls_p256_verify(
    const uint8_t sig[64],
    const uint8_t msg_hash[32],
    const uint8_t public_key[65]
);

#endif /* CONTEST_P256_H */
