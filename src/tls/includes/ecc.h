#ifndef TLS_ECC_H
#define TLS_ECC_H

#include <stdint.h>
#include <stdbool.h>

/* SECP256R1 (P-256) Elliptic Curve Cryptography */

#define P256_BYTES 32  /* 256 bits = 32 bytes */

/**
 * @brief P-256 point in affine coordinates (x, y)
 * Each coordinate is 32 bytes, little-endian
 */
struct p256_point {
    uint8_t x[P256_BYTES];  /* X coordinate, little-endian */
    uint8_t y[P256_BYTES];  /* Y coordinate, little-endian */
};

/**
 * @brief P-256 scalar (private key or random value)
 * 32 bytes, little-endian
 */
typedef uint8_t p256_scalar[P256_BYTES];

/**
 * @brief Initialize P-256 curve (load constants if needed)
 * @return true on success
 */
bool p256_init(void);

/**
 * @brief Scalar multiplication: out = scalar * point
 * @param out      Output point (can alias point for in-place operation)
 * @param scalar   Scalar multiplier (32 bytes, little-endian)
 * @param point    Input point (NULL for generator G)
 * @return true on success, false if point is invalid
 */
bool p256_scalar_mult(struct p256_point *out, const p256_scalar scalar,
                      const struct p256_point *point);

/**
 * @brief ECDH shared secret computation
 * Computes shared_secret = private_key * peer_public_key
 * @param shared_secret  Output: x-coordinate of result (32 bytes)
 * @param private_key    Our private key (32 bytes scalar)
 * @param peer_public    Peer's public key point
 * @return true on success, false if peer_public is invalid
 */
bool p256_ecdh(uint8_t shared_secret[P256_BYTES],
               const p256_scalar private_key,
               const struct p256_point *peer_public);

/**
 * @brief ECDSA signature verification
 * Verifies that signature (r, s) is valid for message hash and public key
 * @param hash       Message hash (32 bytes, SHA-256)
 * @param signature  Signature bytes: r || s (64 bytes total, big-endian)
 * @param public_key Public key point
 * @return true if signature is valid, false otherwise
 */
bool p256_ecdsa_verify(const uint8_t hash[P256_BYTES],
                       const uint8_t signature[P256_BYTES * 2],
                       const struct p256_point *public_key);

/**
 * @brief Decode a P-256 public key from uncompressed format
 * @param point      Output point
 * @param encoded    Encoded point: 0x04 || x || y (65 bytes, big-endian coords)
 * @return true on success, false if encoding is invalid
 */
bool p256_decode_point(struct p256_point *point, const uint8_t encoded[65]);

/**
 * @brief Encode a P-256 public key to uncompressed format
 * @param encoded    Output: 0x04 || x || y (65 bytes, big-endian coords)
 * @param point      Input point
 */
void p256_encode_point(uint8_t encoded[65], const struct p256_point *point);

/* Internal field arithmetic (mod p) - implemented in assembly */

/**
 * @brief Modular addition: out = (a + b) mod p
 * @param out  Result (32 bytes, little-endian)
 * @param a    Operand A (32 bytes, little-endian)
 * @param b    Operand B (32 bytes, little-endian)
 */
void p256_mod_add(uint8_t out[P256_BYTES], const uint8_t a[P256_BYTES],
                  const uint8_t b[P256_BYTES]);

/**
 * @brief Modular subtraction: out = (a - b) mod p
 * @param out  Result (32 bytes, little-endian)
 * @param a    Operand A (32 bytes, little-endian)
 * @param b    Operand B (32 bytes, little-endian)
 */
void p256_mod_sub(uint8_t out[P256_BYTES], const uint8_t a[P256_BYTES],
                  const uint8_t b[P256_BYTES]);

/**
 * @brief Modular multiplication: out = (a * b) mod p
 * @param out  Result (32 bytes, little-endian)
 * @param a    Operand A (32 bytes, little-endian)
 * @param b    Operand B (32 bytes, little-endian)
 */
void p256_mod_mul(uint8_t out[P256_BYTES], const uint8_t a[P256_BYTES],
                  const uint8_t b[P256_BYTES]);

/**
 * @brief Modular squaring: out = (a * a) mod p
 * @param out  Result (32 bytes, little-endian)
 * @param a    Operand A (32 bytes, little-endian)
 */
void p256_mod_sqr(uint8_t out[P256_BYTES], const uint8_t a[P256_BYTES]);

/**
 * @brief Modular inversion: out = a^(-1) mod p
 * Uses Fermat's little theorem: a^(-1) = a^(p-2) mod p
 * @param out  Result (32 bytes, little-endian)
 * @param a    Operand A (32 bytes, little-endian)
 */
void p256_mod_inv(uint8_t out[P256_BYTES], const uint8_t a[P256_BYTES]);

/* Scalar arithmetic (mod n, curve order) - for ECDSA operations */

/**
 * @brief Scalar addition: out = (a + b) mod n
 * @param out  Result (32 bytes, little-endian)
 * @param a    Operand A (32 bytes, little-endian)
 * @param b    Operand B (32 bytes, little-endian)
 */
void p256_scalar_add_mod_n(uint8_t out[P256_BYTES], const uint8_t a[P256_BYTES],
                           const uint8_t b[P256_BYTES]);

/**
 * @brief Scalar multiplication: out = (a * b) mod n
 * @param out  Result (32 bytes, little-endian)
 * @param a    Operand A (32 bytes, little-endian)
 * @param b    Operand B (32 bytes, little-endian)
 */
void p256_scalar_mul_mod_n(uint8_t out[P256_BYTES], const uint8_t a[P256_BYTES],
                           const uint8_t b[P256_BYTES]);

/**
 * @brief Scalar inversion: out = a^(-1) mod n
 * @param out  Result (32 bytes, little-endian)
 * @param a    Operand A (32 bytes, little-endian)
 */
void p256_scalar_inv_mod_n(uint8_t out[P256_BYTES], const uint8_t a[P256_BYTES]);

#endif /* TLS_ECC_H */
