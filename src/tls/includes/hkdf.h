/**
 * @file hkdf.h
 * @brief HMAC-based Key Derivation Function (HKDF) - RFC 5869
 *
 * HKDF is used in TLS 1.3 for all key derivation operations.
 */

#ifndef TLS_HKDF_H
#define TLS_HKDF_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief HKDF-Extract: Extract a fixed-length pseudorandom key
 *
 * PRK = HMAC-Hash(salt, IKM)
 *
 * @param hash_algorithm Hash algorithm (TLS_HASH_SHA256, etc.)
 * @param salt Optional salt value (can be NULL for zero-length)
 * @param salt_len Length of salt in bytes
 * @param ikm Input keying material
 * @param ikm_len Length of IKM in bytes
 * @param prk Output pseudorandom key (hash_len bytes)
 * @return true on success, false on failure
 */
bool tls_hkdf_extract(
    uint8_t hash_algorithm,
    const uint8_t *salt,
    size_t salt_len,
    const uint8_t *ikm,
    size_t ikm_len,
    uint8_t *prk
);

/**
 * @brief HKDF-Expand: Expand PRK to desired length
 *
 * OKM = HKDF-Expand(PRK, info, L)
 *
 * @param hash_algorithm Hash algorithm (TLS_HASH_SHA256, etc.)
 * @param prk Pseudorandom key from HKDF-Extract
 * @param prk_len Length of PRK (typically hash output size)
 * @param info Optional context and application specific information
 * @param info_len Length of info
 * @param okm Output keying material
 * @param okm_len Desired length of OKM (max: 255 * hash_len)
 * @return true on success, false on failure
 */
bool tls_hkdf_expand(
    uint8_t hash_algorithm,
    const uint8_t *prk,
    size_t prk_len,
    const uint8_t *info,
    size_t info_len,
    uint8_t *okm,
    size_t okm_len
);

/**
 * @brief HKDF-Expand-Label: TLS 1.3 specific key derivation
 *
 * Derives keying material from a secret using HKDF with TLS 1.3 label formatting.
 *
 * HkdfLabel structure:
 *   struct {
 *       uint16 length = Length;
 *       opaque label<7..255> = "tls13 " + Label;
 *       opaque context<0..255> = Context;
 *   } HkdfLabel;
 *
 * @param hash_algorithm Hash algorithm (TLS_HASH_SHA256, etc.)
 * @param secret Input secret
 * @param secret_len Length of secret
 * @param label ASCII label string (without "tls13 " prefix)
 * @param label_len Length of label
 * @param context Optional context (typically transcript hash)
 * @param context_len Length of context
 * @param out Output buffer
 * @param out_len Desired output length
 * @return true on success, false on failure
 */
bool tls_hkdf_expand_label(
    uint8_t hash_algorithm,
    const uint8_t *secret,
    size_t secret_len,
    const char *label,
    size_t label_len,
    const uint8_t *context,
    size_t context_len,
    uint8_t *out,
    size_t out_len
);

/**
 * @brief Derive-Secret: TLS 1.3 transcript-based key derivation
 *
 * Convenience function: Derive-Secret(Secret, Label, Messages) =
 *     HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length)
 *
 * @param hash_algorithm Hash algorithm
 * @param secret Input secret
 * @param secret_len Length of secret
 * @param label ASCII label string
 * @param label_len Length of label
 * @param transcript_hash Hash of handshake messages
 * @param transcript_hash_len Length of transcript hash (typically 32 for SHA256)
 * @param out Output buffer (hash_len bytes)
 * @return true on success, false on failure
 */
bool tls_derive_secret(
    uint8_t hash_algorithm,
    const uint8_t *secret,
    size_t secret_len,
    const char *label,
    size_t label_len,
    const uint8_t *transcript_hash,
    size_t transcript_hash_len,
    uint8_t *out
);

#ifdef __cplusplus
}
#endif

#endif /* TLS_HKDF_H */
