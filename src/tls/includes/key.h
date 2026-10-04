/**
 * @file key.h
 * @author Anthony Cagliano
 * @brief Self-describing key container for asymmetric and symmetric operations.
 *
 * A struct tls_key carries both the algorithm identifier and the key material,
 * so callers never pass alg separately.  The alg field determines which union
 * member is valid and which tls_key_* operation makes sense.
 *
 * Algorithm values are split into two ranges:
 *   0x00–0x0F  signing/verification algorithms  (asymmetric)
 *   0x10–0xFE  encryption/decryption algorithms (asymmetric or symmetric)
 *
 * Use tls_x509_oid_to_sig_alg() to map a DER OID to tls_alg_t when building
 * a key from a parsed certificate.
 */

#ifndef TLS_KEY_H
#define TLS_KEY_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "rsa.h"
#include "aes.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Algorithm identifier — encodes key type, cipher, and hash/padding scheme.
 * Drives dispatch in tls_key_verify(), tls_key_sign(), tls_key_encrypt(),
 * and tls_key_decrypt().
 *
 * Signing range (0x00–0x0F): asymmetric signature algorithms.
 * Encryption range (0x10–0xFE): symmetric and asymmetric encryption.
 */
typedef enum
{
    /* --- Signing / verification (0x00–0x0F) --- */
    TLS_ALG_RSA_PSS_RSAE_SHA256    = 0x00, /**< RSASSA-PSS MGF1-SHA-256 saltLen=32. rsa member. */
    TLS_ALG_RSA_PKCS1_SHA256       = 0x01, /**< RSASSA-PKCS1-v1.5 SHA-256.          rsa member. */
    TLS_ALG_ECDSA_SECP256R1_SHA256 = 0x02, /**< ECDSA P-256 SHA-256.                ec member.  */
    /* 0x03–0x0F reserved for future signing algorithms */

    /* --- Encryption / decryption (0x10–0xFE) --- */
    TLS_ALG_AES_128_GCM            = 0x10, /**< AES-128-GCM (AEAD). aes member (128-bit key). IV=12 B, tag=16 B. */
    TLS_ALG_AES_256_GCM            = 0x11, /**< AES-256-GCM (AEAD). aes member (256-bit key). IV=12 B, tag=16 B. */
    TLS_ALG_AES_128_CCM            = 0x12, /**< AES-128-CCM (AEAD). aes member (128-bit key). nonce=13 B, tag=16 B. */
    TLS_ALG_AES_256_CCM            = 0x13, /**< AES-256-CCM (AEAD). aes member (256-bit key). nonce=13 B, tag=16 B. */
    TLS_ALG_AES_128_CBC            = 0x14, /**< AES-128-CBC. aes member (128-bit key). IV=16 B, no tag. */
    TLS_ALG_AES_256_CBC            = 0x15, /**< AES-256-CBC. aes member (256-bit key). IV=16 B, no tag. */
    TLS_ALG_RSA_OAEP_SHA256        = 0x16, /**< RSAES-OAEP SHA-256. rsa member. Encryption only. */
    /* 0x17–0xFE reserved for future encryption algorithms */

    TLS_ALG_UNKNOWN                = 0xFF,
} tls_alg_t;

/** True when @p alg is in the signing range. */
#define TLS_ALG_IS_SIGNING(alg)    ((uint8_t)(alg) <= 0x0F)

/** True when @p alg is in the encryption range. */
#define TLS_ALG_IS_ENCRYPTION(alg) ((uint8_t)(alg) >= 0x10 && (uint8_t)(alg) <= 0xFE)

/* NIST-recommended nonce/IV sizes (SP 800-38D §5.2.1.1, SP 800-38C §A.1). */
#define TLS_KEY_GCM_IV_LEN   12  /**< 96-bit IV for AES-GCM (NIST SP 800-38D). */
#define TLS_KEY_CCM_NONCE_LEN 13 /**< 13-byte nonce for AES-CCM (NIST SP 800-38C); limits msg to 65535 bytes. */
#define TLS_KEY_AES_TAG_LEN  16  /**< 128-bit authentication tag for GCM and CCM. */

/**
 * Result of a key signing or verification operation.
 * Shared by tls_key_verify(), tls_key_sign(), and tls_x509_signature_verify().
 */
typedef enum
{
    TLS_KEY_OP_OK          = 0, /**< Operation succeeded.                                       */
    TLS_KEY_OP_INVALID     = 1, /**< Operation failed (bad signature, wrong key, etc.).          */
    TLS_KEY_OP_UNSUPPORTED = 2, /**< Algorithm is known but not yet implemented (e.g. ECDSA).   */
    TLS_KEY_OP_UNKNOWN     = 3, /**< key->alg is TLS_ALG_UNKNOWN or wrong for this operation.   */
} tls_key_op_result_t;

/**
 * Self-describing key.
 *
 * The alg field drives dispatch; only the matching union member is valid.
 *
 * RSA-PSS example (2048-bit key, e=65537):
 * @code
 *   static const uint8_t exp[] = {0x01, 0x00, 0x01};
 *   struct tls_key k = {
 *       .alg = TLS_ALG_RSA_PSS_RSAE_SHA256,
 *       .rsa = { sizeof(exp), exp, mod_len, mod },
 *   };
 * @endcode
 *
 * AES-128-GCM example (key material pre-loaded into ctx):
 * @code
 *   struct tls_key k = {
 *       .alg = TLS_ALG_AES_128_GCM,
 *       // populate k.aes via tls_aes_init() before use
 *   };
 * @endcode
 */
struct tls_key
{
    tls_alg_t alg;
    union
    {
        struct tls_rsa_key    rsa; /**< Valid for TLS_ALG_RSA_*.  */
        struct
        {
            size_t         len;    /**< Length of raw EC point bytes. */
            const uint8_t *data;   /**< Uncompressed EC public-key.   */
        } ec;                      /**< Valid for TLS_ALG_ECDSA_*.    */
        struct {
            size_t len;
            const uint8_t *data;
        } aes;
    };
};

/**
 * @brief Verify a signature over @p content using @p key.
 *
 * Dispatches on key->alg; SHA-256 hashes @p content internally.
 * Only valid for signing-range algorithms (TLS_ALG_IS_SIGNING).
 */
tls_key_op_result_t tls_key_verify(const uint8_t *content, size_t content_len,
                                    const uint8_t *sig, size_t sig_len,
                                    const struct tls_key *key);

/**
 * @brief Sign @p content with @p key, writing the raw signature to @p sig_out.
 *
 * @p sig_len_out receives the number of bytes written on success.
 * Returns TLS_KEY_OP_UNSUPPORTED for all algorithms until private-key
 * signing is implemented.
 */
tls_key_op_result_t tls_key_sign(const uint8_t *content, size_t content_len,
                                  uint8_t *sig_out, size_t *sig_len_out,
                                  const struct tls_key *key);

/**
 * Ciphertext bundle for one-shot encrypt/decrypt operations.
 *
 * On encrypt, the caller pre-allocates all fields and the function fills them:
 *   - iv      receives the freshly generated nonce/IV
 *   - obuf    receives the ciphertext
 *   - obuf_len must be set by the caller before encrypting:
 *               GCM/CCM: equal to the plaintext length (output is same size)
 *               CBC:     ceil(plaintext_len / 16) * 16  (PKCS#7 padded)
 *   - tag     receives the authentication tag (TLS_KEY_AES_TAG_LEN bytes);
 *             may be NULL for CBC (no tag)
 *
 * On decrypt, the caller populates all fields from the previously stored
 * bundle; the function reads iv/obuf/obuf_len/tag as ciphertext input.
 * The recovered plaintext is written to the separate outbuf/outbuf_len
 * parameters of tls_key_decrypt() / tls_key_decrypt_aad().
 * For CBC, the plaintext is shorter than obuf_len (padding stripped).
 *
 * All of iv, obuf, and tag must be non-NULL for AEAD modes (GCM, CCM).
 */
struct tls_key_cipher_io
{
    uint8_t *iv;       /**< Nonce/IV — written on encrypt, read on decrypt. */
    size_t   obuf_len; /**< Ciphertext length. For CBC: padded to block boundary. */
    uint8_t *obuf;     /**< Ciphertext buffer. */
    uint8_t *tag;      /**< Auth tag (TLS_KEY_AES_TAG_LEN bytes); NULL ok for CBC. */
};

/**
 * @brief One-shot encrypt @p inbuf, writing IV, ciphertext, and auth tag
 *        into @p io.
 *
 *   AES keys — fresh IV/nonce written to io->iv; ciphertext written to
 *              io->obuf (io->obuf_len must equal in_len); auth tag written
 *              to io->tag (GCM/CCM only).
 *   RSA keys — (TLS_ALG_RSA_OAEP_SHA256) io->obuf must be ≥ mod_len bytes;
 *              io->iv and io->tag are unused and may be NULL.
 *
 * @return true on success, false on any error.
 */
bool tls_key_encrypt(struct tls_key *key,
                     const uint8_t *inbuf, size_t in_len,
                     struct tls_key_cipher_io *io);

/**
 * @brief One-shot encrypt with associated data.  Same as tls_key_encrypt()
 *        but feeds @p aad into the AEAD tag before encrypting.
 *        For RSA and CBC, @p aad is ignored.
 */
bool tls_key_encrypt_aad(struct tls_key *key,
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *inbuf, size_t in_len,
                         struct tls_key_cipher_io *io);

/**
 * @brief One-shot decrypt the ciphertext bundle in @p io into @p outbuf.
 *
 *   AES keys — iv and tag are read from @p io; ciphertext is io->obuf
 *              (io->obuf_len bytes).  For GCM/CCM the tag is verified before
 *              decrypting; returns false on tag mismatch.
 *   RSA keys — (TLS_ALG_RSA_OAEP_SHA256) raw RSA + OAEP unpad; io->iv and
 *              io->tag are unused.
 *
 * @param outbuf     Caller-allocated plaintext destination.
 * @param outbuf_len Capacity of @p outbuf in bytes; must be ≥ io->obuf_len.
 *                   For CBC the actual plaintext written will be < io->obuf_len
 *                   (padding stripped); for GCM/CCM it equals io->obuf_len.
 * @return true on success, false on error or tag mismatch.
 */
bool tls_key_decrypt(struct tls_key *key,
                     struct tls_key_cipher_io *io,
                     uint8_t *outbuf, size_t outbuf_len);

/**
 * @brief One-shot decrypt with associated data.  Same as tls_key_decrypt()
 *        but feeds @p aad into AEAD tag verification before decrypting.
 *        For RSA and CBC, @p aad is ignored.
 */
bool tls_key_decrypt_aad(struct tls_key *key,
                         const uint8_t *aad, size_t aad_len,
                         struct tls_key_cipher_io *io,
                         uint8_t *outbuf, size_t outbuf_len);

#ifdef __cplusplus
}
#endif

#endif /* TLS_KEY_H */
