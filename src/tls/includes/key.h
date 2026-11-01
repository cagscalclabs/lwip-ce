/**
 * @file key.h
 * @author Anthony Cagliano
 * @brief Typed key material for asymmetric and symmetric operations.
 *
 * Import infers the key type from the encoded input. Signature schemes and
 * ciphers are selected per operation, independently of the stored key type.
 */

#ifndef TLS_KEY_H
#define TLS_KEY_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "tls_algorithms.h"
#include "rsa.h"
#include "aes.h"

#ifdef __cplusplus
extern "C" {
#endif

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
    TLS_KEY_OP_UNSUPPORTED = 2, /**< Algorithm is known but unsupported for this key/operation
                                     (e.g. RSA private signing).                                  */
    TLS_KEY_OP_UNKNOWN     = 3, /**< Unknown algorithm or wrong operation category.   */
} tls_key_op_result_t;

/** Key material type, independent of padding, hash, or cipher mode.
 * Zero initialization denotes an empty key. EC imports support P-256 and P-384.
 */
typedef enum
{
    TLS_KEY_TYPE_UNKNOWN = 0,
    TLS_KEY_TYPE_RSA,
    TLS_KEY_TYPE_EC_P256,
    TLS_KEY_TYPE_EC_P384,
    TLS_KEY_TYPE_AES,
} tls_key_type_t;

/** Key material. Only the union member selected by type is valid.
 * Manually constructed keys borrow their buffers and leave allocated=false.
 * AES keys contain 16 or 32 raw bytes, not a tls_aes_context.
 */
/** SP 800-38D §8.3: with random 96-bit IVs a key must not exceed 2^32 encrypt
 *  invocations.  tls_cipher_encrypt() increments this and returns NULL once the
 *  limit is reached, requiring the caller to rotate to a fresh key. */
#define TLS_KEY_GCM_INVOC_LIMIT 0xFFFFFFFFu

struct tls_key
{
    tls_key_type_t type;
    bool      allocated; /**< true when this struct was returned by tls_key_import()
                              and must be freed with tls_key_free(). */
    uint32_t  invoc_count; /**< Encrypt invocation counter (AES-GCM/CCM only).
                                Caller must rotate the key once this reaches
                                TLS_KEY_GCM_INVOC_LIMIT. */
    union
    {
        struct tls_rsa_key    rsa; /**< Valid for TLS_ALG_RSA_*.  */
        struct
        {
            size_t         len;    /**< Uncompressed point length: 65 for P-256, 97 for P-384.   */
            const uint8_t *pub;    /**< Uncompressed EC public-key (0x04 || X || Y).             */
            const uint8_t *priv;   /**< 32-byte (P-256) or 48-byte (P-384) scalar, or NULL.      */
        } ec;                      /**< Valid for TLS_ALG_ECDSA_*.    */
        struct {
            size_t len;
            const uint8_t *data;
        } aes;
    };
};

/**
 * Input format for tls_key_import().
 */
typedef enum
{
    TLS_KEY_FORMAT_PEM = 0, /**< PEM text (-----BEGIN ... -----).            */
    TLS_KEY_FORMAT_DER = 1, /**< Raw DER bytes.                              */
} tls_key_format_t;

/**
 * Result codes for tls_key_import().
 */
typedef enum
{
    TLS_KEY_IMPORT_OK             = 0, /**< Success.                                      */
    TLS_KEY_IMPORT_INVALID_ARG    = 1, /**< NULL pointer or zero length.                  */
    TLS_KEY_IMPORT_ALLOC_FAIL     = 2, /**< Memory allocation failed.                     */
    TLS_KEY_IMPORT_PARSE_FAIL     = 3, /**< DER/PEM structure malformed.                  */
    TLS_KEY_IMPORT_BAD_ALG        = 4, /**< Key algorithm OID not recognised.             */
    TLS_KEY_IMPORT_UNSUPPORTED_ENC= 5, /**< Encrypted key uses an unsupported cipher.     */
    TLS_KEY_IMPORT_DECRYPT_FAIL   = 6, /**< PBES2 decryption or tag verification failed.  */
} tls_key_import_result_t;

/**
 * @brief Parse a PEM or DER-encoded key, allocate a typed tls_key,
 *        and store a pointer to it in @p *out.
 *
 * The returned key owns its key material in a trailing allocation; it must be
 * freed with tls_key_free().  Pointer members (rsa.modulus, ec.pub, ec.priv, etc.)
 * reference that same allocation — never point elsewhere.
 *
 * @param out       Receives the allocated key on success; set to NULL on error.
 * @param data      PEM text or raw DER bytes.
 * @param len       Length of @p data in bytes.
 * @param format    TLS_KEY_FORMAT_PEM or TLS_KEY_FORMAT_DER.
 * PEM and DER both infer type from their structure and algorithm OID.
 * Unsupported OIDs/restrictions are rejected, not treated as unrestricted keys.
 * EC private-key imports expose both the public point and the private
 * scalar (P-256 or P-384). RSA private signing is not implemented.
 * @param password  Passphrase for PBES2-encrypted private keys; may be NULL
 *                  for unencrypted keys.
 * @return tls_key_import_result_t status code.
 */
tls_key_import_result_t tls_key_import(struct tls_key **out,
                                        const void *data, size_t len,
                                        tls_key_format_t format,
                                        const char *password);

/**
 * @brief Free a key returned by tls_key_import().
 *
 * Checks key->allocated before doing anything: if the flag is false the
 * function returns immediately (safe to call on stack-allocated or
 * externally-managed keys).  When true, zeroes the entire allocation
 * (key header + trailing key material) and frees it.  Safe to call with NULL.
 */
void tls_key_free(struct tls_key *key);

/**
 * @brief Verify a signature over @p content using @p key.
 *
 * Dispatches on alg after checking key->type. Content is hashed with the
 * scheme's hash: SHA-256 for ECDSA P-256 and the RSA schemes, SHA-384 for
 * ecdsa_secp384r1_sha384. ECDSA signatures may be DER SEQUENCE
 * { INTEGER r, INTEGER s } (X.509/TLS wire format) or the raw 64/96-byte
 * r||s produced by tls_key_sign(). Only valid for signing-range algorithms
 * (TLS_ALG_IS_SIGNING).
 * @param alg Signature scheme to use; must be compatible with key->type.
 */
tls_key_op_result_t tls_key_verify(const uint8_t *content, size_t content_len,
                                    const uint8_t *sig, size_t sig_len,
                                    const struct tls_key *key, tls_alg_t alg);

/**
 * @brief Sign @p content with @p key, writing the raw signature to @p sig_out.
 *
 * Supports ECDSA P-256/SHA-256 (64-byte output) and ECDSA P-384/SHA-384
 * (96-byte output) using RFC 6979 deterministic nonces. The output is the
 * raw r||s form; DER-encode it for X.509/TLS CertificateVerify. RSA private
 * signing is not implemented and returns TLS_KEY_OP_UNSUPPORTED.
 * @param alg Signature scheme to use; must be compatible with key->type.
 * @p sig_len_out receives the number of bytes written on success (at least
 * 64 bytes for P-256, 96 for P-384).
 */
tls_key_op_result_t tls_key_sign(const uint8_t *content, size_t content_len,
                                  uint8_t *sig_out, size_t *sig_len_out,
                                  const struct tls_key *key, tls_alg_t alg);

/**
 * @brief One-shot encrypt.  Allocates and returns a self-describing blob:
 *
 *   <uint16_t iv_len> <iv> <uint16_t ct_len> <ciphertext> <uint16_t tag_len> <tag>
 *
 * All uint16_t values are little-endian.  For RSA-OAEP iv_len and tag_len
 * are 0.  For CBC tag_len is 0.  The RNG health check is performed internally.
 *
 * @param key    Key to encrypt with; alg and key type must be compatible.
 * @param alg    Cipher to use (e.g. TLS_ALG_AES_256_GCM).
 * @param in     Plaintext input.
 * @param in_len Plaintext length in bytes.
 * @return Allocated blob on success, NULL on any error
 *         (bad args, RNG failure, allocation failure, or cipher error).
 *         Free with tls_cipher_blob_free().
 */
uint8_t *tls_cipher_encrypt(struct tls_key *key, tls_alg_t alg,
                          const uint8_t *in, size_t in_len);

/**
 * @brief One-shot encrypt with additional authenticated data (AAD).
 *        The AAD is authenticated but not encrypted; supply the identical
 *        bytes when decrypting. RSA-OAEP and CBC do not support AAD —
 *        a non-NULL aad or non-zero aad_len returns NULL for those algorithms.
 *        Otherwise identical to tls_cipher_encrypt().
 */
uint8_t *tls_cipher_encrypt_aad(struct tls_key *key, tls_alg_t alg,
                               const uint8_t *aad, size_t aad_len,
                               const uint8_t *in, size_t in_len);

/**
 * @brief One-shot decrypt from an encrypt blob.  Allocates and returns a
 *        self-describing plaintext blob:
 *
 *   <uint16_t plain_len> <plaintext>
 *
 * @p blob must be a buffer previously returned by tls_cipher_encrypt() or
 * tls_cipher_encrypt_aad() (or any externally constructed blob in the same
 * format).  For GCM/CCM the auth tag is verified before decrypting; returns
 * NULL on mismatch.
 *
 * @param key   Key to decrypt with.
 * @param alg   Cipher used to encrypt.
 * @param blob  Self-describing ciphertext blob.
 * @return Allocated plaintext blob on success, NULL on any error.
 *         Free with tls_cipher_blob_free().
 */
uint8_t *tls_cipher_decrypt(const struct tls_key *key, tls_alg_t alg,
                          const uint8_t *blob);

/**
 * @brief One-shot decrypt with additional authenticated data.
 *        The AAD must match what was passed to tls_cipher_encrypt_aad().
 *        RSA-OAEP and CBC do not support AAD — a non-NULL aad or non-zero
 *        aad_len returns NULL for those algorithms.
 *        Otherwise identical to tls_cipher_decrypt().
 */
uint8_t *tls_cipher_decrypt_aad(const struct tls_key *key, tls_alg_t alg,
                               const uint8_t *aad, size_t aad_len,
                               const uint8_t *blob);

/**
 * @brief Zero and free a blob returned by tls_cipher_encrypt(),
 *        tls_cipher_encrypt_aad(), tls_cipher_decrypt(), or tls_cipher_decrypt_aad().
 *        Safe to call with NULL.
 */
void tls_cipher_blob_free(uint8_t *buf);

/**
 * @brief Assemble a ciphertext blob from separately held fields.
 *
 * Use this when IV, ciphertext, and tag arrive as distinct buffers (e.g.
 * received over the network) and need to be packed into the blob format
 * expected by tls_cipher_decrypt() / tls_cipher_decrypt_aad().
 *
 * Blob layout:
 *   <uint16_t iv_len><iv><uint16_t ct_len><ct><uint16_t tag_len><tag>
 *
 * Any field may be NULL with a corresponding length of 0 (e.g. RSA-OAEP
 * has no IV or tag; CBC has no tag).
 *
 * @param iv      IV/nonce bytes, or NULL.
 * @param iv_len  Length of @p iv in bytes.
 * @param ct      Ciphertext bytes.
 * @param ct_len  Length of @p ct in bytes.
 * @param tag     Authentication tag bytes, or NULL.
 * @param tag_len Length of @p tag in bytes.
 * @return Allocated ciphertext blob on success, NULL on allocation failure.
 *         Free with tls_cipher_blob_free().
 */
uint8_t *tls_cipher_blob_assemble(const uint8_t *iv,  size_t iv_len,
                                   const uint8_t *ct,  size_t ct_len,
                                   const uint8_t *tag, size_t tag_len);

#ifdef __cplusplus
}
#endif

#endif /* TLS_KEY_H */
