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
#include "rsa.h"
#include "aes.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Operation identifier — selects cipher or signature hash/padding scheme.
 * Drives dispatch in tls_key_verify(), tls_key_sign(), tls_cipher_encrypt(),
 * and tls_cipher_decrypt().
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
    TLS_KEY_OP_UNKNOWN     = 3, /**< Unknown algorithm or wrong operation category.   */
} tls_key_op_result_t;

/** Key material type, independent of padding, hash, or cipher mode.
 * Zero initialization denotes an empty key. EC imports currently support P-256.
 */
typedef enum
{
    TLS_KEY_TYPE_UNKNOWN = 0,
    TLS_KEY_TYPE_RSA,
    TLS_KEY_TYPE_EC_P256,
    TLS_KEY_TYPE_AES,
} tls_key_type_t;

/** Key material. Only the union member selected by type is valid.
 * Manually constructed keys borrow their buffers and leave allocated=false.
 * AES keys contain 16 or 32 raw bytes, not a tls_aes_context.
 */
struct tls_key
{
    tls_key_type_t type;
    bool      allocated; /**< true when this struct was returned by tls_key_import()
                              and must be freed with tls_key_free(). */
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
 * freed with tls_key_free().  Pointer members (rsa.modulus, ec.data, etc.)
 * reference that same allocation — never point elsewhere.
 *
 * @param out       Receives the allocated key on success; set to NULL on error.
 * @param data      PEM text or raw DER bytes.
 * @param len       Length of @p data in bytes.
 * @param format    TLS_KEY_FORMAT_PEM or TLS_KEY_FORMAT_DER.
 * PEM and DER both infer type from their structure and algorithm OID.
 * Unsupported OIDs/restrictions are rejected, not treated as unrestricted keys.
 * Private-key imports currently expose only public components.
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
 * Dispatches on alg after checking key->type; hashes content with SHA-256.
 * Only valid for signing-range algorithms (TLS_ALG_IS_SIGNING).
 * @param alg Signature scheme to use; must be compatible with key->type.
 */
tls_key_op_result_t tls_key_verify(const uint8_t *content, size_t content_len,
                                    const uint8_t *sig, size_t sig_len,
                                    const struct tls_key *key, tls_alg_t alg);

/**
 * @brief Sign @p content with @p key, writing the raw signature to @p sig_out.
 *
 * @param alg Signature scheme to use; must be compatible with key->type.
 * @p sig_len_out receives the number of bytes written on success.
 * Returns TLS_KEY_OP_UNSUPPORTED for all algorithms until private-key
 * signing is implemented.
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
uint8_t *tls_cipher_encrypt(const struct tls_key *key, tls_alg_t alg,
                          const uint8_t *in, size_t in_len);

/**
 * @brief One-shot encrypt with additional authenticated data (AAD).
 *        The AAD is authenticated but not encrypted; supply the identical
 *        bytes when decrypting. RSA and CBC ignore AAD.
 *        Otherwise identical to tls_cipher_encrypt().
 */
uint8_t *tls_cipher_encrypt_aad(const struct tls_key *key, tls_alg_t alg,
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
 *        RSA and CBC ignore AAD. Otherwise identical to tls_cipher_decrypt().
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
