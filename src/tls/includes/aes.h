/**
 * @file aes.h
 * @author Anthony Cagliano
 * @brief AES-GCM, AES-CCM, AES-CBC implementation
 * @license: GNU GPL v3.0
 * @source: https://github.com/B-Con/crypto-algorithms/
 */

#ifndef tls_aes_h
#define tls_aes_h

#include <stdbool.h>
#include <stdint.h>

enum tls_aes_modes
{
    TLS_AES_GCM,
    TLS_AES_CBC,
    TLS_AES_CCM
};

/** @struct private internal structure for GCM. */
struct _gcm_private
{
    uint8_t ghash_key[16];
    uint8_t auth_tag[16];
    uint8_t last_block[16];
    uint8_t last_block_len;
    uint8_t aad_cache[16];
    uint8_t aad_cache_len;
    uint8_t auth_j0[16];
    size_t aad_len;
    size_t ct_len;
    uint8_t lock; /**< sets allowed operations on the context. */
};

/** @struct private internal structure for CCM. */
struct _ccm_private
{
    uint8_t nonce[15];
    uint8_t nonce_len;
    uint8_t tag_len;
    uint8_t L;
    uint8_t mac[16];
    uint8_t ctr[16];
    uint8_t s0[16];
    uint8_t msg_cache[16];
    uint8_t msg_cache_len;
    uint8_t last_block[16];
    uint8_t last_block_len;
    size_t aad_len_total;
    size_t aad_len;
    size_t msg_len;
    size_t msg_processed;
    uint8_t lock;
};

/** @struct AES state context. */
struct tls_aes_context
{
    uint8_t mode;
    uint24_t keysize;
    uint8_t round_keys[15 * 16];
    uint8_t iv[16];
    uint8_t op_assoc; /**< sets to either encrypt or decrypt based on first operation done on context. */
    union
    {
        struct _ccm_private ccm;
        struct _gcm_private gcm;
    } private;
};

#define TLS_AES_BLOCK_SIZE 16
#define TLS_AES_IV_SIZE TLS_AES_BLOCK_SIZE
#define TLS_AES_AUTH_TAG_SIZE TLS_AES_BLOCK_SIZE

/********************************************************************
 * @brief Initializes an AES context.
 * @param ctx       Pointer to an AES context.
 * @param mode      AES mode identifier
 * @param key       Pointer to an AES key.
 * @param key_len        Length of AES key.
 * @param iv        Pointer to initialization vector.
 * @param iv_len     Length of initialization vector.
 * @returns @b true if success, @b false if error.
 */
bool tls_aes_init(struct tls_aes_context *ctx, uint8_t mode,
                  const uint8_t *key, size_t key_len,
                  const uint8_t *iv, size_t iv_len);

/********************************************************************
 * @brief Securely destroys an AES context, including its expanded key.
 * @param ctx Pointer to an AES context. May be NULL.
 */
void tls_aes_destroy_ctx(struct tls_aes_context *ctx);

/********************************************************************
 * @brief Initializes an AES-CCM context.
 * @param ctx       Pointer to an AES context.
 * @param key       Pointer to an AES key.
 * @param key_len   Length of AES key.
 * @param nonce     Pointer to nonce (7-13 bytes).
 * @param nonce_len Length of nonce.
 * @param tag_len   Tag length in bytes (4, 6, 8, 10, 12, 14, 16).
 * @param msg_len   Total plaintext/ciphertext length.
 * @param aad_len   Total associated data length.
 * @returns @b true if success, @b false if error.
 */
bool tls_aes_ccm_init(struct tls_aes_context *ctx,
                      const uint8_t *key, size_t key_len,
                      const uint8_t *nonce, size_t nonce_len,
                      uint8_t tag_len, size_t msg_len, size_t aad_len);

/********************************************************************
 * @brief Updates a context for associated data.
 * @param ctx       Pointer to an AES context.
 * @param aad       Pointer to associated data.
 * @param aad_len        Length of associated data.
 * @returns @b true if success, @b false if error.
 */
bool tls_aes_update_aad(struct tls_aes_context *ctx,
                        const uint8_t *aad, size_t aad_len);

/********************************************************************
 * @brief Encrypts a block of data.
 * @param ctx           Pointer to an AES context.
 * @param inbuf     Pointer to data to encrypt.
 * @param in_len        Length of data to encrypt.
 * @param outbuf    Pointer to buffer to write encrypted data.
 * @returns @b true if success, @b false if error.
 */
bool tls_aes_encrypt(struct tls_aes_context *ctx,
                     const uint8_t *inbuf, size_t in_len,
                     uint8_t *outbuf);

/********************************************************************
 * @brief Returns a digest for the current context state.
 * @param ctx       Pointer to an AES context.
 * @param digest        Pointer to a buffer to write the tag to.
 * @returns @b true if success, @b false if error.
 */
bool tls_aes_digest(struct tls_aes_context *ctx, uint8_t *digest);

/********************************************************************
 * @brief Decrypts a block of data.
 * @param ctx           Pointer to an AES context.
 * @param inbuf     Pointer to data to decrypt.
 * @param in_len        Length of data to decrypt.
 * @param outbuf    Pointer to buffer to write decrypted data.
 * @note GCM and CCM contexts produce plaintext only after a successful
 * tls_aes_verify() call on that context. A NULL output remains available for
 * internal authentication-only streaming.
 * @returns @b true if success, @b false if error.
 */
bool tls_aes_decrypt(struct tls_aes_context *ctx,
                     const uint8_t *inbuf, size_t in_length,
                     uint8_t *outbuf);

/********************************************************************
 * @brief Verifies the given AAD and ciphertext against the given tag.
 * @param ctx           Pointer to an AES context.
 * @param aad           Pointer to associated data to verifiy.
 * @param aad_len   Length of associated data.
 * @param ciphertext        Pointer to ciphertext data to verify.
 * @param ciphertext_len    Length of ciphertext data.
 * @param tag           Pointer to a tag to verify.
 * @note AAD and ciphertext pointers may be NULL when their corresponding
 * lengths are zero.
 * @returns @b true if tag valid, @b false otherwise.
 * @note Success transitions the context to its verified state, authorizing
 * subsequent plaintext-producing decryption.
 * @note For security, this function does not decrypt the ciphertext. Call \p tls_aes_decrypt
 * if this function returns @b true.
 */
bool tls_aes_verify(struct tls_aes_context *ctx,
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *ciphertext, size_t ciphertext_len,
                    const uint8_t *tag);

/**
 * Apply PKCS#7 padding to @p inbuf and write the result to @p outbuf.
 * @p outbuf must hold at least @p in_len + (16 - in_len % 16) bytes.
 * @p inbuf and @p outbuf may alias (in-place is safe).
 * @returns Padded length on success, 0 on invalid arguments.
 */
size_t tls_aes_pkcs7_apply(const uint8_t *inbuf, size_t in_len, uint8_t *outbuf);

/**
 * Strip PKCS#7 padding from @p buf (in-place).  Zeroes the removed bytes.
 * @p buf must be a multiple of 16 bytes.
 * @returns Unpadded length on success, 0 if padding is invalid.
 */
size_t tls_aes_pkcs7_remove(uint8_t *buf, size_t len);

#endif
