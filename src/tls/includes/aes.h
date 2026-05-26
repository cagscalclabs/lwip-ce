
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
    uint32_t round_keys[60];
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
 * @brief One-shot AES-CCM encryption.
 */
bool tls_aes_ccm_encrypt(const uint8_t *key, size_t key_len,
                         const uint8_t *nonce, size_t nonce_len,
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *plaintext, size_t pt_len,
                         uint8_t *ciphertext, uint8_t *tag, size_t tag_len);

/********************************************************************
 * @brief One-shot AES-CCM decryption with tag verification.
 * @note Plaintext is zeroed if tag verification fails.
 */
bool tls_aes_ccm_decrypt(const uint8_t *key, size_t key_len,
                         const uint8_t *nonce, size_t nonce_len,
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *ciphertext, size_t ct_len,
                         const uint8_t *tag, size_t tag_len,
                         uint8_t *plaintext);

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
 * @brief Updates a GCM context with ciphertext bytes for tag computation
 *        only, without producing plaintext.
 *
 * Used as the verification pass of a streaming decrypt: walk the entire
 * ciphertext through GHASH first, compare the resulting tag against the
 * record trailer, and only then run the actual decryption pass on the
 * trusted ciphertext.
 *
 * @param ctx       AES-GCM context (must be post tls_aes_update_aad).
 * @param ct        Ciphertext bytes to authenticate.
 * @param ct_len    Length of ciphertext.
 * @returns @b true if success, @b false if error.
 */
bool tls_aes_update_ciphertext(struct tls_aes_context *ctx,
                               const uint8_t *ct, size_t ct_len);

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
 * @returns @b true if tag valid, @b false otherwise.
 * @note For security, this function does not decrypt the ciphertext. Call \p tls_aes_decrypt
 * if this function returns @b true.
 */
bool tls_aes_verify(struct tls_aes_context *ctx,
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *ciphertext, size_t ciphertext_len,
                    const uint8_t *tag);

#endif
