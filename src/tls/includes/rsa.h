
#ifndef tls_rsa_h
#define tls_rsa_h

#define RSA_MODULUS_MAX_SUPPORTED    4096>>3
#define RSA_MODULUS_MIN_SUPPORTED    1024>>3

#define RSA_PUBLIC_EXP  65537

bool tls_rsa_encode_oaep(const uint8_t *inbuf, size_t in_len, uint8_t *outbuf,
                         size_t modulus_len, const char *auth, uint8_t hash_alg);

size_t tls_rsa_decode_oaep(const uint8_t *inbuf, size_t in_len, uint8_t *outbuf, const char *auth, uint8_t hash_alg);

bool tls_rsa_encrypt(const uint8_t* inbuf, size_t in_len, uint8_t *outbuf,
                     const uint8_t* pubkey, size_t keylen, uint8_t hash_alg);

/* Montgomery multiply (little-endian limbs), len bytes. */
void tls_mont_mul_le(uint8_t *t, const uint8_t *a, const uint8_t *b,
                     const uint8_t *n, uint8_t n0inv, uint16_t len);

/**
 * @brief Verify an RSA-PSS signature using the public exponent 65537.
 *
 * @param signature     Pointer to the signature (big-endian, same length as modulus).
 * @param sig_len       Length of the signature/modulus in bytes (2048-bit => 256).
 * @param modulus       Pointer to the RSA modulus (big-endian).
 * @param mod_len       Length of the modulus in bytes.
 * @param mhash         Hash of the message to verify (already hashed).
 * @param mhash_len     Length of the hash (e.g., 32 for SHA-256).
 * @param hash_alg      Hash algorithm id (TLS_HASH_SHA256, etc.).
 * @param scratch       Caller-provided scratch buffer.
 * @param scratch_len   Length of the scratch buffer.
 * @return true on successful verification, false on failure.
 */
bool tls_rsa_pss_verify(const uint8_t *signature, size_t sig_len,
                        const uint8_t *modulus, size_t mod_len,
                        const uint8_t *mhash, size_t mhash_len,
                        uint8_t hash_alg, uint8_t *scratch, size_t scratch_len);


#endif
