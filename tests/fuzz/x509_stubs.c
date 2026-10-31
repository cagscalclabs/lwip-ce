#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "hash.h"
#include "rsa.h"

uint8_t __rsa_transient[RSA_TRANSIENT_SIZE];

void lwip_event_emit_code(uint8_t module, uint8_t kind, uint32_t loc, uint16_t extra)
{
    (void)module; (void)kind; (void)loc; (void)extra;
}
void tls_crypto_guard_enable(void) {}
void tls_crypto_guard_disable(void) {}
void *tls_fileio_alloc(size_t size) { return malloc(size); }
void tls_fileio_free(void *ptr) { free(ptr); }
void tls_secure_memzero(void *ptr, size_t len) { memset(ptr, 0, len); }
bool tls_hash_context_init(struct tls_hash_context *ctx, uint8_t algorithm)
{
    (void)algorithm;
    memset(ctx, 0, sizeof(*ctx));
    return true;
}
void tls_hash_update(struct tls_hash_context *ctx, const uint8_t *data, size_t len)
{
    (void)ctx; (void)data; (void)len;
}
void tls_hash_digest(struct tls_hash_context *ctx, uint8_t *digest)
{
    (void)ctx;
    memset(digest, 0, 32);
}
bool tls_p256_verify(const uint8_t sig[64], const uint8_t hash[32], const uint8_t pub[65])
{
    (void)sig; (void)hash; (void)pub;
    return false;
}
bool tls_p384_verify(const uint8_t sig[96], const uint8_t hash[48], const uint8_t pub[97])
{
    (void)sig; (void)hash; (void)pub;
    return false;
}
bool tls_rsa_decrypt_signature(const uint8_t *signature, size_t signature_len, uint8_t *outbuf,
                               const struct tls_rsa_key *key)
{
    (void)signature; (void)key;
    memset(outbuf, 0, signature_len);
    return false;
}
bool tls_rsa_pkcs1_v15_sha256_verify(const uint8_t *sig, size_t sig_len, const uint8_t digest[32],
                                     const struct tls_rsa_key *key)
{
    (void)sig; (void)sig_len; (void)digest; (void)key;
    return false;
}
bool tls_rsa_pss_verify(const uint8_t *encoded_msg, size_t em_len, const uint8_t *mhash,
                        size_t mhash_len, uint8_t hash_alg)
{
    (void)encoded_msg; (void)em_len; (void)mhash; (void)mhash_len; (void)hash_alg;
    return false;
}
