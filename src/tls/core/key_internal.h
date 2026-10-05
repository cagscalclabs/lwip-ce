#ifndef TLS_KEY_INTERNAL_H
#define TLS_KEY_INTERNAL_H

#include "../includes/key.h"

/* Inspect the type before accessing any key union member. */
static inline bool tls_key_supports_operation(const struct tls_key *key, tls_alg_t alg)
{
    if (!key) return false;
    switch (alg)
    {
        case TLS_ALG_RSA_PSS_RSAE_SHA256:
        case TLS_ALG_RSA_PKCS1_SHA256:
        case TLS_ALG_RSA_OAEP_SHA256:
            return key->type == TLS_KEY_TYPE_RSA;
        case TLS_ALG_ECDSA_SECP256R1_SHA256:
            return key->type == TLS_KEY_TYPE_EC_P256;
        case TLS_ALG_AES_128_GCM:
        case TLS_ALG_AES_128_CCM:
        case TLS_ALG_AES_128_CBC:
            return key->type == TLS_KEY_TYPE_AES && key->aes.data && key->aes.len == 16;
        case TLS_ALG_AES_256_GCM:
        case TLS_ALG_AES_256_CCM:
        case TLS_ALG_AES_256_CBC:
            return key->type == TLS_KEY_TYPE_AES && key->aes.data && key->aes.len == 32;
        default:
            return false;
    }
}

#endif
