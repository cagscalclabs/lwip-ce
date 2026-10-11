#ifndef LWIP_CE_REFERENCE_P256_H
#define LWIP_CE_REFERENCE_P256_H

#include <stdbool.h>
#include <stdint.h>

bool tls_p256_publickey(uint8_t public_key[65], const uint8_t private_key[32]);
bool tls_p256_secret(uint8_t shared_secret[32], const uint8_t private_key[32],
                     const uint8_t peer_public[65]);
bool tls_p256_sign(uint8_t signature[64], const uint8_t message_hash[32],
                   const uint8_t private_key[32]);
bool tls_p256_verify(const uint8_t signature[64], const uint8_t message_hash[32],
                     const uint8_t public_key[65]);

#endif
