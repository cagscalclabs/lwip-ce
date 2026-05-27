/**
 * @file passwords.h
 * @author Anthony Cagliano
 * @brief Provides PBKDF2 implementation.
 *
 * @license: GNU GPL v3.0
 * @reference: RFC 8018
 * @reference: RFC 6070
 */

#ifndef tls_passwords_h
#define tls_passwords_h
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*********************************************************************
 * @brief Create a secure key from a password.
 * @param password      Pointer to password.
 * @param passlen       Length of password.
 * @param salt              Pointer to salt.
 * @param saltlen       Length of salt.
 * @param key               Pointer to buffer to write key to.
 * @param keylen        Length of key to generate.
 * @param rounds        HMAC rounds per hash output block.
 * @param algorithm     The HMAC algorithm to use.
 */
bool tls_pbkdf2(const char *password, size_t passlen,
                const uint8_t *salt, size_t saltlen,
                uint8_t *key, size_t keylen,
                size_t rounds, uint8_t algorithm);

#endif
