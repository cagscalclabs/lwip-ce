/**
 * @file base64.h
 * @author Anthony Cagliano
 * @brief Base64 encode/decode implementation.
 * @license: GNU GPL v3.0
 * @reference: RFC 4648
 * @reference: https://github.com/openssl/openssl
 */

#ifndef tls_base64_t
#define tls_base64_t

#include <stdint.h>

/***********************************************************************
 * @brief Encodes octets into sextets.
 * @param inbuf     Pointer to data to encode.
 * @param len       Size of data to encode.
 * @param outbuf    Pointer to buffer to write encoded data.
 * @returns Output size of encoded data.
 */
size_t tls_base64_encode(const uint8_t *inbuf, size_t len, uint8_t *outbuf);

/***********************************************************************
 * @brief Decodes sextets into octets.
 * @param inbuf     Pointer to data to decode.
 * @param len       Size of data to decode.
 * @param outbuf    Pointer to buffer to write decoded data.
 * @returns Output size of decoded data.
 */
size_t tls_base64_decode(const uint8_t *inbuf, size_t len, uint8_t *outbuf);

#endif
