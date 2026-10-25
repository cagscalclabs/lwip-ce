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

#include <stddef.h>
#include <stdint.h>

/***********************************************************************
 * @brief Encodes octets into sextets.
 * @param inbuf     Pointer to data to encode.
 * @param len       Size of data to encode.
 * @param outbuf    Pointer to buffer to write encoded data.
 * @param out_cap   Capacity of @p outbuf in bytes; must be at least 4*ceil(len/3).
 *                  Returns 0 if the buffer is too small or arguments are NULL.
 * @returns Output size of encoded data, or 0 on error.
 */
size_t tls_base64_encode(const uint8_t *inbuf, size_t len, uint8_t *outbuf, size_t out_cap);

/***********************************************************************
 * @brief Decodes sextets into octets.
 * @param inbuf     Pointer to data to decode.
 * @param len       Size of data to decode.
 * @param outbuf    Pointer to buffer to write decoded data.
 * @param out_cap   Capacity of @p outbuf in bytes; must be at least (len/4)*3.
 *                  Returns 0 if the buffer is too small.
 * @returns Output size of decoded data, or 0 for invalid input. Input must be
 *          non-empty RFC 4648 base64 with a length divisible by four.
 */
size_t tls_base64_decode(const uint8_t *inbuf, size_t len, uint8_t *outbuf, size_t out_cap);

#endif
