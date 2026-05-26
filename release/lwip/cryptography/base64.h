/*
 * File: base64.h
 * Author: Anthony Cagliano
 * Description: Module providing a Base64 encoder and decoder. #ifndef tls_base64_t
 *              #define tls_base64_t #include <stdint.h>
 * Generated: 2026-05-26T14:35:22Z
 */
/// @file base64.h
/// @author ACagliano
/// @brief Module providing a Base64 encoder and decoder.

#ifndef LWIP_PUBLIC_CRYPTOGRAPHY_BASE64_H
#define LWIP_PUBLIC_CRYPTOGRAPHY_BASE64_H

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
