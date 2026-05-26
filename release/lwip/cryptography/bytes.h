/*
 * File: bytes.h
 * Author: Anthony Cagliano
 * Description: Secure comparison of two buffers.
 * Generated: 2026-05-26T14:35:22Z
 */
#ifndef LWIP_PUBLIC_CRYPTOGRAPHY_BYTES_H
#define LWIP_PUBLIC_CRYPTOGRAPHY_BYTES_H

#include <stdbool.h>
#include <stdint.h>

/***********************************************************************
 * @brief Secure comparison of two buffers.
 * @param buf1      Pointer to first buffer to compare.
 * @param buf2      Pointer to second buffer to compare.
 * @param len       Number of bytes to compare.
 */
bool tls_bytes_compare(const void *buf1, const void *buf2, size_t len);

/***********************************************************************
 * @brief Secure memory zeroing that cannot be optimized away.
 * @param ptr       Pointer to buffer to zero.
 * @param len       Number of bytes to zero.
 *
 * Uses volatile to prevent compiler from optimizing away the zeroing,
 * which is critical for clearing sensitive data like cryptographic keys.
 */
void tls_secure_memzero(void *ptr, size_t len);

#endif

