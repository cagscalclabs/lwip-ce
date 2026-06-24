/**
 * @file url.h
 * @brief URL encoding/decoding for lwIP-CE
 * @author Anthony Cagliano
 * @author Claude Code
 *
 * @note Percent-encoding per RFC 3986. All functions operate on
 * caller-supplied buffers with no heap allocation.
 *
 * Known constraints:
 * - No URL parsing (scheme/host/path splitting) — encoding only.
 * - Space encodes as %20, not '+' (form encoding is not supported).
 */

#ifndef LWIP_CE_URL_H
#define LWIP_CE_URL_H

#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Percent-encode src into dst.
 * Unreserved characters (A-Z a-z 0-9 - _ . ~) are passed through.
 * All other bytes are encoded as %XX.
 *
 * @param dst      output buffer
 * @param dst_len  size of dst (including NUL terminator)
 * @param src      input string (NUL-terminated)
 * @return number of bytes written to dst (excluding NUL), or
 *         (size_t)-1 if dst is too small.
 */
size_t url_encode(char *dst, size_t dst_len, const char *src);

/**
 * Percent-encode a binary buffer into dst (same rules as url_encode).
 */
size_t url_encode_n(char *dst, size_t dst_len, const char *src, size_t src_len);

/**
 * Percent-decode src into dst.
 * %XX sequences are decoded; '+' is left as '+' (not decoded as space).
 *
 * @param dst      output buffer
 * @param dst_len  size of dst (including NUL terminator)
 * @param src      input string (NUL-terminated)
 * @return number of bytes written to dst (excluding NUL), or
 *         (size_t)-1 if dst is too small or input is malformed.
 */
size_t url_decode(char *dst, size_t dst_len, const char *src);

/**
 * Build a query string from key/value pairs into dst.
 * Encodes all keys and values and joins them with '&'.
 * Does NOT include a leading '?'.
 *
 * @param dst      output buffer
 * @param dst_len  size of dst
 * @param keys     NULL-terminated array of key strings
 * @param values   NULL-terminated array of value strings (parallel to keys)
 * @param count    number of pairs
 * @return number of bytes written (excluding NUL), or (size_t)-1 if too small.
 */
size_t url_build_query(char *dst, size_t dst_len,
                       const char * const *keys,
                       const char * const *values,
                       size_t count);

#ifdef __cplusplus
}
#endif

#endif /* LWIP_CE_URL_H */
