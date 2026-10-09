/**
 * @file bytes.h
 * @author Anthony Cagliano
 * @brief Secure buffer compare and secure erasure functions.
 * @license: GNU GPL v3.0
 */

#ifndef tls_bytes_h
#define tls_bytes_h

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

/***********************************************************************
 * @brief Declares a reusable cleanup helper for a fixed-size array type,
 *        for use with TLS_AUTOZERO_BUF() below. Call once at file scope
 *        per distinct (type_, len_) pair -- the generated helper is
 *        shared by every TLS_AUTOZERO_BUF() using that same pair.
 *
 * __attribute__((cleanup(fn))) (a GCC/Clang extension, confirmed
 * supported by this project's ez80-clang/LLVM 19 toolchain) calls
 * `fn(&var)` when `var` leaves scope -- on EVERY exit path, including
 * early `return`/`goto`, not just a single hand-placed call. Since a
 * function definition cannot appear inside a block, the helper must be
 * declared at file scope with this macro before any TLS_AUTOZERO_BUF()
 * that uses the same (type_, len_) pair.
 *
 * @param type_ The element type (e.g. uint8_t).
 * @param len_  Number of elements (NOT bytes if type_ isn't 1 byte).
 */
#define TLS_AUTOZERO_DECL(type_, len_)                                       \
    static void tls_autozero_cleanup_##type_##_##len_(type_ (*p)[len_])      \
    {                                                                        \
        tls_secure_memzero(*p, sizeof(*p));                                  \
    }

/***********************************************************************
 * @brief Declares a fixed-size stack array that is automatically zeroed
 *        via tls_secure_memzero() on every exit from its enclosing
 *        scope. Requires a matching TLS_AUTOZERO_DECL(type_, len_) at
 *        file scope first.
 *
 * Usage:
 *     TLS_AUTOZERO_DECL(uint8_t, 32)   // once, at file scope
 *     ...
 *     bool some_handshake_fn(...)
 *     {
 *         TLS_AUTOZERO_BUF(uint8_t, early_secret, 32);
 *         // use early_secret[0..31] normally from here on;
 *         // any return/goto out of scope zeroes it automatically.
 *     }
 *
 * @param type_ The element type (e.g. uint8_t). Must match a prior
 *              TLS_AUTOZERO_DECL(type_, len_).
 * @param name_ The variable name to declare.
 * @param len_  Number of elements. Must match a prior
 *              TLS_AUTOZERO_DECL(type_, len_).
 */
#define TLS_AUTOZERO_BUF(type_, name_, len_) \
    type_ name_[len_] __attribute__((cleanup(tls_autozero_cleanup_##type_##_##len_)))

/***********************************************************************
 * @brief Struct-type counterpart to TLS_AUTOZERO_DECL(), for secret
 *        state held in a struct rather than a fixed array (e.g. an
 *        HMAC context whose ipad/opad hold derived key material). Call
 *        once at file scope per distinct struct type.
 *
 * @param type_ The struct tag (without the `struct` keyword), e.g.
 *              tls_hmac_context for `struct tls_hmac_context`.
 */
#define TLS_AUTOZERO_DECL_STRUCT(type_)                                      \
    static void tls_autozero_cleanup_##type_(struct type_ *p)                \
    {                                                                        \
        tls_secure_memzero(p, sizeof(*p));                                   \
    }

/***********************************************************************
 * @brief Struct-type counterpart to TLS_AUTOZERO_BUF(). Requires a
 *        matching TLS_AUTOZERO_DECL_STRUCT(type_) at file scope first.
 *
 * @param type_ The struct tag. Must match a prior
 *              TLS_AUTOZERO_DECL_STRUCT(type_).
 * @param name_ The variable name to declare.
 */
#define TLS_AUTOZERO_STRUCT(type_, name_) \
    struct type_ name_ __attribute__((cleanup(tls_autozero_cleanup_##type_)))

#endif
