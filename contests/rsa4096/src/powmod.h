#ifndef CONTEST_POWMOD_H
#define CONTEST_POWMOD_H

#include <stdint.h>

/*
 * Modular exponentiation: result = base^exp mod n
 *
 * All values are big-endian. base and mod are modulus_len bytes wide.
 * modulus_len may be 1–512 (up to 4096-bit modulus).
 *
 * Special cases your implementation must handle:
 *   base = 0  =>  result = 0
 *   base = 1  =>  result = 1
 *   exp  = 0  =>  result = 1  (by convention)
 *   exp  = 1  =>  result = base mod n
 *
 * Choose ONE of the two forms below and declare it in this file.
 * The test harness will call whichever signature is declared here.
 * Remove or comment out the form you are not implementing.
 *
 * --------------------------------------------------------------------
 * Form 1 — fixed u24 exponent
 *
 * Use this if you only need to handle public exponents (e.g. 65537).
 * Covers RSA encrypt and signature verify.
 *
 * Parameters:
 *   result       — output buffer, modulus_len bytes (caller-allocated)
 *   exp          — exponent as a 24-bit integer (e.g. 65537)
 *   base         — base value, modulus_len bytes, 0 <= base < mod
 *   mod          — modulus, modulus_len bytes, must be odd and > 1
 *   modulus_len  — byte width of base, mod, and result
 * --------------------------------------------------------------------
 */
void powmod(
    uint8_t        *result,
    const uint24_t  exp,
    const uint8_t  *base,
    const uint8_t  *mod,
    uint16_t        modulus_len
);

/*
 * --------------------------------------------------------------------
 * Form 2 — variable-length exponent buffer (BONUS — +4 points)
 *
 * Use this if you want to support full-width private exponents.
 * Passing all full-width exponent test vectors with this form also
 * covers RSA decrypt and sign operations.
 *
 * Parameters:
 *   result       — output buffer, modulus_len bytes (caller-allocated)
 *   exp          — exponent, exp_len bytes, big-endian
 *   exp_len      — byte width of the exponent (1–512)
 *   base         — base value, modulus_len bytes, 0 <= base < mod
 *   mod          — modulus, modulus_len bytes, must be odd and > 1
 *   modulus_len  — byte width of base, mod, and result
 * --------------------------------------------------------------------
 */
/*
void powmod(
    uint8_t        *result,
    const uint8_t  *exp,
    uint16_t        exp_len,
    const uint8_t  *base,
    const uint8_t  *mod,
    uint16_t        modulus_len
);
*/

#endif /* CONTEST_POWMOD_H */
