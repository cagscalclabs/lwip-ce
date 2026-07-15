#ifndef CONTEST_POWMOD_H
#define CONTEST_POWMOD_H

#include <stdint.h>

/*
 * Modular exponentiation: result = base^exp mod n
 *
 * All values are big-endian byte arrays of exactly n_len bytes.
 * n_len may be any value from 1 to 512 (i.e. up to 4096-bit modulus).
 *
 * Inputs:
 *   result  — output buffer, n_len bytes (caller-allocated)
 *   base    — base value, n_len bytes, 0 <= base < mod
 *   exp     — exponent, n_len bytes (leading zeros are fine)
 *   mod     — modulus, n_len bytes, must be odd and > 1
 *   n_len   — byte width of all operands
 *
 * Special cases your implementation must handle:
 *   base = 0  =>  result = 0
 *   base = 1  =>  result = 1
 *   exp  = 0  =>  result = 1  (by convention, even if base = 0)
 *   exp  = 1  =>  result = base mod n
 */
void powmod(
    uint8_t       *result,
    const uint8_t *base,
    const uint8_t *exp,
    const uint8_t *mod,
    uint16_t       n_len
);

#endif /* CONTEST_POWMOD_H */
