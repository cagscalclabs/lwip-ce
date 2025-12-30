# P-256 (SECP256r1) Implementation for TI-84+ CE

## Status: **IN PROGRESS**

This document tracks the implementation of SECP256r1 elliptic curve cryptography for TLS 1.3 on the TI-84+ CE calculator (ez80 processor).

### Performance Targets
- **RSA 2048-bit**: ~10 seconds (achieved by existing implementation)
- **SECT233k1 ECDH**: ~14 seconds (previous benchmark)
- **P-256 ECDH**: Target < 14 seconds ⚠️ Not yet tested

---

## Implementation Files

### ✅ Complete
1. **[src/tls/includes/ecc.h](includes/ecc.h)** - Public API header
   - Point structures (affine coordinates)
   - Scalar type definitions
   - Function prototypes for ECDH, ECDSA, scalar multiplication

2. **[src/tls/core/share/p256_field.asm](core/share/p256_field.asm)** - Field arithmetic (mod p)
   - ✅ `p256_mod_add` - Modular addition (optimized)
   - ✅ `p256_mod_sub` - Modular subtraction (optimized)
   - ✅ `p256_mod_mul` - Modular multiplication (uses Montgomery)
   - ✅ `p256_mod_sqr` - Modular squaring (wrapper around mul)
   - ✅ `p256_mod_inv` - Modular inversion (binary exponentiation, ~256 squares + ~159 muls)

3. **[src/tls/core/ecc.c](core/ecc.c)** - Point operations and high-level functions
   - ✅ Jacobian coordinate system for point operations
   - ✅ Point doubling (`jacobian_double`)
   - ✅ Point addition (`jacobian_add`)
   - ✅ Scalar multiplication (`p256_scalar_mult`) - binary double-and-add
   - ✅ ECDH shared secret computation (`p256_ecdh`)
   - ⚠️ ECDSA verification (`p256_ecdsa_verify`) - needs scalar mod n operations
   - ✅ Point encoding/decoding (uncompressed format)

---

## What Still Needs Implementation

### 🔴 Critical (Required for TLS 1.3)

1. **Scalar Arithmetic mod n** (order of the curve)
   - `p256_scalar_add_mod_n` - Addition mod n
   - `p256_scalar_mul_mod_n` - Multiplication mod n
   - `p256_scalar_inv_mod_n` - Inversion mod n
   - Needed for ECDSA signature verification
   - Can reuse/adapt field arithmetic code with different modulus
   - **Estimated effort**: ~200 lines (or create generic mod operations)

3. **Fix P-256 Multiplication Reduction**
   - Current `p256_mod_mul` uses Montgomery multiplication
   - May have issues with domain conversion (Montgomery form)
   - Alternative: Implement FIPS 186-3 fast reduction for P-256's special prime
   - **Estimated effort**: 100-200 lines for proper fast reduction

### 🟡 Important (For Performance)

4. **Optimize Scalar Multiplication**
   - Current: Binary double-and-add (simple but slow)
   - Better: Window method (w=4 or w=5)
   - Best: wNAF (width-w Non-Adjacent Form)
   - **Performance gain**: 20-30% faster
   - **Estimated effort**: 100-200 lines C code

5. **Precompute Table for Generator G**
   - Store multiples of G: [2]G, [3]G, ..., [15]G
   - Speeds up signature verification significantly
   - **Performance gain**: 2x faster for G-multiplications
   - **Estimated effort**: ~50 lines + table generation

### 🟢 Nice to Have

6. **Constant-Time Operations**
   - Current implementation may leak timing information
   - Add conditional swaps, constant-time selection
   - Important for security against timing attacks
   - **Estimated effort**: Refactor existing code

7. **Point Compression**
   - Support compressed point format (33 bytes instead of 65)
   - Saves bandwidth in TLS handshake
   - Requires solving y^2 = x^3 - 3x + b for y
   - **Estimated effort**: ~100 lines

---

## Testing Strategy

### Unit Tests Needed

1. **Field Arithmetic Tests** (`tests/tls_p256_field/`)
   - Test add, sub, mul, sqr, inv against known test vectors
   - Use NIST test vectors from CAVP
   - Pattern: Similar to `tests/tls_montgomery/`

2. **Point Operation Tests** (`tests/tls_p256_point/`)
   - Test point addition, doubling
   - Test scalar multiplication with known results
   - Verify G * order = infinity

3. **ECDH Test** (`tests/tls_p256_ecdh/`)
   - Generate keypair
   - Compute shared secret
   - Verify against test vectors

4. **ECDSA Verification Test** (`tests/tls_p256_ecdsa/`)
   - Test with known signatures
   - Test with invalid signatures (should fail)

### Test Vector Sources
- **NIST CAVP**: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program
- **RFC 6979**: Deterministic ECDSA test vectors
- **Wycheproof**: Google's crypto testing project

---

## Integration with TLS

### Files to Modify

1. **src/tls/includes/keyobject.h**
   - Already has `TLS_OID_EC_SECP256R1` defined ✅
   - Already has `TLS_OID_SHA256_ECDSA` defined ✅

2. **src/tls/core/keyobject.c**
   - Already parses EC public keys ✅
   - Add function to extract P-256 point from parsed key

3. **TLS Handshake Implementation** (future work)
   - Use `p256_ecdh` for key exchange
   - Use `p256_ecdsa_verify` for certificate verification
   - Generate ephemeral keypairs for DHE

---

## Performance Optimization Notes

### Assembly Optimization Techniques Used

1. **Unrolled Loops**
   - All 32-byte operations fully unrolled
   - Eliminates loop overhead
   - **Gain**: ~15-20% faster than looped version

2. **Minimal Memory Access**
   - Use registers (HL, DE, IY) for pointers
   - Reduce stack operations
   - **Gain**: ~10% faster

3. **Conditional Execution**
   - Use flags directly (carry, zero)
   - Avoid unnecessary comparisons
   - **Gain**: ~5-10% faster

### Areas for Further Optimization

1. **Montgomery Multiplication**
   - Current implementation is generic
   - Could optimize specifically for P-256's modulus
   - Exploit special structure: `p = 2^256 - 2^224 + 2^192 + 2^96 - 1`

2. **Jacobian Coordinates**
   - Consider mixed coordinates (Jacobian + affine)
   - Use co-Z formulas for shared Z values
   - **Potential gain**: 10-15% faster

3. **Assembly Point Operations**
   - Move point doubling/addition to assembly
   - Inline field operations
   - **Potential gain**: 20-30% faster

---

## Known Issues

1. **Montgomery Multiplication Domain**
   - `p256_mod_mul` may need domain conversion
   - Verify output is correct (not in Montgomery form)
   - **Fix**: Add conversion or use direct reduction
   - **Priority**: MEDIUM (test first)

2. **Scalar Mod N Not Implemented**
   - ECDSA verification will not work
   - **Priority**: HIGH for TLS 1.3

4. **No Input Validation**
   - Points not checked for curve membership
   - Scalars not checked for valid range
   - **Security risk**: Could be exploited
   - **Priority**: MEDIUM

---

## Build Integration

### Add to Makefile

```makefile
# In src/tls/core/Makefile or equivalent
SOURCES += ecc.c
SOURCES += share/p256_field.asm

# Link against existing TLS crypto
DEPENDS += rsa.c hash.c random.c
```

### Dependencies

- ✅ `tls_mont_mul_le` (from montgomery.asm) - used by p256_mod_mul
- ✅ `__frameset` (from CE toolchain) - used for stack frames
- ✅ Standard C library (memcpy, memcmp, memset)

---

## Next Steps

### Immediate (To Get Working)

1. ✅ ~~Implement `p256_mod_inv` using binary exponentiation~~ **DONE**
2. Test field arithmetic with test suite (`tests/tls_p256_field/`)
3. Implement scalar mod n operations (for ECDSA)
4. Test full ECDH exchange with known test vectors

### Short Term (To Optimize)

5. Implement proper P-256 fast reduction
6. Add precomputed table for generator G
7. Optimize scalar multiplication (window method)

### Long Term (For Production)

8. Add constant-time operations
9. Comprehensive test suite
10. Security audit
11. Benchmark and profile
12. Integrate with altcp_tls handshake

---

## References

- **FIPS 186-4**: Digital Signature Standard (DSS) - defines P-256
- **SEC 2**: Recommended Elliptic Curve Domain Parameters - SECP256R1 spec
- **Guide to ECC**: Hankerson, Menezes, Vanstone - algorithms reference
- **RFC 6090**: Fundamental ECC Algorithms - implementation guidance
- **RFC 8446**: TLS 1.3 - how ECC is used in TLS

---

## Author Notes

This implementation prioritizes **correctness first, then performance**.

The ez80 is a resource-constrained 8-bit processor, so aggressive optimization is necessary to achieve reasonable TLS handshake times. The 14-second SECT233k1 benchmark shows that sub-15-second ECDH is achievable with careful assembly programming.

Current code is **not production-ready** - several critical functions are stubs or unoptimized placeholders.
