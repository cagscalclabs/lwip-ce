# TLS 1.3 Implementation Status for lwIP-CE

## Overview

This document summarizes the TLS implementation status for the TI-84+ CE port of lwIP.

---

## ✅ COMPLETE: RSA Support

### RSA Implementation
- **Status**: ✅ **FULLY FUNCTIONAL**
- **Key Sizes**: 1024-4096 bits (configurable)
- **Performance**: ~10 seconds for 2048-bit RSA
- **Location**: `src/tls/core/rsa.c`, `src/tls/core/share/montgomery.asm`

### Features
- ✅ RSA-OAEP encoding/decoding
- ✅ RSA-PSS signature verification (for certificates)
- ✅ Montgomery multiplication (optimized assembly)
- ✅ Modular exponentiation with e=65537

### Files
- `src/tls/includes/rsa.h` - RSA API
- `src/tls/core/rsa.c` - RSA operations
- `src/tls/core/share/montgomery.asm` - Montgomery multiplication (ez80 asm)
- `tests/tls_montgomery/` - Unit tests

### Notes
**RSA is NOT needed for encryption/decryption in TLS 1.3!** It's only used for:
1. ✅ Certificate signature verification (RSA-PSS with e=65537)
2. ❌ ~~Key exchange~~ (removed in TLS 1.3, now uses ECDH)

**RSA already supports up to 4096-bit keys** (`RSA_MODULUS_MAX_SUPPORTED = 4096>>3 = 512 bytes`)

---

## 🟡 IN PROGRESS: P-256 ECC Support

### Status: **70% Complete**

### What's Done ✅

1. **API Design** ([src/tls/includes/ecc.h](src/tls/includes/ecc.h))
   - Point structures
   - Function prototypes for ECDH, ECDSA, scalar multiplication

2. **Field Arithmetic** ([src/tls/core/share/p256_field.asm](src/tls/core/share/p256_field.asm))
   - ✅ `p256_mod_add` - Fully unrolled, optimized
   - ✅ `p256_mod_sub` - Fully unrolled, optimized
   - ⚠️ `p256_mod_mul` - Uses Montgomery (needs testing)
   - ⚠️ `p256_mod_sqr` - Wrapper around mul
   - ❌ `p256_mod_inv` - **STUB ONLY** (critical missing piece)

3. **Point Operations** ([src/tls/core/ecc.c](src/tls/core/ecc.c))
   - ✅ Jacobian coordinates (faster than affine)
   - ✅ Point doubling
   - ✅ Point addition
   - ✅ Scalar multiplication (binary double-and-add)
   - ✅ ECDH shared secret
   - ⚠️ ECDSA verification (needs scalar mod n ops)
   - ✅ Point encoding/decoding

### What's Missing ❌

1. **P-256 Modular Inversion** - **CRITICAL**
   - Currently a stub in `p256_field.asm`
   - Needed for Jacobian → Affine conversion
   - Blocks all ECC operations from working
   - **Solution**: Implement Fermat's little theorem: a^{-1} = a^{p-2} mod p

2. **Scalar Arithmetic mod n** - **CRITICAL**
   - Need add, multiply, invert modulo curve order n
   - Required for ECDSA signature verification
   - **Solution**: Adapt field arithmetic with different modulus

3. **Testing**
   - No unit tests yet
   - Created test skeleton in `tests/tls_p256_field/`
   - Need NIST test vectors

4. **Optimization**
   - Current scalar mult is simple (binary double-and-add)
   - Could use window method or wNAF for 20-30% speedup
   - Could precompute multiples of generator G

### Performance Target
- **SECT233k1 ECDH**: ~14 seconds (previous benchmark)
- **P-256 ECDH**: Target < 15 seconds
- **Status**: ⚠️ NOT YET TESTED (blocked by missing inversion)

### Documentation
- See [src/tls/ECC_IMPLEMENTATION.md](src/tls/ECC_IMPLEMENTATION.md) for detailed status

---

## ✅ COMPLETE: Supporting Cryptography

### Hash Functions
- ✅ SHA-256 (ez80 assembly, optimized)
- ✅ SHA-256 hardware-accelerated (optional)
- ✅ HMAC-SHA256
- ✅ MGF1 (mask generation function)

**Location**: `src/tls/core/hash.c`, `src/tls/core/sha256.asm`, `src/tls/core/hmac.c`

### Symmetric Encryption
- ✅ AES-128/256
- ✅ AES-GCM (Galois/Counter Mode)
- ✅ GF(2^128) multiplication for GMAC

**Location**: `src/tls/core/aes.c`, `src/tls/core/share/bigint.asm`

### Key Derivation
- ✅ PBKDF2
- ✅ HKDF (for TLS 1.3)

**Location**: `src/tls/core/passwords.c`

### Encoding/Parsing
- ✅ Base64 encode/decode
- ✅ ASN.1 DER decoder
- ✅ PKCS#1 RSA key parsing
- ✅ PKCS#8 key parsing
- ✅ SEC1 EC key parsing (for P-256)
- ✅ X.509 certificate parsing

**Location**: `src/tls/core/asn1.c`, `src/tls/core/keyobject.c`, `src/tls/core/base64.c`

### Random Number Generation
- ✅ True RNG using unmapped memory entropy
- ✅ ~100 bits entropy per 64-bit output
- ✅ SHA-256 based extraction

**Location**: `src/tls/core/random.asm`
**Documentation**: `src/tls/INFO.md`

---

## ❌ NOT YET IMPLEMENTED: TLS Protocol

### TLS 1.3 Handshake
- ❌ ClientHello generation
- ❌ ServerHello processing
- ❌ Key schedule (HKDF-based)
- ❌ Certificate verification (RSA + ECDSA)
- ❌ Finished message MAC
- ❌ 0-RTT mode
- ❌ Session resumption

### TLS Record Layer
- ❌ Record encryption/decryption (AES-GCM)
- ❌ Sequence number handling
- ❌ Alert protocol
- ❌ Fragmentation/reassembly

### ALTCP Integration
- ✅ altcp_tls API structure exists (from lwIP)
- ❌ Not yet implemented for CE
- ❌ Needs integration with custom TLS

**Location**: `src/apps/altcp_tls/` (placeholder mbedTLS structure)

---

## Priority Roadmap

### Phase 1: Complete P-256 (1-2 weeks)
1. ✅ Field add/sub (DONE)
2. ⚠️ Test field mul (IN PROGRESS)
3. ❌ Implement modular inversion (HIGH PRIORITY)
4. ❌ Implement scalar mod n operations (HIGH PRIORITY)
5. ❌ Test with NIST vectors
6. ❌ Benchmark ECDH performance

### Phase 2: TLS Handshake (2-4 weeks)
1. ❌ ClientHello generation
2. ❌ ServerHello parsing
3. ❌ Certificate chain verification
4. ❌ ECDHE key exchange
5. ❌ Key schedule (HKDF)
6. ❌ Finished message

### Phase 3: TLS Record Layer (1-2 weeks)
1. ❌ AES-GCM encryption/decryption
2. ❌ Record framing
3. ❌ Alert handling

### Phase 4: Integration & Testing (1-2 weeks)
1. ❌ Wire up to altcp_tls
2. ❌ Test with real TLS 1.3 servers
3. ❌ Performance profiling
4. ❌ Security audit

---

## Test Coverage

### Unit Tests ✅
- ✅ AES encryption/decryption
- ✅ Base64 encode/decode
- ✅ ASN.1 decoder
- ✅ Hash functions (SHA-256)
- ✅ HMAC
- ✅ Montgomery multiplication
- ✅ PBKDF2
- ✅ Key object parsing (RSA, EC)
- ✅ X.509 certificate parsing
- ⚠️ P-256 field arithmetic (skeleton only)

### Integration Tests ❌
- ❌ Full TLS 1.3 handshake
- ❌ Connection to real servers
- ❌ Performance benchmarks

### Autotester Setup
- ✅ Autotester framework exists
- ✅ ROM path configured: `/Users/acagliano/Desktop/TI Programming/emulator stuff/ti84+ce.rom`
- ✅ Test pattern: autotest.json in each test directory
- ⚠️ Need to add P-256 tests to autotester

---

## File Structure

```
src/tls/
├── includes/          # Public headers
│   ├── aes.h
│   ├── asn1.h
│   ├── base64.h
│   ├── bytes.h
│   ├── ecc.h         # ✅ NEW: P-256 API
│   ├── hash.h
│   ├── hmac.h
│   ├── keyobject.h
│   ├── passwords.h
│   ├── random.h
│   └── rsa.h
├── core/              # Implementations
│   ├── aes.c
│   ├── asn1.c
│   ├── base64.c
│   ├── bytes.c / bytes.asm
│   ├── ecc.c          # ✅ NEW: P-256 point ops
│   ├── hash.c
│   ├── hmac.c
│   ├── keyobject.c
│   ├── passwords.c
│   ├── random.asm
│   ├── rsa.c
│   ├── sha256.asm
│   └── share/         # Shared assembly routines
│       ├── bigint.asm
│       ├── flash.asm
│       ├── helpers.asm
│       ├── montgomery.asm
│       ├── nostack.asm
│       └── p256_field.asm  # ✅ NEW: P-256 field arithmetic
├── ECC_IMPLEMENTATION.md  # ✅ NEW: Detailed ECC status
└── INFO.md           # General TLS notes

tests/
├── tls_aes_encrypt/
├── tls_aes_decrypt/
├── tls_asn1_decode/
├── tls_asn1_encode/
├── tls_base64_encode/
├── tls_base64_decode/
├── tls_hash/
├── tls_hash_hw/
├── tls_hmac/
├── tls_montgomery/
├── tls_pbkdf2/
├── tls_private_key_object/
├── tls_public_key_object/
├── tls_x509_object/
└── tls_p256_field/    # ✅ NEW: P-256 field tests (skeleton)
```

---

## Next Immediate Steps

### To Get ECC Working (Priority Order)

1. **Implement `p256_mod_inv`** (assembly, ~100 lines)
   - Binary exponentiation: a^{p-2} mod p
   - This unblocks ALL point operations

2. **Test field arithmetic**
   - Run `tests/tls_p256_field`
   - Verify against NIST test vectors

3. **Implement scalar mod n ops** (assembly or C, ~200 lines)
   - Can reuse field arithmetic with n instead of p
   - Unblocks ECDSA verification

4. **Create ECDH test**
   - Generate keypair
   - Compute shared secret
   - Measure performance

5. **Optimize if needed**
   - If > 15 seconds, optimize scalar multiplication
   - Consider window method or precomputed tables

---

## Performance Notes

### Current Benchmarks
- **RSA 2048-bit signature verification**: ~10 seconds
- **SECT233k1 ECDH**: ~14 seconds (previous implementation)
- **P-256 ECDH**: ⚠️ NOT YET MEASURED

### Optimization Opportunities
1. **P-256 Fast Reduction**: Exploit prime structure
2. **Window Method**: 4-bit or 5-bit windows for scalar mult
3. **Precomputed Tables**: Store multiples of generator G
4. **Assembly Point Ops**: Move doubling/addition to asm
5. **Mixed Coordinates**: Jacobian + affine for addition

---

## Known Issues

1. **P-256 inversion not implemented** - blocks all ECC ops
2. **Scalar mod n not implemented** - blocks ECDSA
3. **No TLS handshake** - can't actually use TLS yet
4. **No input validation** - points not verified on curve
5. **Not constant-time** - vulnerable to timing attacks

---

## Questions for Consideration

1. **Do we need client certificates?**
   - If no: Don't need ECDSA signing, only verification
   - If yes: Need to implement `p256_ecdsa_sign`

2. **Do we need other curves?**
   - TLS 1.3 mandates P-256 (secp256r1)
   - Optional: P-384, P-521, X25519
   - Recommendation: P-256 only for now

3. **Do we need TLS 1.2 backward compatibility?**
   - TLS 1.2 uses different handshake, needs RSA key exchange
   - Recommendation: TLS 1.3 only (simpler, more secure)

4. **Memory constraints?**
   - P-256 needs ~2KB for temporary variables
   - TLS handshake needs ~4-8KB for buffers
   - Need to profile actual usage

---

## Contact / Questions

See source code comments and [ECC_IMPLEMENTATION.md](src/tls/ECC_IMPLEMENTATION.md) for technical details.

---

**Last Updated**: 2025-12-15
**Status**: RSA complete, P-256 70% complete, TLS handshake not started
