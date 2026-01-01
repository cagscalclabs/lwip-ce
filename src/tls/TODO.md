# TLS 1.3 Implementation TODO

## Current Status

✅ **Working**: PSK-only handshake with AES-128-GCM-SHA256
⚠️ **Blocked**: Full TLS 1.3 handshake (needs ECDHE + ECDSA)

---

## Critical Path to Full TLS 1.3

### 1. Complete P-256 Implementation

#### ✅ Already Implemented
- Field arithmetic (mod p): add, sub, mul, sqr, inv
- Point operations: doubling, addition, scalar multiplication
- ECDH shared secret computation
- Point encoding/decoding (uncompressed format)

#### 🔴 Still Needed for ECDSA

**Scalar arithmetic mod n** (order of curve, not field prime):
- `p256_scalar_add_mod_n` - Addition modulo curve order
- `p256_scalar_mul_mod_n` - Multiplication modulo curve order
- `p256_scalar_inv_mod_n` - Inversion modulo curve order

These are needed for ECDSA signature verification. Can adapt existing field arithmetic code with different modulus (n instead of p).

**Estimated effort**: ~200 lines of assembly

---

### 2. X25519 Key Exchange (Alternative to P-256 ECDHE)

#### ✅ Already Implemented
- Field arithmetic (mod 2^255-19): multiplication, squaring
- Montgomery ladder infrastructure
- Basic field operations optimized in assembly

#### 🔴 Still Needed
- Complete scalar multiplication function (`x25519_scalarmult`)
- Public key generation (`x25519_public_key`)
- Shared secret computation (`x25519_shared_secret`)
- Integration with handshake state machine

X25519 is **faster** than P-256 and has **simpler** implementation (Montgomery curve, no point addition formula needed). This may be the better choice for constrained devices.

**Estimated effort**: ~300 lines (mostly integration, field ops done)

---

### 3. ECDSA Signature Verification

Required for validating server certificates signed with ECDSA.

#### Dependencies
- ✅ P-256 point operations (done)
- ✅ SHA-256 hash (done)
- 🔴 Scalar arithmetic mod n (see item 1 above)

#### Implementation needed
```c
bool p256_ecdsa_verify(
    const uint8_t *message_hash,  // SHA-256 hash of signed data
    const uint8_t *signature_r,    // 32 bytes
    const uint8_t *signature_s,    // 32 bytes
    const struct p256_point *public_key
);
```

**Algorithm**:
1. Compute u1 = hash * s^(-1) mod n
2. Compute u2 = r * s^(-1) mod n
3. Compute point R = u1*G + u2*Q
4. Verify R.x mod n == r

**Estimated effort**: ~150 lines C code (after scalar ops done)

---

### 4. RSA-PSS Signature Verification ✅ **COMPLETE**

Required for validating server certificates signed with RSA-PSS.

#### ✅ Fully Implemented
- ✅ RSA modular exponentiation (Montgomery multiplication)
- ✅ SHA-256 hash
- ✅ PSS padding verification (RFC 8017 compliant)
- ✅ MGF1 mask generation
- ✅ TLS 1.3 salt length enforcement (salt len = hash len)

Function signature:
```c
bool tls_rsa_pss_verify(
    const uint8_t *signature, size_t sig_len,
    const uint8_t *modulus, size_t mod_len,
    const uint8_t *mhash, size_t mhash_len,
    uint8_t hash_alg, uint8_t *scratch, size_t scratch_len
);
```

RSA-PSS is **slower** than ECDSA (~10 seconds vs ~2 seconds) but provides universal compatibility with RSA-only servers.

**Status**: Ready to use for certificate validation!

---

### 5. Full TLS 1.3 Handshake Integration

Integrate ECDHE and signature verification into handshake state machine.

#### 🔴 Required Changes

**In `handshake.c`**:
1. Add ECDHE key exchange to ClientHello:
   - Generate ephemeral keypair (P-256 or X25519)
   - Send public key in `key_share` extension

2. Process ServerHello key share:
   - Extract server's public key
   - Compute shared secret via ECDH
   - Derive handshake traffic keys

3. Verify server certificate:
   - Parse certificate chain
   - Verify signature using ECDSA or RSA-PSS
   - Validate certificate chain up to trusted root

4. Update state machine transitions:
   - `TLS_STATE_CLIENT_HELLO_SENT` → wait for ServerHello
   - `TLS_STATE_SERVER_HELLO_RECEIVED` → compute ECDHE, derive keys
   - `TLS_STATE_CERTIFICATE_RECEIVED` → verify certificate
   - `TLS_STATE_HANDSHAKE_COMPLETE` → ready for application data

**Estimated effort**: ~500 lines C code

---

## Implementation Priority

### Phase 1: Choose Key Exchange (Pick ONE)
**Option A**: Complete P-256 ECDHE
- ✅ Most compatible (widely supported)
- ⚠️ Needs scalar mod n operations
- ⚠️ Slower (~3-5 seconds for ECDH)

**Option B**: Complete X25519
- ✅ Faster (~1-2 seconds for ECDH)
- ✅ Simpler implementation (field ops done)
- ⚠️ Less universal support (but all modern servers support it)

**Recommendation**: Start with X25519 (faster path to working handshake), add P-256 later if needed.

---

### Phase 2: Choose Signature Algorithm (Pick ONE)
**Option A**: ECDSA with P-256
- ✅ Fast verification (~2 seconds)
- ⚠️ Requires scalar mod n operations (same as needed for P-256 ECDHE)
- ✅ Most modern servers use ECDSA

**Option B**: RSA-PSS
- ⚠️ Slow verification (~10 seconds)
- ✅ No new primitives needed (RSA already works)
- ✅ Universal compatibility

**Recommendation**: Implement ECDSA first (faster, pairs with P-256 work).

---

### Phase 3: Handshake Integration
Once you have:
- Key exchange (X25519 or P-256 ECDHE) ✓
- Signature verification (ECDSA or RSA-PSS) ✓

Then integrate into handshake state machine.

---

## Minimum Viable Full Handshake

**Shortest path to working TLS 1.3**:

1. ✅ Complete X25519 (~300 lines)
2. ✅ Implement P-256 scalar mod n (~200 lines assembly)
3. ✅ Implement ECDSA verify (~150 lines C)
4. ✅ Integrate into handshake (~500 lines C)

**Total**: ~1150 lines of code

**Estimated time**:
- X25519: 2-3 days
- Scalar ops: 1-2 days
- ECDSA: 1 day
- Integration: 2-3 days
- Testing/debugging: 2-3 days

**Total: ~10-14 days of focused work**

---

## Additional Nice-to-Haves (Not Required)

- [ ] Certificate chain validation beyond single cert
- [ ] Hostname verification (match CN/SAN to domain)
- [ ] Session resumption (0-RTT)
- [ ] Additional cipher suites (AES-256-GCM, ChaCha20)
- [ ] RSA-PSS (as fallback to ECDSA)
- [ ] P-384 curve support (overkill for calculator)

---

## Testing Requirements

After each phase, add test cases:

### For ECDSA
- `tests/tls_p256_ecdsa/` - Known signature verification vectors

### For X25519
- `tests/tls_x25519/` - Already exists, expand with shared secret tests

### For Full Handshake
- `tests/tls_handshake_ecdhe/` - Full ECDHE handshake (not just PSK)
- Real server test: Connect to `https://www.google.com` or test server

---

## Current Blockers

**None** - All primitives have a clear implementation path. The main requirement is focused development time to:
1. Complete X25519 or P-256 scalar ops
2. Implement ECDSA verification
3. Integrate into handshake state machine
