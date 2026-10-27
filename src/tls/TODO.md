# TLS 1.3 Implementation TODO

## Current Status

The TLS 1.3 client handshake is complete: ECDHE (X25519 and P-256 via HRR),
PSK resumption, certificate chain validation, RSA/ECDSA server signatures,
AEAD record protection. Per-requirement evidence lives in
`docs/tls-specifications.xml`.

What remains is optimization and deliberate scope exclusions, not missing
handshake functionality:

## Open Work

### 1. Symmetric-path performance

`_gf128_mul` in `src/tls/core/primitives/aes.s` is bit-serial: about 318
CPU cycles per byte of GHASH (~0.2 s for a 4096-byte record on a 48 MHz
eZ80), which dominates AEAD record processing. A 4-bit table (16 entries x
16 bytes, built from H at `tls_aes_init`) should cut that by roughly 3x.
Table indices are key-dependent, like the existing byte S-box.

### 2. Asymmetric primitives: what is left is algorithmic

All three asymmetric primitives now execute their hot loops from fast RAM
(`.x25519.reloc`, `.powmod.reloc`, and the two `.p256.*.reloc` MAC blocks),
so what remains is the number of multiplies, not where they run:

- P-256 field multiply: ~8 cycles per 8x8 MAC, i.e. already at the machine
  limit for `ld/ld/mlt/add`. Cutting it means Karatsuba over 16-byte halves
  (~25% fewer products, est. 15-20% end to end) or an x-only ladder for
  keygen (6M+3S per bit instead of 9M+5S, ~35%, needs a `y` recovery).
- Fixed-base comb for `d*G`: constant-time 4-bit table (~1.4 KB rodata) for
  the public generator, which also speeds the `u1*G` half of verification.
- RSA modexp: 18 modmuls at e=65537; Karatsuba/mixed radix is the only lever.

### 3. RSA-PSS Signature Verification (implemented)

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

RSA-PSS is **slower** but provides universal compatibility with RSA-only servers. ECDSA verification is also on the table once EC verification is wired in.

**Status**: Ready to use for certificate validation!

---

### 3. Full TLS 1.3 Handshake Integration

Integrate ECDHE and signature verification into handshake state machine.

#### 🔴 Required Changes

**In `handshake.c`**:
1. Add ECDHE key exchange to ClientHello:
   - Generate ephemeral keypair (X25519)
   - Send public key in `key_share` extension

2. Process ServerHello key share:
   - Extract server's public key
   - Compute shared secret via ECDH
   - Derive handshake traffic keys

3. Verify server certificate:
   - Parse certificate chain
   - Verify signature using RSA-PSS (or ECDSA if enabled)
   - Validate certificate chain up to trusted root

4. Update state machine transitions:
   - `TLS_STATE_CLIENT_HELLO_SENT` → wait for ServerHello
   - `TLS_STATE_SERVER_HELLO_RECEIVED` → compute ECDHE, derive keys
   - `TLS_STATE_CERTIFICATE_RECEIVED` → verify certificate
   - `TLS_STATE_HANDSHAKE_COMPLETE` → ready for application data

**Estimated effort**: ~500 lines C code

---

## Implementation Priority

### Phase 1: X25519 ECDHE
- Complete scalar multiplication + integration

### Phase 2: Certificate Validation
- Use RSA-PSS verification for signatures

### Phase 3: Handshake Integration
- Integrate ECDHE + cert verification into the state machine

---

## Additional Nice-to-Haves (Not Required)

- [ ] Certificate chain validation beyond single cert
- [ ] Hostname verification (match CN/SAN to domain)
- [ ] Session resumption (0-RTT)
- [ ] Additional cipher suites (AES-256-GCM, ChaCha20)
- [ ] P-384 curve support (overkill for calculator)

---

## Testing Requirements

After each phase, add test cases:

### For X25519
- `tests/tls_x25519/` - Already exists, expand with shared secret tests

### For Full Handshake
- `tests/tls_handshake_ecdhe/` - Full ECDHE handshake (not just PSK)
- Real server test: Connect to `https://www.google.com` or test server

---

## Current Blockers

**None** - All primitives have a clear implementation path. The main requirement is focused development time to:
1. Complete X25519 scalar ops
2. Integrate into handshake state machine
