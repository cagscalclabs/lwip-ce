# TLS 1.3 Implementation TODO

## Current Status

✅ **Working**: PSK-only handshake with AES-128-GCM-SHA256
⚠️ **Blocked**: Full TLS 1.3 handshake (needs ECDHE + cert validation)

---

## Critical Path to Full TLS 1.3

### 1. X25519 Key Exchange

#### ✅ Already Implemented
- Field arithmetic (mod 2^255-19): multiplication, squaring
- Montgomery ladder infrastructure
- Basic field operations optimized in assembly

#### 🔴 Still Needed
- Complete scalar multiplication function (`x25519_scalarmult`)
- Public key generation (`x25519_public_key`)
- Shared secret computation (`x25519_shared_secret`)
- Integration with handshake state machine

X25519 has a **simpler** implementation (Montgomery curve, no point addition formula needed). This may be the better choice for constrained devices.

**Estimated effort**: ~300 lines (mostly integration, field ops done)

---

### 2. RSA-PSS Signature Verification ✅ **COMPLETE**

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
