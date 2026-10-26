# TLS 1.3 Implementation Details

## Architecture

### Current Implementation Status
- **Protocol**: TLS 1.3 only
- **Mode**: PSK-only (Pre-Shared Key without ECDHE)
- **Cipher Suites**: TLS_AES_128_GCM_SHA256 (0x13, 0x01) and TLS_AES_128_CCM_SHA256 (0x13, 0x04)
- **State**: Handshake, key derivation, and AES-GCM encryption/decryption working

### Not Yet Implemented
- Full ECDHE (Elliptic Curve Diffie-Hellman Ephemeral) handshake
- Certificate validation beyond parsing
- RSA signature verification
- 0-RTT session resumption
- Additional cipher suites beyond AES-128 GCM/CCM with SHA-256

## Cryptographic Primitives

### Random Number Generator

**Entropy Source**: Unmapped memory region at `$D65800`
- Exhibits quantum noise-induced voltage fluctuations (no memory cells)
- Validated via Dieharder statistical tests (1GB sample)

**Source Selection Algorithm**:
1. Poll 513 bytes starting at `$D65800`
2. For each byte, repeat 256 times:
   - Count ones across both reads for every bit position
   - Count adjacent-read disagreements for every bit position
3. Reject marginal counts outside 25--75% and disagreement counts outside 25--75%
4. Rank primarily by marginal balance; use disagreement balance only as a tie-breaker
5. Retain the true top four candidates and activate the first that passes two fresh production-cadence 1,024-sample 25--75% marginal windows, lag-1 through lag-4 screening, and fresh adjacent-pair gates

**Entropy Extraction**:
1. Read 952 observations from the selected source bit and pack them, eight per byte, into a 119-byte pool
2. Hash pool with SHA-256
3. Retain the first 24 digest bytes as a conditioned 192-bit contribution; the configured `H=0.269` accounts for 256.088 raw bits and preserves a 64-bit conditioning margin
4. Instantiate SHA-256 Hash_DRBG at 192-bit strength with one 24-byte entropy contribution and a separately collected 24-byte nonce contribution (at least 12 nonce bytes are required)
5. Reseed with one complete 24-byte conditioned contribution

**State-compromise boundary**: The calculator has no isolated execution,
immutable monotonic state, secure persistent storage, or guaranteed secure
erasure. Hash_DRBG state and pending reseed material therefore cannot be
protected from an attacker capable of reading or modifying process memory or
restoring an earlier machine state.

### Hash Functions
- **SHA-256**: Implemented (assembly optimized)
- **SHA-384**: Not implemented

### Key Derivation
- **HKDF** (HMAC-based KDF, RFC 5869): Implemented
- **HKDF-Expand-Label** (TLS 1.3 specific): Implemented
- Uses SHA-256 as underlying hash

### Symmetric Encryption
- **AES-GCM**: Implemented (supports 128, 192, and 256-bit keys)
- **AES-CBC**: Implemented (supports 128, 192, and 256-bit keys)
- **AES-CCM**: Not implemented

### Asymmetric Cryptography
- **RSA**: Modular exponentiation implemented, PSS padding not implemented
- **X25519**: Field arithmetic implemented, key exchange not integrated

## Required Object Identifiers (ASN.1)

### For TLS 1.3 Compliance

#### Cipher Suites (TLS Extension)
These are negotiated in TLS handshake, not ASN.1 OIDs:
- **TLS_AES_128_GCM_SHA256**: `0x13, 0x01` (REQUIRED, currently supported)
- **TLS_AES_128_CCM_SHA256**: `0x13, 0x04` (currently supported)
- **TLS_AES_256_GCM_SHA384**: `0x13, 0x02` (recommended, requires SHA-384)
- **TLS_CHACHA20_POLY1305_SHA256**: `0x13, 0x03` (optional)

#### Supported Groups (ECDHE)
For full TLS 1.3 compliance, must support at least one of:
- **x25519**: `1.3.101.110` - Not yet defined in enum
- **secp384r1** (P-384): `1.3.132.0.34` - Not yet defined

#### Signature Algorithms (X.509)
Currently defined in `keyobject.h`:
- **sha256WithRSAEncryption**: `1.2.840.113549.1.1.11` - `TLS_OID_SHA256_RSA_ENCRYPTION`
- **ecdsa-with-SHA256**: `1.2.840.10045.4.3.2` - `TLS_OID_SHA256_ECDSA`

For broader compatibility, consider adding:
- **sha384WithRSAEncryption**: `1.2.840.113549.1.1.12` - Already defined as `TLS_OID_SHA384_RSA_ENCRYPTION`
- **rsassa-pss**: `1.2.840.113549.1.1.10` - Not yet defined

#### Public Key Algorithms
Currently defined:
- **rsaEncryption**: `1.2.840.113549.1.1.1` - `TLS_OID_RSA_ENCRYPTION`
- **id-ecPublicKey**: `1.2.840.10045.2.1` - `TLS_OID_EC_PUBLICKEY`

#### Encryption Algorithms (for encrypted private keys)
Currently defined:
- **aes128-GCM**: `2.16.840.1.101.3.4.1.2` - `TLS_OID_AES_128_GCM`
- **aes256-GCM**: `2.16.840.1.101.3.4.2.1` - `TLS_OID_AES_256_GCM`
- **aes128-CBC**: `2.16.840.1.101.3.4.1.2` - `TLS_OID_AES_128_CBC`
- **aes256-CBC**: `2.16.840.1.101.3.4.1.42` - `TLS_OID_AES_256_CBC`

#### Key Derivation Functions
Currently defined:
- **PBKDF2**: `1.2.840.113549.1.5.12` - `TLS_OID_PBKDF2`
- **PBES2**: `1.2.840.113549.1.5.13` - `TLS_OID_PBES2`
- **HMAC-SHA256**: `1.2.840.113549.2.9` - `TLS_OID_HMAC_SHA256`

## Minimum Compliance Requirements

### For Basic TLS 1.3 Server Compatibility
1. **Cipher Suite**: TLS_AES_128_GCM_SHA256 ✅ (implemented)
2. **Key Exchange**: At least one of:
   - ECDHE with x25519 ⚠️ (field arithmetic only)
3. **Signature Algorithm**: At least one of:
   - rsa_pss_rsae_sha256 ❌ (not implemented)
   - rsa_pkcs1_sha256 ⚠️ (verify only, no PSS)

### Current Workaround
**PSK-only mode**: Bypasses certificate authentication and ECDHE by using pre-shared keys. This works but is not standard TLS 1.3 full handshake.

## Implementation Roadmap

### Phase 1: Complete ECDHE (for full handshake)
1. Implement x25519 shared secret derivation
2. Integrate into handshake state machine

### Phase 2: Certificate Validation
1. Implement RSA-PSS signature verification
2. Add certificate chain validation
3. Add hostname verification

### Phase 3: Session Resumption
1. Implement PSK ticket generation
2. Implement 0-RTT early data
3. Add resumption secret derivation

### Phase 4: Additional Cipher Suites
1. Implement SHA-384 (for AES-256-GCM)
2. Consider ChaCha20-Poly1305 (optional)

## File Organization

### Core Cryptographic Components
- `src/tls/core/primitives/sha256.s` - SHA-256 hash (optimized assembly)
- `src/tls/core/primitives/aes.c`, `aes.s` - AES block cipher and modes
- `src/tls/core/primitives/bytes.s` - constant-time byte primitives
- `src/tls/core/hmac.c` - HMAC construction
- `src/tls/core/primitives/p256.s` - NIST P-256 arithmetic
- `src/tls/core/primitives/rsa.s` - RSA multi-precision arithmetic
- `src/tls/core/hkdf.c` - HKDF key derivation
- `src/tls/core/primitives/random.s` - TRNG implementation
- `src/tls/core/rsa.c` - RSA encoding and verification orchestration
- `src/tls/core/share/x25519_*.asm` - X25519 field arithmetic

### Protocol Components
- `src/tls/core/handshake.c` - TLS 1.3 handshake state machine
- `src/tls/core/keyobject.c` - X.509 certificate/key parsing
- `src/tls/core/asn1.c` - ASN.1 DER parser
- `src/tls/core/base64.c` - Base64 codec (for PEM)

### Integration
- `src/apps/altcp_tls/altcp_tls_ce.c` - lwIP integration layer

## Testing

### Current Test Suites
- `tests/tls_handshake_psk/` - PSK handshake, key derivation, encrypt/decrypt
- `tests/tls_x509_object/` - X.509 certificate parsing (RSA)
- `tests/tls_hkdf/` - HKDF key derivation vectors
- `tests/tls_x25519/` - X25519 key exchange vectors

All tests use CEmu autotester with CRC validation of VRAM output.
