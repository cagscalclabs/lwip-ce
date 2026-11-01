# TLS 1.3 Implementation Details

## Architecture

### Current Implementation Status
- **Protocol**: TLS 1.3 only (RFC 8446)
- **Key exchange**: ECDHE with X25519 (preferred) and secp256r1/P-256
  (HelloRetryRequest path), plus DHE-less PSK resumption. P-384 ECDHE
  primitives (`tls_p384_publickey`/`tls_p384_secret`) are implemented, but the
  secp384r1 key-exchange group (0x0018) is not offered; P-384 is used for
  ECDSA signatures and trust anchors
- **Cipher suites**: TLS_AES_128_GCM_SHA256 (0x1301),
  TLS_AES_256_GCM_SHA384 (0x1302), and TLS_AES_128_CCM_SHA256 (0x1304).
  Non-PSK ClientHello offers those three in that order. PSK/resumption
  offers only the SHA-256 suites because the in-tree PSK store and binder
  are SHA-256 (RFC 8446 4.2.11 hash binding). RFC 8446 Appendix B.4 defines
  no AES-256-CCM suite (0x1305 is TLS_AES_128_CCM_8_SHA256, which needs an
  8-byte tag and is not offered).
- **Authentication**: RSA-PKCS#1 v1.5, RSA-PSS (rsa_pss_rsae_*), ECDSA P-256
  (ecdsa_secp256r1_sha256), and ECDSA P-384 (ecdsa_secp384r1_sha384) server
  signatures; X.509 chain validation against a signed trust store (RSA,
  P-256, and P-384 anchors) with hostname verification
- **Records**: AEAD records with `record_size_limit` (4096) negotiation,
  verify-before-decrypt, KeyUpdate

`docs/tls-specifications.xml` is the authoritative, per-requirement
compliance ledger (grade, code location, reviewer note). Do not duplicate
status claims here; check the ledger.

### Not Implemented (deliberate)
- Revocation (CRL/OCSP; a stapled OCSP extension is rejected, see ledger
  RFC 5280 6.1.3(a)(3))
- 0-RTT early data (never offered)
- id-RSASSA-PSS SubjectPublicKeyInfo certificates (fail-closed; ledger
  RFC 4055 1.2/3.1)
- Key-exchange groups other than X25519 and P-256 (no P-384 group, no
  P-521, no FFDHE). P-384 arithmetic is implemented and used for ECDSA and
  truststore anchors; only its key-exchange group (0x0018) is not offered

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
- **SHA-384**: Implemented (assembly optimized, truncated SHA-512 core)
- **SHA-512**: Implemented (assembly optimized, same core as SHA-384)

SHA-384 is the transcript/HKDF/Finished hash for TLS_AES_256_GCM_SHA384
(0x1302) and the hash used by `ecdsa_secp384r1_sha384`. SHA-512 is exposed
through the hash, HMAC, HKDF, PBKDF2, and MGF1 APIs; RFC 8446 defines no
TLS 1.3 cipher suite that uses SHA-512, so it is not negotiated by TLS.

### Key Derivation
- **HKDF** (HMAC-based KDF, RFC 5869): Implemented
- **HKDF-Expand-Label** (TLS 1.3 specific): Implemented
- Uses the negotiated cipher suite's hash: SHA-256 (32-byte secret/key
  material) for 0x1301/0x1304, SHA-384 (48-byte secrets, 32-byte AES keys)
  for 0x1302

### Symmetric Encryption
- **AES-GCM**: Implemented (supports 128, 192, and 256-bit keys)
- **AES-CBC**: Implemented (supports 128, 192, and 256-bit keys)
- **AES-CCM**: Implemented (supports 128, 192, and 256-bit keys)

### Asymmetric Cryptography
- **RSA**: Modular exponentiation implemented (PKCS#1 v1.5 and PSS-SHA256)
- **X25519**: Implemented and used for ECDHE (group 0x001d)
- **P-256**: ECDH and ECDSA (RFC 6979) implemented; offered for ECDHE (HRR) and
  used for P-256 certificate signatures
- **P-384**: ECDH and ECDSA (RFC 6979) implemented; used for P-384
  CertificateVerify, chain links, and truststore anchors. The ECDHE group
  (0x0018) is not offered

## Required Object Identifiers (ASN.1)

### For TLS 1.3 Compliance

#### Cipher Suites (TLS Extension)
These are negotiated in TLS handshake, not ASN.1 OIDs:
- **TLS_AES_128_GCM_SHA256**: `0x13, 0x01` (REQUIRED, supported)
- **TLS_AES_256_GCM_SHA384**: `0x13, 0x02` (supported, SHA-384 backend)
- **TLS_AES_128_CCM_SHA256**: `0x13, 0x04` (supported)
- **TLS_CHACHA20_POLY1305_SHA256**: `0x13, 0x03` (optional, not implemented)

`ecdsa_secp384r1_sha384` (0x0503) is implemented for CertificateVerify,
chain links, and truststore anchors. The offered signature_algorithms order is
ECDSA-P256, RSA-PSS-SHA256, then ECDSA-P384 (cert list: RSA-PKCS1, RSA-PSS,
ECDSA-P256, ECDSA-P384), so P-384 is the least preferred signature scheme.
The suite hash selects the transcript/PRF hash independently of the
CertificateVerify signature scheme's own hash.

#### Supported Groups (ECDHE)
Offered groups:
- **x25519**: `0x001d` (offered in ClientHello)
- **secp256r1** (P-256): `0x0017` (offered; selected through HRR)
- **secp384r1** (P-384): `0x0018` (primitives implemented, group not offered)

#### Signature Algorithms (X.509)
Recognized by `src/tls/core/x509.c` / `tls_algorithms.h`:
- **sha256WithRSAEncryption**: `1.2.840.113549.1.1.11` - `TLS_OID_SHA256_RSA_ENCRYPTION`
- **ecdsa-with-SHA256**: `1.2.840.10045.4.3.2` (P-256)
- **ecdsa-with-SHA384**: `1.2.840.10045.4.3.3` (P-384)
- **rsassa-pss** (SHA-256/MGF1-SHA-256/salt 32): `1.2.840.113549.1.1.10`

For broader compatibility, consider adding:
- **sha384WithRSAEncryption**: `1.2.840.113549.1.1.12` - OID defined, not implemented

#### Public Key Algorithms
Currently defined:
- **rsaEncryption**: `1.2.840.113549.1.1.1` - `TLS_OID_RSA_ENCRYPTION`
- **id-ecPublicKey**: `1.2.840.10045.2.1` - `TLS_OID_EC_PUBLICKEY`
  (namedCurve params: secp256r1 `1.2.840.10045.3.1.7`, secp384r1
  `1.3.132.0.34` / `TLS_OID_SECP384R1_BYTES`)

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
1. ~~Implement SHA-384 / SHA-512~~ done; SHA-384 wired into client key
   schedule, transcript, Finished, record layer, and 0x1302 suite; SHA-512
   shares the same assembly core (hash, HMAC, HKDF, MGF1)
2. Consider ChaCha20-Poly1305 (optional)
3. ~~P-384 certificate verification / ecdsa_secp384r1_sha384~~ done for
   CertificateVerify, chain links, and truststore anchors; P-384 ECDHE group
   (0x0018) remains unoffered

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
