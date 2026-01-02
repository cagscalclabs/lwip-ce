# TLS 1.3 Full Handshake Test (Direct Function Calls)

## Overview

This test validates the TLS 1.3-PSK handshake implementation by directly calling TLS core functions and feeding pre-recorded packets into the state machine. This is a **unit test** of the TLS protocol logic, isolated from lwIP's network stack.

**No network connection required** - this test runs standalone in CEmu, making it suitable for CI/CD testing.

## What This Tests

1. **PSK Context Initialization**: Verifies TLS context is correctly initialized with pre-shared key and identity
2. **ServerHello Processing**: Tests parsing of ServerHello message and extraction of cipher suite and server random
3. **Handshake Key Derivation**: Validates HKDF-based key derivation produces non-zero keys
4. **Finished Message Generation**: Tests generation of the client Finished message

## Test Approach

Instead of establishing a live network connection, this test:

1. Uses hardcoded PSK and identity values
2. Generates a ClientHello message to initialize the handshake state
3. Feeds pre-recorded ServerHello packet into `tls_process_server_hello()`
4. Calls key derivation functions directly
5. Verifies state transitions and outputs

This approach isolates the TLS protocol logic from network I/O, making tests:
- **Deterministic**: Same inputs always produce same outputs
- **Fast**: No network latency
- **Reliable**: No dependency on external servers
- **Portable**: Runs in CEmu without network support

## Building

```bash
make
```

## Running in CEmu

```bash
AUTOTESTER_ROM='/path/to/ti84+ce.rom' make test:tls_handshake_loopback
```

Or manually:
```bash
cemu-autotester --rom /path/to/ti84+ce.rom --send bin/tls_handshake_loopback.8xp --launch TLSHAND
```

## Test Data

The pre-recorded ServerHello packet in `main.c` was captured from a real TLS 1.3-PSK handshake between:
- **Client**: lwIP TLS CE implementation
- **Server**: OpenSSL s_server with matching PSK

### Generating New Test Data

To capture a fresh handshake for testing:

```bash
# Start OpenSSL server with PSK
openssl s_server -tls1_3 -psk 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  -psk_identity client@test.com -nocert -accept 4433

# Capture traffic with Wireshark or tcpdump
# Extract ServerHello bytes from the capture
```

## Expected Output

The test displays results on the calculator screen with `printf()` and pauses after each test section for review:

**Screen 1 - Test 1:**
```
=== Test 1: Initialize PSK Context ===
[PASS] tls_handshake_init should succeed
[PASS] PSK should be stored correctly
[PASS] PSK identity should be stored correctly
[PASS] Context should be in INIT state

Press any key to continue...
```

**Screen 2 - Test 2:**
```
=== Test 2: Process ServerHello ===
[PASS] ClientHello generation should succeed
[PASS] ServerHello processing should succeed
[PASS] Cipher suite should be TLS_AES_128_GCM_SHA256
[PASS] Server random should be extracted

Press any key to continue...
```

**Screen 3 - Test 3:**
```
=== Test 3: Derive Handshake Keys ===
[PASS] Handshake key derivation should succeed
[PASS] Server handshake key should be non-zero
[PASS] Client handshake key should be non-zero

Press any key to continue...
```

**Screen 4 - Test 4:**
```
=== Test 4: Generate Finished Message ===
[PASS] Finished generation should succeed
[PASS] Finished message should be 36 bytes

Press any key to continue...
```

**Final Summary:**
```
ALL tests PASSED
```

(The test count is now 13: 4 in Test 1 + 4 in Test 2 + 3 in Test 3 + 2 in Test 4)

## Future Improvements

- [ ] Add expected intermediate values (handshake secret, finished verify data) for bit-exact validation
- [ ] Test error cases (invalid cipher suite, malformed ServerHello)
- [ ] Add server-side handshake tests
- [ ] Test session resumption (when X25519 KEX is implemented)
- [ ] Add full handshake flow test (ClientHello → Finished)
