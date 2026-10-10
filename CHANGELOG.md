## v1.0-rc2

- Completely removes the old SPKI pinning trust store, now implements a curated trust store derived from Certificate material in /etc/certs: Subject, SKI, expiry, key algorithm, and public key.
- Due to, at present, limited coverage for existing certificate chain signature algorithms (only RSA-2048), unsupported algorithm during verification throw ALERT("unsupported algorithm - pass") and proceed anyway. This is temporary behavior and will become fail closed once P-256 and/or larger RSA is added.
- Due to, at present, limited coverage for signature algorithms (only RSA-2048), our trust store includes only 46 roots out of ~150. At present, if a chain ends in a root we do not have, ALERT("root not in store") is thrown and the handshake proceeds. Again, this is temporary until P-256 and/or larger RSA is added.
- A transcript hashing bug in PSK session resumption was fixed.
Users can now disable TLS completely through the app config wizard, for any uncomfortable with connecting to secure stuff with their calculator.

## v1.0-rc3

- Stack initialization is now a bit different. Instead of `lwip_init_runtime` and then `lwip_start`, it's now just `lwip_start`. This dynamically-links into the APP, inits its runtime, syncs the imports table, then starts the non-network components of the stack (mainly timers and memory subsystem). Initializing the network requires a call to `lwip_network_up`. This allows people to use the stack for a memory system or for its async-API without using the network.
- A new "network-applications" release tag is created. I'll place services into this release that work with lwip. So far, an IRC client is there. (yes, Codex had a heavy hand in that--I just wanted something to test with quickly, and it turned out to work nicely).

## v1.0-rc4

- TLS now resolves a bug where the connection state would break when the server would send CertificateRequest. I forgot this step existed, so obviously on skip the transcript hash would become invalid.
- Adds an error traceback system.

## v1.0-stable

- Post TLS handshake bug with close notify and KeyUpdate silently dropped is now resolved.
- An additional size-guard for signature_len == key_len on rsa_pss is now included.
- Uninitialized function jumps in lwip.8xv now initialize to a defined no-op in the lib that sets an error state, instead of remaining jp $0, and possibly faulting.
- DAST testing now expands to exercise: (1) proper TLS ECDHE connect, (2) TLS PSK connect, (3) TLS invalid transcript (missing Record), (4) TLS CertificateVerify bad signature.

## v1.1-stable

- Implement Certificate expiry checks, hostname checks, SNI checks.
- Implement RTC auto-set to first build time/date.
- calc84maniac's AES eZ80 rewrite/optimization (PR #49)
- Adding parsers for XML, JSON, and urlencode/decode.
- **TLS certificate chain verification:** Replaced SPKI pinning with full adjacent-link chain signature verification. Each link is verified against the next certificate's public key using RSA-2048/SHA-256 (PKCS#1 v1.5). An unsupported signature algorithm emits an ALERT and accepts; a failed RSA verification aborts with ERROR. The topmost certificate's issuer is looked up in the truststore by subject name and, if RSA, verified for real — a bad signature aborts. Non-RSA or absent root emits ALERT and accepts (interim behavior until P-256 lands).
- **PSK/ticket session cache rewrite:** In-memory cache with up to 8 tickets, RTC-based expiry, and a single load/save at `tls_init`/`tls_cleanup` using the `lwIPPSKC` appvar. Replaces the previous per-ticket `lwIPPSKI` scheme.
- **AES-GCM chunked CTR fix:** Fixed an off-by-one (`idx <= blocks` vs `idx < blocks`) and a `size_t` underflow in the chunked CTR keystream path that caused AEAD decryption to desync on multi-block records. Validated against PyCryptodome test vectors.
- **TCP SYN retransmit hardening:** `TCP_SYNMAXRTX` raised from 2 to 6 to prevent premature connection abort on intermittently lossy links.
- **USB-Ethernet unplug fix:** Fixed a use-after-free crash when the USB adapter was unplugged while a bulk RX transfer was in flight. The disconnect path now sets a dead flag, counts in-flight transfers, and defers the device free until all callbacks have returned.
- **DHCP on link-up fix:** Bulk RX was being armed before the network link was confirmed up, causing the transfer to error and disable itself. RX arming is now gated on `netif_is_link_up()` and triggered from the link callback, fixing a bug where DHCP would stall in SELECTING indefinitely.
- **Connection inactivity watchdog:** The connect/handshake timeout is now an inactivity watchdog that resets on received frames and fires only on a completely dead line. Configurable via `lwip_conn_set_connect_timeout`. Covers WAITING, RESOLVING, and CONNECTING states.
- **Unified debug/logging API:** Single `lwip_set_event_cb()` shared callback replaces per-module debug structs and the old `tls_debug.h`. Debug events carry module, state, error code, line, and depth fields.
- **ClientHello deferred-send:** `altcp_write` `ERR_MEM` on ClientHello is now non-fatal; the record is cached and retried via `lower_recv_process` without regenerating (which would corrupt the transcript hash).
- **CI/CD:** Fan-out test pipeline with parallel unit tests, CAVP vectors, timing analysis, SAST (Semgrep + CodeQL), and DAST. Dylib-level unit tests run on real CEmu with hash-gated screen verification.

## v1.2-stable

- **Socket server API:** `lwip_conn_listen`, `lwip_conn_accept`, and associated types added to the high-level socket API, enabling TCP server applications. Includes an httpd example with file-serving and a JSON stats endpoint.
- **Parser improvements:** XML, JSON, and URL parsers promoted to the v1.2 release with additional fixes and API refinements from post-v1.1 development.

## v1.3-stable

- **XML parser rewrite:** Ring-buffered streaming pull parser with lax/HTML mode. New API: `xml_init`, `xml_take`, `xml_next`, `xml_finish`, `xml_get_attr`, `xml_decode_entity`. Supports chunked input (feeds bytes in, pops complete events out), void element auto-close (`<br>` → START + synthesized END), boolean attributes, unquoted attribute values, case folding, `&nbsp;` and other HTML entities, and `<!DOCTYPE>` skip. Replaces the old slice-based batch parser.
- **JSON parser refinements:** Simplified public API; improved handling of nested structures and edge cases in streaming context.
- **URL encoder/decoder refinements:** API cleanup.
- A PCAP interface

## v2.0-stable

- Significant API changes to cryptography: keys, x509.
- TLS bug in `HelloRetryRequest` handling resolved.
- Implement IP-based SAN verification; Omit SNI for IP literals.
- DAST certificates now include the runner control-source IPv4 address.
- Stabilize RTC locale behavior.

## v2.1-stable

- Fix bug in AES-GCM where 0-length AAD was not handled correctly (CAVP-identified).
- Fix bug where `tls_crypto_guard_disable()` was not freeing the intended stack frames.
- Make `HelloRetryRequest` RFC-compliant.
- Implement USB callback chaining.

## v2.1.1-stable

- TLS handshakes build static portions via memcpy and dynamic portions dynamically
- tls_algorithms.h include file added for easy oid inclusion, and easy reference within project

## v2.1.2-stable

**TLS 1.3 RFC-compliance and security hardening pass by Codex/Daybreak Blue, reviewed against RFC 8446, RFC 5280, RFC 7748, RFC 9525. Incorporates the following changes:**
- **Strict record and handshake framing:** Validate TLS record versions, non-zero and bounded record lengths, nested handshake lengths, empty handshake messages, record-spanning messages, and unexpected inner content types. Large Certificate messages remain streamed so the stricter parser does not require a contiguous certificate-chain allocation.
- **Correct receive failure semantics:** Once encrypted-record input has been consumed, allocation or processing failure is fatal rather than retryable, preventing partially consumed ciphertext from being reparsed as a new record.
- **ClientHello construction and retry safety:** ClientHello is sized before allocation, supports variable-length SNI, ALPN, PSK, and HelloRetryRequest cookies, remains cached across retryable `altcp_write` failures, and advances protocol state only after the serialized flight is accepted for transmission.
- **HelloRetryRequest corrections:** Validate HRR framing, cipher suite, compression, supported version, allowed and duplicate extensions, cookie encoding, and the prohibition on a second HRR. ClientHello2 uses the correct record version, carries the HRR cookie, preserves the permitted X25519 share, performs the RFC 8446 `message_hash` transcript replacement, and computes PSK binders over `message_hash(ClientHello1) || HRR || Truncate(ClientHello2)`.
- **PSK binder and ticket-age corrections:** Derive binder keys using `Transcript-Hash("")`, truncate ClientHello before the complete binders vector, distinguish external and resumption binder labels, and calculate the obfuscated ticket age from elapsed time. Zero-lifetime tickets are discarded, ticket fields are bounded, and persisted PSK-cache entries are validated before use.
- **ServerHello and key-exchange validation:** Enforce required and unique ServerHello extensions, reject unoffered PSK identities and unsupported selections, and reject the all-zero X25519 shared secret required by RFC 7748.
- **ALPN support:** Add application-configurable ALPN offers, strict server-selection validation, negotiated-protocol tracking, a public `tls-alpn.h` header containing common registered identifiers, and ownership-safe copying/freeing of configured protocol lists.
- **EncryptedExtensions handling:** Validate extension framing and duplicates, accept valid informational `supported_groups` contents including unknown/private-use groups, validate an ALPN selection against the offered list, and reject unsolicited or malformed selections with the appropriate alert.
- **CertificateRequest handling:** Parse and transcript-hash TLS 1.3 CertificateRequest messages, require an empty main-handshake request context and `signature_algorithms`, validate supported extension structures and duplicates, reject CertificateRequest during PSK authentication, and send the required empty client Certificate flight when no client certificate is configured.
- **X.509 path validation:** Bind every child certificate's encoded issuer name to the next certificate's subject name; validate CA `basicConstraints`, `pathLenConstraint`, `keyCertSign`, leaf `digitalSignature`, and server-auth EKU; reject duplicate security-relevant extensions and unknown critical extensions; and reject unimplemented `nameConstraints` rather than silently broadening CA authority.
- **Service-identity verification:** Require a non-empty hostname and verify identities exclusively through `subjectAltName`, including strict DNS wildcard and binary IPv4/IPv6 matching. Common Name fallback is removed per RFC 9525, and IP literals continue to omit SNI.
- **Certificate signature policy:** Invalid signatures for algorithms the platform supports fail closed. As a temporary compatibility/testing exception, structurally valid but unsupported signature algorithms and structurally compatible signatures issued by RSA keys larger than 2048 bits emit a warning and proceed; malformed signatures and signature/key width mismatches remain fatal.
- **Truststore validation:** Reset per-session trust state before loading, propagate malformed/version/hash/signature failures from `tls_init`, expose verified-store metadata, reject roots outside their validity window, and warn when the signed truststore is older than 180 days. A missing truststore/root remains a temporary warn-and-proceed compatibility exception.
- **Alert and shutdown behavior:** Send alerts under the correct plaintext, handshake, or application epoch; use the corresponding sequence number; require two-byte incoming alerts; ignore `user_canceled` as recommended; surface `close_notify` as orderly EOF after queued plaintext drains; and reject all other unexpected alerts/content.
- **Compatibility CCS validation:** Ignore only the exact TLS 1.3 middlebox-compatibility ChangeCipherSpec payload in the permitted handshake window instead of accepting arbitrary plaintext CCS records.
- **Traffic-key and sequence-number correctness:** Increment transmit sequence numbers only after successful writes, keep handshake and application counters independent, reset counters when traffic keys change, process KeyUpdate under the old key before ratcheting, respond when requested, cap peer-driven updates, and initiate a write-key update before the AES-GCM record-use limit.
- **Initialization fail-closed behavior:** TLS initialization now fails if the entropy source cannot initialize or if an existing truststore fails validation. Client randoms and ephemeral X25519 private keys use the checked random-request path.
- **Safer generic client API:** `altcp_tls_create_config_client()` now returns `NULL` because that lwIP-compatible entry point has no hostname parameter and therefore cannot perform RFC 9525 service-identity verification; callers must use the hostname-aware CE client factory.
