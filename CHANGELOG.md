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

## Unreleased

- **XML parser rewrite:** Ring-buffered streaming pull parser with lax/HTML mode. New API: `xml_init`, `xml_take`, `xml_next`, `xml_finish`, `xml_get_attr`, `xml_decode_entity`. Supports chunked input (feeds bytes in, pops complete events out), void element auto-close (`<br>` → START + synthesized END), boolean attributes, unquoted attribute values, case folding, `&nbsp;` and other HTML entities, and `<!DOCTYPE>` skip. Replaces the old slice-based batch parser.
- **JSON parser refinements:** Simplified public API; improved handling of nested structures and edge cases in streaming context.
- **URL encoder/decoder refinements:** API cleanup.
