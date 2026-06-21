## Changes - RC2

- Completely removes the old SPKI pinning trust store, now implements a curated trust store derived from Certificate material in /etc/certs: Subject, SKI, expiry, key algorithm, and public key.
- Due to, at present, limited coverage for existing certificate chain signature algorithms (only RSA-2048), unsupported algorithm during verification throw ALERT("unsupported algorithm - pass") and proceed anyway. This is temporary behavior and will become fail closed once P-256 and/or larger RSA is added.
- Due to, at present, limited coverage for signature algorithms (only RSA-2048), our trust store includes only 46 roots out of ~150. At present, if a chain ends in a root we do not have, ALERT("root not in store") is thrown and the handshake proceeds. Again, this is temporary until P-256 and/or larger RSA is added.
- A transcript hashing bug in PSK session resumption was fixed.
Users can now disable TLS completely through the app config wizard, for any uncomfortable with connecting to secure stuff with their calculator.

## Changes - RC3

- Stack initialization is now a bit different. Instead of `lwip_init_runtime` and then `lwip_start`, it's now just `lwip_start`. This dynamically-links into the APP, inits its runtime, syncs the imports table, then starts the non-network components of the stack (mainly timers and memory subsystem). Initializing the network requires a call to `lwip_network_up`. This allows people to use the stack for a memory system or for its async-API without using the network.
- A new "network-applications" release tag is created. I'll place services into this release that work with lwip. So far, an IRC client is there. (yes, Codex had a heavy hand in that--I just wanted something to test with quickly, and it turned out to work nicely).

## Changes - RC4

- TLS now resolves a bug where the connection state would break when the server would send CertificateRequest. I forgot this step existed, so obviously on skip the transcript hash would become invalid.
- Adds an error traceback system.

## Changes - v1.0-stable

- Post TLS handshake bug with close notify and KeyUpdate silently dropped is now resolved.
- An additional size-guard for signature_len == key_len on rsa_pss is now included.
- Uninitialized function jumps in lwip.8xv now initialize to a defined no-op in the lib that sets an error state, instead of remaining jp $0, and possibly faulting.
- DAST testing now expands to exercise: (1) proper TLS ECDHE connect, (2) TLS PSK connect, (3) TLS invalid transcript (missing Record), (4) TLS CertificateVerify bad signature.
