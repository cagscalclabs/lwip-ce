# Security Policy

## Security Mechanisms

- TLS 1.3 is the mechanism for secure communication. It exposes the following algorithms.
  - x25519 ECDHE (WIP)
  - RSA-2048 pubkey-only (encrypt, verify signature)
  - AES-128-GCM with SHA-256
- Auditable Trust Source (SPKI pinning): An SPKI trust store generated via github workflow using the certificates included in typical OS distros (eg: /etc/certs/). We extract the root and intermediate CA's and parse the key fields from them--owner, issuer, not-before, not-after, and SHA-256(SubjectPublicKeyInfo)--into an AppVar the calculator can parse. AppVar is signed with RSA-2048 w SHA-256-PSS. The signature is verified during TLS init. During TLS connect on calculator, we green-light the connection if the certificate chain from the remote has a certificate with a SPKI hash that matches an entry in the trust store.
- Secure Memory: Memory module allows buffers to be initialized with a `secure erase` flag. This causes any `free` or `pop` operation on malloc and ring type buffers respectively (or destruction of the buffer) to erase the chunk of memory before releasing it.
- Memory pressure throttling with hysteresis backs off throughput rate when memory pressure rises to certain levels. Modules have their own pressure throttling behavior--Ethernet slows down rate of RX registration, lwIP core slows down pbuf ingestion rate, TLS slows altcp_recved update rate. Additionally, if lwIP core hits critical pressure, it sets the Ethernet RX to severe state as well. This prevents overload and ensures stability.

## Platform-Specific Shortfalls

- Side Channel
  - Physical access to the device renders the security model null. The memory of the device can be mapped with a USB connection to a computer. We mitigate this the best we can by disabling interrupts during cryptographic algorithms, zeroing the stack frame after, and the `BUFFER_SECURE_ERASE` flag.
  - The slowness of the ez80 processor means strict constant-time isn't possible for all algorithms. We did the best we could to ensure algorithms were constant or as close to constant as possible.
- Arbitrary Code Execution
  - A bad actor could release a program that manipulates callbacks to inject malicious logic--disable integrity checks, stop encrypting, etc. We could try to place secure state data into a write-locked buffer using memory protection registers, but then a bad actor could just turn them off. There is no process isolation, no file access permissioning system, so we have no means to prevent this. Thus liability falls to the end user to ensure you trust the developer of a program you are running.

## Reporting a Vulnerability

If you have encountered what you believe to be a security issue in this project please report it via the Issues tab on GitHub.
If you are reporting a security issue *within* the project, please apply the `vulnerability` tag.
If you are reporting malware (software that abuses arbitrary code execution to malicious effect), please apply the `malware-report` tag.
Both will be investigated and, if verified, will result in a security advisory. Advisories will contain: (for `vulnerability`) the algorithm and version with the issue and the version that patches it, or (for `malware-report`) the name of the program, author name, and what it does.