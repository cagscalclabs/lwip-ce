# Security Policy

lwIP-CE is a TLS-capable network stack for the TI-84 Plus CE (eZ80, no MMU,
no secure enclave, no process isolation). It is used by calculator
applications that need real TLS connections to real internet services. This
document describes what's actually in the security boundary, what isn't,
and how to report problems.

## What This Repo Contains

- A TLS 1.3 client implementation (handshake state machine, record layer,
  key schedule) — see `src/tls/core/handshake.c`.
- A small cryptographic library backing that handshake: AES-GCM, AES-CBC,
  AES-CCM, RSA (1024–2048 bit, PKCS#1 v1.5 and PSS), HMAC, HKDF, PBKDF2,
  SHA-256, X25519, and ASN.1/X.509 parsing — see `src/tls/core/` and
  `src/tls/includes/`.
- A compact trust store and certificate chain verifier, built from a
  GitHub Actions workflow against the host OS's CA bundle and signed
  before distribution — see `src/tls/core/truststore.c`.
- A hardware entropy source (SRAM-tap-based) feeding the RNG used for key
  generation, nonces, and the TLS handshake — see `src/tls/core/random.c`.
- An eZ80 assembly side-channel mitigation layer (`cryptoguard`) used
  around cryptographic transforms.
- The lwIP core network stack (TCP/IP, USB-ethernet drivers) this all sits
  on top of.

A full account of the cryptographic design, threat model, and accepted
tradeoffs is in `docs/whitepaper/whitepaper.tex` (build with `make -C
docs/whitepaper`, or read the rendered PDF if one is published). That
document is the canonical source for "why" — this file is the canonical
source for "how to report a problem."

## Security Mechanisms

- **TLS 1.3** is the only protocol version supported. Leaf
  `CertificateVerify` is mandatory on every full handshake (RSA-PSS-SHA256,
  leaf modulus 1024–2048 bit) — this is what proves the peer controls the
  leaf private key, not just that it possesses a public certificate.
- **Certificate chain trust**: adjacent-link signature verification walks
  the presented chain — RSA-2048+SHA-256 links are cryptographically
  verified (a bad signature is a hard abort), other signature types are
  currently accepted unverified pending broader algorithm support and are
  logged as such. The topmost certificate's issuer is then looked up by
  subject name in the on-device trust store and, if RSA, verified the same
  way. The trust store itself is generated from a host OS CA bundle by a
  signed, auditable GitHub Actions workflow and its own signature is
  checked at TLS init. **No ECDSA/P-256 chain verification exists yet** —
  see `docs/whitepaper/whitepaper.tex` for the current roadmap on this.
- **Entropy**: a hardware SRAM-tap source, conditioned via XOR-folding and
  hashing, gated by runtime health checks at startup. Empirical
  characterization (bias, correlation, min-entropy bounds) is in the
  whitepaper's RNG appendix.
- **Side-channel hardening (`cryptoguard`)**: interrupts are disabled
  during cryptographic transforms and the stack/scratch memory used by
  those transforms is explicitly zeroized afterward. The eZ80 is slow
  enough that strict constant-time execution isn't achievable for every
  primitive; primitives are implemented to be as close to constant-time as
  is practical on this hardware, not as a formal guarantee.
- **Secure erase**: heap and ring buffers support a secure-erase flag that
  zeroizes memory on `free`/pop/destruction rather than leaving plaintext
  or key material behind for the next allocation to inherit.
- **Memory pressure throttling**: Ethernet RX registration, lwIP core pbuf
  ingestion, and TLS `altcp_recved` pacing all back off under memory
  pressure (with hysteresis), and lwIP core hitting critical pressure
  forces Ethernet RX into a severe-backoff state too. This is a stability
  mechanism, not a confidentiality one, but it's part of what keeps a
  loaded device from failing in a way that bypasses the above.

## Known Limitations (Read Before Filing a Report)

These are accepted, documented tradeoffs — not omissions we're unaware of.
Reporting them as new findings without new context (a working exploit, a
realistic attack scenario we haven't considered, a way to make the impact
worse than documented) will likely be closed as a duplicate of the
whitepaper's own threat-model section.

- **Physical access defeats the model.** There is no secure enclave, TPM,
  or MMU-backed isolation on this hardware. Anyone with physical access to
  the calculator and a USB connection can dump its memory, including any
  key material resident at the time. `cryptoguard` and secure-erase reduce
  the *window* of exposure; they do not close it.
- **No process isolation.** Any program a user runs on-device can hook
  callbacks, disable integrity checks, or exfiltrate state — there is no
  OS-level sandboxing to prevent this. The user is trusting every program
  they run, the same way they'd trust a desktop binary with no OS-level
  app sandboxing.
- **Non-constant-time primitives may exist.** We've made a best effort,
  not a formal proof. Timing differential analysis is run as part of CI
  (see `tests/profiling/tls_timing/`) but a passing run is evidence
  against gross timing leakage, not a constant-time certification.
- **Partial chain verification.** See above — non-RSA chain links are
  currently accepted unverified. This is a known gap, already tracked; you
  don't need to discover it for us.

## Reporting a Vulnerability

**Do not open a public GitHub issue for a security report.** Public issues
are fine for usability bugs, but a live vulnerability filed in public
before a fix exists is itself a disclosure. Use one of the private
channels below instead.

### How to report

1. **Preferred: GitHub Security Advisories.** Use the "Report a
   vulnerability" button under this repo's Security tab. This opens a
   private advisory thread visible only to maintainers until you and we
   agree it's ready to publish.
2. **Alternative: direct email** to `info@cagscalclabs.net` if you can't or
   don't want to use GitHub's flow. Encrypt with our PGP key if you have
   sensitive material to attach:
   - Fingerprint: `33AE 1739 EA2F A260 DAFB  477F 8226 A26D 65C9 7747`
   - Available on [keys.openpgp.org](https://keys.openpgp.org).

### What to include

Whichever channel you use, a useful report includes:

- **What kind of issue this is** — pick the closest category:
  - **Protocol/implementation vulnerability** — a flaw in the TLS
    handshake, record layer, or certificate chain logic that lets an
    attacker bypass authentication, downgrade security, or read/inject
    traffic they shouldn't be able to.
  - **Algorithm/cryptographic primitive breakage** — a flaw in AES, RSA,
    HMAC, HKDF, PBKDF2, SHA-256, X25519, or the RNG itself: a forgery, a
    key-recovery attack, a distinguishing attack, a bias in the entropy
    source beyond what's documented in the whitepaper, or a
    implementation bug that weakens a primitive below its nominal
    security level.
  - **Memory safety** — overflow, use-after-free, out-of-bounds read/write
    in any TLS, crypto, or lwIP core code path, especially ones reachable
    from untrusted network input (i.e., before the peer is authenticated).
  - **Leaked or compromised key material** — if you have evidence that a
    *specific* private key used by this project's infrastructure (the
    trust store signing key, a release signing key, etc.) has been
    exposed or compromised, say so explicitly and treat the report as
    time-sensitive; we will rotate the affected key as part of the
    response.
  - **Malware / malicious use of this library** — a published program
    that uses this library's APIs (callback hooks, crypto primitives,
    arbitrary code execution avenues described above) to do something
    harmful to users. This is a different track from the above (see
    "Malware reports" below).
- **Affected version/commit** — a commit hash or tagged release, not just
  "current."
- **Reproduction** — concrete steps, a PoC, or a minimal test case.
  For a cryptographic finding, include the math/attack, not just an
  assertion that something is weak.
- **Impact** — what an attacker actually gains (key recovery, traffic
  decryption, authentication bypass, arbitrary code execution, DoS,
  etc.) and any constraints on the attacker (network position, physical
  access, timing precision required).
- **Suggested fix**, if you have one — not required, but appreciated.

### Malware reports

If you're reporting a *program* that abuses this library (rather than a
flaw *in* this library), the GitHub Issues `malware-report` tag is fine
for that — it doesn't need to be private the way a live vulnerability
does, since the harm is already in the wild and the bug isn't ours to fix
quietly. Include the program name, author (if known), the distribution
channel you found it on, and what it does.

### Response and disclosure

- We will acknowledge a report within 7 days.
- If verified, we will work with you on a fix timeline before any public
  disclosure. We do not have a fixed embargo period; for an actively
  exploited issue we will move as fast as the fix allows, for a
  theoretical one we'll coordinate a reasonable timeline with you.
- Verified reports result in a GitHub Security Advisory crediting the
  reporter (unless you ask to stay anonymous), containing: the affected
  component and version range, the issue class, and the version
  containing the fix.
- We do not currently run a paid bug bounty. Credit in the advisory and
  our thanks are what's on offer — say so up front if that changes
  whether you want to report.
