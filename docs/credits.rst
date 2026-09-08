Credits & References
====================

lwIP-CE is a fork, a port, and a pile of platform-specific glue. This page keeps
the people, reference implementations, and standards links in one place.

lwIP-CE Contributors
--------------------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Area
     - Credit
   * - Lead development
     - Anthony Cagliano
   * - SHA-256 to eZ80 work
     - Adam Beckingham
   * - AES to eZ80 work
     - calc84maniac
   * - Entropy analysis
     - Zeroko
   * - ``modexp_2048``
     - jacobly
   * - ``x25519``
     - Peter Tillema (PT\_)
   * - fasmg to GNU migration
     - TIny_Hacker
   * - Info, optimizations, and supporting algorithms
     - jacobly, calc84maniac, Zeroko, John Caesarz, MateoC
   * - Testing
     - Alessio

Upstream lwIP
-------------

lwIP-CE is forked from lwIP. The upstream project remains the best reference
for general lwIP behavior and raw API concepts that still apply here.

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Link
     - Use
   * - `lwIP GitHub mirror <https://github.com/lwip-tcpip/lwip>`_
     - Convenient source browser for upstream lwIP.
   * - `lwIP documentation <https://www.nongnu.org/lwip/2_1_x/>`_
     - Upstream API and architecture reference.
   * - `lwIP Savannah project <https://savannah.nongnu.org/projects/lwip/>`_
     - Upstream project home.

Reference Implementations
-------------------------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Project
     - Why it matters here
   * - `B-Con crypto-algorithms <https://github.com/B-Con/crypto-algorithms/>`_
     - Reference implementation lineage for AES block/key-schedule routines and
       SHA-256 core hashing primitives.
   * - `tiny-ECDH-c <https://github.com/kokke/tiny-ECDH-c>`_
     - Reference ECDH implementation basis.
   * - `OpenSSL <https://github.com/openssl/openssl>`_
     - Reference material for Base64 behavior and compatibility.

RFCs And Standards
------------------

.. list-table::
   :header-rows: 1
   :widths: 24 76

   * - Reference
     - Topic
   * - `RFC 2104 <https://datatracker.ietf.org/doc/html/rfc2104>`_
     - HMAC.
   * - `RFC 4231 <https://datatracker.ietf.org/doc/html/rfc4231>`_
     - HMAC-SHA test vectors.
   * - `RFC 4086 <https://datatracker.ietf.org/doc/html/rfc4086>`_
     - Randomness requirements for security.
   * - `RFC 4648 <https://datatracker.ietf.org/doc/html/rfc4648>`_
     - Base64 encoding.
   * - `RFC 4868 <https://datatracker.ietf.org/doc/html/rfc4868>`_
     - HMAC-SHA-256 construction details and test-vector guidance.
   * - `RFC 5208 <https://datatracker.ietf.org/doc/html/rfc5208>`_
     - PKCS#8 private-key information syntax.
   * - `RFC 5280 <https://datatracker.ietf.org/doc/html/rfc5280>`_
     - X.509 certificate and CRL profile.
   * - `RFC 5869 <https://datatracker.ietf.org/doc/html/rfc5869>`_
     - HKDF.
   * - `RFC 5915 <https://datatracker.ietf.org/doc/html/rfc5915>`_
     - EC private-key structure.
   * - `RFC 5958 <https://datatracker.ietf.org/doc/html/rfc5958>`_
     - Asymmetric key package syntax.
   * - `RFC 6070 <https://datatracker.ietf.org/doc/html/rfc6070>`_
     - PBKDF2 test vectors.
   * - `RFC 8017 <https://datatracker.ietf.org/doc/html/rfc8017>`_
     - PKCS#1 / RSA cryptography.
   * - `RFC 8018 <https://datatracker.ietf.org/doc/html/rfc8018>`_
     - PBKDF2 and password-based cryptography.
   * - `RFC 8446 <https://datatracker.ietf.org/doc/html/rfc8446>`_
     - TLS 1.3.
   * - `FIPS 197 <https://csrc.nist.gov/pubs/fips/197/final>`_
     - AES.
   * - `FIPS 180-4 <https://csrc.nist.gov/pubs/fips/180-4/upd1/final>`_
     - Secure Hash Standard, including SHA-256.
   * - `NIST SP 800-38A <https://csrc.nist.gov/pubs/sp/800/38/a/final>`_
     - Block cipher confidentiality modes, including CBC.
   * - `NIST SP 800-38C <https://csrc.nist.gov/pubs/sp/800/38/c/upd1/final>`_
     - CCM mode.
   * - `NIST SP 800-38D <https://csrc.nist.gov/pubs/sp/800/38/d/final>`_
     - GCM and GMAC mode.
   * - `NIST SP 800-90A Rev. 1 <https://csrc.nist.gov/pubs/sp/800/90/a/r1/final>`_
     - Deterministic random bit generators.
   * - `NIST SP 800-90B <https://csrc.nist.gov/pubs/sp/800/90/b/final>`_
     - Entropy sources for random bit generation.
   * - `NIST SP 800-90 series <https://csrc.nist.gov/projects/random-bit-generation/sp-800-90>`_
     - Random bit generation guidance and updates.
   * - `NIST CAVP <https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program>`_
     - Algorithm validation program and published vector material.
   * - `ITU-T X.690 <https://www.itu.int/rec/T-REC-X.690>`_
     - ASN.1 BER/CER/DER encoding rules.

Books And Background
--------------------

.. list-table::
   :header-rows: 1
   :widths: 34 66

   * - Source
     - Use
   * - Shemanske, *Modern Cryptography and Elliptic Curves*
     - Elliptic-curve background and conceptual reference.

AI-Assisted Tooling
-------------------

AI-assisted tooling has been used for limited engineering and drafting work,
including code review support, selected debugging sessions, and explanatory
prose organization. It is not treated as an authority for cryptographic claims,
standards compliance, or empirical results.

Human review, implementation decisions, test interpretation, and final
responsibility remain with the project author.
