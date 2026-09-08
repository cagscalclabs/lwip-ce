cryptography.h and lwip/cryptography/
=====================================

``cryptography.h`` is the root-level umbrella for the lower-level
``lwip/cryptography/*.h`` headers. These headers expose algorithmically-secure
primitives that can be used outside the network stack.

.. list-table::
   :header-rows: 1
   :widths: 28 72

   * - Header
     - Purpose
   * - :doc:`aes.h <cryptography/aes>`
     - AES-GCM, AES-CCM, and AES-CBC support.
   * - :doc:`asn1.h <cryptography/asn1>`
     - DER/ASN.1 parsing support.
   * - :doc:`base64.h <cryptography/base64>`
     - Base64 encoding and decoding.
   * - :doc:`bytes.h <cryptography/bytes>`
     - Secure buffer comparison and secure erasure helpers.
   * - :doc:`hash.h <cryptography/hash>`
     - SHA-256 hashing support.
   * - :doc:`hkdf.h <cryptography/hkdf>`
     - HMAC-based key derivation.
   * - :doc:`hmac.h <cryptography/hmac>`
     - HMAC-SHA-256 support.
   * - :doc:`keyobject.h <cryptography/keyobject>`
     - Imported key object handling.
   * - :doc:`passwords.h <cryptography/passwords>`
     - PBKDF2 password-based key derivation.
   * - :doc:`pkcs8.h <cryptography/pkcs8>`
     - PKCS#8 and SEC1 key parsing/serialization.
   * - :doc:`random.h <cryptography/random>`
     - TRNG and secure random byte generation.
   * - :doc:`rsa.h <cryptography/rsa>`
     - RSA support for 1024-bit through 2048-bit keys.
   * - :doc:`truststore.h <cryptography/truststore>`
     - Certificate metadata and chain-verification helpers used by TLS.
   * - :doc:`x25519.h <cryptography/x25519>`
     - X25519 elliptic-curve scalar multiplication.
   * - :doc:`x509.h <cryptography/x509>`
     - X.509 certificate parsing.

.. toctree::
   :hidden:

   cryptography/aes
   cryptography/asn1
   cryptography/base64
   cryptography/bytes
   cryptography/hash
   cryptography/hkdf
   cryptography/hmac
   cryptography/keyobject
   cryptography/passwords
   cryptography/pkcs8
   cryptography/random
   cryptography/rsa
   cryptography/truststore
   cryptography/x25519
   cryptography/x509
