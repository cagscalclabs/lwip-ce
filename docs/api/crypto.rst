crypto/
=======

``lwip/cryptography/`` contains the lower-level cryptographic primitives.
Most callers should use the :doc:`key API <../using-cryptography>` in
``lwip/cryptography/key.h`` rather than these headers directly.

------

Symmetric Encryption
--------------------

AES-GCM, AES-CBC, and AES-CCM are available for symmetric encryption.
Most callers should use the :ref:`Key API <key-api>` below, which wraps the AES
primitives in a self-describing handle and handles IV generation, tag
verification, and algorithm dispatch automatically.

For direct access to the AES context API and one-shot CCM helpers, see
:doc:`api/crypto/aes`.

------

.. list-table::
   :header-rows: 1
   :widths: 28 72

   * - Header
     - Purpose
   * - :doc:`aes.h <crypto/aes>`
     - AES-128/192/256 in GCM, CBC, and CCM modes. Context-based streaming
       and one-shot CCM helpers.
   * - :doc:`rsa.h <crypto/rsa>`
     - RSA-1024/2048 with OAEP encryption and PSS signature verification.
   * - :doc:`x25519.h <crypto/ecc>`
     - X25519 Diffie-Hellman key exchange over Curve25519.
   * - :doc:`x509.h / truststore.h / keyobject.h / pkcs8.h <crypto/pki>`
     - X.509 certificate parsing, CA trust store, and PEM key import.
   * - :doc:`asn1.h <crypto/asn1>`
     - Forward-only DER cursor and TLV parser.
   * - :doc:`base64.h / bytes.h <crypto/encoding>`
     - Base64 encode/decode and constant-time buffer utilities.

.. toctree::
   :hidden:

   crypto/aes
   crypto/rsa
   crypto/ecc
   crypto/pki
   crypto/asn1
   crypto/encoding
