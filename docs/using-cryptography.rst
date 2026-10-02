Using Cryptography
==================

lwIP-CE exposes a set of cryptographic primitives that you can use
independently of the network stack. TLS over a network connection is also
covered here.

Setup
-----

Call ``lwip_start()`` before using any crypto API. You do **not** need to call
``lwip_network_up()`` for crypto-only programs. Every unit test under
``tests/unit/`` relies on this pattern.

.. code-block:: c

   #include <cryptography.h>

   int main(void)
   {
       if (!lwip_start())
           return 1;

       /* crypto primitives are ready — no network interface needed */
   }

Include ``cryptography.h`` for the full set of primitives, or include
individual headers from ``lwip/cryptography/`` for a narrower surface.

TLS is gated on the **Enable TLS** setting in the lwIP-CE app configuration
wizard. If TLS is disabled by the end user, any attempt to open a TLS socket
will fail immediately. There is no way to override this from application code;
the user has final authority.

Available Primitives
--------------------

``cryptography.h`` is an umbrella over:

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Header
     - Contents
   * - ``lwip/cryptography/aes.h``
     - AES-GCM, AES-CCM, and AES-CBC (128/192/256-bit keys). One-shot and
       streaming (init/update/digest) interfaces.
   * - ``lwip/cryptography/hash.h``
     - SHA-256. Streaming (``tls_sha256_init`` / ``tls_sha256_update`` /
       ``tls_sha256_digest``) and generic context (``tls_hash_context_init``).
   * - ``lwip/cryptography/hmac.h``
     - HMAC-SHA-256 (``tls_hmac_context_init`` / ``tls_hmac_update`` /
       ``tls_hmac_digest``).
   * - ``lwip/cryptography/hkdf.h``
     - HKDF-Extract, HKDF-Expand, and HKDF-Expand-Label (RFC 5869 / TLS 1.3).
   * - ``lwip/cryptography/rsa.h``
     - RSA 1024–2048 bit. OAEP encode/decode, encrypt, signature decryption,
       and PSS padding verification.
   * - ``lwip/cryptography/x25519.h``
     - X25519 Diffie-Hellman: shared secret derivation and public key
       generation. Both functions accept an optional ``yield_fn`` callback for
       long operations.
   * - ``lwip/cryptography/random.h``
     - SRAM-noise-derived TRNG. ``tls_random_init_entropy()``,
       ``tls_random()``, ``tls_random_bytes()``. Use these instead of the
       toolchain ``rand()`` functions for anything security-sensitive.
   * - ``lwip/cryptography/x509.h``
     - X.509 DER/PEM import, field parsing, hostname matching, and validity
       window checking.
   * - ``lwip/cryptography/truststore.h``
     - CA root trust store initialization (``tls_truststore_init()``) and
       lookup by Subject Key Identifier.
   * - ``lwip/cryptography/asn1.h``
     - ASN.1/DER parsing helpers used by X.509 and RSA.
   * - ``lwip/cryptography/base64.h``
     - Base64 encode/decode helpers.
   * - ``lwip/cryptography/bytes.h``
     - Utility byte-manipulation helpers.
   * - ``lwip/cryptography/keyobject.h``
     - Key object wrappers used internally by the TLS handshake.
   * - ``lwip/cryptography/passwords.h``
     - Password-hashing helpers.
   * - ``lwip/cryptography/pkcs8.h``
     - PKCS#8 private key import.

Performance note: RSA and X25519 operations are compute-heavy on the eZ80.
Expect measurable pauses for RSA key operations at 1024+ bits. The
``yield_fn`` parameter on X25519 functions lets you pump your UI or key
handler during the computation. Do not expect desktop-class throughput.

Hashing Example
---------------

.. code-block:: c

   #include <cryptography.h>

   uint8_t digest[TLS_SHA256_DIGEST_LEN];
   struct tls_sha256_context ctx;

   tls_sha256_init(&ctx);
   tls_sha256_update(&ctx, (const uint8_t *)"hello", 5);
   tls_sha256_digest(&ctx, digest);
   /* digest now holds the SHA-256 of "hello" */

Random Bytes Example
--------------------

.. code-block:: c

   #include <cryptography.h>

   uint8_t key[32];
   tls_random_init_entropy();        /* initialize the entropy source */
   tls_random_bytes(key, sizeof(key));

``tls_request_random_bytes()`` provides an async version that gathers entropy
in timed chunks via lwIP timers, which avoids blocking the main loop. Only one
request can be in flight at a time.

TLS Over a Network Socket
-------------------------

For TLS client connections, use ``LWIP_SOCKET_ALTCP_TLS`` as the transport
selector in ``lwip_socket_create()``. WebSocket-over-TLS uses
``LWIP_SOCKET_ALTCP_WSS``. Both require networking to be up and TLS enabled in
the wizard.

.. code-block:: c

   #include <lwip.h>

   struct lwip_socket sock = {0};

   if (!lwip_start())        return 1;
   if (!lwip_network_up())   return 1;

   if (lwip_socket_create(&sock, LWIP_SOCKET_ALTCP_TLS,
                          LWIP_NETIF_EXT, NULL, 60000) != LWIP_OK) {
       lwip_socket_destroy(&sock);
       return 1;
   }

   /* subscribe to events, then connect */
   lwip_socket_connect(&sock, "example.com", 443);

The TLS stack handles certificate chain verification, trust store lookup, and
CertificateVerify automatically. You do not need to call any TLS setup
functions directly; the socket layer drives the handshake.

See :doc:`using-the-network` for the full socket lifecycle (event callbacks,
read/write, shutdown, and destroy). See :doc:`technical-details` for the
security posture of the TLS implementation, including current limitations
around P-256 and the trust store.
