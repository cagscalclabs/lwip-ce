rsa.h — RSA 1024–2048
======================

RSA (Rivest–Shamir–Adleman) encodes a message with a randomised padding scheme
(OAEP) and passes the result through modular exponentiation against a very
large modulus. Its security rests on the difficulty of factoring large
semiprime numbers. Advances in computation have pushed minimum recommended key
sizes upward — keys below 2048 bits are no longer considered secure.

RSA operations are supported for key sizes 1024–2048 bits (128–256 byte
modulus). The public exponent is always ``65537`` (``RSA_PUBLIC_EXP``).

.. warning::

   RSA modular exponentiation takes several seconds on the eZ80. Design your
   application to expect a visible pause whenever an RSA operation runs.

OAEP Padding
------------

.. c:function:: bool tls_rsa_encode_oaep(const uint8_t *inbuf, size_t in_len, uint8_t *outbuf, size_t modulus_len, const char *auth, uint8_t hash_alg)

   Apply OAEP padding to a message. Padding only — does not perform
   exponentiation. In-place operation (``inbuf == outbuf``) is supported for
   exact overlap only; partial overlap is rejected.

   :param inbuf: Input message.
   :param in_len: Message length in bytes.
   :param outbuf: Output buffer (``modulus_len`` bytes; 128 for RSA-1024, 256 for RSA-2048).
   :param modulus_len: RSA modulus length in bytes.
   :param auth: Optional OAEP label string. Pass ``NULL`` for none.
   :param hash_alg: Hash algorithm (``TLS_HASH_SHA256``).
   :returns: ``true`` on success, ``false`` on failure or overlap error.

.. c:function:: size_t tls_rsa_decode_oaep(const uint8_t *inbuf, size_t in_len, uint8_t *outbuf, const char *auth, uint8_t hash_alg)

   Strip OAEP padding from a decrypted message. Padding only — does not
   perform exponentiation. In-place supported for exact overlap only.

   :param inbuf: OAEP-padded input (typically ``modulus_len`` bytes).
   :param in_len: Input length in bytes.
   :param outbuf: Output buffer for the decoded message.
   :param auth: Optional OAEP label string. Pass ``NULL`` for none.
   :param hash_alg: Hash algorithm (``TLS_HASH_SHA256``).
   :returns: Decoded message length on success, ``0`` on failure.

Encryption
----------

.. c:function:: bool tls_rsa_encrypt(const uint8_t *inbuf, size_t in_len, uint8_t *outbuf, const uint8_t *pubkey, size_t keylen, uint8_t hash_alg)

   OAEP-encode and encrypt a message with an RSA public key (one-shot:
   encode + exponentiation).

   :param inbuf: Plaintext input.
   :param in_len: Plaintext length.
   :param outbuf: Output ciphertext buffer (``keylen`` bytes).
   :param pubkey: RSA public key (modulus, big-endian).
   :param keylen: Modulus length in bytes (128 or 256).
   :param hash_alg: Hash algorithm for OAEP (``TLS_HASH_SHA256``).
   :returns: ``true`` on success, ``false`` on failure.

Signatures
----------

.. c:function:: bool tls_rsa_decrypt_signature(const uint8_t *signature, size_t signature_len, uint8_t *outbuf, const uint8_t *pubkey, size_t keylen)

   Decrypt an RSA signature using a public key (modular exponentiation only).
   Does not verify padding — always follow with ``tls_rsa_pss_verify()`` for
   PSS signatures. PKCS#1 v1.5 verification is handled internally by the TLS
   handshake.

   :param signature: Signature bytes.
   :param signature_len: Signature length (must equal ``keylen``).
   :param outbuf: Output encoded-message buffer (``keylen`` bytes).
   :param pubkey: RSA public key (modulus, big-endian).
   :param keylen: Modulus length in bytes.
   :returns: ``true`` on success, ``false`` on failure.

.. c:function:: bool tls_rsa_decrypt_signature_exp(const uint8_t *signature, size_t signature_len, uint8_t *outbuf, uint24_t exp, const uint8_t *pubkey, size_t keylen)

   Same as ``tls_rsa_decrypt_signature()`` but with an explicit public
   exponent. Use when the exponent is not ``65537``.

   :param signature: Signature bytes.
   :param signature_len: Signature length.
   :param outbuf: Output buffer.
   :param exp: Public exponent.
   :param pubkey: RSA public key (modulus, big-endian).
   :param keylen: Modulus length in bytes.
   :returns: ``true`` on success, ``false`` on failure.

.. c:function:: bool tls_rsa_pss_verify(const uint8_t *encoded_msg, size_t em_len, const uint8_t *mhash, size_t mhash_len, uint8_t hash_alg)

   Verify RSA-PSS padding on an already-decrypted signature. Does not perform
   exponentiation — call ``tls_rsa_decrypt_signature()`` first.

   :param encoded_msg: Decrypted signature (EM), big-endian, ``em_len`` bytes.
   :param em_len: Encoded message length (same as modulus length).
   :param mhash: Hash of the message being verified.
   :param mhash_len: Hash length (must match the hash algorithm's digest size).
   :param hash_alg: Hash algorithm (``TLS_HASH_SHA256``).
   :returns: ``true`` if PSS padding is valid, ``false`` otherwise.

Examples
--------

**OAEP encode/decode (padding only):**

.. code-block:: c

   uint8_t encoded[128];
   tls_rsa_encode_oaep(message, msg_len, encoded, 128, NULL, TLS_HASH_SHA256);

   uint8_t decoded[128];
   size_t decoded_len = tls_rsa_decode_oaep(encoded, 128, decoded, NULL, TLS_HASH_SHA256);

**RSA signature verification (two steps):**

.. code-block:: c

   uint8_t em[256];
   tls_rsa_decrypt_signature(signature, sig_len, em, pubkey, keylen);

   uint8_t mhash[TLS_SHA256_DIGEST_LEN];
   tls_sha256_digest(&hash_ctx, mhash);
   tls_rsa_pss_verify(em, keylen, mhash, sizeof(mhash), TLS_HASH_SHA256);
