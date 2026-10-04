aes.h — AES-GCM, AES-CBC, AES-CCM
===================================

AES-128, AES-192, and AES-256 are all supported across all three modes.
AES-GCM and AES-CCM are authenticated encryption modes — they produce an
authentication tag alongside the ciphertext. AES-CBC provides confidentiality
only. ``TLS_AES_BLOCK_SIZE``, ``TLS_AES_IV_SIZE``, and
``TLS_AES_AUTH_TAG_SIZE`` are all 16 bytes.

Context API
-----------

.. c:function:: bool tls_aes_init(struct tls_aes_context *ctx, uint8_t mode, const uint8_t *key, size_t key_len, const uint8_t *iv, size_t iv_len)

   Initialize an AES context for a single message. Must be called before any
   other context operation. A new call is required per message — context reuse
   across messages is not supported. The context is caller-allocated and
   stack-safe.

   :param ctx: Caller-allocated AES context.
   :param mode: ``TLS_AES_GCM``, ``TLS_AES_CBC``, or ``TLS_AES_CCM``.
   :param key: AES key (16, 24, or 32 bytes for AES-128/192/256).
   :param key_len: Length of ``key`` in bytes.
   :param iv: Initialization vector (16 bytes for GCM/CBC).
   :param iv_len: Length of ``iv`` in bytes.
   :returns: ``true`` on success, ``false`` on invalid parameters.

.. c:function:: bool tls_aes_update_aad(struct tls_aes_context *ctx, const uint8_t *aad, size_t aad_len)

   Feed associated data (AAD) into a GCM or CCM context. Must be called after
   ``tls_aes_init()`` and before any encrypt/decrypt call. AAD is authenticated
   but not encrypted. Not applicable to CBC.

   :param ctx: Initialized AES context.
   :param aad: Associated data buffer.
   :param aad_len: Length of associated data.
   :returns: ``true`` on success, ``false`` if the context state does not
      permit AAD (e.g. encrypt/decrypt already started).

.. c:function:: bool tls_aes_encrypt(struct tls_aes_context *ctx, const uint8_t *inbuf, size_t in_len, uint8_t *outbuf)

   Encrypt a block of data. May be called multiple times (streaming). For
   GCM/CCM, call ``tls_aes_digest()`` after the final chunk to retrieve the
   authentication tag.

   :param ctx: Initialized AES context.
   :param inbuf: Plaintext input.
   :param in_len: Length of plaintext.
   :param outbuf: Ciphertext output buffer (must be at least ``in_len`` bytes).
   :returns: ``true`` on success, ``false`` on error.

.. c:function:: bool tls_aes_decrypt(struct tls_aes_context *ctx, const uint8_t *inbuf, size_t in_len, uint8_t *outbuf)

   Decrypt a block of data. For authenticated modes (GCM/CCM), always verify
   the tag with ``tls_aes_verify()`` before calling this — decrypting
   unauthenticated ciphertext is a security error.

   :param ctx: Initialized AES context.
   :param inbuf: Ciphertext input.
   :param in_len: Length of ciphertext.
   :param outbuf: Plaintext output buffer (must be at least ``in_len`` bytes).
   :returns: ``true`` on success, ``false`` on error.

.. c:function:: bool tls_aes_digest(struct tls_aes_context *ctx, uint8_t *digest)

   Retrieve the authentication tag from a GCM or CCM context after all
   encrypt/decrypt chunks have been fed. The tag is ``TLS_AES_AUTH_TAG_SIZE``
   (16) bytes.

   :param ctx: Initialized AES context after all data has been processed.
   :param digest: Output buffer for the authentication tag (16 bytes).
   :returns: ``true`` on success, ``false`` if the context is not in a
      state that permits tag retrieval.

.. c:function:: bool tls_aes_verify(struct tls_aes_context *ctx, const uint8_t *aad, size_t aad_len, const uint8_t *ciphertext, size_t ciphertext_len, const uint8_t *tag)

   Authenticate ciphertext and AAD against a tag without decrypting. For
   security, always call this before ``tls_aes_decrypt()`` on authenticated
   modes. Does not produce plaintext.

   :param ctx: Initialized AES context.
   :param aad: Associated data (``NULL`` if none).
   :param aad_len: Length of associated data (``0`` if none).
   :param ciphertext: Ciphertext to authenticate.
   :param ciphertext_len: Length of ciphertext.
   :param tag: Expected authentication tag.
   :returns: ``true`` if the tag is valid, ``false`` if authentication fails.

.. c:function:: bool tls_aes_update_ciphertext(struct tls_aes_context *ctx, const uint8_t *ct, size_t ct_len)

   Feed ciphertext into a GCM context for GHASH computation only, without
   producing plaintext. Used for a verify-before-decrypt streaming pattern:
   walk the full ciphertext through GHASH, check the tag, then decrypt in a
   second pass over the authenticated ciphertext.

   :param ctx: AES-GCM context, after ``tls_aes_update_aad()``.
   :param ct: Ciphertext bytes to authenticate.
   :param ct_len: Length of ciphertext.
   :returns: ``true`` on success, ``false`` on error.

CCM one-shot API
----------------

.. c:function:: bool tls_aes_ccm_init(struct tls_aes_context *ctx, const uint8_t *key, size_t key_len, const uint8_t *nonce, size_t nonce_len, uint8_t tag_len, size_t msg_len, size_t aad_len)

   Initialize an AES-CCM context for incremental AAD and data feeding. Use
   this when you cannot supply all data at once; otherwise prefer the
   one-shot ``tls_aes_ccm_encrypt()`` / ``tls_aes_ccm_decrypt()`` helpers.
   Total ``msg_len`` and ``aad_len`` must be known up front.

   :param ctx: Caller-allocated AES context.
   :param key: AES key (16, 24, or 32 bytes).
   :param key_len: Length of ``key``.
   :param nonce: CCM nonce (7–13 bytes).
   :param nonce_len: Length of nonce.
   :param tag_len: Authentication tag length in bytes (4, 6, 8, 10, 12, 14, or 16).
   :param msg_len: Total plaintext/ciphertext length.
   :param aad_len: Total associated data length.
   :returns: ``true`` on success, ``false`` on invalid parameters.

.. c:function:: bool tls_aes_ccm_encrypt(const uint8_t *key, size_t key_len, const uint8_t *nonce, size_t nonce_len, const uint8_t *aad, size_t aad_len, const uint8_t *plaintext, size_t pt_len, uint8_t *ciphertext, uint8_t *tag, size_t tag_len)

   One-shot AES-CCM encryption. Encrypts ``plaintext`` and produces
   ``ciphertext`` and an authentication ``tag`` in a single call.

   :param key: AES key.
   :param key_len: Key length (16, 24, or 32 bytes).
   :param nonce: CCM nonce (7–13 bytes).
   :param nonce_len: Nonce length.
   :param aad: Associated data (authenticated but not encrypted). ``NULL`` if none.
   :param aad_len: Associated data length.
   :param plaintext: Input plaintext.
   :param pt_len: Plaintext length.
   :param ciphertext: Output ciphertext buffer (at least ``pt_len`` bytes).
   :param tag: Output authentication tag buffer.
   :param tag_len: Desired tag length (4, 6, 8, 10, 12, 14, or 16 bytes).
   :returns: ``true`` on success, ``false`` on error.

.. c:function:: bool tls_aes_ccm_decrypt(const uint8_t *key, size_t key_len, const uint8_t *nonce, size_t nonce_len, const uint8_t *aad, size_t aad_len, const uint8_t *ciphertext, size_t ct_len, const uint8_t *tag, size_t tag_len, uint8_t *plaintext)

   One-shot AES-CCM decryption with tag verification. If the tag check fails,
   ``plaintext`` is zeroed and ``false`` is returned — never use output from a
   failed call.

   :param key: AES key.
   :param key_len: Key length (16, 24, or 32 bytes).
   :param nonce: CCM nonce.
   :param nonce_len: Nonce length.
   :param aad: Associated data. ``NULL`` if none.
   :param aad_len: Associated data length.
   :param ciphertext: Input ciphertext.
   :param ct_len: Ciphertext length.
   :param tag: Authentication tag to verify.
   :param tag_len: Tag length.
   :param plaintext: Output plaintext buffer (at least ``ct_len`` bytes).
   :returns: ``true`` on success and tag valid, ``false`` if tag verification
      fails (plaintext is zeroed on failure).

Examples
--------

**Context-based (streaming) GCM encrypt:**

.. code-block:: c

   struct tls_aes_context ctx;

   tls_aes_init(&ctx, TLS_AES_GCM, key, key_len, iv, iv_len);
   tls_aes_update_aad(&ctx, aad, aad_len);   /* optional */
   tls_aes_encrypt(&ctx, plaintext, pt_len, ciphertext);
   uint8_t tag[TLS_AES_AUTH_TAG_SIZE];
   tls_aes_digest(&ctx, tag);

**GCM decrypt — verify before decrypting:**

.. code-block:: c

   tls_aes_init(&ctx, TLS_AES_GCM, key, key_len, iv, iv_len);
   if (tls_aes_verify(&ctx, aad, aad_len, ciphertext, ct_len, tag)) {
       tls_aes_decrypt(&ctx, ciphertext, ct_len, plaintext);
   }

**One-shot CCM:**

.. code-block:: c

   /* Encrypt */
   tls_aes_ccm_encrypt(key, key_len, nonce, nonce_len,
                       aad, aad_len,
                       plaintext, pt_len,
                       ciphertext, tag, tag_len);

   /* Decrypt — zeroes plaintext and returns false if tag fails */
   tls_aes_ccm_decrypt(key, key_len, nonce, nonce_len,
                       aad, aad_len,
                       ciphertext, ct_len,
                       tag, tag_len,
                       plaintext);

For incremental CCM, use ``tls_aes_ccm_init()`` followed by
``tls_aes_update_aad()`` and ``tls_aes_encrypt()`` / ``tls_aes_decrypt()``.
