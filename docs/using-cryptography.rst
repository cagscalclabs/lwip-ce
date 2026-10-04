Using Cryptography
==================

lwIP-CE exposes a set of cryptographic primitives independently of the network
stack. This section will go over the modules of the cryptography API, and end with some use-case examples.

.. important::

   The calculator has no secure enclave or cryptographic acceleration. It has no concept of permissions, file ownership, or process ownership. There are no built-in controls to ensure file integrity or prevent arbitrary code execution. Please be aware of this when using TLS or any cryptographic module in this project. Operate under the premise that your calculator is your trust boundary.

Setup
-----

Call ``lwip_start()`` before using any crypto API (it patches the LibLoad stub so that the function table is correct). You do **not** need to call ``lwip_network_up()`` for crypto-only programs.

.. code-block:: c

   #include <lwip.h>       // for lwip_start()
   #include <cryptography.h>

   int main(void)
   {
       if (!lwip_start())
           return 1;

       /* crypto primitives are ready — no network interface needed */
   }

Include ``cryptography.h`` for the full set of primitives, or include individual headers from ``lwip/cryptography/`` for a narrower surface.

``lwip_start()`` also initializes the RNG.

-----

Randomness
-----------

The calculator has no hardware RNG. lwIP-CE derives entropy from SRAM noise —
the electrical state of uninitialized SRAM varies between power cycles. The
generator is designed in alignment with NIST SP 800-90 standards and achieves
a measured min-entropy of H∞ ≈ 0.99998 bits per output bit (≈ 1.00000 across
the full entropy pool), with a median correlation coefficient of k\ :sub:`eff`
= 1.031, computed over a 1.2 MB nominal dataset per unit tested. For the full entropy analysis,
see the `whitepaper <https://github.com/cagscalclabs/lwip-ce/releases/tag/whitepaper-latest>`_.
Do not use the toolchain ``rand()`` functions for anything security-sensitive;
they are not cryptographically secure.

``lwip/cryptography/random.h`` — SRAM-noise TRNG
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. c:function:: bool tls_random_init_entropy(void)

   Initialize the cryptographic TRNG. Selects an SRAM entropy source, runs the
   conditioning pass, and seeds the DRBG. Must be called before
   ``tls_random()`` or ``tls_random_bytes()`` unless ``lwip_start()`` has
   already been called (which initializes entropy automatically).

   :returns: ``true`` on success, ``false`` if entropy initialization failed
      (e.g. no suitable SRAM source found).

.. c:function:: bool tls_rng_healthcheck(void)

   Run one immediate health-check cycle — the same lightweight sanity and
   recovery logic used by the periodic RNG health timer. If repeated failures
   have been detected, this may trigger a re-initialization of the entropy
   source. **Always call this before generating random data.**

   :returns: ``true`` if the RNG is healthy and safe to use, ``false``
      otherwise. On ``false``, retry ``tls_random_init_entropy()`` or abort.

.. c:function:: void *tls_random_bytes(void *buffer, size_t len)

   Fill ``buffer`` with ``len`` cryptographically random bytes, synchronously.
   The health check must pass before calling this.

   :param buffer: Caller-supplied destination buffer.
   :param len: Number of bytes to fill.
   :returns: ``buffer`` on success.

.. c:function:: uint64_t tls_random(void)

   Return a single cryptographically random 64-bit value, synchronously.
   The health check must pass before calling this.

   :returns: A 64-bit random integer.

.. c:function:: bool tls_request_random_bytes(uint8_t *out, size_t len, tls_random_request_cb_t cb, void *arg, bool blocking)

   Request ``len`` random bytes into ``out``, either synchronously or via
   lwIP timer callbacks. Only one request can be active at a time — check
   ``tls_rng_is_busy()`` before calling. The caller must keep ``out`` valid
   until the request completes (i.e. until ``cb`` is invoked in async mode).

   :param out: Destination buffer. Must remain valid until completion.
   :param len: Number of random bytes requested.
   :param cb: Optional completion callback
      (``void cb(bool ok, void *arg)``). ``ok`` is ``true`` on success.
   :param arg: Opaque pointer passed through to ``cb``.
   :param blocking: ``true`` to gather entropy immediately in the caller
      (may block for a long time); ``false`` to gather in chunks via
      ``lwip_service_events()`` and invoke ``cb`` when done.
   :returns: ``true`` if the request started or completed successfully,
      ``false`` on failure (busy, bad args, or health failure).

.. c:function:: bool tls_rng_is_busy(void)

   Returns ``true`` if a ``tls_request_random_bytes()`` request is currently
   in progress. Use this to guard against starting a second request before
   the first completes.

   :returns: ``true`` if busy, ``false`` if idle.

**Simple synchronous use:**

.. code-block:: c

   /* generator already initialized by lwip_start() */
   uint8_t key[32];

   if(tls_rng_healthcheck())              /* always ensure healthiness before generating */
      tls_random_bytes(key, sizeof(key)); /* fill with cryptographic random bytes */
   else printf("error: rng");
   /* ^ You'll want to actually handle this (ex: retry tls_random_init_entropy()) */

   // ... a bit later ...
   if(tls_rng_healthcheck())              /* always ensure healthiness before generating */
      uint64_t r = tls_random();          /* get a single random 64-bit value */
   else printf("error: rng");
   /* ^ You'll want to actually handle this (ex: retry tls_random_init_entropy()) */

After ``lwip_start()``, the entropy source is initialized automatically as part of the TLS subsystem setup; calling ``tls_random_init_entropy()`` again after that is harmless but redundant.

**Async gathering (large requests, main-loop friendly):**

.. code-block:: c

   static void on_random(bool ok, void *arg) {
       /* called from lwip_service_events() when entropy is ready */
   }

   uint8_t entropy_buf[64];
   tls_request_random_bytes(entropy_buf, sizeof(entropy_buf),
                            on_random, NULL,
                            false);  /* false = async via lwIP timers */

   /* OR: blocking (may stall the UI for a moment) */
   tls_request_random_bytes(entropy_buf, sizeof(entropy_buf),
                            NULL, NULL,
                            true);   /* true = gather immediately */

Only one request can be in flight at a time. ``tls_rng_is_busy()`` returns
``true`` if a request is active. The ``out`` buffer must remain valid until
the callback fires (async) or the call returns (blocking).

``tls_rng_healthcheck()`` runs the same lightweight sanity check the periodic
internal timer runs. It returns ``true`` if the RNG health is currently
acceptable.

------

Symmetric Encryption
--------------------

**Symmetric encryption** is a type of encryption in which a single key can be used to both encrypt and decrypt data. AES (Advanced Encryption Standard) is one of the symmetric ciphers used to obfuscate messages in flight in TLS 1.3 and can also be used to encrypt files at rest.

``lwip/cryptography/aes.h`` — AES-GCM, AES-CBC, AES-CCM
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

AES-128, AES-192, and AES-256 are all supported across all three modes.
AES-GCM and AES-CCM are authenticated encryption modes — they produce an
authentication tag alongside the ciphertext. AES-CBC provides confidentiality
only. ``TLS_AES_BLOCK_SIZE``, ``TLS_AES_IV_SIZE``, and
``TLS_AES_AUTH_TAG_SIZE`` are all 16 bytes.

.. c:function:: bool tls_aes_init(struct tls_aes_context *ctx, uint8_t mode, const uint8_t *key, size_t key_len, const uint8_t *iv, size_t iv_len)

   Initialize an AES context for a single message. Must be called before any
   other context operation. A new call is required per message — context reuse
   across messages is not supported. The context is caller-allocated and
   stack-safe.

   :param ctx: Caller-allocated AES context.
   :param mode: ``TLS_AES_GCM``, ``TLS_AES_CBC``, or ``TLS_AES_CCM``.
   :param key: AES key (16, 24, or 32 bytes for AES-128/192/256).
   :param key_len: Length of ``key`` in bytes.
   :param iv: Initialization vector (16 bytes).
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
   :param aad: Associated data.
   :param aad_len: Length of associated data.
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
   :param aad: Associated data (authenticated but not encrypted).
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
   :param aad: Associated data.
   :param aad_len: Associated data length.
   :param ciphertext: Input ciphertext.
   :param ct_len: Ciphertext length.
   :param tag: Authentication tag to verify.
   :param tag_len: Tag length.
   :param plaintext: Output plaintext buffer (at least ``ct_len`` bytes).
   :returns: ``true`` on success and tag valid, ``false`` if tag verification
      fails (plaintext is zeroed on failure).

**Context-based (streaming) API:**

.. code-block:: c

   struct tls_aes_context ctx;

   /* Initialize once per message */
   tls_aes_init(&ctx, TLS_AES_GCM, key, key_len, iv, iv_len);

   /* Optional: feed associated data (GCM/CCM only) */
   tls_aes_update_aad(&ctx, aad, aad_len);

   /* Encrypt, then retrieve authentication tag */
   tls_aes_encrypt(&ctx, plaintext, pt_len, ciphertext);
   uint8_t tag[TLS_AES_AUTH_TAG_SIZE];
   tls_aes_digest(&ctx, tag);

For decryption, always verify before decrypting. ``tls_aes_verify()`` checks
the tag without producing plaintext — only call ``tls_aes_decrypt()`` if it
returns ``true``:

.. code-block:: c

   tls_aes_init(&ctx, TLS_AES_GCM, key, key_len, iv, iv_len);
   if (tls_aes_verify(&ctx, aad, aad_len, ciphertext, ct_len, tag)) {
       tls_aes_decrypt(&ctx, ciphertext, ct_len, plaintext);
   }

**One-shot CCM API (no context):**

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

----

Hashing and HMAC
-----------------

A hash function produces a fixed-size **digest** that is unique to its input.
An HMAC (hash-based message authentication code) folds a secret key into the
hash so a valid tag cannot be reproduced without the key.

``lwip/cryptography/hash.h`` — SHA-256
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

SHA-256 is the only implemented algorithm. ``TLS_SHA256_DIGEST_LEN`` (32) is
the digest length. Both a direct SHA-256 API and a generic algorithm-selecting
wrapper are provided; they are interchangeable. Both contexts are
caller-allocated and require no teardown — to hash a new message, call the
init function again on the same context.

.. c:function:: bool tls_hash_context_init(struct tls_hash_context *ctx, uint8_t algorithm)

   Initialize a generic hash context to the specified algorithm.

   :param ctx: Caller-allocated generic hash context.
   :param algorithm: ``TLS_HASH_SHA256`` (the only implemented value).
   :returns: ``true`` on success, ``false`` if the algorithm is unrecognized.

.. c:function:: void tls_hash_update(struct tls_hash_context *ctx, const uint8_t *data, size_t len)

   Feed data into a generic hash context.

   :param ctx: Initialized generic hash context.
   :param data: Input data.
   :param len: Length of input data.

.. c:function:: void tls_hash_digest(struct tls_hash_context *ctx, uint8_t *digest)

   Finalize and write the digest from a generic hash context.

   :param ctx: Initialized generic hash context with data fed in.
   :param digest: Output buffer sized to the algorithm's digest length
      (``TLS_SHA256_DIGEST_LEN`` = 32 bytes for SHA-256).

.. c:function:: bool tls_mgf1(const uint8_t *data, size_t datalen, uint8_t *outbuf, size_t outlen, uint8_t hash_alg)

   Compute an MGF1 mask. Used internally by RSA-OAEP and RSA-PSS; exposed
   for callers that need the same mask generation function.

   :param data: Seed data.
   :param datalen: Length of seed.
   :param outbuf: Output mask buffer.
   :param outlen: Desired mask length in bytes.
   :param hash_alg: Hash algorithm to use (``TLS_HASH_SHA256``).
   :returns: ``true`` on success, ``false`` on error.

.. code-block:: c

   uint8_t digest[TLS_SHA256_DIGEST_LEN];
   struct tls_hash_context hctx;

   tls_hash_context_init(&hctx, TLS_HASH_SHA256);
   tls_hash_update(&hctx, data, len);
   tls_hash_digest(&hctx, digest);

``lwip/cryptography/hmac.h`` — HMAC-SHA-256
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

HMAC wraps the hash context with a key. The interface mirrors the hash API:
init with a key, feed data with update, retrieve the MAC with digest. The
context is caller-allocated and requires no teardown.

.. c:function:: bool tls_hmac_context_init(struct tls_hmac_context *ctx, uint8_t algorithm, const uint8_t *key, size_t keylen)

   Initialize an HMAC context with a key and hash algorithm.

   :param ctx: Caller-allocated HMAC context.
   :param algorithm: ``TLS_HASH_SHA256``.
   :param key: HMAC key.
   :param keylen: Key length in bytes.
   :returns: ``true`` on success, ``false`` on error.

.. c:function:: void tls_hmac_update(struct tls_hmac_context *ctx, const uint8_t *data, size_t len)

   Feed data into an HMAC context. May be called any number of times.

   :param ctx: Initialized HMAC context.
   :param data: Input data.
   :param len: Length of input data.

.. c:function:: void tls_hmac_digest(struct tls_hmac_context *ctx, uint8_t *digest)

   Finalize and write the MAC. The context state is consumed; call
   ``tls_hmac_context_init()`` again before reuse.

   :param ctx: Initialized HMAC context with data fed in.
   :param digest: Output buffer (``TLS_SHA256_DIGEST_LEN`` = 32 bytes for HMAC-SHA-256).

.. code-block:: c

   struct tls_hmac_context ctx;
   uint8_t mac[TLS_SHA256_DIGEST_LEN];

   tls_hmac_context_init(&ctx, TLS_HASH_SHA256, key, key_len);
   tls_hmac_update(&ctx, data, len);
   tls_hmac_digest(&ctx, mac);

----

Key Derivation
--------------

``lwip/cryptography/hkdf.h`` — HKDF (RFC 5869)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

HKDF derives keying material from an input secret in two steps: **extract**
condenses potentially weak or non-uniform input keying material (IKM) into a
pseudorandom key (PRK), then **expand** stretches the PRK into output keying
material of any desired length. TLS 1.3-specific label expansion is provided
as a convenience. All functions are stateless — no context struct, each call
is independent.

.. c:function:: bool tls_hkdf_extract(uint8_t hash_algorithm, const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len, uint8_t *prk)

   Extract a fixed-length pseudorandom key from input keying material.
   ``PRK = HMAC-Hash(salt, IKM)``.

   :param hash_algorithm: ``TLS_HASH_SHA256``.
   :param salt: Optional salt. Pass ``NULL`` and ``0`` for no salt.
   :param salt_len: Length of salt in bytes.
   :param ikm: Input keying material.
   :param ikm_len: Length of IKM in bytes.
   :param prk: Output PRK buffer (``TLS_SHA256_DIGEST_LEN`` = 32 bytes for SHA-256).
   :returns: ``true`` on success, ``false`` on failure.

.. c:function:: bool tls_hkdf_expand(uint8_t hash_algorithm, const uint8_t *prk, size_t prk_len, const uint8_t *info, size_t info_len, uint8_t *okm, size_t okm_len)

   Expand a PRK to the desired output length.
   ``OKM = HKDF-Expand(PRK, info, L)``.

   :param hash_algorithm: ``TLS_HASH_SHA256``.
   :param prk: Pseudorandom key from ``tls_hkdf_extract()``.
   :param prk_len: Length of PRK (typically the hash digest length).
   :param info: Optional context info. Pass ``NULL`` and ``0`` for none.
   :param info_len: Length of info.
   :param okm: Output keying material buffer.
   :param okm_len: Desired output length in bytes (max: ``255 * hash_len``).
   :returns: ``true`` on success, ``false`` on failure.

.. c:function:: bool tls_hkdf_expand_label(uint8_t hash_algorithm, const uint8_t *secret, size_t secret_len, const char *label, size_t label_len, const uint8_t *context, size_t context_len, uint8_t *out, size_t out_len)

   TLS 1.3 HKDF-Expand-Label. Formats the label with the ``"tls13 "`` prefix
   per RFC 8446 before calling Expand.

   :param hash_algorithm: ``TLS_HASH_SHA256``.
   :param secret: Input secret.
   :param secret_len: Length of secret.
   :param label: ASCII label string, without the ``"tls13 "`` prefix.
   :param label_len: Length of label.
   :param context: Optional context (typically a transcript hash). Pass ``NULL`` and ``0`` for none.
   :param context_len: Length of context.
   :param out: Output buffer.
   :param out_len: Desired output length in bytes.
   :returns: ``true`` on success, ``false`` on failure.

.. c:function:: bool tls_derive_secret(uint8_t hash_algorithm, const uint8_t *secret, size_t secret_len, const char *label, size_t label_len, const uint8_t *transcript_hash, size_t transcript_hash_len, uint8_t *out)

   TLS 1.3 Derive-Secret. Convenience wrapper equivalent to
   ``HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length)``.

   :param hash_algorithm: ``TLS_HASH_SHA256``.
   :param secret: Input secret.
   :param secret_len: Length of secret.
   :param label: ASCII label string.
   :param label_len: Length of label.
   :param transcript_hash: Hash of the handshake transcript.
   :param transcript_hash_len: Length of transcript hash (32 for SHA-256).
   :param out: Output buffer (``hash_len`` bytes).
   :returns: ``true`` on success, ``false`` on failure.

.. code-block:: c

   uint8_t prk[TLS_SHA256_DIGEST_LEN];
   uint8_t okm[42];

   /* Step 1: extract */
   tls_hkdf_extract(TLS_HASH_SHA256,
                    salt, salt_len,   /* NULL/0 for no salt */
                    ikm, ikm_len,
                    prk);

   /* Step 2: expand */
   tls_hkdf_expand(TLS_HASH_SHA256,
                   prk, sizeof(prk),
                   info, info_len,   /* NULL/0 for no info */
                   okm, sizeof(okm));

``lwip/cryptography/passwords.h`` — PBKDF2 (RFC 8018)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

PBKDF2 derives a key from a password and salt by iterating HMAC many times.
More rounds increase resistance to brute-force, but on the eZ80 this is
measurably slow — keep the round count low for interactive use. The output
buffer is caller-allocated; no heap allocation occurs.

.. c:function:: bool tls_pbkdf2(const char *password, size_t passlen, const uint8_t *salt, size_t saltlen, uint8_t *key, size_t keylen, size_t rounds, uint8_t algorithm)

   Derive a key from a password using PBKDF2-HMAC.

   :param password: Password string.
   :param passlen: Length of password in bytes.
   :param salt: Salt value.
   :param saltlen: Length of salt in bytes.
   :param key: Output key buffer.
   :param keylen: Desired key length in bytes.
   :param rounds: HMAC iterations per output block. Higher is slower and more secure.
   :param algorithm: Hash algorithm (``TLS_HASH_SHA256``).
   :returns: ``true`` on success, ``false`` on failure.

.. code-block:: c

   uint8_t key[32];
   tls_pbkdf2("password", 8,
              salt, salt_len,
              key, sizeof(key),
              100,           /* iteration count */
              TLS_HASH_SHA256);

----

Asymmetric / Public-Key Cryptography
-------------------------------------

**Asymmetric encryption** (also called public-key encryption) uses a key pair:
a public key and a private key. The public key encrypts; the private key
decrypts. The same key pair is also used for signatures: the message is hashed,
the hash is run through a probabilistic encoding algorithm, and the result is
signed with the private key. To verify, the public key operation recovers the
encoded message, which is decoded and compared against a freshly computed hash
of the same message.

``lwip/cryptography/rsa.h`` — RSA 1024–2048
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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

.. code-block:: c

   /* OAEP encode/decode (padding only) */
   uint8_t encoded[128];
   tls_rsa_encode_oaep(message, msg_len, encoded, 128, NULL, TLS_HASH_SHA256);

   uint8_t decoded[128];
   size_t decoded_len = tls_rsa_decode_oaep(encoded, 128, decoded, NULL, TLS_HASH_SHA256);

   /* RSA signature verification (two steps) */
   uint8_t em[256];
   tls_rsa_decrypt_signature(signature, sig_len, em, pubkey, keylen);

   uint8_t mhash[TLS_SHA256_DIGEST_LEN];
   tls_sha256_digest(&hash_ctx, mhash);
   tls_rsa_pss_verify(em, keylen, mhash, sizeof(mhash), TLS_HASH_SHA256);

``lwip/cryptography/x25519.h`` — X25519 Diffie-Hellman
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Elliptic-curve algorithms are a newer construction preferred over RSA for key
exchange. Their security rests on the **elliptic curve discrete logarithm
problem (ECDLP)**: given a public point ``Q = k·G`` on the curve (where ``G``
is the well-known base point and ``k`` is a private scalar), recovering ``k``
is computationally infeasible. Unlike integer factorization, no known
sub-exponential algorithm exists for ECDLP on well-chosen curves, which is why
a 256-bit ECDHE key provides roughly the same strength as a 2048-bit RSA key
with significantly faster math. TLS 1.3 removes RSA key exchange entirely,
requiring elliptic-curve Diffie-Hellman instead.

X25519 is an elliptic-curve Diffie-Hellman function over Curve25519, a
Montgomery curve (``By² = x³ + Ax² + x``). Both X25519 and P-256 are
mandatory-to-implement in TLS 1.3; X25519 was chosen as the primary algorithm
here because the Montgomery ladder — the scalar multiplication algorithm
Montgomery curves use — runs in constant time and is amenable to the kind of
tight assembly optimization this platform requires. P-256 is not yet
implemented, but is planned.

Private keys are automatically clamped per RFC 7748 — no pre-clamping needed.

.. note::

   X25519 is notably slow on the eZ80. Use the ``yield_fn`` callback to keep
   your UI responsive during the computation.

.. c:function:: bool tls_x25519_secret(uint8_t shared_secret[32], const uint8_t my_private[32], const uint8_t their_public[32], void (*yield_fn)(void *), void *yield_data)

   Compute an X25519 shared secret from a private scalar and a peer's public
   key (scalar multiplication).

   :param shared_secret: Output shared secret (32 bytes, little-endian).
   :param my_private: Our private scalar (32 bytes; clamped internally).
   :param their_public: Peer's public key u-coordinate (32 bytes).
   :param yield_fn: Optional callback invoked periodically during computation.
      Pass ``NULL`` if not needed.
   :param yield_data: Context pointer passed to ``yield_fn``. Pass ``NULL``
      if not needed.
   :returns: ``true`` on success, ``false`` on low-order point input
      (RFC 7748 §6 check).

.. c:function:: bool tls_x25519_publickey(uint8_t public_key[32], const uint8_t private_key[32], void (*yield_fn)(void *), void *yield_data)

   Derive an X25519 public key from a private scalar (multiply by the
   Curve25519 base point).

   :param public_key: Output public key u-coordinate (32 bytes).
   :param private_key: Input private scalar (32 bytes; clamped internally).
   :param yield_fn: Optional yield callback. Pass ``NULL`` if not needed.
   :param yield_data: Context pointer for ``yield_fn``. Pass ``NULL`` if not needed.
   :returns: ``true`` on success, ``false`` on error.

.. code-block:: c

   uint8_t my_private[32];    /* 32-byte private scalar */
   uint8_t their_public[32];  /* peer's public key (u-coordinate) */
   uint8_t shared_secret[32];
   uint8_t my_public[32];

   tls_x25519_publickey(my_public, my_private, NULL, NULL);
   tls_x25519_secret(shared_secret, my_private, their_public, NULL, NULL);

----

Certificate and PKI Utilities
-------------------------------

``lwip/cryptography/x509.h`` — X.509 Certificates
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Parses DER or PEM-encoded X.509 certificates and provides field access,
hostname validation, and validity window checks. The heap-allocated
``tls_x509_object`` embeds the DER bytes; its ``parsed`` member holds
``tls_asn1_serialization`` pointers directly into those bytes — do not free
the object while any pointer into it is still in use.

.. c:function:: struct tls_x509_object *tls_x509_import_certificate(const char *pem_data, size_t size)

   Parse a PEM-encoded X.509 certificate into a heap-allocated
   ``tls_x509_object``. Converts PEM to DER internally.

   :param pem_data: PEM certificate data (``-----BEGIN CERTIFICATE-----`` block).
   :param size: Length of ``pem_data``.
   :returns: Pointer to a heap-allocated ``tls_x509_object``, or ``NULL`` on
      parse failure.

.. c:function:: void tls_x509_object_destroy(struct tls_x509_object *obj)

   Free a ``tls_x509_object`` returned by ``tls_x509_import_certificate()``.
   All ``parsed`` pointers into the object become invalid after this call.

   :param obj: Object to free.

.. c:function:: bool tls_x509_parse_certificate(const uint8_t *cert_der, size_t cert_len, struct tls_asn1_serialization fields[13], struct tls_x509_parse_result *out)

   Parse a DER-encoded certificate into caller-supplied buffers. No heap
   allocation. The ``fields`` array and the DER buffer must remain valid for
   as long as ``out`` is used.

   :param cert_der: DER-encoded certificate bytes.
   :param cert_len: Length of ``cert_der``.
   :param fields: Caller-supplied array of 13 ``tls_asn1_serialization`` slots.
   :param out: Receives parsed field pointers (subject CN, issuer CN, SPKI, etc.).
   :returns: ``true`` on success, ``false`` on parse failure.

.. c:function:: bool tls_x509_import_and_parse_certificate(const char *pem_data, size_t size, uint8_t *der_out, size_t der_out_len, size_t *der_written, struct tls_asn1_serialization fields[13], struct tls_x509_parse_result *out)

   Convert PEM to DER into a caller-supplied buffer and parse in one step.
   No heap allocation.

   :param pem_data: PEM certificate data.
   :param size: Length of ``pem_data``.
   :param der_out: Caller-supplied buffer to receive DER bytes.
   :param der_out_len: Size of ``der_out``.
   :param der_written: Receives the number of DER bytes written.
   :param fields: Caller-supplied array of 13 ``tls_asn1_serialization`` slots.
   :param out: Receives parsed field pointers.
   :returns: ``true`` on success, ``false`` on failure.

.. c:function:: bool tls_x509_hostname_matches(const uint8_t *ext_data, size_t ext_len, const struct tls_asn1_serialization *subject_cn, const char *hostname)

   Check whether a certificate is valid for the given hostname. Walks the
   subjectAltName extension for dNSName entries (including single
   leading-label wildcards such as ``*.example.com``). Falls back to the
   subject CommonName if no SAN extension is present (RFC 6125). Comparison
   is ASCII case-insensitive. Fails closed on any parse error.

   :param ext_data: Raw bytes of the leaf's extensions field (``parsed.extensions->data``).
   :param ext_len: Length of ``ext_data``.
   :param subject_cn: Parsed subject CN for CN fallback. May be ``NULL``.
   :param hostname: NUL-terminated hostname the connection was made to.
   :returns: ``true`` if the certificate covers ``hostname``, ``false`` otherwise.

.. c:function:: bool tls_x509_time_to_unix(const struct tls_asn1_serialization *tlv, uint32_t *out_secs)

   Parse an ASN.1 UTCTime or GeneralizedTime value into a Unix timestamp.
   Accepts only UTC (trailing ``Z``); fractional seconds and explicit offsets
   are rejected. UTCTime two-digit years use the RFC 5280 pivot: 50–99 → 19xx,
   00–49 → 20xx. Fails closed on malformed input.

   :param tlv: Parsed ``ASN1_UTCTIME`` or ``ASN1_GENERALIZEDTIME`` TLV.
   :param out_secs: Receives the Unix timestamp on success.
   :returns: ``true`` on success, ``false`` on malformed input.

.. c:function:: bool tls_x509_time_in_validity(const struct tls_asn1_serialization *valid_before, const struct tls_asn1_serialization *valid_after, uint32_t now_secs)

   Check whether ``now_secs`` falls within the certificate's validity window
   ``[notBefore, notAfter]``. Fails closed on any parse error.

   :param valid_before: Parsed notBefore field.
   :param valid_after: Parsed notAfter field.
   :param now_secs: Current time as a Unix timestamp (from SNTP or RTC).
   :returns: ``true`` if ``now_secs`` is within the validity window.

.. c:function:: bool tls_x509_has_required_ca_constraints(const uint8_t *cert_der, size_t cert_len)

   Check whether a DER certificate carries the BasicConstraints extension
   with ``cA=TRUE`` and, if KeyUsage is present, has ``keyCertSign`` set.
   Used to validate intermediate CA certificates in a chain.

   :param cert_der: DER-encoded certificate.
   :param cert_len: Length of ``cert_der``.
   :returns: ``true`` if the CA constraints are satisfied.

.. code-block:: c

   /* Heap-allocated import */
   struct tls_x509_object *cert = tls_x509_import_certificate(pem_data, pem_size);
   if (!cert) { /* parse failed */ }

   /* Access parsed fields */
   /* cert->parsed.subject_cn, issuer_cn, spki_raw, valid_before, etc. */

   /* Hostname check */
   bool ok = tls_x509_hostname_matches(
       cert->parsed.extensions->data, cert->parsed.extensions->len,
       cert->parsed.subject_cn, "example.com");

   /* Validity window check */
   uint32_t now = /* Unix seconds from SNTP or RTC */;
   bool valid = tls_x509_time_in_validity(
       cert->parsed.valid_before, cert->parsed.valid_after, now);

   tls_x509_object_destroy(cert);

``lwip/cryptography/truststore.h`` — CA Root Trust Store
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The trust store is a signed AppVar (``lwIPCERT``) shipped with the lwIP-CE
release. It contains a curated set of CA public keys and is verified at init
time with RSA-PSS-SHA256 against an embedded public key. The TLS socket layer
initialises it internally; call it directly only when doing manual chain
verification. Lookup is by Subject Key Identifier (SKI) or by subject name;
subject-name lookup is also available as public API.

.. c:function:: tls_truststore_status_t tls_truststore_init(void)

   Load and verify the ``lwIPCERT`` AppVar. Must be called before any lookup.
   The TLS socket layer calls this automatically; manual callers should call
   it once and check the return code before any lookup.

   :returns: ``TLS_STORE_OK`` on success, otherwise one of:

   .. list-table::
      :header-rows: 1
      :widths: 45 55

      * - Code
        - Meaning
      * - ``TLS_STORE_OK``
        - Verified and ready.
      * - ``TLS_STORE_NOT_FOUND``
        - The ``lwIPCERT`` AppVar is missing from the calculator.
      * - ``TLS_STORE_SIZE_INVALID``
        - AppVar size field is corrupt.
      * - ``TLS_STORE_VERSION_MISMATCH``
        - AppVar was built for a different truststore format version.
      * - ``TLS_STORE_HASH_FAIL``
        - Internal hash computation failed.
      * - ``TLS_STORE_SIG_INVALID``
        - RSA-PSS-SHA256 signature verification failed; AppVar may be
          tampered or corrupted.

.. c:function:: bool tls_truststore_lookup(const uint8_t *ski, struct tls_truststore_entry **result)

   Look up a trust store entry by Subject Key Identifier.

   :param ski: 32-byte SKI value from the certificate's SubjectKeyIdentifier extension.
   :param result: Out-pointer set to the matching in-place entry on success.
      May be ``NULL`` if the entry pointer is not needed.
   :returns: ``true`` if a matching entry was found.

.. c:function:: bool tls_truststore_lookup_by_subject(const uint8_t *subject, size_t subject_len, struct tls_truststore_entry **result)

   Look up a trust store entry by subject CommonName. Used internally by the
   TLS handshake to anchor the topmost certificate in a chain.

   :param subject: Subject name bytes (up to ``TLS_TRUSTSTORE_SUBJECT_LEN`` = 32), null-padded.
   :param subject_len: Meaningful bytes in ``subject`` (1–32).
   :param result: Out-pointer set to the matching in-place entry on success.
      May be ``NULL``.
   :returns: ``true`` if a matching entry was found.

.. code-block:: c

   tls_truststore_status_t status = tls_truststore_init();
   if (status != TLS_STORE_OK) {
       /* TLS_STORE_NOT_FOUND, TLS_STORE_SIG_INVALID, etc. */
   }

   struct tls_truststore_entry *entry;
   if (tls_truststore_lookup(ski_bytes, &entry)) {
       /* entry->subject, entry->alg_id, entry->key[] accessible */
   }

``lwip/cryptography/keyobject.h`` — Key/Certificate Import
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``tls_keyobject`` is a heap-allocated container for a parsed private key,
public key, or X.509 certificate. It handles PKCS#1, PKCS#8, and SEC1 PEM
formats. The ``type`` field is a bitmask of ``TLS_KEY_PUBLIC`` /
``TLS_KEY_PRIVATE``, ``TLS_KEY_RSA`` / ``TLS_KEY_ECC``, and
``TLS_CERTIFICATE``. ``tls_keyobject_destroy()`` zeroes the object before
freeing it so that private key material does not linger in freed memory.

.. c:function:: struct tls_keyobject *tls_keyobject_import_private(const char *pem_data, size_t size, const char *password)

   Parse a PEM private key (PKCS#8, PKCS#1, or SEC1) into a heap-allocated
   ``tls_keyobject``. Encrypted PKCS#8 keys require a password.

   :param pem_data: PEM-encoded private key.
   :param size: Length of ``pem_data``.
   :param password: Decryption password for encrypted PKCS#8. Pass ``NULL``
      for unencrypted keys.
   :returns: Pointer to a ``tls_keyobject``, or ``NULL`` on failure.

.. c:function:: struct tls_keyobject *tls_keyobject_import_public(const char *pem_data, size_t size)

   Parse a PEM public key (PKCS#1 or PKCS#8 SubjectPublicKeyInfo) into a
   heap-allocated ``tls_keyobject``.

   :param pem_data: PEM-encoded public key.
   :param size: Length of ``pem_data``.
   :returns: Pointer to a ``tls_keyobject``, or ``NULL`` on failure.

.. c:function:: struct tls_keyobject *tls_keyobject_import_certificate(const char *pem_data, size_t size)

   Parse a PEM X.509 certificate into a heap-allocated ``tls_keyobject``.

   :param pem_data: PEM-encoded certificate.
   :param size: Length of ``pem_data``.
   :returns: Pointer to a ``tls_keyobject``, or ``NULL`` on failure.

.. c:function:: void tls_keyobject_destroy(struct tls_keyobject *kf)

   Zero the object's data, then free it. Always use this instead of ``free()``
   to ensure private key material is cleared.

   :param kf: Object to destroy.

.. code-block:: c

   struct tls_keyobject *kf =
       tls_keyobject_import_private(pem_data, size, NULL /* or password */);
   if (!kf) { /* failed */ }

   /* Access fields: kf->meta.privkey.rsa.field.modulus, etc. */

   tls_keyobject_destroy(kf);

``lwip/cryptography/pkcs8.h`` — PKCS#8 / SEC1 Parser
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Lower-level interface that exposes the raw ``tls_pkcs8_object`` parse
structure without going through the ``tls_keyobject`` wrapper. Supports
PKCS#8 (encrypted and unencrypted), PKCS#1, and SEC1 (EC). Encrypted PKCS#8
supports AES-128/256-GCM/CBC with PBKDF2 key derivation. RSA and EC
algorithms are supported.

.. c:function:: struct tls_pkcs8_object *tls_pkcs8_import(const char *pem_data, size_t size, const char *password, tls_pkcs8_error_t *error)

   Parse any supported PEM key format into a ``tls_pkcs8_object``.

   :param pem_data: PEM-encoded key data.
   :param size: Length of ``pem_data``.
   :param password: Decryption password for encrypted PKCS#8. Pass ``NULL``
      for unencrypted keys.
   :param error: Receives a ``tls_pkcs8_error_t`` code on failure. May be
      ``NULL``.
   :returns: Pointer to a ``tls_pkcs8_object``, or ``NULL`` on failure.

.. c:function:: struct tls_keyobject *tls_pkcs8_import_private(const char *pem_data, size_t size, const char *password)

   Parse a PEM private key and return a ``tls_keyobject`` directly.
   Equivalent to ``tls_keyobject_import_private()``.

   :param pem_data: PEM private key.
   :param size: Length of ``pem_data``.
   :param password: Decryption password, or ``NULL``.
   :returns: ``tls_keyobject *`` or ``NULL`` on failure.

.. c:function:: struct tls_keyobject *tls_pkcs8_import_public(const char *pem_data, size_t size)

   Parse a PEM public key and return a ``tls_keyobject`` directly.
   Equivalent to ``tls_keyobject_import_public()``.

   :param pem_data: PEM public key.
   :param size: Length of ``pem_data``.
   :returns: ``tls_keyobject *`` or ``NULL`` on failure.

.. c:function:: struct tls_pkcs8_object *tls_pkcs8_object_import_private(const char *pem_data, size_t size, const char *password)

   Parse a PEM private key into the lower-level ``tls_pkcs8_object`` (not
   wrapped in ``tls_keyobject``).

   :param pem_data: PEM private key.
   :param size: Length of ``pem_data``.
   :param password: Decryption password, or ``NULL``.
   :returns: ``tls_pkcs8_object *`` or ``NULL`` on failure.

.. c:function:: struct tls_pkcs8_object *tls_pkcs8_object_import_public(const char *pem_data, size_t size)

   Parse a PEM public key into the lower-level ``tls_pkcs8_object``.

   :param pem_data: PEM public key.
   :param size: Length of ``pem_data``.
   :returns: ``tls_pkcs8_object *`` or ``NULL`` on failure.

.. c:function:: void tls_pkcs8_object_destroy(struct tls_pkcs8_object *obj)

   Free a ``tls_pkcs8_object``.

   :param obj: Object to free.

.. c:function:: char *tls_pkcs8_strerror(tls_pkcs8_error_t error)

   Return a human-readable string for a ``tls_pkcs8_error_t`` code.

   :param error: Error code from a failed ``tls_pkcs8_import()`` call.
   :returns: Static error string.

.. code-block:: c

   tls_pkcs8_error_t err;
   struct tls_pkcs8_object *obj =
       tls_pkcs8_import(pem_data, size, NULL, &err);
   if (!obj) {
       /* tls_pkcs8_strerror(err) for a human-readable reason */
   }
   tls_pkcs8_object_destroy(obj);

----

ASN.1 / DER Parsing
--------------------

``lwip/cryptography/asn1.h`` — DER cursor and TLV parser
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A forward-only cursor-based DER parser. All pointers in ``tls_asn1_tlv``
reference the original input buffer — no copies are made. Both the cursor
and TLV structs are caller-allocated.

Tag class constants: ``ASN1_UNIVERSAL``, ``ASN1_APPLICATION``,
``ASN1_CONTEXTSPEC``, ``ASN1_PRIVATE``. Common tag numbers:
``ASN1_INTEGER`` (2), ``ASN1_BITSTRING`` (3), ``ASN1_OCTETSTRING`` (4),
``ASN1_OBJECTID`` (6), ``ASN1_SEQUENCE`` (16), ``ASN1_UTCTIME`` (23),
``ASN1_GENERALIZEDTIME`` (24).

.. c:function:: bool tls_asn1_cursor_init(struct tls_asn1_cursor *cursor, const uint8_t *data, size_t len)

   Initialize a cursor over a DER buffer.

   :param cursor: Caller-allocated cursor to initialize.
   :param data: Pointer to the first DER byte.
   :param len: Number of bytes available from ``data``.
   :returns: ``true`` on success, ``false`` on invalid arguments.

.. c:function:: bool tls_asn1_next(struct tls_asn1_cursor *cursor, struct tls_asn1_tlv *out)

   Parse the next TLV from the cursor and advance it. Returns ``false`` at
   end of data (normal completion) or on malformed input — callers that need
   to distinguish the two should track expected fields and treat a premature
   ``false`` as a parse failure.

   :param cursor: Active cursor.
   :param out: Receives the parsed TLV descriptor.
   :returns: ``true`` if a TLV was parsed; ``false`` at end of input or on
      malformed DER.

.. c:function:: bool tls_asn1_child_cursor(const struct tls_asn1_tlv *parent, struct tls_asn1_cursor *child)

   Create a cursor over the value bytes of a constructed TLV (SEQUENCE, SET,
   or context-constructed). Call only when ``tls_asn1_tag_constructed()`` is
   true for the parent tag.

   :param parent: A parsed TLV with the constructed form bit set.
   :param child: Receives a cursor spanning the parent's content bytes.
   :returns: ``true`` on success, ``false`` if the parent is not constructed
      or arguments are invalid.

.. c:function:: uint8_t tls_asn1_tag_number(uint8_t tag)

   Extract the low 5-bit tag number from a raw tag byte.

   :param tag: Raw ASN.1 tag byte.
   :returns: Tag number (0–30).

.. c:function:: uint8_t tls_asn1_tag_class(uint8_t tag)

   Extract the class bits from a raw tag byte.

   :param tag: Raw ASN.1 tag byte.
   :returns: One of ``ASN1_UNIVERSAL``, ``ASN1_APPLICATION``,
      ``ASN1_CONTEXTSPEC``, ``ASN1_PRIVATE``.

.. c:function:: bool tls_asn1_tag_constructed(uint8_t tag)

   Return whether the constructed form bit is set on a raw tag byte.

   :param tag: Raw ASN.1 tag byte.
   :returns: ``true`` if the tag indicates a constructed (nested) element.

.. code-block:: c

   struct tls_asn1_cursor cursor;
   struct tls_asn1_tlv tlv;

   tls_asn1_cursor_init(&cursor, der_bytes, der_len);

   while (tls_asn1_next(&cursor, &tlv)) {
       /* tlv.tag, tlv.len, tlv.value */

       if (tls_asn1_tag_constructed(tlv.tag)) {
           struct tls_asn1_cursor child;
           tls_asn1_child_cursor(&tlv, &child);
           /* iterate child elements... */
       }
   }

----

Encoding Utilities
------------------

``lwip/cryptography/base64.h`` — Base64 encode/decode
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Standard Base64 (RFC 4648) with ``+``/``/`` alphabet and ``=`` padding.
Both functions return the number of bytes written. Output buffer sizing:
encode output is ``4 * ((input_len + 2) / 3)`` bytes; decode output is at
most ``input_len * 3 / 4`` bytes.

.. c:function:: size_t tls_base64_encode(const uint8_t *inbuf, size_t len, uint8_t *outbuf)

   Encode binary data as Base64.

   :param inbuf: Input binary data.
   :param len: Length of input in bytes.
   :param outbuf: Output buffer (at least ``4 * ((len + 2) / 3)`` bytes).
   :returns: Number of bytes written to ``outbuf``.

.. c:function:: size_t tls_base64_decode(const uint8_t *inbuf, size_t len, uint8_t *outbuf)

   Decode Base64 data to binary.

   :param inbuf: Base64-encoded input.
   :param len: Length of input in bytes.
   :param outbuf: Output buffer (at least ``len * 3 / 4`` bytes).
   :returns: Number of bytes written to ``outbuf``.

.. code-block:: c

   uint8_t encoded[512];
   size_t enc_len = tls_base64_encode(binary, bin_len, encoded);

   uint8_t decoded[256];
   size_t dec_len = tls_base64_decode(encoded, enc_len, decoded);

``lwip/cryptography/bytes.h`` — Secure compare and erase
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Two small utilities for safely handling sensitive data. Use
``tls_bytes_compare()`` instead of ``memcmp()`` when comparing MACs, tags,
or other secrets — timing leaks from early-exit comparisons can reveal
information about secret values. Use ``tls_secure_memzero()`` to clear key
material before freeing or reusing a buffer.

.. c:function:: bool tls_bytes_compare(const void *buf1, const void *buf2, size_t len)

   Constant-time buffer comparison. Does not short-circuit on mismatch,
   preventing timing side-channels.

   :param buf1: First buffer.
   :param buf2: Second buffer.
   :param len: Number of bytes to compare.
   :returns: ``true`` if the buffers are identical, ``false`` otherwise.

.. c:function:: void tls_secure_memzero(void *ptr, size_t len)

   Zero a buffer in a way the compiler cannot optimize away. Uses
   ``volatile`` writes to ensure the zeroing is not elided, which is
   critical for clearing cryptographic key material.

   :param ptr: Buffer to zero.
   :param len: Number of bytes to zero.


----

Common Cryptography Usages
---------------------------

The examples below cover common patterns. They are not exhaustive, but
demonstrate the idiomatic way to combine the APIs above.

File Integrity
~~~~~~~~~~~~~~~

Hash a file's contents at two points in time and compare the digests to
detect tampering or corruption. ``tls_bytes_compare()`` is used instead of
``memcmp()`` to avoid timing leaks.

.. code-block:: c

   #include <fileioc.h>
   #include <lwip.h>
   #include <cryptography.h>

   if(!lwip_start()) return 1;

   uint8_t digest_initial[TLS_SHA256_DIGEST_LEN];
   uint8_t digest_second[TLS_SHA256_DIGEST_LEN];
   struct tls_hash_context h;

   /* Hash on first read */
   if (tls_hash_context_init(&h, TLS_HASH_SHA256)) {
       uint8_t f = ti_Open("lwIP", "r");
       if (f) {
           size_t f_len = ti_GetSize(f);
           uint8_t *fp = ti_GetDataPtr(f);
           tls_hash_update(&h, fp, f_len);
           tls_hash_digest(&h, digest_initial);
           ti_Close(f);
       }
   }

   /* ... intervening activity ... */

   /* Hash again and compare */
   if (tls_hash_context_init(&h, TLS_HASH_SHA256)) {
       uint8_t f = ti_Open("lwIP", "r");
       if (f) {
           size_t f_len = ti_GetSize(f);
           uint8_t *fp = ti_GetDataPtr(f);
           tls_hash_update(&h, fp, f_len);
           tls_hash_digest(&h, digest_second);
           ti_Close(f);
           if (!tls_bytes_compare(digest_initial, digest_second, TLS_SHA256_DIGEST_LEN))
               printf("file contents have changed\n");
       }
   }

Encrypt a File at Rest
~~~~~~~~~~~~~~~~~~~~~~~

Derive a key from a user password with PBKDF2, then encrypt data with
AES-GCM. The IV and salt are written to the file alongside the ciphertext
and authentication tag so decryption can reconstruct the same key and IV.

.. code-block:: c

   #include <fileioc.h>
   #include <lwip.h>
   #include <cryptography.h>
   #include <string.h>

   #define KDF_ROUNDS /* benchmark and choose for your application's latency budget */

   if (!lwip_start()) return 1;

   const char *secure_me = "This is a string that shouldn't be stored in the clear";

   uint8_t f = ti_Open("SaveMe", "w");
   if (!f) return 2;

   char *passwd = /* prompt user for password */;
   uint8_t key[TLS_SHA256_DIGEST_LEN];   /* 32-byte AES-256 key */
   uint8_t salt[TLS_AES_BLOCK_SIZE];     /* 16-byte PBKDF2 salt */
   uint8_t iv[TLS_AES_IV_SIZE];          /* 16-byte AES IV */

   /* Generate random salt and IV */
   if (!tls_rng_healthcheck()) return 3;
   tls_random_bytes(salt, sizeof(salt));
   tls_random_bytes(iv, sizeof(iv));

   /* Derive key from password */
   tls_pbkdf2(passwd, strlen(passwd),
              salt, sizeof(salt),
              key, sizeof(key),
              KDF_ROUNDS,
              TLS_HASH_SHA256);

   /* Encrypt */
   struct tls_aes_context e;
   if (!tls_aes_init(&e, TLS_AES_GCM, key, sizeof(key), iv, sizeof(iv))) return 4;
   ti_Write(iv, sizeof(iv), 1, f);               /* IV: not in AAD */
   tls_aes_update_aad(&e, salt, sizeof(salt));   /* salt: authenticated as AAD */
   ti_Write(salt, sizeof(salt), 1, f);
   tls_aes_encrypt(&e, (const uint8_t *)secure_me, strlen(secure_me),
                   (uint8_t *)secure_me);
                  // ^ yes the in and out bufs are aliasable
   ti_Write(secure_me, strlen(secure_me), 1, f);
   uint8_t tag[TLS_AES_AUTH_TAG_SIZE];
   tls_aes_digest(&e, tag);
   ti_Write(tag, sizeof(tag), 1, f);
   ti_Close(f);

Decrypt a File at Rest
~~~~~~~~~~~~~~~~~~~~~~~

The mirror of the encrypt example. Read the IV and salt back from the file,
re-derive the key with PBKDF2, then **verify the authentication tag before
decrypting**. If ``tls_aes_verify()`` returns ``false``, the file is corrupt
or tampered — do not decrypt.

.. code-block:: c

   #include <fileioc.h>
   #include <lwip.h>
   #include <cryptography.h>
   #include <string.h>

   #define KDF_ROUNDS /* benchmark and choose for your application's latency budget */

   if (!lwip_start()) return 1;

   uint8_t f = ti_Open("SaveMe", "r");
   if (!f) return 2;

   size_t f_len = ti_GetSize(f);
   uint8_t *fp = ti_GetDataPtr(f);

   /* Layout written by the encrypt example:
    *   [IV: TLS_AES_IV_SIZE][salt: TLS_AES_BLOCK_SIZE][ciphertext][tag: TLS_AES_AUTH_TAG_SIZE] */
   if (f_len < TLS_AES_IV_SIZE + TLS_AES_BLOCK_SIZE + TLS_AES_AUTH_TAG_SIZE) {
       ti_Close(f);
       return 3;
   }

   uint8_t *iv   = fp;
   uint8_t *salt = fp + TLS_AES_IV_SIZE;
   size_t ct_len = f_len - TLS_AES_IV_SIZE - TLS_AES_BLOCK_SIZE - TLS_AES_AUTH_TAG_SIZE;
   uint8_t *ct   = salt + TLS_AES_BLOCK_SIZE;
   uint8_t *tag  = ct + ct_len;

   char *passwd = /* prompt user for password */;
   uint8_t key[TLS_SHA256_DIGEST_LEN];
   tls_pbkdf2(passwd, strlen(passwd),
              salt, TLS_AES_BLOCK_SIZE,
              key, sizeof(key),
              KDF_ROUNDS,
              TLS_HASH_SHA256);

   /* Verify tag before decrypting */
   struct tls_aes_context e;
   if (!tls_aes_init(&e, TLS_AES_GCM, key, sizeof(key), iv, TLS_AES_IV_SIZE)) return 4;
   if (!tls_aes_verify(&e, salt, TLS_AES_BLOCK_SIZE, ct, ct_len, tag)) {
       ti_Close(f);
       return 5;   /* tampered or wrong password */
   }

   /* Tag valid — safe to decrypt */
   uint8_t plaintext[/* some size large enough to hold decryption */];
   tls_aes_decrypt(&e, ct, ct_len, plaintext);
   ti_Close(f);
