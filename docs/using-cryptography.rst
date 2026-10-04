Using Cryptography
==================

lwIP-CE exposes a set of cryptographic primitives independently of the network
stack. This section will go over the modules of the cryptography API, and end with some use-case examples.

.. important::

   The calculator has no secure enclave or cryptographic acceleration. It has no concept of permissions, file ownership, or process ownership. There are no built-in controls to ensure file integrity or prevent arbitrary code execution. Please be aware of this when using TLS or any cryptographic module in this project. Operate under the premise that your calculator is your trust boundary.

.. note::

   Call ``lwip_start()`` before using any lwIP-CE cryptography. This patches the LibLoad jump
   table so lwIP-CE calls are safe, and initializes the TRNG.

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

The recommended API surface consists of:

- TRNG
- Hashing & HMAC
- Keys
- Passwords
- Bytes

.. contents:: :local:
   :depth: 3

-----

Recommended API
-----------------

A simple API is provided that dispatches to many of the cryptographic primitives where
algorithm-specific best-practices are implemented. It is highly recommended that you use this API
for any cryptography in your programs to avoid omitting edge-case handling where mistakes might
render your programs insecure.

TRNG
~~~~~

| **Header:** ``lwip/cryptography/random.h``
| **References:** `NIST SP 800-90A Rev.1 <https://doi.org/10.6028/NIST.SP.800-90Ar1>`_ — DRBG; `NIST SP 800-90B <https://doi.org/10.6028/NIST.SP.800-90B>`_ — Entropy assessment

The calculator has no hardware RNG. lwIP-CE derives entropy from SRAM noise —
the electrical state of uninitialized SRAM varies between power cycles. The generator is designed in alignment with NIST SP 800-90 guidance. Testing indicates that the entropy source provides sufficient min-entropy for lwIP-CE's cryptographic random-value requirements, with an estimated min-entropy of H∞ ≈ 0.99998 bits per output bit (≈ 1.00000 across
the full entropy pool), with a median correlation factor of k\ :sub:`eff`
= 1.031, computed over a 1.2 MB nominal dataset per unit tested. For the full entropy analysis,
see the `whitepaper <https://github.com/cagscalclabs/lwip-ce/releases/tag/whitepaper-latest>`_.
Do not use the toolchain ``random()`` functions for anything security-sensitive;
they are not cryptographically secure.

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

Hashing and HMAC
-----------------

| **Headers:** ``lwip/cryptography/hash.h``, ``lwip/cryptography/hmac.h``
| **References:** `FIPS 180-4 <https://doi.org/10.6028/NIST.FIPS.180-4>`_ — SHA-256; `RFC 2104 <https://www.rfc-editor.org/rfc/rfc2104>`_ — HMAC

A hash function produces a fixed-size **digest** that is unique to its input.
An HMAC (hash-based message authentication code) folds a secret key into the
hash so a valid tag cannot be reproduced without the key.

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

| **Headers:** ``lwip/cryptography/hkdf.h``, ``lwip/cryptography/passwords.h``
| **References:** `RFC 5869 <https://www.rfc-editor.org/rfc/rfc5869>`_ — HKDF; `RFC 8018 <https://www.rfc-editor.org/rfc/rfc8018>`_ — PBKDF2

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

Key API
---------

The **Key API** is a frontend for all encryption and signing operations within this library.

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
