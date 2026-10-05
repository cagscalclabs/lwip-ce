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

.. contents:: :local:
   :depth: 2

-----

TRNG
-----

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
   uint64_t r;
   if(tls_rng_healthcheck())
      r = tls_random();                  /* get a single random 64-bit value */
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

Hashing
~~~~~~~~
| **Headers:** ``lwip/cryptography/hash.h``
| **References:** `FIPS 180-4 <https://doi.org/10.6028/NIST.FIPS.180-4>`_ — SHA-256

A hash function produces a fixed-size **digest** of its input.
An HMAC (hash-based message authentication code) folds a secret key into the
hash so a valid tag cannot be reproduced without the key.

SHA-256 is the only implemented algorithm. ``TLS_SHA256_DIGEST_LEN`` (32) is
the digest length.

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

HMAC
~~~~~~

| **Headers:** ``lwip/cryptography/hmac.h``
| **References:** `RFC 2104 <https://www.rfc-editor.org/rfc/rfc2104>`_ — HMAC

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

HKDF
~~~~
| **Headers:** ``lwip/cryptography/hkdf.h``
| **References:** `RFC 5869 <https://www.rfc-editor.org/rfc/rfc5869>`_ — HKDF

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

PBKDF2
~~~~~~~
| **Headers:** ``lwip/cryptography/passwords.h``
| **References:** `RFC 8018 <https://www.rfc-editor.org/rfc/rfc8018>`_ — PBKDF2

PBKDF2 derives a key from a password and salt by iterating HMAC many times.
More rounds increase resistance to brute-force, but on the eZ80 this is
measurably slow. Benchmark the round count against your application's
latency budget and password-protection requirements. The output
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

Key Operations
---------------

| **Header:** ``lwip/cryptography/key.h``

The **Key API** stores typed key material in ``struct tls_key``. Import
infers ``type`` from the encoded input; it does not select an operation.
Verification, signing, encryption, and decryption take a separate ``alg``
argument to select the signature scheme or cipher.

Allocating and Setting a Key
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A ``struct tls_key`` is a self-describing key container. The ``type`` field
identifies the key material stored in the union. The algorithm (``tls_alg_t``)
is a separate concept — it is chosen per operation, not stored in the key.
Keys can be allocated by the caller and populated by hand, or allocated and
populated by lwIP-CE via ``tls_key_import()``.

Key types and algorithms are related but orthogonal: ``type`` says what
material is held; ``alg`` says what operation to perform. An RSA key can be
used with ``TLS_ALG_RSA_PKCS1_SHA256`` or ``TLS_ALG_RSA_PSS_RSAE_SHA256``; an
AES-128 key can be used with GCM, CCM, or CBC. Operations reject a key whose
``type`` is incompatible with the requested ``alg``.

.. c:type:: tls_key_type_t

   Identifies the key material stored in a ``struct tls_key``. Set this to
   match whichever union member you populate.

   .. c:macro:: TLS_KEY_TYPE_UNKNOWN

      Zero value; denotes an empty or uninitialised key. Operations reject
      keys of this type.

   .. c:macro:: TLS_KEY_TYPE_RSA

      RSA key. Populate the ``rsa`` union member. Compatible with
      ``TLS_ALG_RSA_PKCS1_SHA256``, ``TLS_ALG_RSA_PSS_RSAE_SHA256``, and
      ``TLS_ALG_RSA_OAEP_SHA256``.

   .. c:macro:: TLS_KEY_TYPE_EC_P256

      EC P-256 key. Populate the ``ec`` union member. Compatible with
      ``TLS_ALG_ECDSA_SECP256R1_SHA256`` (currently unimplemented).

   .. c:macro:: TLS_KEY_TYPE_AES

      AES key. Populate the ``aes`` union member. Compatible with all
      ``TLS_ALG_AES_*`` ciphers; the key length (``aes.len``) must match the
      selected algorithm (16 bytes for ``_128_*``, 32 bytes for ``_256_*``).

.. c:struct:: tls_key

   Self-describing key. Populate ``type`` and exactly one union member.

   .. c:member:: tls_key_type_t type

      Key material type. Drives dispatch — operations check this against the
      requested ``alg`` and reject mismatches before touching key material.
      Must be set correctly before passing the key to any operation.

   .. c:member:: bool allocated

      ``true`` when this struct was returned by ``tls_key_import()`` and must
      be freed with ``tls_key_free()``. Leave ``false`` for stack-allocated or
      externally-managed keys. Do not set this flag manually.

   .. c:member:: struct tls_rsa_key rsa

      Valid when ``type == TLS_KEY_TYPE_RSA``. Contains ``modulus``,
      ``mod_len``, ``exponent``, and ``exp_len`` — unsigned big-endian byte
      pointers and their lengths. Strip the DER INTEGER sign-padding byte when
      constructing RSA keys manually. The backend supports 128–256-byte moduli
      and exponents of at most three bytes.

   .. c:member:: struct { size_t len; const uint8_t *data; } ec

      Valid when ``type == TLS_KEY_TYPE_EC_P256``. Raw EC key bytes. For
      public keys this is the uncompressed point (``04 || X || Y`` from the
      SPKI BIT STRING). For private keys this is the raw private scalar.

   .. c:member:: struct { size_t len; const uint8_t *data; } aes

      Valid when ``type == TLS_KEY_TYPE_AES``. Points to the raw key bytes;
      ``len`` must be 16 (128-bit) or 32 (256-bit) to match the selected
      cipher.

Stack-allocated keys borrow their buffers — keep those buffers alive for
every operation. ``tls_key_free()`` is a no-op on a caller-allocated key because
``allocated`` is false.

.. c:function:: tls_key_import_result_t tls_key_import(struct tls_key **out, const void *data, size_t len, tls_key_format_t format, const char *password)

   Import encoded key material into a new heap allocation. The returned key
   owns a copy of its data, so the input buffer can be released after import.
   The ``type`` field is set from the encoded key type
   (RSA → ``TLS_KEY_TYPE_RSA``, EC → ``TLS_KEY_TYPE_EC_P256``). The algorithm
   (``tls_alg_t``) is not stored in the key — it is chosen per operation.

   AES keys are not supported — there is no standard encoding for a raw
   symmetric key. Construct AES keys directly on the stack instead.

   :param out: Receives the allocated key on success; set to ``NULL`` on error.
   :param data: PEM text or DER bytes.
   :param len: Input length in bytes.
   :param format: ``TLS_KEY_FORMAT_PEM`` or ``TLS_KEY_FORMAT_DER``.
   :param password: Passphrase for an encrypted PKCS#8 key; ``NULL`` for
      unencrypted input.
   :returns: ``TLS_KEY_IMPORT_OK`` on success. Failures include
      ``TLS_KEY_IMPORT_INVALID_ARG``, ``TLS_KEY_IMPORT_ALLOC_FAIL``,
      ``TLS_KEY_IMPORT_PARSE_FAIL``, ``TLS_KEY_IMPORT_BAD_ALG``,
      ``TLS_KEY_IMPORT_UNSUPPORTED_ENC``, and ``TLS_KEY_IMPORT_DECRYPT_FAIL``.

It follows that there are two ways to define a ``tls_key`` struct. The code below will illustrate both.

.. code::

   uint8_t aes_key[16] = { /* this should be TRNG output */ };
   struct tls_key my_aes_key = {
       .type      = TLS_KEY_TYPE_AES,
       .allocated = false,
       .aes       = { .len = sizeof(aes_key), .data = aes_key },
   };

   /* ... a bit later ... */
   uint8_t f = ti_Open("KeyFile", "r");
   if(f){
      struct tls_key *my_rsa_key = NULL;
      const char *passwd = "/* User input here */";
      if(tls_key_import(&my_rsa_key,
                        ti_GetDataPtr(f), ti_GetSize(f),
                        TLS_KEY_FORMAT_PEM, passwd) != TLS_KEY_IMPORT_OK)
         printf("error");
      ti_Close(f);
      /* ... use my_rsa_key ... */
      tls_key_free(my_rsa_key);
   }

When constructing a key manually:

- Set ``type`` to the appropriate ``TLS_KEY_TYPE_*`` constant.
- For AES, set ``aes.data`` to the key bytes and ``aes.len`` to 16 or 32,
  matching the ``_128_*`` or ``_256_*`` algorithm you intend to use.
- For RSA, set ``rsa.modulus`` and ``rsa.exponent`` to unsigned big-endian byte
  arrays with lengths in ``rsa.mod_len`` and ``rsa.exp_len``. Strip the DER
  INTEGER sign-padding byte. The backend supports 128–256-byte moduli and
  exponents of at most three bytes.
- For EC, set ``ec.data`` to the uncompressed public point and ``ec.len`` to
  its length (65 bytes for P-256).

Manually constructed keys borrow their buffers. Keep those buffers alive for
every operation and leave ``allocated`` false. Zero key material with
``tls_secure_memzero()`` when it is no longer needed. Operation calls reject an
incompatible ``type`` or AES key length before accessing key material.
``TLS_ALG_IS_SIGNING()`` and ``TLS_ALG_IS_ENCRYPTION()`` classify algorithm
ranges; they do not establish that an operation is implemented.

Encryption/Decryption over a Key
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Encrypt and decrypt operations use a **self-describing blob** format so that
no caller-managed buffers are required. The encrypt blob is a flat byte array:

.. code-block:: text

   <uint16_t iv_len> <iv bytes> <uint16_t ct_len> <ciphertext bytes> <uint16_t tag_len> <tag bytes>

All ``uint16_t`` fields are little-endian. ``iv_len`` is 0 for RSA-OAEP.
``tag_len`` is 0 for CBC and RSA-OAEP (no authentication tag).

The decrypt blob contains the recovered plaintext:

.. code-block:: text

   <uint16_t plain_len> <plaintext bytes>

Both blob types are freed with the same function: ``tls_cipher_blob_free()``.
The blobs are self-describing, so an externally received ciphertext can be
decoded into this format and passed to ``tls_cipher_decrypt()`` without having
originated from ``tls_cipher_encrypt()``.

.. note::

   **AAD is not included in the ciphertext blob.** It is authenticated by the
   tag but never encrypted or stored. If you used ``tls_cipher_encrypt_aad()``,
   you must transmit the AAD to the recipient through a separate channel and
   pass the identical bytes to ``tls_cipher_decrypt_aad()``. A mismatch causes
   tag verification to fail and decrypt returns ``NULL``.

.. c:function:: uint8_t *tls_cipher_encrypt(const struct tls_key *key, tls_alg_t alg, const uint8_t *in, size_t in_len)

   Encrypt ``in`` and return an allocated ciphertext blob. A fresh random IV
   is generated internally. The RNG health check runs before generating the IV.

   :param key: Key to encrypt with; ``alg`` and key type must be compatible.
   :param alg: Cipher to use (e.g. ``TLS_ALG_AES_256_GCM``).
   :param in: Plaintext input.
   :param in_len: Plaintext length in bytes.
   :returns: Allocated ciphertext blob on success, ``NULL`` on any error
      (bad args, RNG failure, allocation failure, or cipher error).
      Free with ``tls_cipher_blob_free()``.

.. c:function:: uint8_t *tls_cipher_encrypt_aad(const struct tls_key *key, tls_alg_t alg, const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t in_len)

   Encrypt with additional authenticated data (AAD). The AAD is authenticated
   but not encrypted; supply the identical bytes to the matching decrypt call.
   RSA-OAEP and CBC do not support AAD — passing a non-``NULL`` ``aad`` or a
   non-zero ``aad_len`` with those algorithms returns ``NULL``.
   Otherwise identical to ``tls_cipher_encrypt()``.

   :param aad: Additional authenticated data. Pass ``NULL`` and ``0`` for none.
   :param aad_len: Length of AAD in bytes.
   :returns: Allocated ciphertext blob on success, ``NULL`` on error.
      Free with ``tls_cipher_blob_free()``.

.. c:function:: uint8_t *tls_cipher_decrypt(const struct tls_key *key, tls_alg_t alg, const uint8_t *blob)

   Decrypt a ciphertext blob and return an allocated plaintext blob. For
   GCM/CCM the authentication tag is verified before decrypting; returns
   ``NULL`` on mismatch. Use the same ``alg`` that was passed to encrypt.
   ``blob`` need not have come from ``tls_cipher_encrypt()``; any correctly
   formatted blob is accepted.

   :param key: Key to decrypt with.
   :param alg: Cipher used to encrypt.
   :param blob: Self-describing ciphertext blob.
   :returns: Allocated plaintext blob on success, ``NULL`` on any error or
      tag mismatch. The plaintext is at ``blob + 2`` and its length is the
      little-endian ``uint16_t`` at ``blob[0..1]``.
      Free with ``tls_cipher_blob_free()``.

.. c:function:: uint8_t *tls_cipher_decrypt_aad(const struct tls_key *key, tls_alg_t alg, const uint8_t *aad, size_t aad_len, const uint8_t *blob)

   Decrypt with AAD. The AAD is fed into tag verification before any bytes are
   decrypted; a mismatch returns ``NULL``. RSA-OAEP and CBC do not support AAD
   — passing a non-``NULL`` ``aad`` or a non-zero ``aad_len`` with those
   algorithms returns ``NULL``. Otherwise identical to ``tls_cipher_decrypt()``.

   :param aad: Additional authenticated data; must match what was passed to encrypt.
   :param aad_len: Length of AAD in bytes.
   :returns: Allocated plaintext blob on success, ``NULL`` on error or mismatch.
      Free with ``tls_cipher_blob_free()``.

.. c:function:: uint8_t *tls_cipher_blob_assemble(const uint8_t *iv, size_t iv_len, const uint8_t *ct, size_t ct_len, const uint8_t *tag, size_t tag_len)

   Assemble a ciphertext blob from separately held fields. Use this when the
   IV, ciphertext, and tag arrive as distinct buffers (e.g. received over the
   network) and need to be packed into the format expected by
   ``tls_cipher_decrypt()`` / ``tls_cipher_decrypt_aad()``.

   Any field may be ``NULL`` with a corresponding length of 0 (e.g. RSA-OAEP
   has no IV or tag; CBC has no tag).

   :param iv:      IV/nonce bytes, or ``NULL``.
   :param iv_len:  Length of ``iv`` in bytes.
   :param ct:      Ciphertext bytes.
   :param ct_len:  Length of ``ct`` in bytes.
   :param tag:     Authentication tag bytes, or ``NULL``.
   :param tag_len: Length of ``tag`` in bytes.
   :returns: Allocated ciphertext blob on success, ``NULL`` on allocation failure.
      Free with ``tls_cipher_blob_free()``.

.. list-table:: Encryption ciphers and support
   :header-rows: 1
   :widths: 45 15 40

   * - Cipher
     - Member
     - Operation
   * - ``TLS_ALG_AES_128_GCM``, ``TLS_ALG_AES_256_GCM``
     - ``aes``
     - Authenticated encryption/decryption; 12-byte IV, 16-byte tag.
   * - ``TLS_ALG_AES_128_CCM``, ``TLS_ALG_AES_256_CCM``
     - ``aes``
     - Authenticated encryption/decryption; 13-byte nonce, 16-byte tag.
   * - ``TLS_ALG_AES_128_CBC``, ``TLS_ALG_AES_256_CBC``
     - ``aes``
     - Encryption/decryption; 16-byte IV, no authentication tag.
   * - ``TLS_ALG_RSA_OAEP_SHA256``
     - ``rsa``
     - RSA-OAEP encryption with SHA-256; see decryption limitations below.


**Example — AES-128-GCM round-trip**

.. code-block:: c

   /* Stack-allocated AES key. */
   static const uint8_t raw_key[16] = { /* 16 key bytes */ };
   struct tls_key k = {
       .type     = TLS_KEY_TYPE_AES,
       .aes      = { .data = raw_key, .len = sizeof raw_key },
       .allocated = false,
   };

   /* Encrypt. */
   const uint8_t plaintext[] = "hello";
   uint8_t *enc = tls_cipher_encrypt(&k, TLS_ALG_AES_128_GCM,
                                   plaintext, sizeof plaintext);
   if (!enc) { /* handle error */ }

   /* Decrypt. */
   uint8_t *dec = tls_cipher_decrypt(&k, TLS_ALG_AES_128_GCM, enc);
   if (!dec) { /* tag mismatch or error */ }

   /* Parse the plaintext from the decrypt blob. */
   uint16_t plain_len = (uint16_t)(dec[0] | ((uint16_t)dec[1] << 8));
   const uint8_t *pt  = dec + 2;
   /* use pt[0..plain_len-1] here */

   tls_cipher_blob_free(enc);
   tls_cipher_blob_free(dec);

Signing and Verifying
~~~~~~~~~~~~~~~~~~~~~~

Result type
^^^^^^^^^^^

.. c:type:: tls_key_op_result_t

   Return value for ``tls_key_verify()`` and ``tls_key_sign()``.

   .. c:macro:: TLS_KEY_OP_OK

      Operation succeeded.

   .. c:macro:: TLS_KEY_OP_INVALID

      Operation failed: bad signature, key/algorithm mismatch, or wrong key
      type for the requested algorithm.

   .. c:macro:: TLS_KEY_OP_UNSUPPORTED

      Algorithm is recognized but not yet implemented (e.g. ECDSA, RSA
      signing).

   .. c:macro:: TLS_KEY_OP_UNKNOWN

      Algorithm value is out of range for the requested operation category
      (e.g. an encryption algorithm passed to ``tls_key_verify()``).

Functions
^^^^^^^^^

.. c:function:: tls_key_op_result_t tls_key_verify(const uint8_t *content, size_t content_len, const uint8_t *sig, size_t sig_len, const struct tls_key *key, tls_alg_t alg)

   Verify a signature over ``content`` using ``key``.

   Hashes ``content`` with SHA-256 internally; pass the raw message, not a
   pre-computed digest.  Dispatches on ``alg`` after checking ``key->type``;
   returns ``TLS_KEY_OP_INVALID`` when ``key->type`` does not match ``alg``.

   Only signing-range algorithms are accepted (``TLS_ALG_IS_SIGNING``).
   Passing an encryption-range ``alg`` returns ``TLS_KEY_OP_UNKNOWN``.

   :param content: Message bytes to verify.
   :param content_len: Length of ``content`` in bytes.
   :param sig: Raw signature bytes.
   :param sig_len: Length of ``sig`` in bytes.
   :param key: Key holding the public material; ``key->type`` must match ``alg``.
   :param alg: Signature scheme to use (e.g. ``TLS_ALG_RSA_PKCS1_SHA256``).
   :returns: ``TLS_KEY_OP_OK`` on valid signature; ``TLS_KEY_OP_INVALID``,
             ``TLS_KEY_OP_UNSUPPORTED``, or ``TLS_KEY_OP_UNKNOWN`` otherwise.

.. c:function:: tls_key_op_result_t tls_key_sign(const uint8_t *content, size_t content_len, uint8_t *sig_out, size_t *sig_len_out, const struct tls_key *key, tls_alg_t alg)

   Sign ``content`` with ``key``, writing the raw signature to ``sig_out``.

   Hashes ``content`` with SHA-256 internally; pass the raw message, not a
   pre-computed digest.  ``sig_len_out`` receives the number of bytes written on
   success.  The caller must pre-allocate ``sig_out`` large enough to hold the
   output (RSA signatures are ``key->rsa.mod_len`` bytes).

   .. note::

      Signing is currently unimplemented for all algorithms, including RSA.
      All calls return ``TLS_KEY_OP_UNSUPPORTED`` until private-key signing is
      added.

   :param content: Message bytes to sign.
   :param content_len: Length of ``content`` in bytes.
   :param sig_out: Caller-allocated buffer to receive the raw signature.
   :param sig_len_out: Receives the number of bytes written on success.
   :param key: Key holding the private material.
   :param alg: Signature scheme to use.
   :returns: ``TLS_KEY_OP_OK`` on success; ``TLS_KEY_OP_UNSUPPORTED`` until
             signing is implemented; ``TLS_KEY_OP_INVALID`` or
             ``TLS_KEY_OP_UNKNOWN`` on bad arguments.

.. list-table:: Signature schemes and support
   :header-rows: 1
   :widths: 45 15 40

   * - Algorithm
     - Member
     - Operation
   * - ``TLS_ALG_RSA_PKCS1_SHA256``
     - ``rsa``
     - Verify PKCS#1 v1.5 signatures with SHA-256.
   * - ``TLS_ALG_RSA_PSS_RSAE_SHA256``
     - ``rsa``
     - Verify PSS signatures with SHA-256, MGF1-SHA-256 and a 32-byte salt.
   * - ``TLS_ALG_ECDSA_SECP256R1_SHA256``
     - ``ec``
     - Recognized, but verification and signing are unimplemented.

Example::

   struct tls_key *pub = ...; /* imported RSA public key */
   const uint8_t *msg = (const uint8_t *)"hello";
   const uint8_t sig[128] = { /* signature bytes from peer */ };

   tls_key_op_result_t r = tls_key_verify(msg, 5, sig, sizeof(sig),
                                           pub, TLS_ALG_RSA_PKCS1_SHA256);
   if (r != TLS_KEY_OP_OK) {
       /* signature invalid or algorithm not supported */
   }

Freeing Keys
~~~~~~~~~~~~~

There are two distinct lifetimes to manage: the ``struct tls_key`` itself
(heap-allocated by ``tls_key_import()``) and any cipher blobs produced by
encrypt or decrypt operations.

.. c:function:: void tls_key_free(struct tls_key *key)

   Zero and release a key returned by ``tls_key_import()``.

   Checks ``key->allocated`` before doing anything: if ``false`` the function
   returns immediately, making it safe to call on stack-allocated or
   externally-managed keys. When ``true``, zeroes the entire allocation
   (key header plus trailing key material) and frees it.

   Safe to call with ``NULL``.

   .. warning::

      Do not call ``tls_key_free()`` on the ``pubkey`` member embedded inside
      a ``struct tls_x509_object``. That key borrows its buffers from the
      certificate allocation. Free the owning certificate object instead.

   .. note::

      Stack-allocated keys (``allocated = false``) borrow their buffers from
      the caller. Use ``tls_secure_memzero()`` to zero those buffers when the
      key is no longer needed — ``tls_key_free()`` will not touch them.

.. c:function:: void tls_cipher_blob_free(uint8_t *buf)

   Zero and free a blob returned by ``tls_cipher_encrypt()``,
   ``tls_cipher_encrypt_aad()``, ``tls_cipher_decrypt()``,
   ``tls_cipher_decrypt_aad()``, or ``tls_cipher_blob_assemble()``.

   The allocator records the full allocation size in a hidden header, so the
   blob is zeroed in its entirety (IV, ciphertext, tag, and plaintext for
   decrypt blobs) before the memory is released.

   Safe to call with ``NULL``.

Summary of ownership rules:

- ``tls_key_import()`` → free with ``tls_key_free()``.
- Stack ``struct tls_key`` → call ``tls_secure_memzero()`` on borrowed buffers
  yourself; never pass to ``tls_key_free()``.
- ``tls_cipher_encrypt()`` / ``tls_cipher_decrypt()`` / ``tls_cipher_blob_assemble()``
  → free with ``tls_cipher_blob_free()``.
- ``struct tls_x509_object`` → free with ``tls_x509_object_free()``; never free
  its embedded ``pubkey`` independently.

-----

Certificates
-------------

A ``struct tls_x509_object`` holds the parsed fields of a single X.509
certificate — distinguished names, validity window, extensions, and the
extracted public key. All pointer members reference DER bytes; the object
does **not** own independent copies of each field.

There are two ways to obtain one, with different ownership rules:

- **Standalone import** via ``tls_x509_import_certificate()``: allocates a
  single heap block (object header + trailing DER copy). Pointer members
  reference that trailing copy. Must be released with
  ``tls_x509_object_free()``.
- **Parse-in-place** via ``tls_x509_parse_certificate()``: populates a
  caller-allocated ``struct tls_x509_object`` with pointers into the
  caller-supplied DER buffer. No heap allocation; the caller keeps the DER
  buffer alive. ``tls_x509_object_free()`` is a no-op on these (``from_handshake``
  is ``true``).

In both cases ``pubkey.allocated`` is always ``false`` — the key material lives
inside the DER bytes, not in a separate allocation. Never call ``tls_key_free()``
on ``obj->pubkey``; use ``tls_x509_object_free()`` on the certificate instead.

The Object
~~~~~~~~~~

.. c:struct:: tls_x509_object

   Parsed X.509 certificate. All pointer members reference DER bytes.

   .. c:member:: bool from_handshake

      ``true`` when populated by ``tls_x509_parse_certificate()`` (pointers
      borrow the caller's buffer; ``tls_x509_object_free()`` is a no-op).
      ``false`` when allocated by ``tls_x509_import_certificate()`` (must be
      freed).

   .. c:member:: const uint8_t *issuer_cn
   .. c:member:: size_t issuer_cn_len

      Issuer CommonName — raw string bytes (no NUL terminator).

   .. c:member:: const uint8_t *subject_cn
   .. c:member:: size_t subject_cn_len

      Subject CommonName — raw string bytes (no NUL terminator).

   .. c:member:: const uint8_t *not_before
   .. c:member:: size_t not_before_len
   .. c:member:: uint8_t not_before_tag

      RFC 5280 ``notBefore`` field: raw value bytes and the ASN.1 tag
      (``ASN1_UTCTIME`` or ``ASN1_GENERALIZEDTIME``). The certificate is not
      valid before this time.

   .. c:member:: const uint8_t *not_after
   .. c:member:: size_t not_after_len
   .. c:member:: uint8_t not_after_tag

      RFC 5280 ``notAfter`` field: raw value bytes and ASN.1 tag. The
      certificate is not valid after this time.

   .. c:member:: const uint8_t *extensions
   .. c:member:: size_t extensions_len

      Raw bytes of the ``SEQUENCE OF Extension`` inside the ``[3] EXPLICIT``
      extensions wrapper; ``NULL`` / 0 when no extensions are present.

   .. c:member:: struct tls_key pubkey

      Public key extracted from SubjectPublicKeyInfo. ``pubkey.allocated`` is
      always ``false``; never pass to ``tls_key_free()``.

   .. c:member:: size_t der_len
   .. c:member:: uint8_t der[]

      Heap-owned DER copy (only meaningful when ``!from_handshake``). The
      flexible array member trails the struct in the same allocation.

Importing and Freeing
~~~~~~~~~~~~~~~~~~~~~

.. c:function:: struct tls_x509_object *tls_x509_import_certificate(const char *pem_data, size_t size)

   Parse a PEM-encoded certificate and return an allocated
   ``tls_x509_object``. Allocates a single block: object header plus a DER
   copy; all pointer members reference that trailing DER. The input
   ``pem_data`` buffer can be released after this call returns.

   :param pem_data: PEM text starting with ``-----BEGIN CERTIFICATE-----``.
   :param size: Length of ``pem_data`` in bytes.
   :returns: Allocated object on success, ``NULL`` on parse or allocation
      failure. Free with ``tls_x509_object_free()``.

.. c:function:: bool tls_x509_parse_certificate(const uint8_t *cert_der, size_t cert_len, struct tls_x509_object *out)

   Parse a DER-encoded certificate into a caller-allocated
   ``struct tls_x509_object``. All pointer members in ``out`` reference bytes
   inside ``cert_der``; the caller must keep ``cert_der`` live for the entire
   lifetime of ``out``. Sets ``out->from_handshake = true``.

   :param cert_der: DER-encoded certificate bytes.
   :param cert_len: Length of ``cert_der`` in bytes.
   :param out: Caller-allocated object to receive parsed fields.
   :returns: ``true`` on success, ``false`` on parse failure.

.. c:function:: void tls_x509_object_free(struct tls_x509_object *obj)

   Release a certificate object allocated by ``tls_x509_import_certificate()``.
   Zeroes the entire allocation (header + DER copy) before freeing.

   No-op when ``obj->from_handshake`` is ``true`` (parse-in-place objects
   borrow their DER; the caller owns that buffer). Safe to call with ``NULL``.

Validation Helpers
~~~~~~~~~~~~~~~~~~

.. c:function:: bool tls_x509_hostname_matches(const uint8_t *ext_data, size_t ext_len, const uint8_t *subject_cn, size_t subject_cn_len, const char *hostname)

   Check whether a leaf certificate covers ``hostname``.

   Walks the subjectAltName extension for dNSName entries, matching each
   against ``hostname`` with ASCII case-insensitive comparison and single
   leading-label wildcard support (``*.example.com`` matches
   ``foo.example.com`` but not ``foo.bar.example.com`` or ``example.com``
   itself). Falls back to matching the subject CommonName when no
   subjectAltName extension is present (RFC 6125 legacy). Fails closed on any
   parse error.

   IP literals require an exact binary ``iPAddress`` SAN match (IPv4 or
   IPv6). Neither DNS SANs nor CommonName can authenticate an IP destination.
   IPv6 literals must be unbracketed and have no zone identifier. TLS omits
   SNI when connecting to an IP literal.

   :param ext_data: Raw bytes of ``obj->extensions``.
   :param ext_len: ``obj->extensions_len``.
   :param subject_cn: ``obj->subject_cn`` for CN fallback; may be ``NULL``.
   :param subject_cn_len: ``obj->subject_cn_len``.
   :param hostname: NUL-terminated hostname the connection was made to.
   :returns: ``true`` if the certificate covers ``hostname``.

.. c:function:: bool tls_x509_time_in_validity(const struct tls_x509_object *cert, uint32_t now_secs)

   Check whether ``now_secs`` falls within the certificate's notBefore–notAfter
   window. Reads validity fields directly from the parsed object. Fails closed
   on any parse error or inverted validity window.

   :param cert: Parsed certificate.
   :param now_secs: Current time as a Unix timestamp (seconds since epoch).
   :returns: ``true`` if ``now_secs`` is within ``[notBefore, notAfter]``.

.. c:function:: bool tls_x509_time_to_unix(const uint8_t *data, size_t len, uint8_t tag, uint32_t *out_secs)

   Convert a raw ASN.1 UTCTime or GeneralizedTime value to a Unix timestamp.
   Pass the value bytes and tag directly from a ``tls_x509_object`` validity
   field. Fails closed on malformed input.

   :param data: Raw value bytes (the TLV value, not the tag or length).
   :param len: Length of ``data``.
   :param tag: ASN.1 tag byte (``ASN1_UTCTIME`` or ``ASN1_GENERALIZEDTIME``).
   :param out_secs: Receives the Unix timestamp on success.
   :returns: ``true`` on success.

Signature Verification
~~~~~~~~~~~~~~~~~~~~~~

These functions verify signatures in certificate-processing contexts. For
verifying application signatures against an imported key use ``tls_key_verify()``
instead.

.. c:function:: tls_key_op_result_t tls_x509_signature_verify(const uint8_t *content, size_t content_len, const uint8_t *sig, size_t sig_len, const struct tls_key *key, tls_alg_t alg)

   Verify a signature over arbitrary content using a key and an explicit
   scheme. SHA-256 hashes ``content`` internally before verifying.

   Dispatches on ``alg``:

   - ``TLS_ALG_RSA_PKCS1_SHA256`` — RSASSA-PKCS1-v1.5 SHA-256
   - ``TLS_ALG_RSA_PSS_RSAE_SHA256`` — RSASSA-PSS SHA-256 (saltLen=32)
   - ``TLS_ALG_ECDSA_SECP256R1_SHA256`` — returns ``TLS_KEY_OP_UNSUPPORTED``
   - Encryption-range or unknown ``alg`` — returns ``TLS_KEY_OP_UNKNOWN``

   :param content: Signed data (e.g. DER TBSCertificate bytes).
   :param content_len: Length of ``content``.
   :param sig: Raw signature bytes.
   :param sig_len: Length of ``sig``.
   :param key: Self-describing key; ``key->type`` must match ``alg``.
   :param alg: Signature scheme to verify.
   :returns: ``TLS_KEY_OP_OK`` on valid signature; ``TLS_KEY_OP_INVALID``,
      ``TLS_KEY_OP_UNSUPPORTED``, or ``TLS_KEY_OP_UNKNOWN`` otherwise.

.. c:function:: tls_key_op_result_t tls_x509_signature_verify_digest(const uint8_t digest[32], const uint8_t *sig, size_t sig_len, const struct tls_key *key, tls_alg_t alg)

   Verify a signature over a pre-computed SHA-256 digest. Same dispatch as
   ``tls_x509_signature_verify()`` but accepts a 32-byte digest instead of
   raw content. Used when the TBS bytes are no longer available (e.g. a
   certificate chain walker that pre-hashes and then discards the TBS).

   :param digest: 32-byte SHA-256 digest of the signed content.
   :param sig: Raw signature bytes.
   :param sig_len: Length of ``sig``.
   :param key: Self-describing key.
   :param alg: Signature scheme to verify.
   :returns: ``TLS_KEY_OP_OK`` on success; ``TLS_KEY_OP_INVALID``,
      ``TLS_KEY_OP_UNSUPPORTED``, or ``TLS_KEY_OP_UNKNOWN`` otherwise.

-----

Byte Operations
-----------------

Secure Buffer Utilities
~~~~~~~~~~~~~~~~~~~~~~~~

.. c:function:: bool tls_bytes_compare(const void *buf1, const void *buf2, size_t len)

   Constant-time comparison of two buffers. Always examines all ``len`` bytes
   regardless of where a difference is found, so the result does not leak
   information about the position of the mismatch through timing.

   Use this instead of ``memcmp()`` whenever comparing secrets — MACs,
   digests, or decrypted values.

   :param buf1: First buffer.
   :param buf2: Second buffer.
   :param len: Number of bytes to compare.
   :returns: ``true`` if the buffers are identical, ``false`` otherwise.

.. c:function:: void tls_secure_memzero(void *ptr, size_t len)

   Zero ``len`` bytes at ``ptr`` in a way the compiler cannot optimize away.
   Uses a volatile write loop so that zeroing of sensitive material (keys,
   plaintexts, passwords) is guaranteed to reach memory even when the buffer
   is not used afterwards.

   Call this before freeing or reusing any stack buffer that held key material
   or plaintext.

   :param ptr: Buffer to zero.
   :param len: Number of bytes to zero.

-----

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
~~~~~~~~~~~~~~~~~~~~~~~~~~

This example uses the key API to encrypt a complete file with AES-256-GCM.
The application supplies the password and a nonzero PBKDF2 iteration count
chosen for its latency and password-protection requirements. Both examples
assume ``lwip_start()`` has succeeded.

The salt is authenticated as AAD. The stored layout is
``[16-byte salt][encrypt blob]`` where the blob is the self-describing buffer
returned by ``tls_cipher_encrypt_aad()`` — it contains the IV, ciphertext, and
GCM tag in one contiguous allocation. The application must retain the same
iteration count for decryption; this minimal format does not store it.

.. code-block:: c

   #include <fileioc.h>
   #include <cryptography.h>
   #include <string.h>

   bool save_encrypted(const char *name, const char *password, size_t rounds,
                       const uint8_t *plaintext, size_t len)
   {
       if (!name || !password || !plaintext || !len || !rounds)
           return false;
       uint8_t secret[32], salt[16];
       uint8_t *blob = NULL;
       bool ok = false;
       uint8_t file = 0;
       struct tls_key key = {
           .type = TLS_KEY_TYPE_AES,
           .aes = { .len = sizeof(secret), .data = secret },
       };

       tls_random_bytes(salt, sizeof(salt));
       if (!tls_pbkdf2(password, strlen(password), salt, sizeof(salt),
                       secret, sizeof(secret), rounds, TLS_HASH_SHA256))
           goto cleanup;
       /* Encrypt; IV is generated internally. Salt is the AAD. */
       blob = tls_cipher_encrypt_aad(&key, TLS_ALG_AES_256_GCM,
                                     salt, sizeof(salt), plaintext, len);
       if (!blob) goto cleanup;

       /* blob layout: <u16 iv_len><iv><u16 ct_len><ciphertext><u16 tag_len><tag> */
       file = ti_Open(name, "w");
       if (!file) goto cleanup;
       /* Determine blob size: 3 × uint16_t headers + IV + ciphertext + tag. */
       size_t blob_len = 6 + TLS_KEY_GCM_IV_LEN + len + TLS_KEY_AES_TAG_LEN;
       ok = ti_Write(salt, 1, sizeof(salt), file) == sizeof(salt) &&
            ti_Write(blob, 1, blob_len, file) == blob_len;
   cleanup:
       if (file) ti_Close(file);
       tls_cipher_blob_free(blob);
       tls_secure_memzero(secret, sizeof(secret));
       return ok;
   }

Decrypt a File at Rest
~~~~~~~~~~~~~~~~~~~~~~~~~~

Read the stored salt and encrypt blob, then derive the same key and decrypt.
``tls_cipher_decrypt_aad()`` verifies the GCM tag before decrypting and returns
``NULL`` on any mismatch or error. The plaintext blob it returns carries a
``uint16_t`` length prefix followed by the plaintext bytes.
The headers from the encryption example are also required here.

.. code-block:: c

   bool load_encrypted(const char *name, const char *password, size_t rounds,
                       uint8_t *plaintext, size_t capacity, size_t *written)
   {
       if (!written) return false;
       *written = 0;
       if (!name || !password || !rounds || !plaintext) return false;
       uint8_t file = ti_Open(name, "r");
       if (!file) return false;
       uint8_t secret[32], salt[16];
       size_t size = ti_GetSize(file);
       /* File layout: [16-byte salt][blob]; blob minimum is 6 bytes of headers. */
       size_t salt_len = sizeof(salt);
       bool ok = false;
       uint8_t *enc_blob = NULL, *dec_blob = NULL;
       if (size <= salt_len + 6) goto cleanup;
       size_t blob_len = size - salt_len;
       enc_blob = malloc(blob_len);
       if (!enc_blob) goto cleanup;
       if (ti_Read(salt,     1, salt_len,  file) != salt_len ||
           ti_Read(enc_blob, 1, blob_len,  file) != blob_len)
           goto cleanup;
       if (!tls_pbkdf2(password, strlen(password), salt, salt_len,
                       secret, sizeof(secret), rounds, TLS_HASH_SHA256))
           goto cleanup;
       struct tls_key key = {
           .type = TLS_KEY_TYPE_AES,
           .aes = { .len = sizeof(secret), .data = secret },
       };
       /* salt is the AAD; tag is verified internally before any decryption. */
       dec_blob = tls_cipher_decrypt_aad(&key, TLS_ALG_AES_256_GCM,
                                         salt, salt_len, enc_blob);
       if (!dec_blob) goto cleanup;
       /* dec_blob layout: <uint16_t plain_len><plaintext> */
       size_t plain_len = (size_t)(dec_blob[0] | ((uint16_t)dec_blob[1] << 8));
       if (plain_len > capacity) goto cleanup;
       memcpy(plaintext, dec_blob + 2, plain_len);
       *written = plain_len;
       ok = true;
   cleanup:
       tls_cipher_blob_free(dec_blob);
       free(enc_blob);
       ti_Close(file);
       tls_secure_memzero(secret, sizeof(secret));
       return ok;
   }
