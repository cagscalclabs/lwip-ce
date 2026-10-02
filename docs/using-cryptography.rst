Using Cryptography
==================

lwIP-CE exposes a set of cryptographic primitives independently of the network
stack. TLS over a network connection is also covered here.

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
fails immediately. There is no way to override this from application code.

----

Symmetric Encryption
--------------------

``lwip/cryptography/aes.h`` — AES-GCM, AES-CBC, AES-CCM
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

AES-128, AES-192, and AES-256 are all supported across all three modes.
AES-GCM and AES-CCM are authenticated encryption modes (they produce an
authentication tag alongside the ciphertext). AES-CBC provides confidentiality
only.

**Context-based (streaming) API:**

.. code-block:: c

   struct tls_aes_context ctx;

   /* Initialize once per message */
   tls_aes_init(&ctx, TLS_AES_GCM, key, key_len, iv, iv_len);

   /* Optional: feed associated data (GCM/CCM only) */
   tls_aes_update_aad(&ctx, aad, aad_len);

   /* Encrypt */
   tls_aes_encrypt(&ctx, plaintext, pt_len, ciphertext);

   /* Retrieve authentication tag */
   uint8_t tag[TLS_AES_AUTH_TAG_SIZE];  /* 16 bytes */
   tls_aes_digest(&ctx, tag);

For decryption, call ``tls_aes_verify()`` before ``tls_aes_decrypt()`` to
authenticate the ciphertext first. ``tls_aes_verify()`` does not decrypt;
it only checks the tag. Only call ``tls_aes_decrypt()`` if verify returns
``true``:

.. code-block:: c

   tls_aes_init(&ctx, TLS_AES_GCM, key, key_len, iv, iv_len);
   if (tls_aes_verify(&ctx, aad, aad_len, ciphertext, ct_len, tag)) {
       tls_aes_decrypt(&ctx, ciphertext, ct_len, plaintext);
   }

There is also a streaming ciphertext-authentication helper
``tls_aes_update_ciphertext()`` for GCM, which feeds ciphertext through GHASH
without producing plaintext. This is useful when you need to verify a tag over
a ciphertext before committing to decrypting it in a separate pass.

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

For CCM, ``tls_aes_ccm_init()`` is also available if you need to feed
AAD and data incrementally.

Key function signatures:

.. code-block:: c

   bool tls_aes_init(struct tls_aes_context *ctx, uint8_t mode,
                     const uint8_t *key, size_t key_len,
                     const uint8_t *iv, size_t iv_len);

   bool tls_aes_update_aad(struct tls_aes_context *ctx,
                           const uint8_t *aad, size_t aad_len);
   bool tls_aes_encrypt(struct tls_aes_context *ctx,
                        const uint8_t *inbuf, size_t in_len,
                        uint8_t *outbuf);
   bool tls_aes_decrypt(struct tls_aes_context *ctx,
                        const uint8_t *inbuf, size_t in_len,
                        uint8_t *outbuf);
   bool tls_aes_digest(struct tls_aes_context *ctx, uint8_t *digest);
   bool tls_aes_verify(struct tls_aes_context *ctx,
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *ciphertext, size_t ciphertext_len,
                       const uint8_t *tag);

   bool tls_aes_ccm_encrypt(const uint8_t *key, size_t key_len,
                            const uint8_t *nonce, size_t nonce_len,
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *plaintext, size_t pt_len,
                            uint8_t *ciphertext, uint8_t *tag, size_t tag_len);
   bool tls_aes_ccm_decrypt(const uint8_t *key, size_t key_len,
                            const uint8_t *nonce, size_t nonce_len,
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *ciphertext, size_t ct_len,
                            const uint8_t *tag, size_t tag_len,
                            uint8_t *plaintext);

``mode`` is one of ``TLS_AES_GCM``, ``TLS_AES_CBC``, ``TLS_AES_CCM``.
All functions return ``true`` on success and ``false`` on failure. The context
``struct tls_aes_context`` is caller-allocated and stack-safe. A new
``tls_aes_init()`` call is required for each new message; reuse is not
supported across messages.

``TLS_AES_BLOCK_SIZE`` (16), ``TLS_AES_IV_SIZE`` (16), and
``TLS_AES_AUTH_TAG_SIZE`` (16) are the relevant size constants.

----

Hashing and MAC
---------------

``lwip/cryptography/hash.h`` — SHA-256
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

SHA-256 is the only implemented hash algorithm. SHA-256 hardware acceleration
is present in the header but not yet wired (the relevant functions are
commented out).

.. code-block:: c

   #define TLS_SHA256_DIGEST_LEN 32

   struct tls_sha256_context ctx;
   uint8_t digest[TLS_SHA256_DIGEST_LEN];

   tls_sha256_init(&ctx);
   tls_sha256_update(&ctx, (const uint8_t *)"hello", 5);
   tls_sha256_digest(&ctx, digest);

The generic ``tls_hash_context`` wrapper selects the algorithm at runtime:

.. code-block:: c

   struct tls_hash_context ctx;
   tls_hash_context_init(&ctx, TLS_HASH_SHA256);
   tls_hash_update(&ctx, data, len);
   tls_hash_digest(&ctx, digest);

The context also exposes function pointers (``ctx.update``, ``ctx.digest``)
that call through to the underlying algorithm. Both calling styles are valid.

The context is caller-allocated. There is no teardown step. To hash a new
message, call ``tls_hash_context_init()`` or ``tls_sha256_init()`` again on
the same context.

``tls_mgf1()`` computes an MGF1 mask (used internally by RSA-OAEP/PSS):

.. code-block:: c

   bool tls_mgf1(const uint8_t *data, size_t datalen,
                 uint8_t *outbuf, size_t outlen,
                 uint8_t hash_alg);

``lwip/cryptography/hmac.h`` — HMAC-SHA-256
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

HMAC wraps the hash context with a key. The interface mirrors the hash API.

.. code-block:: c

   struct tls_hmac_context ctx;
   uint8_t mac[TLS_SHA256_DIGEST_LEN];

   tls_hmac_context_init(&ctx, TLS_HASH_SHA256, key, key_len);
   tls_hmac_update(&ctx, data, len);
   tls_hmac_digest(&ctx, mac);

Function signatures:

.. code-block:: c

   bool tls_hmac_context_init(struct tls_hmac_context *ctx,
                              uint8_t algorithm,
                              const uint8_t *key, size_t keylen);
   void tls_hmac_update(struct tls_hmac_context *ctx,
                        const uint8_t *data, size_t len);
   void tls_hmac_digest(struct tls_hmac_context *ctx, uint8_t *digest);

Like the hash context, ``ctx.update`` and ``ctx.digest`` function pointers are
also valid calling paths. The context is caller-allocated; no teardown is
needed.

----

Key Derivation
--------------

``lwip/cryptography/hkdf.h`` — HKDF (RFC 5869)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

HKDF derives keying material from an input secret in two steps: extract, then
expand. Both steps are available separately, and TLS 1.3-specific label
expansion is provided as a convenience.

**Extract** condenses potentially weak or non-uniform input keying material
(IKM) into a pseudorandom key (PRK):

.. code-block:: c

   uint8_t prk[32];
   tls_hkdf_extract(TLS_HASH_SHA256,
                    salt, salt_len,   /* NULL/0 for no salt */
                    ikm, ikm_len,
                    prk);

**Expand** stretches a PRK into output keying material of any desired length:

.. code-block:: c

   uint8_t okm[42];
   tls_hkdf_expand(TLS_HASH_SHA256,
                   prk, sizeof(prk),
                   info, info_len,   /* NULL/0 for no info */
                   okm, sizeof(okm));

**Expand-Label** formats the label with the TLS 1.3 ``"tls13 "`` prefix:

.. code-block:: c

   bool tls_hkdf_expand_label(uint8_t hash_algorithm,
                              const uint8_t *secret, size_t secret_len,
                              const char *label, size_t label_len,
                              const uint8_t *context, size_t context_len,
                              uint8_t *out, size_t out_len);

**Derive-Secret** is a convenience that combines Expand-Label with an
already-computed transcript hash:

.. code-block:: c

   bool tls_derive_secret(uint8_t hash_algorithm,
                          const uint8_t *secret, size_t secret_len,
                          const char *label, size_t label_len,
                          const uint8_t *transcript_hash, size_t transcript_hash_len,
                          uint8_t *out);

All functions are stateless (no context struct); each call is independent.
All return ``true`` on success and ``false`` on failure.

``lwip/cryptography/passwords.h`` — PBKDF2 (RFC 8018)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

PBKDF2 derives a key from a password and salt using many HMAC rounds. Use
this when you need to stretch a user-supplied password into a key. More rounds
means more resistance to brute-force, but on the eZ80 this is measurably
slow — keep rounds low for interactive use.

.. code-block:: c

   uint8_t key[32];
   tls_pbkdf2("password", 8,
              salt, salt_len,
              key, sizeof(key),
              10000,           /* iteration count */
              TLS_HASH_SHA256);

Function signature:

.. code-block:: c

   bool tls_pbkdf2(const char *password, size_t passlen,
                   const uint8_t *salt, size_t saltlen,
                   uint8_t *key, size_t keylen,
                   size_t rounds, uint8_t algorithm);

Returns ``true`` on success, ``false`` on failure. The output buffer is
caller-allocated; no heap allocation occurs.

----

Asymmetric / Public-Key Cryptography
-------------------------------------

``lwip/cryptography/rsa.h`` — RSA 1024–2048
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

RSA operations are supported for key sizes from 1024 bits to 2048 bits
(128 to 256 bytes modulus). RSA-3072 and RSA-4096 are not supported.

The public exponent is always ``65537`` (``RSA_PUBLIC_EXP``).

.. warning::

   RSA operations are slow on the eZ80. A single modular exponentiation at
   2048 bits takes several seconds. Design your application around this —
   do not call RSA in a tight loop or block key input.

**OAEP encode/decode** (padding only, no exponentiation):

.. code-block:: c

   uint8_t encoded[128];  /* modulus_len bytes */
   tls_rsa_encode_oaep(message, msg_len,
                       encoded, modulus_len,   /* 128 = RSA-1024, 256 = RSA-2048 */
                       NULL,                   /* optional label string */
                       TLS_HASH_SHA256);

   uint8_t decoded[128];
   size_t decoded_len = tls_rsa_decode_oaep(encoded, modulus_len,
                                            decoded,
                                            NULL, TLS_HASH_SHA256);

Note: in-place operation (``inbuf == outbuf``) is supported for exact overlap
only. Partial overlap is rejected and returns false/0.

**RSA encrypt** (OAEP encode + public key exponentiation):

.. code-block:: c

   bool tls_rsa_encrypt(const uint8_t *inbuf, size_t in_len,
                        uint8_t *outbuf,
                        const uint8_t *pubkey, size_t keylen,
                        uint8_t hash_alg);

**Signature verification** (two steps: decrypt then verify padding):

.. code-block:: c

   uint8_t em[256];   /* modulus_len bytes */

   /* Step 1: decrypt signature using public key (RSA raw decrypt) */
   tls_rsa_decrypt_signature(signature, sig_len, em, pubkey, keylen);

   /* Step 2: verify PSS padding over the message hash */
   uint8_t mhash[32];
   tls_sha256_digest(&ctx, mhash);
   tls_rsa_pss_verify(em, sizeof(em), mhash, sizeof(mhash), TLS_HASH_SHA256);

``tls_rsa_decrypt_signature()`` performs only the modular exponentiation; it
does not verify padding. Always follow it with ``tls_rsa_pss_verify()`` (for
PSS signatures). PKCS#1 v1.5 signature verification is handled internally by
the TLS handshake code.

``__rsa_transient`` is a 256-byte BSS scratch region the RSA functions share.
Its contents are undefined between calls and callers must not read it.

``lwip/cryptography/x25519.h`` — X25519 Diffie-Hellman
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

X25519 is an elliptic-curve Diffie-Hellman function over Curve25519. It is
used by the TLS 1.3 handshake for key exchange and is also available directly.

Private keys are automatically clamped to Curve25519 spec (RFC 7748); you do
not need to pre-clamp the scalar.

.. code-block:: c

   uint8_t my_private[32];   /* 32-byte private scalar */
   uint8_t their_public[32]; /* peer's public key (u-coordinate) */
   uint8_t shared_secret[32];

   /* Compute shared secret */
   tls_x25519_secret(shared_secret, my_private, their_public, NULL, NULL);

   /* Derive your own public key from a private key */
   uint8_t my_public[32];
   tls_x25519_publickey(my_public, my_private, NULL, NULL);

Both functions accept optional ``yield_fn`` / ``yield_data`` parameters. Pass
a function that pumps your UI or key handler if you need to stay responsive
during the computation. Pass ``NULL`` for both if you do not need this.

.. code-block:: c

   bool tls_x25519_secret(uint8_t shared_secret[32],
                          const uint8_t my_private[32],
                          const uint8_t their_public[32],
                          void (*yield_fn)(void *), void *yield_data);

   bool tls_x25519_publickey(uint8_t public_key[32],
                             const uint8_t private_key[32],
                             void (*yield_fn)(void *), void *yield_data);

Both return ``true`` on success. ``tls_x25519_secret()`` returns ``false`` on
low-order point inputs (RFC 7748 §6 check).

.. note::

   X25519 is still notably slow on the eZ80 even compared to other
   operations. The ``yield_fn`` callback is provided precisely for this
   reason.

----

Randomness
----------

``lwip/cryptography/random.h`` — SRAM-noise TRNG
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The calculator has no hardware RNG. lwIP-CE derives entropy from SRAM noise —
the electrical state of uninitialized SRAM varies between power cycles. Do not
use the toolchain ``rand()`` functions for anything security-sensitive; they
are not cryptographically secure.

**Simple synchronous use:**

.. code-block:: c

   uint8_t key[32];
   tls_random_init_entropy();          /* initialize entropy source once */
   tls_random_bytes(key, sizeof(key)); /* fill with cryptographic random bytes */

   uint64_t r = tls_random();          /* get a single random 64-bit value */

``tls_random_init_entropy()`` must be called before ``tls_random()`` or
``tls_random_bytes()``. It returns ``true`` on success and ``false`` if
entropy initialization fails. After ``lwip_start()``, the entropy source is
initialized automatically as part of the TLS subsystem setup; calling
``tls_random_init_entropy()`` again after that is harmless but redundant.

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

----

Certificate and PKI Utilities
-------------------------------

``lwip/cryptography/x509.h`` — X.509 Certificates
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Parses DER or PEM-encoded X.509 certificates and provides field access,
hostname validation, and validity window checks.

**Import a PEM certificate (heap-allocated):**

.. code-block:: c

   struct tls_x509_object *cert =
       tls_x509_import_certificate(pem_data, pem_size);
   if (!cert) { /* parse failed */ }

   /* Access parsed fields */
   /* cert->parsed.subject_cn, issuer_cn, spki_raw, etc. */

   tls_x509_object_destroy(cert);   /* free when done */

The returned ``tls_x509_object`` is heap-allocated. Its ``parsed`` member
contains ``struct tls_asn1_serialization`` pointers that reference the DER
bytes embedded in the object itself. Do not free the object until you are done
with all pointers into it.

**Parse without allocation (caller-supplied buffers):**

.. code-block:: c

   struct tls_asn1_serialization fields[13];
   struct tls_x509_parse_result result;
   tls_x509_parse_certificate(der_bytes, der_len, fields, &result);

**Check hostname against a certificate:**

.. code-block:: c

   /* Checks subjectAltName dNSName entries; falls back to CN if no SAN */
   bool ok = tls_x509_hostname_matches(
       result.extensions->data, result.extensions->len,
       result.subject_cn,   /* CN fallback, may be NULL */
       "example.com");

**Check certificate validity window:**

.. code-block:: c

   uint32_t now = /* Unix seconds from SNTP or RTC */;
   bool valid = tls_x509_time_in_validity(
       result.valid_before, result.valid_after, now);

Key function signatures:

.. code-block:: c

   struct tls_x509_object *tls_x509_import_certificate(
       const char *pem_data, size_t size);
   void tls_x509_object_destroy(struct tls_x509_object *obj);

   bool tls_x509_parse_certificate(const uint8_t *cert_der, size_t cert_len,
                                   struct tls_asn1_serialization fields[13],
                                   struct tls_x509_parse_result *out);

   bool tls_x509_hostname_matches(const uint8_t *ext_data, size_t ext_len,
                                  const struct tls_asn1_serialization *subject_cn,
                                  const char *hostname);

   bool tls_x509_time_in_validity(
       const struct tls_asn1_serialization *valid_before,
       const struct tls_asn1_serialization *valid_after,
       uint32_t now_secs);

``lwip/cryptography/truststore.h`` — CA Root Trust Store
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The trust store is a signed AppVar (``lwIPCERT``) shipped with the lwIP-CE
release. It contains a curated set of CA public keys and is verified at init
time with RSA-PSS-SHA256 against an embedded public key.

**Initialize and use:**

.. code-block:: c

   tls_truststore_status_t status = tls_truststore_init();
   if (status != TLS_STORE_OK) {
       /* handle error — TLS_STORE_NOT_FOUND, TLS_STORE_SIG_INVALID, etc. */
   }

   /* Look up a CA by Subject Key Identifier */
   struct tls_truststore_entry *entry;
   if (tls_truststore_lookup(ski_bytes, &entry)) {
       /* entry->subject, entry->alg_id, entry->key[] are accessible */
   }

``tls_truststore_init()`` must be called before ``tls_truststore_lookup()``.
The TLS socket layer calls it internally; you only need to call it directly if
you are performing manual certificate chain verification.

The trust store lookup is by Subject Key Identifier (32-byte SKI value from
the certificate's SubjectKeyIdentifier extension), not by subject name.
Internally the TLS handshake also does subject-name lookups; those are not
exposed as public API.

Return codes from ``tls_truststore_init()``:

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Code
     - Meaning
   * - ``TLS_STORE_OK``
     - Verified and ready.
   * - ``TLS_STORE_NOT_FOUND``
     - The ``lwIPCERT`` AppVar is missing from the calculator.
   * - ``TLS_STORE_SIZE_INVALID``
     - AppVar is present but the size field is corrupt.
   * - ``TLS_STORE_VERSION_MISMATCH``
     - AppVar was built for a different truststore format version.
   * - ``TLS_STORE_HASH_FAIL``
     - Internal hash computation failed.
   * - ``TLS_STORE_SIG_INVALID``
     - RSA-PSS-SHA256 signature verification failed; the AppVar may be
       tampered or corrupted.

``lwip/cryptography/keyobject.h`` — Key/Certificate Import
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``tls_keyobject`` is a heap-allocated container for a parsed private key,
public key, or X.509 certificate. It handles PKCS#1, PKCS#8, and SEC1 PEM
formats. Encrypted PKCS#8 private keys are supported with a password.

.. code-block:: c

   /* Import a PEM private key (PKCS#8, PKCS#1, or SEC1) */
   struct tls_keyobject *kf =
       tls_keyobject_import_private(pem_data, size, NULL /* or password */);
   if (!kf) { /* failed */ }

   /* Import a PEM public key */
   struct tls_keyobject *pub = tls_keyobject_import_public(pem_data, size);

   /* Import an X.509 certificate */
   struct tls_keyobject *cert = tls_keyobject_import_certificate(pem_data, size);

   /* Use fields via kf->meta.privkey.rsa.field.modulus etc. */

   tls_keyobject_destroy(kf);   /* zeroes sensitive data, then frees */

The ``type`` field holds a bitmask of ``TLS_KEY_PUBLIC``/``TLS_KEY_PRIVATE``,
``TLS_KEY_RSA``/``TLS_KEY_ECC``, and ``TLS_CERTIFICATE``.

``tls_keyobject_destroy()`` zeroes the object before freeing it so that
private key material does not linger in freed memory.

For a lower-level interface that exposes the raw PKCS#8 parse structure
without going through the ``tls_keyobject`` wrapper, see
``lwip/cryptography/pkcs8.h``.

``lwip/cryptography/pkcs8.h`` — PKCS#8 / SEC1 Parser
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The PKCS#8 API parses PEM private and public keys into a raw
``tls_pkcs8_object`` structure, or directly into a ``tls_keyobject``.

.. code-block:: c

   tls_pkcs8_error_t err;
   struct tls_pkcs8_object *obj =
       tls_pkcs8_import(pem_data, size, NULL /* or password */, &err);
   if (!obj) {
       printf("pkcs8 error: %s\n", tls_pkcs8_strerror(err));
   }
   tls_pkcs8_object_destroy(obj);

``tls_pkcs8_import_private()`` and ``tls_pkcs8_import_public()`` return a
``tls_keyobject *`` directly (equivalent to the ``tls_keyobject_import_*``
calls above). Use ``tls_pkcs8_object_import_private/public()`` when you want
the lower-level ``tls_pkcs8_object`` instead.

Supported formats: PKCS#8 (encrypted and unencrypted), PKCS#1, SEC1 (EC).
Supported algorithms: RSA, EC. Encrypted PKCS#8 supports AES-128/256-GCM/CBC
with PBKDF2 key derivation.

``tls_pkcs8_strerror()`` returns a human-readable error string for any
``tls_pkcs8_error_t`` value.

----

ASN.1 / DER Parsing
--------------------

``lwip/cryptography/asn1.h`` — DER cursor and TLV parser
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A forward-only cursor-based DER parser. Useful when you need to walk raw
certificate or key bytes without a higher-level wrapper.

.. code-block:: c

   struct tls_asn1_cursor cursor;
   struct tls_asn1_tlv tlv;

   tls_asn1_cursor_init(&cursor, der_bytes, der_len);

   while (tls_asn1_next(&cursor, &tlv)) {
       /* tlv.tag, tlv.len, tlv.value */

       if (tls_asn1_tag_constructed(tlv.tag)) {
           /* descend into nested elements */
           struct tls_asn1_cursor child;
           tls_asn1_child_cursor(&tlv, &child);
           /* iterate child ... */
       }
   }

All pointers in ``tls_asn1_tlv`` reference the original input buffer; no
copies are made. The cursor and TLV structs are caller-allocated.

Tag inspection helpers:

.. code-block:: c

   uint8_t tls_asn1_tag_number(uint8_t tag);      /* low 5 bits */
   uint8_t tls_asn1_tag_class(uint8_t tag);       /* ASN1_UNIVERSAL etc. */
   bool    tls_asn1_tag_constructed(uint8_t tag); /* true if constructed form */

Tag class constants: ``ASN1_UNIVERSAL``, ``ASN1_APPLICATION``,
``ASN1_CONTEXTSPEC``, ``ASN1_PRIVATE``.

Common tag numbers: ``ASN1_INTEGER`` (2), ``ASN1_BITSTRING`` (3),
``ASN1_OCTETSTRING`` (4), ``ASN1_OBJECTID`` (6), ``ASN1_SEQUENCE`` (16),
``ASN1_UTCTIME`` (23), ``ASN1_GENERALIZEDTIME`` (24).

----

Encoding Utilities
------------------

``lwip/cryptography/base64.h`` — Base64 encode/decode
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Standard Base64 (RFC 4648) with ``+`` and ``/`` alphabet and ``=`` padding.

.. code-block:: c

   /* Encode */
   uint8_t encoded[512];
   size_t out_len = tls_base64_encode(binary, bin_len, encoded);
   /* out_len = 4 * ((bin_len + 2) / 3) */

   /* Decode */
   uint8_t decoded[256];
   size_t dec_len = tls_base64_decode(encoded, out_len, decoded);

Both functions return the number of bytes written to the output buffer.
Output buffer sizing: encode output is ``4 * ((input_len + 2) / 3)`` bytes;
decode output is at most ``input_len * 3 / 4`` bytes.

``lwip/cryptography/bytes.h`` — Secure compare and erase
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Two small utilities for handling sensitive data safely:

.. code-block:: c

   /* Constant-time comparison — does not short-circuit on mismatch */
   bool tls_bytes_compare(const void *buf1, const void *buf2, size_t len);

   /* Zeroing that the compiler cannot optimize away */
   void tls_secure_memzero(void *ptr, size_t len);

Use ``tls_bytes_compare()`` instead of ``memcmp()`` when comparing MACs,
tags, or other secrets where timing leaks could reveal information.
Use ``tls_secure_memzero()`` to clear key material before freeing or reusing
a buffer.

----

TLS Over a Network Socket
--------------------------

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

   lwip_socket_on_event(&sock, LWIP_SOCKET_EVENTF_ALL, on_event, &state);
   lwip_socket_connect(&sock, "example.com", 443);

   while (!done) {
       lwip_service_events();
       /* ... */
   }

   lwip_socket_destroy(&sock);

The TLS stack handles certificate chain verification, trust store lookup, and
CertificateVerify automatically. You do not need to call any TLS setup
functions directly; the socket layer drives the handshake.

See ``examples/tls_https/`` for a complete working example.
See :doc:`using-the-network` for the full socket lifecycle.
See :doc:`technical-details` for the security posture of the TLS
implementation, including current limitations around P-256 and the trust store.
