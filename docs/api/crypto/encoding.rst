Encoding Utilities
===================

| **Headers:** ``lwip/cryptography/base64.h``, ``lwip/cryptography/bytes.h``
| **References:** `RFC 4648 <https://www.rfc-editor.org/rfc/rfc4648>`_ — Base64

``lwip/cryptography/base64.h`` — Base64 encode/decode
------------------------------------------------------

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
---------------------------------------------------------

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
