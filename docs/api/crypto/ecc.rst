x25519.h — X25519 Diffie-Hellman
=================================

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

Key Operations
--------------

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

Examples
--------

.. code-block:: c

   uint8_t my_private[32];    /* 32-byte private scalar */
   uint8_t their_public[32];  /* peer's public key (u-coordinate) */
   uint8_t shared_secret[32];
   uint8_t my_public[32];

   tls_x25519_publickey(my_public, my_private, NULL, NULL);
   tls_x25519_secret(shared_secret, my_private, their_public, NULL, NULL);
