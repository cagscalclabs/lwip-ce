# Upcoming P-256 test

This target compiles `ref/p256/p256.c` directly and checks RFC 5903 ECDH,
RFC 6979 deterministic ECDSA, verification, and malformed-input rejection.
It exists to validate future assembly work without exposing P-256 from the
resident lwIP library prematurely.

From this directory, `make` performs a compile/link check. The autotest is not
part of normal CI while the implementation remains under `ref/`.
