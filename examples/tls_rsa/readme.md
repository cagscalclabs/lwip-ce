### lwIP TLS RSA Example

Connects to `rsa2048.badssl.com:443` with `LWIP_PROTO_ALTCP_TLS`, sends a minimal HTTP request, and checks for an HTTP response.

This requires the lwIP app to be installed on the calculator before running the example. TLS verification also depends on the trust configuration installed for the lwIP TLS stack.
