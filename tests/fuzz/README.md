# Fuzzing

libFuzzer harnesses (ASan + UBSan) for every parser that takes untrusted
input. Each builds the production source on the host; `shim/` stubs the CE
SDK headers and `x509_stubs.c` stands in for the assembly crypto.

| Target | Code under test |
| --- | --- |
| `json`, `xml`, `url` | `src/parsers` |
| `base64`, `asn1` | `src/tls/core/base64.c`, `asn1.c` |
| `x509` | `src/tls/core/x509.c`: DER/PEM import, SAN/CN matching, validity, path extensions |
| `pcap` | `src/drivers/pcap_decode.h` |
| `ws` | `src/apps/altcp_ws/altcp_ws.c` upgrade response and frame parser, chunked input |
| `tls` | `src/tls/core/handshake.c`: EncryptedExtensions, CertificateRequest, streamed Certificate walker and chain jobs |

`ws` and `tls` reuse the mocks of `tests/host/altcp_ws` and
`tests/host/tls_signatures`.

```sh
make -C tests/fuzz run-x509 FUZZ_SECONDS=300   # one target
make -C tests/fuzz run                          # all targets
```

New inputs go to `out/<target>`, crashes to `out/artifacts`. Seeds live in
`corpus/<target>`. CI runs every target on push and pull request, and ten
times longer nightly (`.github/workflows/host.yml`).
