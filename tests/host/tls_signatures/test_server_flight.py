#!/usr/bin/env python3
"""Guard the TLS 1.3 certificate-server flight and signed transcript order."""

from pathlib import Path
import re
import subprocess
import tempfile


source = (Path(__file__).resolve().parents[3] / "src/tls/core/handshake.c").read_text()
hello_start = source.index("bool tls_server_recv_client_hello(")
hello_end = source.index("\n/* Encode a raw 32-byte", hello_start)
hello = source[hello_start:hello_end]
start = source.index("bool tls_server_send_flight(")
end = source.index("\nbool tls_server_recv_finished(", start)
flight = source[start:end]

encrypted_extensions = flight.index(
    "out[off + 0] = TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS;"
)
certificate = flight.index("out[off + 0] = TLS_HANDSHAKE_CERTIFICATE;")
certificate_verify = flight.index("out[off + 0] = 0x0f;")
finished = flight.index("tls_send_finished(")

assert encrypted_extensions < certificate < certificate_verify < finished
assert flight.index("transcript_hash_update", encrypted_extensions) < flight.index(
    "tls_key_sign("
)

# Certificate-only ClientHellos do not contain the PSK extensions.  Keep the
# external-PSK requirements and ServerHello selection confined to that mode.
assert "!cert_mode && (!psk_modes_seen || !psk_seen || !dhe_mode || !psk_ok)" in hello
assert "!suite || !groups_seen || !x25519_group" in hello
assert "cert_mode && (!sigalgs_seen || !p256_signature" in hello
assert "TLS_SIG_ECDSA_SECP256R1_SHA256" in hello
assert "ctx->psk_mode = !cert_mode;" in hello
assert "(cert_mode ? 0 : 6)" in hello
assert hello.count("if (!cert_mode)") >= 3

# The server sends one legal X25519 HRR, performs RFC 8446 transcript
# replacement, and requires CH2 to contain exactly the requested share.
assert "ctx->hrr_requested_group = TLS_NAMED_GROUP_X25519;" in hello
assert "uint8_t synth[36] = {0xfe, 0, 0, 32};" in hello
assert "share_entries != 1" in hello
assert "offer_gcm ? TLS_AES_128_GCM_SHA256" in hello


def function(name: str) -> str:
    match = re.search(r"^static size_t " + name + r"\([^;]*?\)\s*\{", source, re.M)
    assert match
    pos = match.end()
    depth = 1
    while depth:
        depth += (source[pos] == "{") - (source[pos] == "}")
        pos += 1
    return source[match.start():pos]


c_test = r"""
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
""" + function("der_encode_integer") + function("der_encode_ecdsa_sig") + r"""
int main(void)
{
    uint8_t value[64] = {0};
    uint8_t encoded[72];
    size_t len;

    value[31] = 1;
    len = der_encode_integer(encoded, value);
    assert(len == 3 && encoded[0] == 2 && encoded[1] == 1 && encoded[2] == 1);

    memset(value, 0, sizeof(value));
    value[0] = 0x80;
    len = der_encode_integer(encoded, value);
    assert(len == 35 && encoded[0] == 2 && encoded[1] == 33 && encoded[2] == 0);

    memset(value, 0, sizeof(value));
    value[31] = 1;
    value[32] = 0x80;
    len = der_encode_ecdsa_sig(encoded, value);
    assert(len == 40 && encoded[0] == 0x30 && encoded[1] == 38);
    assert(encoded[2] == 2 && encoded[3] == 1 && encoded[4] == 1);
    assert(encoded[5] == 2 && encoded[6] == 33 && encoded[7] == 0);
    return 0;
}
"""

with tempfile.TemporaryDirectory(prefix="tls-server-flight-") as tmp:
    tmp = Path(tmp)
    unit = tmp / "test.c"
    binary = tmp / "test"
    unit.write_text(c_test)
    subprocess.run(["cc", "-std=c99", "-Wall", "-Wextra", str(unit), "-o", str(binary)],
                   check=True)
    subprocess.run([str(binary)], check=True)

print("TLS server certificate flight order: PASS")
