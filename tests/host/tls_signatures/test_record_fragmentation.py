#!/usr/bin/env python3
"""Regress RFC 8446 section 5.1 handshake fragmentation aliasing."""

from pathlib import Path
import re
import subprocess
import tempfile


source = (Path(__file__).resolve().parents[3] /
          "src/apps/altcp_tls/altcp_tls_ce.c").read_text()


def function(name: str) -> str:
    match = re.search(
        r"^static err_t " + name + r"\([^;]*?\)\s*\{", source, re.M
    )
    assert match, name
    pos = match.end()
    depth = 1
    while depth:
        depth += (source[pos] == "{") - (source[pos] == "}")
        pos += 1
    return source[match.start():pos] + "\n"


# Both certificate directions must go through the overlap-safe common path.
assert source.count("altcp_tls_ce_write_handshake_fragments(") == 3
assert "record + 5 + sent" not in source

c_test = r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define ALTCP_TLS_CE_MAX_RECORD_PLAINTEXT 32u
#define TLS_AES_AUTH_TAG_SIZE 16u
#define TLS_CONTENT_TYPE_HANDSHAKE 22u
#define TCP_WRITE_FLAG_COPY 1u
#define ERR_OK 0
#define ERR_ARG -1
#define ERR_VAL -2
typedef int err_t;
typedef uint16_t u16_t;

struct altcp_pcb { unsigned marker; };
struct tls_handshake_context { uint64_t client_hs_seq_num; };

static uint8_t observed[256];
static size_t observed_len;
static unsigned write_calls;

static void tls_secure_memzero(void *p, size_t n) { memset(p, 0, n); }

/* Capture the plaintext offered to AEAD, then deliberately overwrite the
 * complete output record including the inner type and tag. This reproduces
 * the alias that used to corrupt the next fragment. */
static bool altcp_tls_ce_encrypt_record_stream(
    struct tls_handshake_context *ctx, bool handshake_keys,
    uint8_t content_type, const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *record, size_t record_cap, size_t *written)
{
    (void)ctx;
    assert(handshake_keys && content_type == TLS_CONTENT_TYPE_HANDSHAKE);
    assert(observed_len + plaintext_len <= sizeof(observed));
    memcpy(observed + observed_len, plaintext, plaintext_len);
    observed_len += plaintext_len;
    memset(record, 0xee, record_cap);
    *written = record_cap;
    return true;
}

static err_t altcp_write(struct altcp_pcb *pcb, const void *data,
                         u16_t len, uint8_t flags)
{
    (void)pcb;
    assert(data != NULL && len >= 22 && flags == TCP_WRITE_FLAG_COPY);
    write_calls++;
    return ERR_OK;
}
'''
c_test += function("altcp_tls_ce_write_handshake_fragments")
c_test += r'''
int main(void)
{
    struct altcp_pcb pcb = {0};
    struct tls_handshake_context ctx = {0};
    uint8_t storage[5 + 96 + 1 + TLS_AES_AUTH_TAG_SIZE];
    uint8_t original[80];
    for (size_t i = 0; i < sizeof(original); i++)
        original[i] = (uint8_t)(i ^ 0xa5u);
    memcpy(storage + 5, original, sizeof(original));

    assert(altcp_tls_ce_write_handshake_fragments(
               &pcb, &ctx, storage, sizeof(original)) == ERR_OK);
    assert(write_calls == 3);
    assert(ctx.client_hs_seq_num == 3);
    assert(observed_len == sizeof(original));
    assert(memcmp(observed, original, sizeof(original)) == 0);

    /* Also retain the in-place one-record fast path. */
    observed_len = write_calls = 0;
    ctx.client_hs_seq_num = 0;
    memcpy(storage + 5, original, 12);
    assert(altcp_tls_ce_write_handshake_fragments(&pcb, &ctx, storage, 12) == ERR_OK);
    assert(write_calls == 1 && ctx.client_hs_seq_num == 1);
    assert(observed_len == 12 && memcmp(observed, original, 12) == 0);
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix="tls-record-fragments-") as tmp:
    tmp = Path(tmp)
    unit = tmp / "test.c"
    binary = tmp / "test"
    unit.write_text(c_test)
    subprocess.run(
        ["cc", "-std=c99", "-Wall", "-Wextra", "-Werror",
         "-fsanitize=address,undefined", str(unit), "-o", str(binary)],
        check=True,
    )
    subprocess.run([str(binary)], check=True)

print("TLS handshake record fragmentation: PASS")
