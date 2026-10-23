#!/usr/bin/env python3
"""Execute the production RNG lifecycle with deterministic host mocks."""

from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[3]
RANDOM_C = (ROOT / "src/tls/core/random.c").read_text()
RANDOM_H = ROOT / "src/tls/includes/random.h"
BODY = RANDOM_C[RANDOM_C.index("#define TLS_RNG_REQUEST_INTERVAL_MS"):]

MOCKS = f'''\
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "{RANDOM_H}"

#define LWIP_TIMERS 1
#define LWIP_DISPATCH_TLS_RNG_REQUEST 0
#define TLS_SHA256_DIGEST_LEN 32
#define TLS_HASH_SHA256 1
#define ERROR_CODE(x) ((void)(x))
#define ERROR() ((void)0)
#define WARN_CODE(x) ((void)(x))
#define ERROR_INFO(x) ((void)(x))
#define INFO(x) ((void)(x))
#define DEBUG() ((void)0)

struct tls_hash_context {{ uint32_t state; }};
static uint32_t mock_now;
static uint16_t mock_period;
static void (*mock_dispatch)(void);
static unsigned mock_init_failures;
static uint32_t mock_scan_ms;
static unsigned mock_gathers;
static uint8_t mock_source;
static uint8_t mock_epoch;
static bool mock_source_ready;
uint8_t sprng_last_health_mask = TLS_RNG_HEALTH_ALL_PASS;

static uint32_t sys_now(void) {{ return mock_now; }}
static void lwip_dispatch_attach(int id, void (*fn)(void))
{{ assert(id == 0); mock_dispatch = fn; }}
static void lwip_dispatch_start(void) {{}}
static void lwip_dispatch_set_period(int id, uint16_t period)
{{ assert(id == 0); mock_period = period; }}
static uint16_t lwip_dispatch_period_from_ms(uint32_t ms)
{{ return (uint16_t)ms; }}

static void *mem_buffer_custom_malloc(size_t n) {{ return malloc(n); }}
static void mem_buffer_custom_free(void *p) {{ free(p); }}
static void tls_secure_memzero(void *p, size_t n)
{{ volatile uint8_t *q = p; while (n--) *q++ = 0; }}

static bool tls_hash_context_init(struct tls_hash_context *ctx, uint8_t alg)
{{ ctx->state = alg; return true; }}
static void tls_hash_update(struct tls_hash_context *ctx,
                            const uint8_t *p, size_t n)
{{ while (n--) ctx->state = ctx->state * 33u + *p++; }}
static void tls_hash_digest(struct tls_hash_context *ctx, uint8_t out[32])
{{ for (unsigned i = 0; i < 32; i++) out[i] = (uint8_t)(ctx->state + i * 17u); }}

bool tls_random_init_entropy(void)
{{
    mock_now += mock_scan_ms;
    if (mock_init_failures != 0) {{ mock_init_failures--; return false; }}
    mock_source_ready = true;
    mock_epoch++;
    return true;
}}
void *tls_random_debug_source_ptr(void)
{{ return mock_source_ready ? &mock_source : NULL; }}
uint8_t tls_random_debug_source_mask(void)
{{ return mock_source_ready ? 1u : 0u; }}
uint8_t tls_random_health_epoch(void) {{ return mock_epoch; }}
void *tls_entropy_collect(void *buffer, size_t len)
{{
    uint8_t *out = buffer;
    mock_gathers++;
    for (size_t i = 0; i < len; i++) out[i] = (uint8_t)(mock_gathers * 41u + i);
    return buffer;
}}
'''

TEST = r'''
static void tick(void)
{
    assert(mock_dispatch != NULL && mock_period == 50u);
    mock_now += 50u;
    mock_dispatch();
}

int main(void)
{
    uint8_t out[32];

    /* tls_init() selects the source before starting the asynchronous DRBG
     * lifecycle. Source discovery itself is intentionally not timer-retried. */
    assert(tls_random_init_entropy());
    tls_rng_start();
    assert(tls_rng_status() == TLS_RNG_AWAITING_INIT);
    assert(tls_rng_available_strength() == 0u);

    tick();
    assert(tls_rng_status() == TLS_RNG_DRBG_SEEDING);
    assert(mock_gathers == 0u); /* source validation owns its complete tick */

    tick();
    assert(tls_rng_status() == TLS_RNG_DRBG_READY_128);
    assert(tls_rng_available_strength() == 128u && mock_gathers == 1u);
    assert(tls_random_bytes_ex(out, sizeof(out), TLS_RNG_STRENGTH_128) == out);

    tick();
    assert(tls_rng_status() == TLS_RNG_DRBG_READY_128 && mock_gathers == 2u);
    tick();
    assert(tls_rng_status() == TLS_RNG_DRBG_READY_192 && mock_gathers == 3u);
    assert(tls_rng_available_strength() == 192u);
    tick();
    assert(mock_gathers == 4u && mock_period == 0u); /* reseed reserve is full */
    assert(tls_random_bytes(out, sizeof(out)) == out);

    tls_rng_cleanup();
    assert(tls_rng_status() == TLS_RNG_STOPPED);

    mock_now = 0;
    mock_period = 0;
    mock_init_failures = 100;
    mock_scan_ms = 4000;
    mock_source_ready = false;
    tls_rng_start();
    while (tls_rng_status() != TLS_RNG_FAILED)
        tick();
    assert(mock_now >= 15000u);
    assert(tls_rng_available_strength() == 0u);
    assert(tls_rng_last_failure() == TLS_RNG_FAILURE_TIMEOUT);

    puts("RNG lifecycle passed: READY_128, fresh 192-bit promotion, reseed, timeout");
    return 0;
}
'''


with tempfile.TemporaryDirectory() as tmp:
    unit = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    unit.write_text(MOCKS + "\n" + BODY + "\n" + TEST)
    subprocess.run(
        [
            "cc", "-std=c99", "-Wall", "-Wextra", "-Werror",
            "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
            str(unit), "-o", str(binary),
        ],
        check=True,
    )
    subprocess.run([str(binary)], check=True)
