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
static uint32_t mock_now_step;
static uint16_t mock_period;
static void (*mock_dispatch)(void);
static unsigned mock_init_failures;
static uint32_t mock_scan_ms;
static unsigned mock_gathers;
static unsigned mock_epoch_changes_remaining;
static uint8_t mock_source;
static uint8_t mock_epoch;
static bool mock_source_ready;
uint8_t sprng_last_health_mask = TLS_RNG_HEALTH_ALL_PASS;

static uint32_t sys_now(void)
{{
    uint32_t now = mock_now;
    mock_now += mock_now_step;
    return now;
}}
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
    if (mock_epoch_changes_remaining != 0u)
    {{
        mock_epoch_changes_remaining--;
        mock_epoch++;
    }}
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

static void reference_mock_digest(const uint8_t *data, size_t len,
                                  uint8_t out[TLS_SHA256_DIGEST_LEN])
{
    uint32_t state = TLS_HASH_SHA256;
    size_t i;

    while (len-- != 0u)
        state = state * 33u + *data++;
    for (i = 0; i < TLS_SHA256_DIGEST_LEN; i++)
        out[i] = (uint8_t)(state + i * 17u);
}

static void test_hashgen_wrap_and_truncation(void)
{
    struct tls_hash_drbg_state state = {0};
    uint8_t zero[TLS_HASH_DRBG_SEED_BYTES] = {0};
    uint8_t expected[TLS_SHA256_DIGEST_LEN + 1u];
    uint8_t second[TLS_SHA256_DIGEST_LEN];
    uint8_t actual[TLS_SHA256_DIGEST_LEN + 2u];
    size_t i;

    memset(state.v, 0xff, sizeof(state.v));
    reference_mock_digest(state.v, sizeof(state.v), expected);
    reference_mock_digest(zero, sizeof(zero), second);
    expected[TLS_SHA256_DIGEST_LEN] = second[0];

    memset(actual, 0xa5, sizeof(actual));
    assert(tls_hash_drbg_hashgen(&state, actual,
                                 TLS_SHA256_DIGEST_LEN + 1u));
    assert(memcmp(actual, expected, sizeof(expected)) == 0);
    assert(actual[TLS_SHA256_DIGEST_LEN + 1u] == 0xa5);
    for (i = 0; i < sizeof(state.v); i++)
        assert(state.v[i] == 0xff);
}

static void test_generate_state_update(void)
{
    struct tls_hash_drbg_state state = {0};
    uint8_t original_c[TLS_HASH_DRBG_SEED_BYTES] = {0};
    uint8_t material[1u + TLS_HASH_DRBG_SEED_BYTES] = {0};
    uint8_t h[TLS_SHA256_DIGEST_LEN];
    uint8_t expected_v[TLS_HASH_DRBG_SEED_BYTES] = {0};
    uint8_t one = 1u;
    uint8_t aligned[2] = {1u, 2u};
    uint8_t output;
    unsigned carry = 3u; /* C = 2 plus the old reseed_counter = 1. */
    size_t i;

    /* Exercise the production big-endian helper's alignment and modulo wrap. */
    tls_hash_drbg_add(expected_v, aligned, sizeof(aligned));
    assert(expected_v[TLS_HASH_DRBG_SEED_BYTES - 2u] == 1u);
    assert(expected_v[TLS_HASH_DRBG_SEED_BYTES - 1u] == 2u);
    memset(expected_v, 0xff, sizeof(expected_v));
    tls_hash_drbg_add(expected_v, &one, sizeof(one));
    for (i = 0; i < sizeof(expected_v); i++)
        assert(expected_v[i] == 0u);

    state.seeded = true;
    state.strength_bits = TLS_RNG_STRENGTH_192;
    state.reseed_counter = 1u;
    state.c[TLS_HASH_DRBG_SEED_BYTES - 1u] = 2u;
    memcpy(original_c, state.c, sizeof(original_c));

    material[0] = 3u; /* Remaining bytes are the pre-update all-zero V. */
    reference_mock_digest(material, sizeof(material), h);
    memset(expected_v, 0, sizeof(expected_v));
    memcpy(expected_v + TLS_HASH_DRBG_SEED_BYTES - sizeof(h), h, sizeof(h));
    for (i = sizeof(expected_v); i != 0u && carry != 0u; i--)
    {
        unsigned sum = (unsigned)expected_v[i - 1u] + carry;
        expected_v[i - 1u] = (uint8_t)sum;
        carry = sum >> 8;
    }

    assert(tls_drbg_generate_bytes(&state, &output, sizeof(output)));
    assert(memcmp(state.v, expected_v, sizeof(expected_v)) == 0);
    assert(memcmp(state.c, original_c, sizeof(original_c)) == 0);
    assert(state.reseed_counter == 2u);
}

int main(void)
{
    uint8_t out[32];
    uint8_t *large = malloc(TLS_HASH_DRBG_MAX_REQUEST_BYTES + 1u);
    uint64_t counter_before;

    assert(large != NULL);
    test_hashgen_wrap_and_truncation();
    test_generate_state_update();

    /* tls_init() selects the source before starting the asynchronous DRBG
     * lifecycle. Source discovery itself is intentionally not timer-retried. */
    assert(tls_random_init_entropy());
    tls_rng_start();
    assert(tls_rng_status() == TLS_RNG_AWAITING_INIT);
    assert(tls_rng_available_strength() == 0u);
    memset(out, 0xa5, sizeof(out));
    assert(tls_random_bytes_ex(out, sizeof(out), TLS_RNG_STRENGTH_128) == NULL);
    for (size_t i = 0; i < sizeof(out); i++) assert(out[i] == 0u);

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
    assert(g_tls_entropy_reserve_bits == TLS_HASH_DRBG_RESEED_TARGET_BITS);
    assert(g_tls_drbg.reseed_counter == 1u);
    assert(tls_random_bytes(out, sizeof(out)) == out);
    assert(g_tls_entropy_reserve_bits == 0u);
    assert(g_tls_drbg.reseed_counter == 2u);

    /* Ordinary generation may continue while the background dispatcher
     * replenishes the optional reserve. A completed reserve is consumed by
     * the following generate and resets the seedlife counter first. */
    assert(tls_random_bytes(out, sizeof(out)) == out);
    assert(g_tls_drbg.reseed_counter == 3u);
    tick();
    assert(mock_gathers == 5u && mock_period == 0u);
    assert(g_tls_entropy_reserve_bits == TLS_HASH_DRBG_RESEED_TARGET_BITS);

    /* Prediction resistance covers one Generate request. An oversized call
     * must fail before consuming the reserve or changing DRBG state. */
    counter_before = g_tls_drbg.reseed_counter;
    memset(large, 0xa5, TLS_HASH_DRBG_MAX_REQUEST_BYTES + 1u);
    assert(tls_random_bytes_pr(large,
                               TLS_HASH_DRBG_MAX_REQUEST_BYTES + 1u,
                               TLS_RNG_STRENGTH_192) == NULL);
    assert(g_tls_entropy_reserve_bits == TLS_HASH_DRBG_RESEED_TARGET_BITS);
    assert(g_tls_drbg.reseed_counter == counter_before);
    for (size_t i = 0; i < TLS_HASH_DRBG_MAX_REQUEST_BYTES + 1u; i++)
        assert(large[i] == 0u);

    assert(tls_random_bytes(out, sizeof(out)) == out);
    assert(g_tls_entropy_reserve_bits == 0u);
    assert(g_tls_drbg.reseed_counter == 2u);

    /* The strict seedlife boundary permits request 2^48, increments past the
     * interval, then fails closed until fresh reseed material is available. */
    g_tls_drbg.reseed_counter = TLS_HASH_DRBG_RESEED_INTERVAL;
    assert(tls_drbg_generate_bytes(&g_tls_drbg, out, sizeof(out)));
    assert(g_tls_drbg.reseed_counter == TLS_HASH_DRBG_RESEED_INTERVAL + 1u);
    memset(out, 0xa5, sizeof(out));
    assert(tls_random_bytes(out, sizeof(out)) == NULL);
    for (size_t i = 0; i < sizeof(out); i++) assert(out[i] == 0u);
    tick();
    assert(mock_gathers == 6u);
    assert(tls_random_bytes(out, sizeof(out)) == out);
    assert(g_tls_drbg.reseed_counter == 2u);

    /* The primitive rejects more than 2^19 bits, while the ordinary wrapper
     * splits 65537 bytes into two complete Generate calls. */
    counter_before = g_tls_drbg.reseed_counter;
    memset(large, 0xa5, TLS_HASH_DRBG_MAX_REQUEST_BYTES + 1u);
    assert(!tls_drbg_generate_bytes(&g_tls_drbg, large,
                                    TLS_HASH_DRBG_MAX_REQUEST_BYTES + 1u));
    assert(g_tls_drbg.reseed_counter == counter_before);
    assert(large[0] == 0xa5 && large[TLS_HASH_DRBG_MAX_REQUEST_BYTES] == 0xa5);
    assert(tls_random_bytes(large, TLS_HASH_DRBG_MAX_REQUEST_BYTES + 1u) == large);
    assert(g_tls_drbg.reseed_counter == counter_before + 2u);

    /* One recovered health failure is treated as intermittent. Two gather
     * steps with no clean source interval are persistent and must latch the
     * terminal error state rather than silently starting another lifecycle. */
    mock_epoch_changes_remaining = TLS_DRBG_GATHER_MAX_EPOCH_CHANGES;
    tick();
    assert(tls_rng_status() == TLS_RNG_DRBG_READY_192);
    assert(tls_rng_available_strength() == TLS_RNG_STRENGTH_192);
    assert(g_tls_rng_epoch_changes == 1u);
    tick();
    assert(tls_rng_status() == TLS_RNG_FAILED);
    assert(tls_rng_available_strength() == 0u);
    assert(tls_rng_last_failure() == TLS_RNG_FAILURE_SOURCE_HEALTH);
    assert(mock_period == 0u);
    memset(out, 0xa5, sizeof(out));
    assert(tls_random_bytes(out, sizeof(out)) == NULL);
    for (size_t i = 0; i < sizeof(out); i++) assert(out[i] == 0u);

    tls_rng_cleanup();
    assert(tls_rng_status() == TLS_RNG_STOPPED);
    assert(tls_rng_available_strength() == 0u);

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
    memset(out, 0xa5, sizeof(out));
    assert(tls_random_bytes_ex(out, sizeof(out), TLS_RNG_STRENGTH_128) == NULL);
    for (size_t i = 0; i < sizeof(out); i++) assert(out[i] == 0u);
    assert(tls_rng_status() == TLS_RNG_FAILED);

    /* A blocking request has an absolute deadline of its own. Repeated
     * initialization failure must terminate and clear the active request. */
    tls_rng_cleanup();
    mock_now = 0u;
    mock_now_step = 1000u;
    mock_source_ready = false;
    assert(!tls_request_random_bytes(out, sizeof(out), NULL, NULL, true));
    assert(mock_now >= TLS_RNG_READY_TIMEOUT_MS);
    assert(tls_rng_status() == TLS_RNG_FAILED);
    assert(tls_rng_last_failure() == TLS_RNG_FAILURE_TIMEOUT);
    assert(!tls_rng_is_busy());

    free(large);
    puts("RNG lifecycle passed: Hashgen and state update, READY_128, 192-bit promotion, reseed, request cap/splitting, persistent health failure, timeout");
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
    subprocess.run([str(binary)], check=True, timeout=5)
