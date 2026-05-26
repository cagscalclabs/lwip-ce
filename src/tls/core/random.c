#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "lwip/opt.h"
#include "lwip/timeouts.h"
#include "../includes/random.h"
#include "../includes/hash.h"
#include "../../drivers/mem.h"

#define TLS_RNG_HEALTHCHECK_INTERVAL_MS 30000u
#define TLS_RNG_HEALTHCHECK_FAIL_THRESHOLD 3u
#define TLS_RNG_HEALTHCHECK_SAMPLE_BYTES 32u
#define TLS_RNG_HEALTHCHECK_MIN_ONES 88u
#define TLS_RNG_HEALTHCHECK_MAX_ONES 168u
#define TLS_RNG_HEALTHCHECK_MAX_EQUAL_RUN 4u
#define TLS_RNG_REQUEST_INTERVAL_MS 50u
#define TLS_RNG_REQUEST_BLOCKING_MAX_RETRIES 16u
#define TLS_RNG_REQUEST_QUEUE_MAX_DEPTH 16u
#define TLS_DRBG_STATE_BYTES 32u
#define TLS_DRBG_ENTROPY_BUDGET_MAX 32u
#define TLS_DRBG_ENTROPY_STEP_BYTES 8u

static bool g_tls_rng_health_timer_running = false;
static bool g_tls_rng_health_ready = false;
static uint8_t g_tls_rng_health_failures = 0;
static bool g_tls_rng_prev_sample_valid = false;
static uint8_t g_tls_rng_prev_sample[TLS_RNG_HEALTHCHECK_SAMPLE_BYTES];
static bool tls_rng_healthcheck_run_once(void);
static bool g_tls_rng_entropy_timer_running = false;
static bool g_tls_rng_request_active = false;
static uint8_t *g_tls_rng_request_out = NULL;
static size_t g_tls_rng_request_len = 0;
static size_t g_tls_rng_request_collected = 0;
static tls_random_request_cb_t g_tls_rng_request_cb = NULL;
static void *g_tls_rng_request_arg = NULL;

struct tls_rng_request_ctx
{
    struct tls_rng_request_ctx *next;
    uint8_t *out;
    size_t len;
    tls_random_request_cb_t cb;
    void *arg;
};

static struct tls_rng_request_ctx *g_tls_rng_request_q_head = NULL;
static struct tls_rng_request_ctx *g_tls_rng_request_q_tail = NULL;
static uint8_t g_tls_rng_request_q_depth = 0;
static bool g_tls_drbg_seeded = false;
static uint8_t g_tls_drbg_state[TLS_DRBG_STATE_BYTES];
static uint8_t g_tls_drbg_seed_material[TLS_DRBG_STATE_BYTES];
static size_t g_tls_drbg_seed_material_len = 0;
static size_t g_tls_drbg_entropy_budget = 0;
static uint64_t g_tls_drbg_counter = 1;

static void tls_rng_request_reset_state(void)
{
    g_tls_rng_request_active = false;
    g_tls_rng_request_out = NULL;
    g_tls_rng_request_len = 0;
    g_tls_rng_request_collected = 0;
    g_tls_rng_request_cb = NULL;
    g_tls_rng_request_arg = NULL;
}

static bool tls_rng_request_q_push(uint8_t *out, size_t len, tls_random_request_cb_t cb, void *arg)
{
    struct tls_rng_request_ctx *node;

    if (g_tls_rng_request_q_depth >= TLS_RNG_REQUEST_QUEUE_MAX_DEPTH)
    {
        return false;
    }

    node = (struct tls_rng_request_ctx *)mem_buffer_custom_malloc(sizeof(struct tls_rng_request_ctx));
    if (node == NULL)
    {
        return false;
    }

    node->next = NULL;
    node->out = out;
    node->len = len;
    node->cb = cb;
    node->arg = arg;

    if (g_tls_rng_request_q_tail != NULL)
    {
        g_tls_rng_request_q_tail->next = node;
    }
    else
    {
        g_tls_rng_request_q_head = node;
    }
    g_tls_rng_request_q_tail = node;
    g_tls_rng_request_q_depth++;
    return true;
}

static bool tls_rng_request_q_pop_start_active(void)
{
    struct tls_rng_request_ctx *node;

    node = g_tls_rng_request_q_head;
    if (node == NULL)
    {
        return false;
    }

    g_tls_rng_request_q_head = node->next;
    if (g_tls_rng_request_q_head == NULL)
    {
        g_tls_rng_request_q_tail = NULL;
    }
    if (g_tls_rng_request_q_depth > 0)
    {
        g_tls_rng_request_q_depth--;
    }

    g_tls_rng_request_active = true;
    g_tls_rng_request_out = node->out;
    g_tls_rng_request_len = node->len;
    g_tls_rng_request_collected = 0;
    g_tls_rng_request_cb = node->cb;
    g_tls_rng_request_arg = node->arg;

    mem_buffer_custom_free(node);
    return true;
}

static void tls_rng_request_q_clear(void)
{
    struct tls_rng_request_ctx *node = g_tls_rng_request_q_head;
    struct tls_rng_request_ctx *next;

    while (node != NULL)
    {
        next = node->next;
        mem_buffer_custom_free(node);
        node = next;
    }
    g_tls_rng_request_q_head = NULL;
    g_tls_rng_request_q_tail = NULL;
    g_tls_rng_request_q_depth = 0;
}

static bool tls_sha256_buf(const uint8_t *in, size_t in_len, uint8_t out[32])
{
    struct tls_hash_context hctx;
    if (!tls_hash_context_init(&hctx, TLS_HASH_SHA256))
    {
        return false;
    }
    tls_hash_update(&hctx, in, in_len);
    tls_hash_digest(&hctx, out);
    return true;
}

static void tls_store_u64_be(uint64_t x, uint8_t out[8])
{
    out[0] = (uint8_t)(x >> 56);
    out[1] = (uint8_t)(x >> 48);
    out[2] = (uint8_t)(x >> 40);
    out[3] = (uint8_t)(x >> 32);
    out[4] = (uint8_t)(x >> 24);
    out[5] = (uint8_t)(x >> 16);
    out[6] = (uint8_t)(x >> 8);
    out[7] = (uint8_t)x;
}

static bool tls_drbg_instantiate_from_seed_material(void)
{
    if (g_tls_drbg_seed_material_len < TLS_DRBG_STATE_BYTES)
    {
        return false;
    }
    if (!tls_sha256_buf(g_tls_drbg_seed_material, TLS_DRBG_STATE_BYTES, g_tls_drbg_state))
    {
        return false;
    }
    g_tls_drbg_seeded = true;
    g_tls_drbg_counter = 1;
    g_tls_drbg_seed_material_len = 0;
    memset(g_tls_drbg_seed_material, 0, sizeof(g_tls_drbg_seed_material));
    return true;
}

static bool tls_drbg_reseed_with_entropy(const uint8_t entropy[TLS_DRBG_ENTROPY_STEP_BYTES])
{
    uint8_t material[TLS_DRBG_STATE_BYTES + TLS_DRBG_ENTROPY_STEP_BYTES + 8];
    uint8_t ctr_be[8];

    if (!g_tls_drbg_seeded)
    {
        return false;
    }

    tls_store_u64_be(g_tls_drbg_counter, ctr_be);
    memcpy(material, g_tls_drbg_state, TLS_DRBG_STATE_BYTES);
    memcpy(material + TLS_DRBG_STATE_BYTES, entropy, TLS_DRBG_ENTROPY_STEP_BYTES);
    memcpy(material + TLS_DRBG_STATE_BYTES + TLS_DRBG_ENTROPY_STEP_BYTES, ctr_be, sizeof(ctr_be));
    if (!tls_sha256_buf(material, sizeof(material), g_tls_drbg_state))
    {
        return false;
    }
    g_tls_drbg_counter++;
    return true;
}

static bool tls_drbg_generate_bytes(uint8_t *out, size_t len)
{
    uint8_t block[32];
    uint8_t material[TLS_DRBG_STATE_BYTES + 8];
    uint8_t update_mat[TLS_DRBG_STATE_BYTES + 32 + 1];
    uint8_t ctr_be[8];
    size_t produced = 0;
    size_t take;

    if (!g_tls_drbg_seeded || out == NULL)
    {
        return false;
    }

    while (produced < len)
    {
        tls_store_u64_be(g_tls_drbg_counter, ctr_be);
        memcpy(material, g_tls_drbg_state, TLS_DRBG_STATE_BYTES);
        memcpy(material + TLS_DRBG_STATE_BYTES, ctr_be, sizeof(ctr_be));
        if (!tls_sha256_buf(material, sizeof(material), block))
        {
            return false;
        }

        take = ((len - produced) < sizeof(block)) ? (len - produced) : sizeof(block);
        memcpy(out + produced, block, take);

        memcpy(update_mat, g_tls_drbg_state, TLS_DRBG_STATE_BYTES);
        memcpy(update_mat + TLS_DRBG_STATE_BYTES, block, sizeof(block));
        update_mat[TLS_DRBG_STATE_BYTES + sizeof(block)] = 0xA5;
        if (!tls_sha256_buf(update_mat, sizeof(update_mat), g_tls_drbg_state))
        {
            return false;
        }

        g_tls_drbg_counter++;
        produced += take;
    }
    return true;
}

static bool tls_drbg_entropy_gather_step(void)
{
    uint64_t r64;
    uint8_t entropy[TLS_DRBG_ENTROPY_STEP_BYTES];

    if (!tls_rng_healthcheck_run_once())
    {
        return false;
    }

    r64 = tls_random();
    memcpy(entropy, &r64, sizeof(entropy));

    if (!g_tls_drbg_seeded)
    {
        size_t remain = TLS_DRBG_STATE_BYTES - g_tls_drbg_seed_material_len;
        size_t take = (remain < sizeof(entropy)) ? remain : sizeof(entropy);
        memcpy(g_tls_drbg_seed_material + g_tls_drbg_seed_material_len, entropy, take);
        g_tls_drbg_seed_material_len += take;
        if (g_tls_drbg_seed_material_len >= TLS_DRBG_STATE_BYTES)
        {
            if (!tls_drbg_instantiate_from_seed_material())
            {
                return false;
            }
        }
    }
    else if (!tls_drbg_reseed_with_entropy(entropy))
    {
        return false;
    }

    if (g_tls_drbg_entropy_budget < TLS_DRBG_ENTROPY_BUDGET_MAX)
    {
        size_t next = g_tls_drbg_entropy_budget + TLS_DRBG_ENTROPY_STEP_BYTES;
        g_tls_drbg_entropy_budget = (next > TLS_DRBG_ENTROPY_BUDGET_MAX) ? TLS_DRBG_ENTROPY_BUDGET_MAX : next;
    }
    return true;
}

static bool tls_rng_request_try_complete(void)
{
    size_t remain;
    size_t take;

    if (!g_tls_rng_request_active)
    {
        return true;
    }
    if (!g_tls_drbg_seeded)
    {
        return false;
    }

    remain = g_tls_rng_request_len - g_tls_rng_request_collected;
    if (remain == 0)
    {
        return true;
    }
    if (g_tls_drbg_entropy_budget == 0)
    {
        return false;
    }

    take = (remain < g_tls_drbg_entropy_budget) ? remain : g_tls_drbg_entropy_budget;
    if (!tls_drbg_generate_bytes(g_tls_rng_request_out + g_tls_rng_request_collected, take))
    {
        return false;
    }
    g_tls_drbg_entropy_budget -= take;
    g_tls_rng_request_collected += take;
    return g_tls_rng_request_collected >= g_tls_rng_request_len;
}

static uint8_t tls_popcount_u8(uint8_t x)
{
    uint8_t c = 0;
    while (x != 0)
    {
        c += (uint8_t)(x & 1u);
        x >>= 1;
    }
    return c;
}

static bool tls_rng_healthcheck_sample_ok(void)
{
    uint8_t sample[TLS_RNG_HEALTHCHECK_SAMPLE_BYTES];
    uint16_t ones = 0;
    uint8_t max_equal_run = 1;
    uint8_t run_len = 1;
    size_t i;

    tls_random_bytes(sample, sizeof(sample));

    if (g_tls_rng_prev_sample_valid &&
        memcmp(sample, g_tls_rng_prev_sample, sizeof(sample)) == 0)
    {
        return false;
    }

    for (i = 0; i < sizeof(sample); i++)
    {
        ones += tls_popcount_u8(sample[i]);
        if ((i > 0) && (sample[i] == sample[i - 1]))
        {
            run_len++;
            if (run_len > max_equal_run)
            {
                max_equal_run = run_len;
            }
        }
        else
        {
            run_len = 1;
        }
    }

    if ((ones < TLS_RNG_HEALTHCHECK_MIN_ONES) || (ones > TLS_RNG_HEALTHCHECK_MAX_ONES))
    {
        return false;
    }
    if (max_equal_run > TLS_RNG_HEALTHCHECK_MAX_EQUAL_RUN)
    {
        return false;
    }

    memcpy(g_tls_rng_prev_sample, sample, sizeof(sample));
    g_tls_rng_prev_sample_valid = true;
    return true;
}

static bool tls_rng_healthcheck_run_once(void)
{
    if (!g_tls_rng_health_ready)
    {
        g_tls_rng_health_ready = tls_random_init_entropy();
        if (g_tls_rng_health_ready)
        {
            g_tls_rng_health_failures = 0;
            g_tls_rng_prev_sample_valid = false;
        }
        return g_tls_rng_health_ready;
    }

    if (tls_rng_healthcheck_sample_ok())
    {
        g_tls_rng_health_failures = 0;
        return true;
    }

    g_tls_rng_health_failures++;
    if (g_tls_rng_health_failures >= TLS_RNG_HEALTHCHECK_FAIL_THRESHOLD)
    {
        g_tls_rng_health_ready = tls_random_init_entropy();
        g_tls_rng_health_failures = g_tls_rng_health_ready ? 0 : TLS_RNG_HEALTHCHECK_FAIL_THRESHOLD;
    }
    return g_tls_rng_health_ready;
}

#if LWIP_TIMERS
static void tls_rng_request_timer(void *arg)
{
    bool done = false;
    bool gather_ok;
    tls_random_request_cb_t cb;
    void *cb_arg;

    (void)arg;
    if (g_tls_rng_request_active)
    {
        done = tls_rng_request_try_complete();
    }
    if (!done && (g_tls_rng_request_active || !g_tls_drbg_seeded || (g_tls_drbg_entropy_budget < TLS_DRBG_ENTROPY_BUDGET_MAX)))
    {
        gather_ok = tls_drbg_entropy_gather_step();
        if (gather_ok && g_tls_rng_request_active)
        {
            done = tls_rng_request_try_complete();
        }
    }

    if (done)
    {
        cb = g_tls_rng_request_cb;
        cb_arg = g_tls_rng_request_arg;
        if (cb != NULL)
        {
            cb(true, cb_arg);
        }
        tls_rng_request_reset_state();
        (void)tls_rng_request_q_pop_start_active();
    }

    if ((g_tls_rng_request_active) || (g_tls_rng_request_q_head != NULL) || (!g_tls_drbg_seeded) || (g_tls_drbg_entropy_budget < TLS_DRBG_ENTROPY_BUDGET_MAX))
    {
        sys_timeout(TLS_RNG_REQUEST_INTERVAL_MS, tls_rng_request_timer, NULL);
        g_tls_rng_entropy_timer_running = true;
    }
    else
    {
        g_tls_rng_entropy_timer_running = false;
    }
}

static void tls_rng_healthcheck_timer(void *arg)
{
    (void)arg;

    if (!g_tls_rng_health_timer_running)
    {
        return;
    }

    (void)tls_rng_healthcheck_run_once();

    sys_timeout(TLS_RNG_HEALTHCHECK_INTERVAL_MS, tls_rng_healthcheck_timer, NULL);
}

static void tls_rng_healthcheck_start(void)
{
    if (g_tls_rng_health_timer_running)
    {
        return;
    }
    g_tls_rng_health_failures = 0;
    g_tls_rng_health_ready = tls_random_init_entropy();
    g_tls_rng_prev_sample_valid = false;
    g_tls_drbg_seeded = false;
    g_tls_drbg_seed_material_len = 0;
    g_tls_drbg_entropy_budget = 0;
    g_tls_drbg_counter = 1;
    memset(g_tls_drbg_state, 0, sizeof(g_tls_drbg_state));
    memset(g_tls_drbg_seed_material, 0, sizeof(g_tls_drbg_seed_material));
    g_tls_rng_health_timer_running = true;
    if (!g_tls_rng_entropy_timer_running)
    {
        g_tls_rng_entropy_timer_running = true;
        sys_timeout(TLS_RNG_REQUEST_INTERVAL_MS, tls_rng_request_timer, NULL);
    }
    sys_timeout(TLS_RNG_HEALTHCHECK_INTERVAL_MS, tls_rng_healthcheck_timer, NULL);
}

static void tls_rng_healthcheck_stop(void)
{
    if (!g_tls_rng_health_timer_running)
    {
        return;
    }
    g_tls_rng_health_timer_running = false;
    g_tls_rng_health_ready = false;
    g_tls_rng_health_failures = 0;
    g_tls_rng_prev_sample_valid = false;
    g_tls_rng_entropy_timer_running = false;
    g_tls_drbg_seeded = false;
    g_tls_drbg_seed_material_len = 0;
    g_tls_drbg_entropy_budget = 0;
    g_tls_drbg_counter = 1;
    memset(g_tls_drbg_state, 0, sizeof(g_tls_drbg_state));
    memset(g_tls_drbg_seed_material, 0, sizeof(g_tls_drbg_seed_material));
    sys_untimeout(tls_rng_healthcheck_timer, NULL);
    sys_untimeout(tls_rng_request_timer, NULL);
}
#endif

bool tls_rng_healthcheck(void)
{
    return tls_rng_healthcheck_run_once();
}

bool tls_request_random_bytes(uint8_t *out, size_t len, tls_random_request_cb_t cb, void *arg, bool blocking)
{
    bool done = false;
    uint8_t retries = 0;

    if (out == NULL || len == 0)
    {
        return false;
    }

    if (blocking)
    {
        if (g_tls_rng_request_active || (g_tls_rng_request_q_head != NULL))
        {
            return false;
        }

        g_tls_rng_request_active = true;
        g_tls_rng_request_out = out;
        g_tls_rng_request_len = len;
        g_tls_rng_request_collected = 0;
        g_tls_rng_request_cb = cb;
        g_tls_rng_request_arg = arg;

        while (!done)
        {
            done = tls_rng_request_try_complete();
            if (done)
            {
                continue;
            }
            if (!tls_drbg_entropy_gather_step())
            {
                retries++;
                if (retries >= TLS_RNG_REQUEST_BLOCKING_MAX_RETRIES)
                {
                    if (cb != NULL)
                    {
                        cb(false, arg);
                    }
                    tls_rng_request_reset_state();
                    return false;
                }
                continue;
            }
            retries = 0;
            done = tls_rng_request_try_complete();
        }
        if (cb != NULL)
        {
            cb(true, arg);
        }
        tls_rng_request_reset_state();
        return true;
    }

#if LWIP_TIMERS
    if (!g_tls_rng_request_active)
    {
        g_tls_rng_request_active = true;
        g_tls_rng_request_out = out;
        g_tls_rng_request_len = len;
        g_tls_rng_request_collected = 0;
        g_tls_rng_request_cb = cb;
        g_tls_rng_request_arg = arg;
    }
    else if (!tls_rng_request_q_push(out, len, cb, arg))
    {
        return false;
    }

    if (!g_tls_rng_entropy_timer_running)
    {
        g_tls_rng_entropy_timer_running = true;
        sys_timeout(TLS_RNG_REQUEST_INTERVAL_MS, tls_rng_request_timer, NULL);
    }
    return true;
#else
    if (cb != NULL)
    {
        cb(false, arg);
    }
    tls_rng_request_reset_state();
    return false;
#endif
}

bool tls_rng_is_busy(void)
{
    return g_tls_rng_request_active || (g_tls_rng_request_q_head != NULL);
}

void tls_rng_start(void)
{
#if LWIP_TIMERS
    tls_rng_healthcheck_start();
#endif
}

void tls_rng_cleanup(void)
{
#if LWIP_TIMERS
    tls_rng_healthcheck_stop();
#endif
    tls_rng_request_reset_state();
    tls_rng_request_q_clear();
}
