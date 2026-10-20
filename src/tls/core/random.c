#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "lwip/opt.h"
#include "lwip/timeouts.h"
#include "lwip/dispatch.h"
#include "../includes/random.h"
#include "../includes/hash.h"
#include "../includes/bytes.h"
#include "../../drivers/mem.h"

#define LWIP_DBG_FILE_ID LWIP_FILE_RANDOM
#define LWIP_DBG_MODULE  LWIP_DBG_MOD_TLS
#include "lwip/logging.h"

#define TLS_RNG_REQUEST_INTERVAL_MS 50u
#define TLS_RNG_REQUEST_QUEUE_MAX_DEPTH 16u
#define TLS_RNG_SOURCE_INIT_MAX_ATTEMPTS 2u
#define TLS_HASH_DRBG_SEED_BYTES 55u
#define TLS_HASH_DRBG_ENTROPY_BYTES 32u
#define TLS_HASH_DRBG_NONCE_BYTES 32u
#define TLS_HASH_DRBG_INSTANTIATE_BYTES \
    (TLS_HASH_DRBG_ENTROPY_BYTES + TLS_HASH_DRBG_NONCE_BYTES)
#define TLS_HASH_DRBG_ENTROPY_STEP_BYTES 32u
#define TLS_HASH_DRBG_SECURITY_STRENGTH_BITS 256u
#define TLS_HASH_DRBG_RESEED_TARGET_BITS 256u
#define TLS_HASH_DRBG_INSTANTIATE_TARGET_BITS 512u
#define TLS_ENTROPY_RAW_SAMPLES_PER_STEP (UINT32_C(119) * UINT32_C(8))
/* Provisional engineering floor: 0.35 bits per selected raw bit, Q16. The
 * conditioner emits 256 bits, so min(raw_samples * Hmin, 256) credits the
 * complete 32-byte block. Replace this floor after the non-IID assessment. */
#define TLS_ENTROPY_HMIN_Q16 UINT32_C(22938)
#define TLS_ENTROPY_RAW_CREDIT_BITS \
    ((TLS_ENTROPY_RAW_SAMPLES_PER_STEP * TLS_ENTROPY_HMIN_Q16) >> 16)
#if TLS_ENTROPY_RAW_CREDIT_BITS < TLS_HASH_DRBG_SECURITY_STRENGTH_BITS
#error "Configured entropy policy cannot support 256-bit Hash_DRBG strength"
#endif
#if (TLS_HASH_DRBG_ENTROPY_BYTES * 8u) < TLS_HASH_DRBG_SECURITY_STRENGTH_BITS
#error "Hash_DRBG entropy input is shorter than its security strength"
#endif
#if (TLS_HASH_DRBG_NONCE_BYTES * 8u) < \
    (TLS_HASH_DRBG_SECURITY_STRENGTH_BITS / 2u)
#error "Hash_DRBG nonce is shorter than half its security strength"
#endif
#if TLS_HASH_DRBG_INSTANTIATE_TARGET_BITS != \
    (TLS_HASH_DRBG_INSTANTIATE_BYTES * 8u)
#error "Hash_DRBG instantiation accounting does not match its seed material"
#endif
#if TLS_HASH_DRBG_RESEED_TARGET_BITS != (TLS_HASH_DRBG_ENTROPY_BYTES * 8u)
#error "Hash_DRBG reseed accounting does not match its entropy input"
#endif
#define TLS_HASH_DRBG_MAX_REQUEST_BYTES 65536u
#define TLS_HASH_DRBG_RESEED_INTERVAL UINT64_C(0x0001000000000000)
#define TLS_RNG_STATS_CAPTURE_CHUNK 32u

/* Assembly accessor for the selected bit within the sampled SRAM byte. */
extern uint8_t tls_random_debug_source_mask(void);
extern uint8_t tls_random_health_epoch(void);
extern void *tls_entropy_collect(void *buffer, size_t len);

static bool g_tls_rng_entropy_timer_running = false;
static bool g_tls_rng_started = false;
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
static uint8_t g_tls_drbg_v[TLS_HASH_DRBG_SEED_BYTES];
static uint8_t g_tls_drbg_c[TLS_HASH_DRBG_SEED_BYTES];
static uint64_t g_tls_drbg_reseed_counter = 0;
/* Before instantiation: entropy_input || nonce. After instantiation: entropy_input. */
static uint8_t g_tls_entropy_reserve[TLS_HASH_DRBG_INSTANTIATE_BYTES];
static size_t g_tls_entropy_reserve_len = 0;
static uint16_t g_tls_entropy_reserve_bits = 0;
static uint8_t g_tls_rng_source_epoch = 0;
static uint8_t g_tls_rng_source_init_attempts = 0;

static uint16_t tls_entropy_reserve_target_bits(void)
{
    return g_tls_drbg_seeded
               ? TLS_HASH_DRBG_RESEED_TARGET_BITS
               : TLS_HASH_DRBG_INSTANTIATE_TARGET_BITS;
}

static void tls_drbg_reset(void)
{
    g_tls_drbg_seeded = false;
    g_tls_drbg_reseed_counter = 0;
    g_tls_entropy_reserve_len = 0;
    g_tls_entropy_reserve_bits = 0;
    tls_secure_memzero(g_tls_drbg_v, sizeof(g_tls_drbg_v));
    tls_secure_memzero(g_tls_drbg_c, sizeof(g_tls_drbg_c));
    tls_secure_memzero(g_tls_entropy_reserve, sizeof(g_tls_entropy_reserve));
}

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
        ERROR();
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

/* SP 800-90A Rev. 1 Hash_DRBG with SHA-256 uses seedlen=440 bits. */
static bool tls_hash_df(const uint8_t *input, size_t input_len,
                        uint8_t output[TLS_HASH_DRBG_SEED_BYTES])
{
    uint8_t digest[TLS_SHA256_DIGEST_LEN];
    uint8_t header[5] = {1u, 0u, 0u, 1u, 0xB8u}; /* 440, big endian. */
    size_t written = 0;

    while (written < TLS_HASH_DRBG_SEED_BYTES)
    {
        struct tls_hash_context ctx;
        size_t take;

        if (!tls_hash_context_init(&ctx, TLS_HASH_SHA256))
            return false;
        tls_hash_update(&ctx, header, sizeof(header));
        tls_hash_update(&ctx, input, input_len);
        tls_hash_digest(&ctx, digest);

        take = TLS_HASH_DRBG_SEED_BYTES - written;
        if (take > sizeof(digest))
            take = sizeof(digest);
        memcpy(output + written, digest, take);
        written += take;
        header[0]++;
    }

    tls_secure_memzero(digest, sizeof(digest));
    return true;
}

static void tls_hash_drbg_add(uint8_t value[TLS_HASH_DRBG_SEED_BYTES],
                              const uint8_t *addend, size_t addend_len)
{
    size_t vi = TLS_HASH_DRBG_SEED_BYTES;
    size_t ai = addend_len;
    uint16_t carry = 0;

    while (vi != 0u)
    {
        uint16_t sum = (uint16_t)value[--vi] + carry;
        if (ai != 0u)
            sum += addend[--ai];
        value[vi] = (uint8_t)sum;
        carry = sum >> 8;
    }
}

static void tls_hash_drbg_increment(uint8_t value[TLS_HASH_DRBG_SEED_BYTES])
{
    size_t i = TLS_HASH_DRBG_SEED_BYTES;
    while (i != 0u)
    {
        value[--i]++;
        if (value[i] != 0u)
            break;
    }
}

static bool tls_hash_drbg_make_c(void)
{
    uint8_t material[1u + TLS_HASH_DRBG_SEED_BYTES];
    material[0] = 0u;
    memcpy(material + 1u, g_tls_drbg_v, sizeof(g_tls_drbg_v));
    if (!tls_hash_df(material, sizeof(material), g_tls_drbg_c))
    {
        tls_secure_memzero(material, sizeof(material));
        return false;
    }
    tls_secure_memzero(material, sizeof(material));
    return true;
}

static bool tls_hash_drbg_instantiate(
    const uint8_t seed_material[TLS_HASH_DRBG_INSTANTIATE_BYTES])
{
    /* SP 800-90A Rev. 1, 10.1.1.2: seed_material is
     * entropy_input || nonce || personalization_string.  The first 32 bytes
     * carry 256 credited entropy bits and the following 32 bytes are an
     * independently collected 256-bit nonce.  No personalization string is
     * used.  This satisfies instantiation at 256-bit security strength. */
    if (!tls_hash_df(seed_material, TLS_HASH_DRBG_INSTANTIATE_BYTES,
                     g_tls_drbg_v) ||
        !tls_hash_drbg_make_c())
    {
        tls_drbg_reset();
        return false;
    }
    g_tls_drbg_reseed_counter = 1u;
    g_tls_drbg_seeded = true;
    return true;
}

static bool tls_hash_drbg_reseed(const uint8_t entropy[TLS_HASH_DRBG_ENTROPY_BYTES])
{
    uint8_t material[1u + TLS_HASH_DRBG_SEED_BYTES + TLS_HASH_DRBG_ENTROPY_BYTES];
    uint8_t new_v[TLS_HASH_DRBG_SEED_BYTES];

    if (!g_tls_drbg_seeded)
        return false;
    material[0] = 1u;
    memcpy(material + 1u, g_tls_drbg_v, sizeof(g_tls_drbg_v));
    memcpy(material + 1u + sizeof(g_tls_drbg_v), entropy,
           TLS_HASH_DRBG_ENTROPY_BYTES);
    if (!tls_hash_df(material, sizeof(material), new_v))
    {
        tls_secure_memzero(material, sizeof(material));
        tls_secure_memzero(new_v, sizeof(new_v));
        return false;
    }
    memcpy(g_tls_drbg_v, new_v, sizeof(g_tls_drbg_v));
    tls_secure_memzero(new_v, sizeof(new_v));
    tls_secure_memzero(material, sizeof(material));
    if (!tls_hash_drbg_make_c())
    {
        tls_drbg_reset();
        return false;
    }
    g_tls_drbg_reseed_counter = 1u;
    return true;
}

static bool tls_hash_drbg_hashgen(uint8_t *out, size_t len)
{
    uint8_t data[TLS_HASH_DRBG_SEED_BYTES];
    uint8_t digest[TLS_SHA256_DIGEST_LEN];
    size_t produced = 0;

    memcpy(data, g_tls_drbg_v, sizeof(data));
    while (produced < len)
    {
        size_t take = len - produced;
        if (!tls_sha256_buf(data, sizeof(data), digest))
            goto fail;
        if (take > sizeof(digest))
            take = sizeof(digest);
        memcpy(out + produced, digest, take);
        produced += take;
        tls_hash_drbg_increment(data);
    }
    tls_secure_memzero(data, sizeof(data));
    tls_secure_memzero(digest, sizeof(digest));
    return true;

fail:
    tls_secure_memzero(data, sizeof(data));
    tls_secure_memzero(digest, sizeof(digest));
    return false;
}

static bool tls_drbg_generate_bytes(uint8_t *out, size_t len)
{
    uint8_t material[1u + TLS_HASH_DRBG_SEED_BYTES];
    uint8_t h[TLS_SHA256_DIGEST_LEN];
    uint8_t counter_be[8];

    if (!g_tls_drbg_seeded || out == NULL ||
        len > TLS_HASH_DRBG_MAX_REQUEST_BYTES ||
        g_tls_drbg_reseed_counter > TLS_HASH_DRBG_RESEED_INTERVAL)
        return false;
    if (!tls_hash_drbg_hashgen(out, len))
        return false;

    material[0] = 3u;
    memcpy(material + 1u, g_tls_drbg_v, sizeof(g_tls_drbg_v));
    if (!tls_sha256_buf(material, sizeof(material), h))
        goto fail;
    tls_hash_drbg_add(g_tls_drbg_v, h, sizeof(h));
    tls_hash_drbg_add(g_tls_drbg_v, g_tls_drbg_c, sizeof(g_tls_drbg_c));
    tls_store_u64_be(g_tls_drbg_reseed_counter, counter_be);
    tls_hash_drbg_add(g_tls_drbg_v, counter_be, sizeof(counter_be));
    g_tls_drbg_reseed_counter++;
    tls_secure_memzero(material, sizeof(material));
    tls_secure_memzero(h, sizeof(h));
    return true;

fail:
    tls_secure_memzero(material, sizeof(material));
    tls_secure_memzero(h, sizeof(h));
    return false;
}

static bool tls_drbg_entropy_gather_step(void)
{
    uint8_t entropy[TLS_HASH_DRBG_ENTROPY_STEP_BYTES];
    uint8_t source_epoch;
    size_t target_bytes = g_tls_drbg_seeded
                              ? TLS_HASH_DRBG_ENTROPY_BYTES
                              : TLS_HASH_DRBG_INSTANTIATE_BYTES;
    uint16_t target_bits = g_tls_drbg_seeded
                               ? TLS_HASH_DRBG_RESEED_TARGET_BITS
                               : TLS_HASH_DRBG_INSTANTIATE_TARGET_BITS;
    size_t collect_len;
    uint16_t conditioned_bits;

    if (g_tls_entropy_reserve_bits >= target_bits)
        return true;
    if (g_tls_entropy_reserve_len >= target_bytes)
    {
        ERROR_CODE(TLS_RNG_FAILURE_ACCOUNTING);
        return false;
    }
    if (!tls_rng_healthcheck())
        return false;

    collect_len = target_bytes - g_tls_entropy_reserve_len;
    if (collect_len > sizeof(entropy))
        collect_len = sizeof(entropy);

    source_epoch = tls_random_health_epoch();
    if (tls_entropy_collect(entropy, collect_len) == NULL)
    {
        ERROR_CODE(TLS_RNG_FAILURE_COLLECTION);
        tls_drbg_reset();
        g_tls_rng_source_epoch = tls_random_health_epoch();
        return false;
    }

    /* Never combine observations spanning a failed or replaced source. */
    if ((source_epoch != tls_random_health_epoch()) ||
        (g_tls_rng_source_epoch != tls_random_health_epoch()))
    {
        ERROR_CODE(TLS_RNG_FAILURE_SOURCE_HEALTH);
        tls_drbg_reset();
        g_tls_rng_source_epoch = tls_random_health_epoch();
    }

    memcpy(g_tls_entropy_reserve + g_tls_entropy_reserve_len,
           entropy, collect_len);
    g_tls_entropy_reserve_len += collect_len;
    conditioned_bits = (uint16_t)(collect_len * 8u);
    g_tls_entropy_reserve_bits = (uint16_t)(
        g_tls_entropy_reserve_bits + conditioned_bits);
    tls_secure_memzero(entropy, sizeof(entropy));

    if (!g_tls_drbg_seeded &&
        g_tls_entropy_reserve_bits >= TLS_HASH_DRBG_INSTANTIATE_TARGET_BITS)
    {
        if (!tls_hash_drbg_instantiate(g_tls_entropy_reserve))
        {
            ERROR_CODE(TLS_RNG_FAILURE_INSTANTIATE);
            return false;
        }
        tls_secure_memzero(g_tls_entropy_reserve, sizeof(g_tls_entropy_reserve));
        g_tls_entropy_reserve_len = 0;
        g_tls_entropy_reserve_bits = 0;
    }
    return true;
}

static bool tls_drbg_apply_entropy_reserve(void)
{
    bool ok;
    if (g_tls_entropy_reserve_bits < TLS_HASH_DRBG_RESEED_TARGET_BITS)
        return true;
    if (!g_tls_drbg_seeded ||
        g_tls_entropy_reserve_len < TLS_HASH_DRBG_ENTROPY_BYTES)
    {
        ERROR_CODE(TLS_RNG_FAILURE_ACCOUNTING);
        return false;
    }
    ok = tls_hash_drbg_reseed(g_tls_entropy_reserve);
    tls_secure_memzero(g_tls_entropy_reserve, sizeof(g_tls_entropy_reserve));
    g_tls_entropy_reserve_len = 0;
    g_tls_entropy_reserve_bits = 0;
    if (!ok)
        ERROR_CODE(TLS_RNG_FAILURE_RESEED);
    return ok;
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
    if (!tls_drbg_apply_entropy_reserve())
        return false;
    take = remain;
    if (take > TLS_HASH_DRBG_MAX_REQUEST_BYTES)
        take = TLS_HASH_DRBG_MAX_REQUEST_BYTES;
    if (!tls_drbg_generate_bytes(g_tls_rng_request_out + g_tls_rng_request_collected, take))
    {
        ERROR_CODE(TLS_RNG_FAILURE_GENERATE);
        return false;
    }
    g_tls_rng_request_collected += take;
    return g_tls_rng_request_collected >= g_tls_rng_request_len;
}

#if LWIP_TIMERS
static void tls_rng_fail_pending_requests(void)
{
    while (g_tls_rng_request_active || tls_rng_request_q_pop_start_active())
    {
        tls_random_request_cb_t cb = g_tls_rng_request_cb;
        void *cb_arg = g_tls_rng_request_arg;
        if (cb != NULL)
        {
            cb(false, cb_arg);
        }
        tls_rng_request_reset_state();
    }
}

/* Dispatcher entry: drive the entropy pump. Initial instantiation gathers a
 * 256-bit entropy input plus a separately conditioned 256-bit nonce. Once
 * Hash_DRBG is instantiated and a complete 256-bit reseed reserve is waiting,
 * the dispatcher disables itself. Consuming that reserve or submitting a
 * request re-arms it. */
static void tls_rng_request_dispatch(void)
{
    bool done = false;
    bool gather_ok;
    tls_random_request_cb_t cb;
    void *cb_arg;

    if (g_tls_rng_request_active)
    {
        done = tls_rng_request_try_complete();
    }
    if (!done && (g_tls_rng_request_active || !g_tls_drbg_seeded ||
                  (g_tls_entropy_reserve_bits <
                   tls_entropy_reserve_target_bits())))
    {
        gather_ok = tls_drbg_entropy_gather_step();
        if (gather_ok && g_tls_rng_request_active)
        {
            done = tls_rng_request_try_complete();
        }
        else if (!gather_ok)
        {
            tls_rng_fail_pending_requests();
            lwip_dispatch_set_period(LWIP_DISPATCH_TLS_RNG_REQUEST, 0);
            g_tls_rng_entropy_timer_running = false;
            return;
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

    if ((g_tls_rng_request_active) || (g_tls_rng_request_q_head != NULL) ||
        (!g_tls_drbg_seeded) ||
        (g_tls_entropy_reserve_bits < tls_entropy_reserve_target_bits()))
    {
        /* Stay armed at the request cadence — there's still work. */
        lwip_dispatch_set_period(LWIP_DISPATCH_TLS_RNG_REQUEST,
                                 lwip_dispatch_period_from_ms(TLS_RNG_REQUEST_INTERVAL_MS));
        g_tls_rng_entropy_timer_running = true;
    }
    else
    {
        /* Idle: disable until the next request brings us back online. */
        lwip_dispatch_set_period(LWIP_DISPATCH_TLS_RNG_REQUEST, 0);
        g_tls_rng_entropy_timer_running = false;
    }
}

/* Attach the entropy-pump dispatcher exactly once. */
static void tls_rng_ensure_attached(void)
{
    static bool attached = false;
    if (attached)
    {
        return;
    }
    lwip_dispatch_attach(LWIP_DISPATCH_TLS_RNG_REQUEST, tls_rng_request_dispatch);
    attached = true;
}

static void tls_rng_timer_start(void)
{
    if (g_tls_rng_started)
    {
        return;
    }
    g_tls_rng_started = true;
    g_tls_rng_source_init_attempts = 0;
    g_tls_rng_source_epoch = tls_random_health_epoch();
    tls_drbg_reset();

    tls_rng_ensure_attached();
    lwip_dispatch_start();
    (void)tls_rng_healthcheck();
    if (!g_tls_rng_entropy_timer_running)
    {
        g_tls_rng_entropy_timer_running = true;
        lwip_dispatch_set_period(LWIP_DISPATCH_TLS_RNG_REQUEST,
                                 lwip_dispatch_period_from_ms(TLS_RNG_REQUEST_INTERVAL_MS));
    }
}

static void tls_rng_timer_stop(void)
{
    if (!g_tls_rng_started)
    {
        return;
    }
    g_tls_rng_started = false;
    g_tls_rng_entropy_timer_running = false;
    g_tls_rng_source_init_attempts = 0;
    tls_drbg_reset();
    lwip_dispatch_set_period(LWIP_DISPATCH_TLS_RNG_REQUEST, 0);
}
#endif

bool tls_rng_healthcheck(void)
{
    void *source = tls_random_debug_source_ptr();
    uint8_t mask = tls_random_debug_source_mask();

    if ((source != NULL) && (mask != 0u) && ((mask & (uint8_t)(mask - 1u)) == 0u))
    {
        g_tls_rng_source_init_attempts = 0;
        return true;
    }
    /* Source discovery is a complete, fixed-size SRAM scan. Bound automatic
     * retries so a machine with no usable tap cannot repeatedly monopolize
     * the dispatcher or every randomness-consuming call. An explicit
     * tls_random_init_entropy() may still recover the source; the validity
     * check above recognizes that on the next call. */
    if (g_tls_rng_source_init_attempts >= TLS_RNG_SOURCE_INIT_MAX_ATTEMPTS)
    {
        return false;
    }
    g_tls_rng_source_init_attempts++;
    if (!tls_random_init_entropy())
    {
        ERROR_CODE(TLS_RNG_FAILURE_SOURCE_INIT);
        return false;
    }
    g_tls_rng_source_init_attempts = 0;
    g_tls_rng_source_epoch = tls_random_health_epoch();
    tls_drbg_reset();
    return true;
}

void *tls_random_bytes(void *buffer, size_t len)
{
    uint8_t *out = (uint8_t *)buffer;
    size_t requested_len = len;

    if (buffer == NULL)
        return NULL;
    if (len == 0u)
        return buffer;
    if (!g_tls_rng_started)
        tls_rng_start();
    if (g_tls_rng_request_active || (g_tls_rng_request_q_head != NULL))
        return NULL;

    while (!g_tls_drbg_seeded)
    {
        if (!tls_drbg_entropy_gather_step())
            goto fail;
    }
    if (g_tls_drbg_reseed_counter > TLS_HASH_DRBG_RESEED_INTERVAL)
    {
        while (g_tls_entropy_reserve_bits < TLS_HASH_DRBG_RESEED_TARGET_BITS)
        {
            if (!tls_drbg_entropy_gather_step())
                goto fail;
        }
    }
    if (!tls_drbg_apply_entropy_reserve())
        goto fail;

    while (len != 0u)
    {
        size_t take = len;
        if (take > TLS_HASH_DRBG_MAX_REQUEST_BYTES)
            take = TLS_HASH_DRBG_MAX_REQUEST_BYTES;
        if (!tls_drbg_generate_bytes(out, take))
        {
            ERROR_CODE(TLS_RNG_FAILURE_GENERATE);
            goto fail;
        }
        out += take;
        len -= take;
    }

#if LWIP_TIMERS
    if (g_tls_rng_started && !g_tls_rng_entropy_timer_running &&
        g_tls_entropy_reserve_bits < TLS_HASH_DRBG_RESEED_TARGET_BITS)
    {
        g_tls_rng_entropy_timer_running = true;
        tls_rng_ensure_attached();
        lwip_dispatch_start();
        lwip_dispatch_set_period(LWIP_DISPATCH_TLS_RNG_REQUEST,
                                 lwip_dispatch_period_from_ms(TLS_RNG_REQUEST_INTERVAL_MS));
    }
#endif
    return buffer;

fail:
    tls_secure_memzero(buffer, requested_len);
    return NULL;
}

uint64_t tls_random(void)
{
    uint64_t value = 0;
    if (tls_random_bytes(&value, sizeof(value)) == NULL)
        return 0;
    return value;
}

bool tls_request_random_bytes(uint8_t *out, size_t len, tls_random_request_cb_t cb, void *arg, bool blocking)
{
    bool done = false;
    if (out == NULL || len == 0)
    {
        return false;
    }
    if (!g_tls_rng_started)
        tls_rng_start();
    if (!tls_rng_healthcheck())
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
                if (cb != NULL)
                {
                    cb(false, arg);
                }
                tls_rng_request_reset_state();
                return false;
            }
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
        ERROR();
        return false;
    }

    if (!g_tls_rng_entropy_timer_running)
    {
        g_tls_rng_entropy_timer_running = true;
        tls_rng_ensure_attached();
        lwip_dispatch_start();
        lwip_dispatch_set_period(LWIP_DISPATCH_TLS_RNG_REQUEST,
                                 lwip_dispatch_period_from_ms(TLS_RNG_REQUEST_INTERVAL_MS));
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

bool tls_rng_compute_stats(size_t sample_count, struct tls_rng_stats *stats)
{
    const volatile uint8_t *source;
    uint8_t source_mask;
    uint8_t captured[TLS_RNG_STATS_CAPTURE_CHUNK];
    uint8_t previous = 0;
    uint32_t current_run = 0;
    uint32_t remaining;
    bool have_previous = false;

    if (stats == NULL)
    {
        return false;
    }
    memset(stats, 0, sizeof(*stats));

    if ((sample_count < TLS_RNG_STATS_MIN_SAMPLES) ||
        (sample_count > TLS_RNG_STATS_MAX_SAMPLES) ||
        tls_rng_is_busy())
    {
        return false;
    }

    source = (const volatile uint8_t *)tls_random_debug_source_ptr();
    source_mask = tls_random_debug_source_mask();
    if ((source == NULL) || (source_mask == 0u) ||
        ((source_mask & (uint8_t)(source_mask - 1u)) != 0u))
    {
        return false;
    }

    stats->source_address = (uintptr_t)source;
    stats->source_mask = source_mask;
    stats->sample_count = (uint32_t)sample_count;
    remaining = (uint32_t)sample_count;

    while (remaining != 0u)
    {
        uint8_t count = (remaining > TLS_RNG_STATS_CAPTURE_CHUNK)
                            ? TLS_RNG_STATS_CAPTURE_CHUNK
                            : (uint8_t)remaining;
        uint8_t i;

        /* Keep raw reads adjacent and independent of the observed bit value. */
        for (i = 0; i < count; i++)
        {
            captured[i] = *source;
        }

        for (i = 0; i < count; i++)
        {
            uint8_t bit = (captured[i] & source_mask) != 0u;

            if (bit != 0u)
            {
                stats->ones++;
            }

            if (have_previous)
            {
                if (previous == 0u)
                {
                    if (bit == 0u)
                    {
                        stats->pairs_00++;
                    }
                    else
                    {
                        stats->pairs_01++;
                    }
                }
                else
                {
                    if (bit == 0u)
                    {
                        stats->pairs_10++;
                    }
                    else
                    {
                        stats->pairs_11++;
                    }
                }
            }

            if (!have_previous)
            {
                current_run = 1u;
                have_previous = true;
            }
            else if (bit == previous)
            {
                current_run++;
            }
            else
            {
                stats->transitions++;
                current_run = 1u;
            }

            if (current_run > stats->longest_run)
            {
                stats->longest_run = current_run;
            }
            if ((bit == 0u) && (current_run > stats->longest_zero_run))
            {
                stats->longest_zero_run = current_run;
            }
            if ((bit != 0u) && (current_run > stats->longest_one_run))
            {
                stats->longest_one_run = current_run;
            }

            previous = bit;
        }

        remaining -= count;
    }

    stats->zeros = stats->sample_count - stats->ones;
    stats->p1_q16 = (uint32_t)((((uint64_t)stats->ones << 16) +
                                (stats->sample_count / 2u)) /
                               stats->sample_count);
    stats->bias_q16 = (stats->p1_q16 >= 32768u)
                          ? stats->p1_q16 - 32768u
                          : 32768u - stats->p1_q16;
    stats->transition_rate_q16 = (uint32_t)(
        (((uint64_t)stats->transitions << 16) +
         ((stats->sample_count - 1u) / 2u)) /
        (stats->sample_count - 1u));

    return true;
}

void tls_rng_start(void)
{
#if LWIP_TIMERS
    tls_rng_timer_start();
#else
    /* Readiness is checked by each randomness-consuming operation. Startup
     * must not make deterministic crypto primitives depend on entropy being
     * immediately available. */
    g_tls_rng_source_init_attempts = 0;
    (void)tls_rng_healthcheck();
#endif
}

void tls_rng_cleanup(void)
{
#if LWIP_TIMERS
    tls_rng_timer_stop();
#endif
    tls_rng_request_reset_state();
    tls_rng_request_q_clear();
}
