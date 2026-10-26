#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "lwip/opt.h"
#include "lwip/timeouts.h"
#include "lwip/dispatch.h"
#include "lwip/sys.h"
#include "../includes/random.h"
#include "../includes/hash.h"
#include "../includes/bytes.h"
#include "../../drivers/mem.h"

#define LWIP_DBG_FILE_ID LWIP_FILE_RANDOM
#define LWIP_DBG_MODULE  LWIP_DBG_MOD_TLS
#include "lwip/logging.h"

#define TLS_RNG_REQUEST_INTERVAL_MS 50u
#define TLS_RNG_READY_TIMEOUT_MS 15000u
#define TLS_RNG_REQUEST_QUEUE_MAX_DEPTH 16u
#define TLS_HASH_DRBG_SEED_BITS 440u
#define TLS_HASH_DRBG_SEED_BYTES (TLS_HASH_DRBG_SEED_BITS / 8u)
#define TLS_HASH_DRBG_ENTROPY_BYTES 24u
#define TLS_HASH_DRBG_NONCE_BYTES 24u
#define TLS_HASH_DRBG_128_INSTANTIATE_BYTES TLS_HASH_DRBG_ENTROPY_BYTES
#define TLS_HASH_DRBG_192_INSTANTIATE_BYTES \
    (TLS_HASH_DRBG_ENTROPY_BYTES + TLS_HASH_DRBG_NONCE_BYTES)
#define TLS_HASH_DRBG_MAX_INSTANTIATE_BYTES TLS_HASH_DRBG_192_INSTANTIATE_BYTES
#define TLS_HASH_DRBG_ENTROPY_STEP_BYTES TLS_HASH_DRBG_ENTROPY_BYTES
#define TLS_HASH_DRBG_RESEED_TARGET_BITS 192u
#define TLS_HASH_DRBG_128_INSTANTIATE_TARGET_BITS 192u
#define TLS_HASH_DRBG_192_INSTANTIATE_TARGET_BITS 384u
#define TLS_ENTROPY_RAW_SAMPLES_PER_STEP (UINT32_C(119) * UINT32_C(8))
/* Provisional engineering floor: 0.269 bits per selected raw bit, Q16.
 * h_in = 952 * 0.269 = 256.088 bits. The 64-bit excess over the
 * 192-bit contribution is a conservative local conditioning margin, not an
 * SP 800-90C full-entropy claim: direct SHA-256 has output_len = 256 and
 * Section 3.2.2.2 would require 320 credited input bits. Replace the floor
 * after formal non-IID assessment. */
#define TLS_ENTROPY_HMIN_Q16 UINT32_C(17630)
#define TLS_ENTROPY_RAW_CREDIT_BITS \
    ((TLS_ENTROPY_RAW_SAMPLES_PER_STEP * TLS_ENTROPY_HMIN_Q16) >> 16)
#define TLS_ENTROPY_CONTRIBUTION_BITS (TLS_HASH_DRBG_ENTROPY_BYTES * 8u)
#define TLS_ENTROPY_CONDITIONING_MARGIN_BITS 64u
#if (TLS_HASH_DRBG_SEED_BITS % 8u) != 0u || TLS_HASH_DRBG_SEED_BYTES != 55u
#error "SHA-256 Hash_DRBG seedlen must be exactly 440 bits"
#endif
#if TLS_ENTROPY_RAW_CREDIT_BITS < \
    (TLS_ENTROPY_CONTRIBUTION_BITS + TLS_ENTROPY_CONDITIONING_MARGIN_BITS)
#error "Configured entropy policy lacks the conditioning safety margin"
#endif
#if TLS_ENTROPY_CONTRIBUTION_BITS != TLS_RNG_STRENGTH_192
#error "Hash_DRBG entropy input is shorter than its security strength"
#endif
#if TLS_HASH_DRBG_128_INSTANTIATE_TARGET_BITS != \
    (TLS_HASH_DRBG_128_INSTANTIATE_BYTES * 8u)
#error "128-bit Hash_DRBG instantiation accounting does not match its seed material"
#endif
#if TLS_HASH_DRBG_128_INSTANTIATE_TARGET_BITS < \
    ((TLS_RNG_STRENGTH_128 * 3u) / 2u)
#error "128-bit Hash_DRBG instantiation lacks 3/2-strength entropy for an implicit nonce"
#endif
#if (TLS_HASH_DRBG_NONCE_BYTES * 8u) < \
    (TLS_RNG_STRENGTH_192 / 2u)
#error "Hash_DRBG nonce is shorter than half its security strength"
#endif
#if TLS_HASH_DRBG_192_INSTANTIATE_TARGET_BITS != \
    (TLS_HASH_DRBG_192_INSTANTIATE_BYTES * 8u)
#error "Hash_DRBG instantiation accounting does not match its seed material"
#endif
#if TLS_HASH_DRBG_192_INSTANTIATE_TARGET_BITS < \
    ((TLS_RNG_STRENGTH_192 * 3u) / 2u)
#error "192-bit Hash_DRBG instantiation lacks 3/2-strength entropy and nonce material"
#endif
#if TLS_HASH_DRBG_RESEED_TARGET_BITS != (TLS_HASH_DRBG_ENTROPY_BYTES * 8u)
#error "Hash_DRBG reseed accounting does not match its entropy input"
#endif
#define TLS_HASH_DRBG_MAX_REQUEST_BITS (UINT32_C(1) << 19)
#define TLS_HASH_DRBG_MAX_REQUEST_BYTES (TLS_HASH_DRBG_MAX_REQUEST_BITS / 8u)
#if (TLS_HASH_DRBG_MAX_REQUEST_BITS % 8u) != 0u || \
    TLS_HASH_DRBG_MAX_REQUEST_BYTES != 65536u
#error "SHA-256 Hash_DRBG request limit must be exactly 2^19 bits"
#endif
#define TLS_HASH_DRBG_RESEED_INTERVAL (UINT64_C(1) << 48)
#define TLS_RNG_STATS_CAPTURE_CHUNK 32u

/* Assembly accessor for the selected bit within the sampled SRAM byte. */
extern uint8_t tls_random_debug_source_mask(void);
extern uint8_t tls_random_health_epoch(void);
extern void *tls_entropy_collect(void *buffer, size_t len);

/* Assembly retains the active tap's seven-bit pass mask before recovery can
 * run candidate qualification and reuse its diagnostic scratch. */
extern uint8_t sprng_last_health_mask;

static void tls_rng_log_health_failure(void)
{
    uint8_t mask = sprng_last_health_mask & TLS_RNG_HEALTH_ALL_PASS;

    /* Source recovery continues after this event. Keep the failed test mask
     * in the traceback, but reserve ERROR for a terminal RNG failure. */
    WARN_CODE(mask);
}

static bool g_tls_rng_entropy_timer_running = false;
static bool g_tls_rng_started = false;
static tls_rng_state_t g_tls_rng_state = TLS_RNG_STOPPED;
static tls_rng_failure_t g_tls_rng_last_failure = 0;
static uint32_t g_tls_rng_ready_deadline = 0;
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
struct tls_hash_drbg_state
{
    /* SP 800-90A 10.1.1.1 working state, followed by administrative state. */
    uint8_t v[TLS_HASH_DRBG_SEED_BYTES];
    uint8_t c[TLS_HASH_DRBG_SEED_BYTES];
    uint64_t reseed_counter;
    uint16_t strength_bits;
    bool seeded;
};

static struct tls_hash_drbg_state g_tls_drbg;
static struct tls_hash_drbg_state g_tls_drbg_upgrade;
/* During startup this holds seed material for the current lifecycle phase.
 * At READY_192 it instead holds a prepared 192-bit reseed input. */
static uint8_t g_tls_entropy_reserve[TLS_HASH_DRBG_MAX_INSTANTIATE_BYTES];
static size_t g_tls_entropy_reserve_len = 0;
static uint16_t g_tls_entropy_reserve_bits = 0;
static bool g_tls_rng_external = false;
/* Consecutive gather steps discarded for a source-health epoch change. Reset
 * on DRBG reset, RNG start, and every successful gather step. (F4) */
static uint8_t g_tls_rng_epoch_changes = 0;

static uint16_t tls_entropy_reserve_target_bits(void)
{
    switch (g_tls_rng_state)
    {
    case TLS_RNG_DRBG_SEEDING:
        return TLS_HASH_DRBG_128_INSTANTIATE_TARGET_BITS;
    case TLS_RNG_DRBG_READY_128:
        return TLS_HASH_DRBG_192_INSTANTIATE_TARGET_BITS;
    case TLS_RNG_DRBG_READY_192:
        return TLS_HASH_DRBG_RESEED_TARGET_BITS;
    default:
        return 0;
    }
}

static size_t tls_entropy_reserve_target_bytes(void)
{
    switch (g_tls_rng_state)
    {
    case TLS_RNG_DRBG_SEEDING:
        return TLS_HASH_DRBG_128_INSTANTIATE_BYTES;
    case TLS_RNG_DRBG_READY_128:
        return TLS_HASH_DRBG_192_INSTANTIATE_BYTES;
    case TLS_RNG_DRBG_READY_192:
        return TLS_HASH_DRBG_ENTROPY_BYTES;
    default:
        return 0;
    }
}

static void tls_hash_drbg_reset(struct tls_hash_drbg_state *drbg)
{
    if (drbg != NULL)
        tls_secure_memzero(drbg, sizeof(*drbg));
}

static void tls_entropy_reserve_reset(void)
{
    g_tls_entropy_reserve_len = 0;
    g_tls_entropy_reserve_bits = 0;
    tls_secure_memzero(g_tls_entropy_reserve, sizeof(g_tls_entropy_reserve));
}

static void tls_drbg_reset(void)
{
    tls_hash_drbg_reset(&g_tls_drbg);
    tls_hash_drbg_reset(&g_tls_drbg_upgrade);
    tls_entropy_reserve_reset();
    g_tls_rng_epoch_changes = 0;
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
    struct tls_hash_context hctx = {0};
    if (!tls_hash_context_init(&hctx, TLS_HASH_SHA256))
    {
        tls_secure_memzero(&hctx, sizeof hctx);
        return false;
    }
    tls_hash_update(&hctx, in, in_len);
    tls_hash_digest(&hctx, out);
    tls_secure_memzero(&hctx, sizeof hctx);
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
        struct tls_hash_context ctx = {0};
        size_t take;

        if (!tls_hash_context_init(&ctx, TLS_HASH_SHA256))
        {
            tls_secure_memzero(&ctx, sizeof ctx);
            tls_secure_memzero(digest, sizeof digest);
            return false;
        }
        tls_hash_update(&ctx, header, sizeof(header));
        tls_hash_update(&ctx, input, input_len);
        tls_hash_digest(&ctx, digest);
        tls_secure_memzero(&ctx, sizeof ctx);

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
    /* Both operands are big-endian. Align the addend at the least-significant
     * end of V and discard final carry to compute modulo 2^440. */
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
    /* V/data is big-endian; discarding carry out of byte zero implements
     * addition modulo 2^440. */
    size_t i = TLS_HASH_DRBG_SEED_BYTES;
    while (i != 0u)
    {
        value[--i]++;
        if (value[i] != 0u)
            break;
    }
}

static bool tls_hash_drbg_make_c(struct tls_hash_drbg_state *drbg)
{
    uint8_t material[1u + TLS_HASH_DRBG_SEED_BYTES];
    material[0] = 0u;
    memcpy(material + 1u, drbg->v, sizeof(drbg->v));
    if (!tls_hash_df(material, sizeof(material), drbg->c))
    {
        tls_secure_memzero(material, sizeof(material));
        return false;
    }
    tls_secure_memzero(material, sizeof(material));
    return true;
}

static bool tls_hash_drbg_instantiate(
    struct tls_hash_drbg_state *drbg,
    const uint8_t *seed_material,
    size_t seed_material_len,
    uint16_t strength_bits)
{
    /* Personalization input is not supported, so the optional parameter is
     * omitted and seed_material consists only of entropy input and nonce.
     * Under SP 800-90A section 8.6.7 case (a), the nonce may be acquired from
     * the entropy source with the entropy input and treated as one extra-strong
     * entropy input. The 128-bit instance uses one conditioned 192-bit
     * contribution, exactly meeting that 3/2-strength requirement.
     * The 192-bit instance uses a fresh 192-bit entropy input followed by a
     * second fresh conditioned 192-bit contribution as nonce material (only
     * 96 bits are required). Seed material is never reused between instances. */
    if (drbg == NULL || seed_material == NULL ||
        (strength_bits != TLS_RNG_STRENGTH_128 &&
         strength_bits != TLS_RNG_STRENGTH_192))
        return false;
    tls_hash_drbg_reset(drbg);
    if (!tls_hash_df(seed_material, seed_material_len, drbg->v) ||
        !tls_hash_drbg_make_c(drbg))
    {
        tls_hash_drbg_reset(drbg);
        return false;
    }
    drbg->reseed_counter = 1u;
    drbg->strength_bits = strength_bits;
    drbg->seeded = true;
    return true;
}

static bool tls_hash_drbg_reseed(
    struct tls_hash_drbg_state *drbg,
    const uint8_t entropy[TLS_HASH_DRBG_ENTROPY_BYTES])
{
    uint8_t material[1u + TLS_HASH_DRBG_SEED_BYTES + TLS_HASH_DRBG_ENTROPY_BYTES];
    uint8_t new_v[TLS_HASH_DRBG_SEED_BYTES];

    /* Additional input is not supported, so seed material is 0x01 || V ||
     * entropy_input as permitted by SP 800-90A section 10.1.1.3. */
    if (drbg == NULL || entropy == NULL || !drbg->seeded)
        return false;
    material[0] = 1u;
    memcpy(material + 1u, drbg->v, sizeof(drbg->v));
    memcpy(material + 1u + sizeof(drbg->v), entropy,
           TLS_HASH_DRBG_ENTROPY_BYTES);
    if (!tls_hash_df(material, sizeof(material), new_v))
    {
        tls_secure_memzero(material, sizeof(material));
        tls_secure_memzero(new_v, sizeof(new_v));
        return false;
    }
    memcpy(drbg->v, new_v, sizeof(drbg->v));
    tls_secure_memzero(new_v, sizeof(new_v));
    tls_secure_memzero(material, sizeof(material));
    if (!tls_hash_drbg_make_c(drbg))
    {
        tls_hash_drbg_reset(drbg);
        return false;
    }
    drbg->reseed_counter = 1u;
    return true;
}

static bool tls_hash_drbg_hashgen(
    const struct tls_hash_drbg_state *drbg,
    uint8_t *out,
    size_t len)
{
    uint8_t data[TLS_HASH_DRBG_SEED_BYTES];
    uint8_t digest[TLS_SHA256_DIGEST_LEN];
    size_t produced = 0;

    memcpy(data, drbg->v, sizeof(data));
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

static bool tls_drbg_generate_bytes(
    struct tls_hash_drbg_state *drbg,
    uint8_t *out,
    size_t len)
{
    uint8_t material[1u + TLS_HASH_DRBG_SEED_BYTES];
    uint8_t h[TLS_SHA256_DIGEST_LEN];
    uint8_t counter_be[8];

    if (drbg == NULL || !drbg->seeded || out == NULL ||
        len > TLS_HASH_DRBG_MAX_REQUEST_BYTES ||
        drbg->reseed_counter > TLS_HASH_DRBG_RESEED_INTERVAL)
        return false;
    /* Generate-time additional input is not supported, so SP 800-90A
     * 10.1.1.4 step 2 is omitted and Hashgen uses the current V directly. */
    if (!tls_hash_drbg_hashgen(drbg, out, len))
        return false;

    material[0] = 3u;
    memcpy(material + 1u, drbg->v, sizeof(drbg->v));
    if (!tls_sha256_buf(material, sizeof(material), h))
        goto fail;
    tls_hash_drbg_add(drbg->v, h, sizeof(h));
    tls_hash_drbg_add(drbg->v, drbg->c, sizeof(drbg->c));
    tls_store_u64_be(drbg->reseed_counter, counter_be);
    tls_hash_drbg_add(drbg->v, counter_be, sizeof(counter_be));
    drbg->reseed_counter++;
    tls_secure_memzero(material, sizeof(material));
    tls_secure_memzero(h, sizeof(h));
    return true;

fail:
    tls_secure_memzero(material, sizeof(material));
    tls_secure_memzero(h, sizeof(h));
    return false;
}

/* Maximum consecutive gather steps discarded for a source-health epoch change
 * (g_tls_rng_epoch_changes) before failing. A health failure may trigger a
 * full source rescan (~3-4s on hardware); repeated failures with no clean
 * gather in between indicate no stable source exists. */
#define TLS_DRBG_GATHER_MAX_EPOCH_CHANGES 2u

static bool tls_rng_deadline_expired(void)
{
    return g_tls_rng_ready_deadline != 0u &&
           (int32_t)(sys_now() - g_tls_rng_ready_deadline) >= 0;
}

static void tls_rng_begin_initialization(tls_rng_failure_t reason)
{
    bool preserve_deadline =
        g_tls_rng_ready_deadline != 0u &&
        tls_rng_available_strength() == 0u &&
        (g_tls_rng_state == TLS_RNG_AWAITING_INIT ||
         g_tls_rng_state == TLS_RNG_DRBG_SEEDING);
    uint32_t deadline = g_tls_rng_ready_deadline;

    tls_drbg_reset();
    g_tls_rng_state = TLS_RNG_AWAITING_INIT;
    g_tls_rng_last_failure = 0;
    (void)reason;
    g_tls_rng_ready_deadline = preserve_deadline
                                   ? deadline
                                   : sys_now() + TLS_RNG_READY_TIMEOUT_MS;
}

static void tls_rng_fail(tls_rng_failure_t reason)
{
    tls_drbg_reset();
    g_tls_rng_state = TLS_RNG_FAILED;
    g_tls_rng_last_failure = reason;
    g_tls_rng_ready_deadline = 0;
    ERROR_CODE(reason);
}

/* Run one lifecycle step. Source selection is intentionally a blocking scan;
 * after that, each call performs at most one conditioned entropy gather. */
static bool tls_rng_drive_initialization(void);

static bool tls_drbg_entropy_gather_step(void)
{
    uint8_t entropy[TLS_HASH_DRBG_ENTROPY_STEP_BYTES];
    uint8_t health_epoch;
    uint8_t source_epoch;
    size_t target_bytes;
    uint16_t target_bits;
    size_t collect_len;
    uint16_t conditioned_bits;

    if (g_tls_rng_state != TLS_RNG_DRBG_SEEDING &&
        g_tls_rng_state != TLS_RNG_DRBG_READY_128 &&
        g_tls_rng_state != TLS_RNG_DRBG_READY_192)
        return false;

    /* A source disappearing after startup restarts the complete lifecycle;
     * no seed material from before the failure is reused. */
    health_epoch = tls_random_health_epoch();
    if (!tls_rng_healthcheck())
    {
        tls_rng_begin_initialization(TLS_RNG_FAILURE_SOURCE_INIT);
        return false;
    }
    if (health_epoch != tls_random_health_epoch())
    {
        /* Source selection changed before this gather. Keep an already
         * instantiated DRBG, but discard pending seed/reseed material. */
        DEBUG(); /* health epoch changed mid-gather -- discarding pending seed material */
        tls_entropy_reserve_reset();
    }

    target_bytes = tls_entropy_reserve_target_bytes();
    target_bits = tls_entropy_reserve_target_bits();

    if (g_tls_entropy_reserve_bits >= target_bits)
    {
        return true;
    }
    if (g_tls_entropy_reserve_len >= target_bytes)
    {
        ERROR_CODE(TLS_RNG_FAILURE_ACCOUNTING);
        return false;
    }

    collect_len = target_bytes - g_tls_entropy_reserve_len;
    if (collect_len > sizeof(entropy))
        collect_len = sizeof(entropy);

    source_epoch = tls_random_health_epoch();
    if (tls_entropy_collect(entropy, collect_len) == NULL)
    {
        tls_rng_log_health_failure();
        tls_rng_begin_initialization(TLS_RNG_FAILURE_COLLECTION);
        return false;
    }

    /* Never combine observations spanning a failed or replaced source.
     * If the epoch changed the asm layer already selected a new tap and
     * wiped its pool -- discard this step's bytes and let the caller loop
     * back to collect fresh entropy from the replacement source.
     * Bound retries: each health failure may cost a full rescan; reaching
     * TLS_DRBG_GATHER_MAX_EPOCH_CHANGES without a clean gather means no
     * stable source exists. (B3) */
    if (source_epoch != tls_random_health_epoch())
    {
        tls_rng_log_health_failure();
        tls_secure_memzero(entropy, sizeof(entropy));
        /* Discard material that may span two physical sources. An already
         * instantiated DRBG remains valid after a recovered source change. */
        tls_entropy_reserve_reset();
        g_tls_rng_epoch_changes++;
        if (g_tls_rng_epoch_changes >= TLS_DRBG_GATHER_MAX_EPOCH_CHANGES)
        {
            /* The first recovered source change is treated as intermittent.
             * A second change without a clean gather is persistent: notify
             * the consumer and cease output until an explicit restart. */
            tls_rng_fail(TLS_RNG_FAILURE_SOURCE_HEALTH);
            return false;
        }
        DEBUG(); /* source changed mid-gather -- retrying rather than abandoning */
        return true; /* silent retry — caller will gather again */
    }

    memcpy(g_tls_entropy_reserve + g_tls_entropy_reserve_len,
           entropy, collect_len);
    g_tls_entropy_reserve_len += collect_len;
    /* tls_entropy_collect() truncates SHA-256 to 192 bits. The raw source
     * supplies at least 256 accounted bits, leaving the configured 64-bit
     * full-entropy conditioning margin. */
    conditioned_bits = (uint16_t)(collect_len * 8u);
    g_tls_entropy_reserve_bits = (uint16_t)(
        g_tls_entropy_reserve_bits + conditioned_bits);
    g_tls_rng_epoch_changes = 0;
    tls_secure_memzero(entropy, sizeof(entropy));

    if (g_tls_rng_state == TLS_RNG_DRBG_SEEDING &&
        g_tls_entropy_reserve_bits >= TLS_HASH_DRBG_128_INSTANTIATE_TARGET_BITS)
    {
        if (!tls_hash_drbg_instantiate(&g_tls_drbg,
                                       g_tls_entropy_reserve,
                                       TLS_HASH_DRBG_128_INSTANTIATE_BYTES,
                                       TLS_RNG_STRENGTH_128))
        {
            tls_rng_fail(TLS_RNG_FAILURE_INSTANTIATE);
            return false;
        }
        INFO("rng seed drbg ok 128");
        tls_entropy_reserve_reset();
        g_tls_rng_state = TLS_RNG_DRBG_READY_128;
        g_tls_rng_ready_deadline = 0;
    }
    else if (g_tls_rng_state == TLS_RNG_DRBG_READY_128 &&
             g_tls_entropy_reserve_bits >= TLS_HASH_DRBG_192_INSTANTIATE_TARGET_BITS)
    {
        if (!tls_hash_drbg_instantiate(&g_tls_drbg_upgrade,
                                       g_tls_entropy_reserve,
                                       TLS_HASH_DRBG_192_INSTANTIATE_BYTES,
                                       TLS_RNG_STRENGTH_192))
        {
            tls_rng_fail(TLS_RNG_FAILURE_INSTANTIATE);
            return false;
        }
        INFO("rng seed drbg ok 192");
        tls_hash_drbg_reset(&g_tls_drbg);
        memcpy(&g_tls_drbg, &g_tls_drbg_upgrade, sizeof(g_tls_drbg));
        tls_hash_drbg_reset(&g_tls_drbg_upgrade);
        tls_entropy_reserve_reset();
        g_tls_rng_state = TLS_RNG_DRBG_READY_192;
    }
    return true;
}

static bool tls_drbg_apply_entropy_reserve(void)
{
    bool ok;
    if (g_tls_entropy_reserve_bits < TLS_HASH_DRBG_RESEED_TARGET_BITS)
    {
        return true;
    }
    if (g_tls_rng_state != TLS_RNG_DRBG_READY_192 ||
        !g_tls_drbg.seeded ||
        g_tls_entropy_reserve_len < TLS_HASH_DRBG_ENTROPY_BYTES)
    {
        ERROR_CODE(TLS_RNG_FAILURE_ACCOUNTING);
        return false;
    }
    ok = tls_hash_drbg_reseed(&g_tls_drbg, g_tls_entropy_reserve);
    tls_entropy_reserve_reset();
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
    /* The compatibility request API requires the maximum supported strength. */
    if (tls_rng_available_strength() < TLS_RNG_STRENGTH_192)
    {
        return false;
    }

    remain = g_tls_rng_request_len - g_tls_rng_request_collected;
    if (remain == 0)
    {
        return true;
    }
    if (g_tls_rng_state == TLS_RNG_DRBG_READY_192 &&
        !tls_drbg_apply_entropy_reserve())
        return false;
    take = remain;
    if (take > TLS_HASH_DRBG_MAX_REQUEST_BYTES)
        take = TLS_HASH_DRBG_MAX_REQUEST_BYTES;
    if (!tls_drbg_generate_bytes(&g_tls_drbg,
                                 g_tls_rng_request_out + g_tls_rng_request_collected,
                                 take))
    {
        tls_rng_fail(TLS_RNG_FAILURE_GENERATE);
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

/* Dispatcher entry: select the source, instantiate a 128-bit DRBG, then build
 * a separate 192-bit instance from entirely fresh material and promote it.
 * Each post-scan invocation performs no more than one conditioned gather. */
static void tls_rng_request_dispatch(void)
{
    bool done = false;
    bool gather_ok;
    bool source_step = false;
    tls_random_request_cb_t cb;
    void *cb_arg;

    if (tls_rng_available_strength() == 0u && tls_rng_deadline_expired())
    {
        tls_rng_fail(TLS_RNG_FAILURE_TIMEOUT);
    }
    else if (g_tls_rng_state == TLS_RNG_AWAITING_INIT)
    {
        source_step = true;
        (void)tls_rng_drive_initialization();
    }

    if (g_tls_rng_state == TLS_RNG_FAILED)
    {
        tls_rng_fail_pending_requests();
        lwip_dispatch_set_period(LWIP_DISPATCH_TLS_RNG_REQUEST, 0);
        g_tls_rng_entropy_timer_running = false;
        return;
    }

    if (g_tls_rng_request_active)
    {
        done = tls_rng_request_try_complete();
    }
    if (!done && !source_step && g_tls_rng_state != TLS_RNG_AWAITING_INIT &&
        (g_tls_rng_state == TLS_RNG_DRBG_SEEDING ||
         g_tls_rng_state == TLS_RNG_DRBG_READY_128 ||
         g_tls_rng_request_active ||
         (!g_tls_rng_external && g_tls_rng_state == TLS_RNG_DRBG_READY_192 &&
          g_tls_entropy_reserve_bits < TLS_HASH_DRBG_RESEED_TARGET_BITS)))
    {
        gather_ok = tls_drbg_entropy_gather_step();
        if (gather_ok && g_tls_rng_request_active)
        {
            done = tls_rng_request_try_complete();
        }
        else if (!gather_ok && g_tls_rng_state == TLS_RNG_FAILED)
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
        g_tls_rng_state == TLS_RNG_AWAITING_INIT ||
        g_tls_rng_state == TLS_RNG_DRBG_SEEDING ||
        g_tls_rng_state == TLS_RNG_DRBG_READY_128 ||
        (!g_tls_rng_external && g_tls_rng_state == TLS_RNG_DRBG_READY_192 &&
         g_tls_entropy_reserve_bits < TLS_HASH_DRBG_RESEED_TARGET_BITS))
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

static void tls_rng_timer_rearm(void)
{
    if (g_tls_rng_started && !g_tls_rng_entropy_timer_running)
    {
        g_tls_rng_entropy_timer_running = true;
        tls_rng_ensure_attached();
        lwip_dispatch_start();
        lwip_dispatch_set_period(LWIP_DISPATCH_TLS_RNG_REQUEST,
                                 lwip_dispatch_period_from_ms(TLS_RNG_REQUEST_INTERVAL_MS));
    }
}

static void tls_rng_timer_start(void)
{
    if (g_tls_rng_started)
    {
        return;
    }
    g_tls_rng_started = true;
    g_tls_rng_epoch_changes = 0;
    tls_rng_begin_initialization(0);

    tls_rng_ensure_attached();
    lwip_dispatch_start();
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
    tls_drbg_reset();
    g_tls_rng_state = TLS_RNG_STOPPED;
    g_tls_rng_last_failure = 0;
    g_tls_rng_ready_deadline = 0;
    lwip_dispatch_set_period(LWIP_DISPATCH_TLS_RNG_REQUEST, 0);
}
#endif

bool tls_rng_healthcheck(void)
{
    void *source = tls_random_debug_source_ptr();
    uint8_t mask = tls_random_debug_source_mask();

    if ((source != NULL) && (mask != 0u) && ((mask & (uint8_t)(mask - 1u)) == 0u))
    {
        return true;
    }
    /* Source not valid and re-selection is not retried on the async path —
     * tls_random_init_entropy() runs once at tls_init() time. */
    return false;
}

static bool tls_rng_drive_initialization(void)
{
    if (g_tls_rng_state == TLS_RNG_STOPPED)
        tls_rng_begin_initialization(0);
    if (g_tls_rng_state == TLS_RNG_FAILED)
    {
        return false;
    }
    if (tls_rng_available_strength() == 0u && tls_rng_deadline_expired())
    {
        tls_rng_fail(TLS_RNG_FAILURE_TIMEOUT);
        return false;
    }
    if (g_tls_rng_state == TLS_RNG_AWAITING_INIT)
    {
        if (!tls_rng_healthcheck())
        {
            if (tls_rng_deadline_expired())
            {
                tls_rng_fail(TLS_RNG_FAILURE_TIMEOUT);
            }
            return false;
        }
        g_tls_rng_state = TLS_RNG_DRBG_SEEDING;
        return true;
    }
    return tls_drbg_entropy_gather_step();
}

tls_rng_state_t tls_rng_status(void)
{
    return g_tls_rng_state;
}

uint16_t tls_rng_available_strength(void)
{
    if (!g_tls_drbg.seeded)
        return 0;
    return g_tls_drbg.strength_bits;
}

tls_rng_failure_t tls_rng_last_failure(void)
{
    return g_tls_rng_last_failure;
}

void *tls_random_bytes_ex(void *buffer, size_t len, uint16_t strength_bits)
{
    uint8_t *out = (uint8_t *)buffer;
    size_t requested_len = len;

    if (buffer == NULL)
        return NULL;
    if (len == 0u)
        return buffer;
    if (strength_bits != TLS_RNG_STRENGTH_128 &&
        strength_bits != TLS_RNG_STRENGTH_192)
    {
        DEBUG(); /* bad strength_bits argument -- caller bug, not an RNG state problem */
        goto fail;
    }
    if (g_tls_rng_request_active || (g_tls_rng_request_q_head != NULL))
    {
        ERROR_CODE(TLS_RNG_FAILURE_BUSY);
        goto fail;
    }

    /* The DRBG is driven exclusively by the async timer; fail immediately if
     * the required strength is not yet available rather than spin-blocking. */
    if (tls_rng_available_strength() < strength_bits)
    {
        goto fail;
    }
    if (g_tls_drbg.reseed_counter > TLS_HASH_DRBG_RESEED_INTERVAL)
    {
        /* Reseed entropy is gathered by the async timer. Fail fast if not ready;
         * the caller retries on the next tick once the reserve is full. */
        if (g_tls_rng_state != TLS_RNG_DRBG_READY_192 ||
            g_tls_entropy_reserve_bits < TLS_HASH_DRBG_RESEED_TARGET_BITS)
        {
            goto fail;
        }
    }
    if (g_tls_rng_state == TLS_RNG_DRBG_READY_192 &&
        !tls_drbg_apply_entropy_reserve())
        goto fail;

    while (len != 0u)
    {
        size_t take = len;
        if (take > TLS_HASH_DRBG_MAX_REQUEST_BYTES)
            take = TLS_HASH_DRBG_MAX_REQUEST_BYTES;
        if (!tls_drbg_generate_bytes(&g_tls_drbg, out, take))
        {
            ERROR_CODE(TLS_RNG_FAILURE_GENERATE);
            goto fail;
        }
        out += take;
        len -= take;
    }

#if LWIP_TIMERS
    if (g_tls_rng_started && !g_tls_rng_entropy_timer_running && !g_tls_rng_external &&
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

void *tls_random_bytes(void *buffer, size_t len)
{
    return tls_random_bytes_ex(buffer, len, TLS_RNG_STRENGTH_192);
}

void *tls_random_bytes_pr(void *buffer, size_t len, uint16_t strength_bits)
{
    if (buffer == NULL)
        return NULL;
    if (len == 0u)
        return buffer;
    /* Prediction resistance applies to one Generate request. Do not turn one
     * reseed into multiple requests when the caller exceeds the DRBG limit. */
    if (len > TLS_HASH_DRBG_MAX_REQUEST_BYTES)
    {
        DEBUG();
        tls_secure_memzero(buffer, len);
        return NULL;
    }
    if (strength_bits != TLS_RNG_STRENGTH_128 &&
        strength_bits != TLS_RNG_STRENGTH_192)
    {
        DEBUG();
        tls_secure_memzero(buffer, len);
        return NULL;
    }
    /* SP 800-90A §9.3.1 prediction resistance: force an immediate reseed from
     * the entropy reserve before generating. Fail if the reserve is not ready
     * — never produce output from a state that has not been freshly reseeded
     * on this call. */
    if (g_tls_rng_state != TLS_RNG_DRBG_READY_192 ||
        g_tls_entropy_reserve_bits < TLS_HASH_DRBG_RESEED_TARGET_BITS)
    {
        tls_secure_memzero(buffer, len);
        return NULL;
    }
    if (!tls_drbg_apply_entropy_reserve())
    {
        tls_secure_memzero(buffer, len);
        return NULL;
    }
    return tls_random_bytes_ex(buffer, len, strength_bits);
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
    if (blocking)
    {
        uint32_t request_deadline = sys_now() + TLS_RNG_READY_TIMEOUT_MS;

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
            if ((int32_t)(sys_now() - request_deadline) >= 0)
            {
                tls_rng_fail(TLS_RNG_FAILURE_TIMEOUT);
                if (cb != NULL)
                    cb(false, arg);
                tls_rng_request_reset_state();
                return false;
            }
            done = tls_rng_request_try_complete();
            if (done)
            {
                continue;
            }
            if (!tls_rng_drive_initialization() &&
                g_tls_rng_state == TLS_RNG_FAILED)
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

bool tls_random_add_entropy(const uint8_t *data, size_t len)
{
    if (data == NULL)
        return false;
    if (len == TLS_HASH_DRBG_192_INSTANTIATE_BYTES)
    {
        uint8_t material[TLS_HASH_DRBG_192_INSTANTIATE_BYTES + TLS_HASH_DRBG_ENTROPY_BYTES];
        bool ok;

        if (!g_tls_drbg.seeded)
            return false;
        memcpy(material, data, len);
        ok = tls_drbg_generate_bytes(&g_tls_drbg, material + len, TLS_HASH_DRBG_ENTROPY_BYTES) &&
             tls_hash_drbg_instantiate(&g_tls_drbg_upgrade, material, sizeof(material),
                                       TLS_RNG_STRENGTH_192);
        tls_secure_memzero(material, sizeof(material));
        if (!ok)
        {
            tls_hash_drbg_reset(&g_tls_drbg_upgrade);
            return false;
        }
        memcpy(&g_tls_drbg, &g_tls_drbg_upgrade, sizeof(g_tls_drbg));
        tls_hash_drbg_reset(&g_tls_drbg_upgrade);
        tls_entropy_reserve_reset();
        g_tls_rng_state = TLS_RNG_DRBG_READY_192;
        g_tls_rng_ready_deadline = 0;
        return true;
    }
    return len == TLS_HASH_DRBG_ENTROPY_BYTES && tls_hash_drbg_reseed(&g_tls_drbg, data);
}

void tls_random_set_external(bool external)
{
    g_tls_rng_external = external;
#if LWIP_TIMERS
    if (!external)
        tls_rng_timer_rearm();
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
    uint8_t lag_history[TLS_RNG_STATS_LAG_COUNT];
    uint8_t lag_history_count = 0u;
    uint8_t lag_history_next = 0u;
    uint8_t previous = 0;
    uint8_t window_history[TLS_RNG_STATS_LAG_COUNT];
    uint8_t window_history_count = 0u;
    uint8_t window_history_next = 0u;
    uint8_t distribution_pair_first = 0u;
    uint32_t current_run = 0;
    uint32_t apt_position = 0u;
    uint32_t apt_ones = 0u;
    uint32_t window_lag_mismatches[TLS_RNG_STATS_LAG_COUNT] = {0u};
    uint32_t distribution_position = 0u;
    uint32_t distribution_ones = 0u;
    uint32_t distribution_disagreements = 0u;
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
    stats->health_tests_evaluated = TLS_RNG_HEALTH_RCT_PASS;
    stats->health_tests_passed = TLS_RNG_HEALTH_ALL_PASS;
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
            uint8_t lag;

            if (bit != 0u)
            {
                stats->ones++;
            }

            for (lag = 1u; lag <= lag_history_count; lag++)
            {
                uint8_t history_index =
                    (uint8_t)(lag_history_next + TLS_RNG_STATS_LAG_COUNT - lag);
                if (history_index >= TLS_RNG_STATS_LAG_COUNT)
                {
                    history_index -= TLS_RNG_STATS_LAG_COUNT;
                }
                if (bit != lag_history[history_index])
                {
                    stats->lag_mismatches[lag - 1u]++;
                }
            }
            lag_history[lag_history_next] = bit;
            lag_history_next++;
            if (lag_history_next == TLS_RNG_STATS_LAG_COUNT)
            {
                lag_history_next = 0u;
            }
            if (lag_history_count < TLS_RNG_STATS_LAG_COUNT)
            {
                lag_history_count++;
            }

            for (lag = 1u; lag <= window_history_count; lag++)
            {
                uint8_t history_index = (uint8_t)(
                    window_history_next + TLS_RNG_STATS_LAG_COUNT - lag);
                if (history_index >= TLS_RNG_STATS_LAG_COUNT)
                {
                    history_index -= TLS_RNG_STATS_LAG_COUNT;
                }
                if (bit != window_history[history_index])
                {
                    window_lag_mismatches[lag - 1u]++;
                }
            }
            window_history[window_history_next] = bit;
            window_history_next++;
            if (window_history_next == TLS_RNG_STATS_LAG_COUNT)
            {
                window_history_next = 0u;
            }
            if (window_history_count < TLS_RNG_STATS_LAG_COUNT)
            {
                window_history_count++;
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
            if (current_run == TLS_RNG_STATS_RCT_CUTOFF)
            {
                stats->rct_failure_runs++;
            }

            apt_ones += bit;
            apt_position++;
            if (apt_position == TLS_RNG_STATS_APT_WINDOW)
            {
                uint32_t apt_zeros = TLS_RNG_STATS_APT_WINDOW - apt_ones;
                static const uint16_t lag_min[TLS_RNG_STATS_LAG_COUNT] =
                    {TLS_RNG_STATS_LAG1_MISMATCH_MIN,
                     TLS_RNG_STATS_LAG2_MISMATCH_MIN,
                     TLS_RNG_STATS_LAG3_MISMATCH_MIN,
                     TLS_RNG_STATS_LAG4_MISMATCH_MIN};
                static const uint16_t lag_max[TLS_RNG_STATS_LAG_COUNT] =
                    {TLS_RNG_STATS_LAG1_MISMATCH_MAX,
                     TLS_RNG_STATS_LAG2_MISMATCH_MAX,
                     TLS_RNG_STATS_LAG3_MISMATCH_MAX,
                     TLS_RNG_STATS_LAG4_MISMATCH_MAX};

                if ((stats->apt_windows == 0u) ||
                    (apt_ones < stats->apt_min_ones))
                {
                    stats->apt_min_ones = apt_ones;
                }
                if (apt_ones > stats->apt_max_ones)
                {
                    stats->apt_max_ones = apt_ones;
                }
                stats->apt_windows++;
                if ((apt_ones >= TLS_RNG_STATS_APT_CUTOFF) ||
                    (apt_zeros >= TLS_RNG_STATS_APT_CUTOFF))
                {
                    stats->apt_failures++;
                }
                if ((apt_ones < TLS_RNG_STATS_STARTUP_ONES_MIN) ||
                    (apt_ones > TLS_RNG_STATS_STARTUP_ONES_MAX))
                {
                    stats->startup_marginal_failures++;
                }
                for (lag = 0u; lag < TLS_RNG_STATS_LAG_COUNT; lag++)
                {
                    uint32_t mismatches = window_lag_mismatches[lag];
                    if ((stats->apt_windows == 1u) ||
                        (mismatches < stats->lag_window_min_mismatches[lag]))
                    {
                        stats->lag_window_min_mismatches[lag] = mismatches;
                    }
                    if (mismatches > stats->lag_window_max_mismatches[lag])
                    {
                        stats->lag_window_max_mismatches[lag] = mismatches;
                    }
                    if ((mismatches < lag_min[lag]) ||
                        (mismatches > lag_max[lag]))
                    {
                        stats->lag_window_failures[lag]++;
                    }
                    window_lag_mismatches[lag] = 0u;
                }
                apt_position = 0u;
                apt_ones = 0u;
                window_history_count = 0u;
                window_history_next = 0u;
            }

            distribution_ones += bit;
            if ((distribution_position & 1u) == 0u)
            {
                distribution_pair_first = bit;
            }
            else if (bit != distribution_pair_first)
            {
                distribution_disagreements++;
            }
            distribution_position++;
            if (distribution_position == TLS_RNG_STATS_DISTRIBUTION_WINDOW)
            {
                if ((stats->distribution_windows == 0u) ||
                    (distribution_ones < stats->distribution_min_ones))
                {
                    stats->distribution_min_ones = distribution_ones;
                }
                if (distribution_ones > stats->distribution_max_ones)
                {
                    stats->distribution_max_ones = distribution_ones;
                }
                if ((stats->distribution_windows == 0u) ||
                    (distribution_disagreements <
                     stats->distribution_min_disagreements))
                {
                    stats->distribution_min_disagreements =
                        distribution_disagreements;
                }
                if (distribution_disagreements >
                    stats->distribution_max_disagreements)
                {
                    stats->distribution_max_disagreements =
                        distribution_disagreements;
                }
                stats->distribution_windows++;
                if ((distribution_ones <
                     TLS_RNG_STATS_DISTRIBUTION_ONES_MIN) ||
                    (distribution_ones >
                     TLS_RNG_STATS_DISTRIBUTION_ONES_MAX) ||
                    (distribution_disagreements <
                     TLS_RNG_STATS_DISTRIBUTION_DISAGREEMENTS_MIN) ||
                    (distribution_disagreements >
                     TLS_RNG_STATS_DISTRIBUTION_DISAGREEMENTS_MAX))
                {
                    stats->distribution_failures++;
                }
                distribution_position = 0u;
                distribution_ones = 0u;
                distribution_disagreements = 0u;
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

    if (stats->rct_failure_runs != 0u)
    {
        stats->health_tests_passed &= (uint8_t)~TLS_RNG_HEALTH_RCT_PASS;
    }
    if (stats->apt_windows != 0u)
    {
        uint8_t lag;
        stats->health_tests_evaluated |=
            TLS_RNG_HEALTH_APT_PASS | TLS_RNG_HEALTH_LAG1_PASS |
            TLS_RNG_HEALTH_LAG2_PASS | TLS_RNG_HEALTH_LAG3_PASS |
            TLS_RNG_HEALTH_LAG4_PASS;
        if (stats->apt_failures != 0u)
        {
            stats->health_tests_passed &= (uint8_t)~TLS_RNG_HEALTH_APT_PASS;
        }
        for (lag = 0u; lag < TLS_RNG_STATS_LAG_COUNT; lag++)
        {
            if (stats->lag_window_failures[lag] != 0u)
            {
                stats->health_tests_passed &= (uint8_t)~(1u << (lag + 2u));
            }
        }
    }
    if ((stats->apt_windows != 0u) &&
        (stats->distribution_windows != 0u))
    {
        stats->health_tests_evaluated |= TLS_RNG_HEALTH_DISTRIBUTION_PASS;
        if ((stats->startup_marginal_failures != 0u) ||
            (stats->distribution_failures != 0u))
        {
            stats->health_tests_passed &=
                (uint8_t)~TLS_RNG_HEALTH_DISTRIBUTION_PASS;
        }
    }
    stats->health_tests_passed &= stats->health_tests_evaluated;

    return true;
}

void tls_rng_start(void)
{
#if LWIP_TIMERS
    tls_rng_timer_start();
#else
    tls_rng_begin_initialization(0);
#endif
}

void tls_rng_cleanup(void)
{
    g_tls_rng_external = false;
#if LWIP_TIMERS
    tls_rng_timer_stop();
#endif
    tls_rng_request_reset_state();
    tls_rng_request_q_clear();
}
