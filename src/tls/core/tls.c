#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "lwip/opt.h"
#include "lwip/mem.h"
#include "lwip/timeouts.h"
#include "../includes/tls.h"
#include "../includes/rsa.h"
#include "../includes/random.h"
#include "../../drivers/mem.h"

/**
 * TLS Memory Module
 *
 * This module manages static memory allocation for TLS cryptographic operations.
 * All memory is allocated through lwIP's general memory pool (mem_malloc/mem_free).
 *
 * Users must configure MEM_SIZE in lwipopts.h to account for TLS memory requirements:
 * - Base lwIP: ~8-16KB (depends on configuration)
 * - TLS addition: ~2KB
 * - Recommended MEM_SIZE: 20KB or more when using TLS
 *
 * Memory Budget:
 * - RSA scratch buffer: 1KB (for OAEP/PSS with up to 4096-bit keys)
 * - ECC scratch buffer: 1KB (reserved for future X25519 operations)
 * - Total TLS overhead: ~2KB
 */

/* RSA scratch buffer sizing for 4096-bit (512 byte) modulus:
 * For OAEP decode: 1024 bytes (mgf1_digest[512] + tmp[512])
 * For PSS verify:  ~600 bytes (db_len[479] + tmp[72])
 * Use the larger requirement: 1024 bytes
 */
#define RSA_SCRATCH_SIZE (RSA_MODULUS_MAX_SUPPORTED * 2)

/* ECC scratch buffer (reserved for future X25519 operations) */
#define ECC_SCRATCH_SIZE 1024
#define TLS_FILEIO_MAX_SIZE (32u * 1024u)
#define TLS_RNG_HEALTHCHECK_INTERVAL_MS 30000u
#define TLS_RNG_HEALTHCHECK_FAIL_THRESHOLD 3u
#define TLS_RNG_HEALTHCHECK_SAMPLE_BYTES 32u
#define TLS_RNG_HEALTHCHECK_MIN_ONES 88u
#define TLS_RNG_HEALTHCHECK_MAX_ONES 168u
#define TLS_RNG_HEALTHCHECK_MAX_EQUAL_RUN 4u

/* Global TLS context (non-static so RSA/ECC code can access scratch buffers) */
struct tls_context tls_ctx = {
    .rsa_scratch = NULL,
    .ecc_scratch = NULL,
    .initialized = false,
    .truststore = {
        .status = TLS_STORE_NOT_FOUND,
        .size = 0,
        .entry_count = 0,
        .version = 0,
        .created_timestamp = 0}};

static struct mem_buffer *g_tls_fileio_buffer = NULL;
static bool g_tls_rng_health_timer_running = false;
static bool g_tls_rng_health_ready = false;
static uint8_t g_tls_rng_health_failures = 0;
static bool g_tls_rng_prev_sample_valid = false;
static uint8_t g_tls_rng_prev_sample[TLS_RNG_HEALTHCHECK_SAMPLE_BYTES];

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
    g_tls_rng_health_timer_running = true;
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
    sys_untimeout(tls_rng_healthcheck_timer, NULL);
}
#endif

bool tls_rng_healthcheck(void)
{
    return tls_rng_healthcheck_run_once();
}

static bool tls_fileio_buffer_ensure(void)
{
    if (g_tls_fileio_buffer != NULL)
    {
        return true;
    }

    g_tls_fileio_buffer = mem_buffer_create(MEM_BUFFER_FILE, 0, TLS_FILEIO_MAX_SIZE, 0, BUFFER_SECURE_MODE);
    return g_tls_fileio_buffer != NULL;
}

bool tls_init(void)
{
    /* Check if already initialized */
    if (tls_ctx.initialized)
    {
        return true;
    }

    /* Allocate RSA scratch buffer */
    tls_ctx.rsa_scratch = (uint8_t *)mem_malloc(RSA_SCRATCH_SIZE);
    if (tls_ctx.rsa_scratch == NULL)
    {
        tls_cleanup(); /* Clean up any partial allocations */
        return false;
    }

    /* Allocate ECC scratch buffer (reserved for future use) */
    tls_ctx.ecc_scratch = (uint8_t *)mem_malloc(ECC_SCRATCH_SIZE);
    if (tls_ctx.ecc_scratch == NULL)
    {
        tls_cleanup(); /* Clean up any partial allocations */
        return false;
    }

    tls_ctx.initialized = true;
#if LWIP_TIMERS
    tls_rng_healthcheck_start();
#endif
    return true;
}

void tls_cleanup(void)
{
#if LWIP_TIMERS
    tls_rng_healthcheck_stop();
#endif
    if (g_tls_fileio_buffer != NULL)
    {
        mem_buffer_destroy(g_tls_fileio_buffer);
        g_tls_fileio_buffer = NULL;
    }

    if (tls_ctx.rsa_scratch != NULL)
    {
        mem_free(tls_ctx.rsa_scratch);
        tls_ctx.rsa_scratch = NULL;
    }

    if (tls_ctx.ecc_scratch != NULL)
    {
        mem_free(tls_ctx.ecc_scratch);
        tls_ctx.ecc_scratch = NULL;
    }

    tls_ctx.initialized = false;
    tls_ctx.truststore.status = TLS_STORE_NOT_FOUND;
    tls_ctx.truststore.size = 0;
    tls_ctx.truststore.entry_count = 0;
    tls_ctx.truststore.version = 0;
    tls_ctx.truststore.created_timestamp = 0;
}

void *tls_fileio_alloc(size_t size)
{
    if (size == 0)
    {
        return NULL;
    }
    if (!tls_fileio_buffer_ensure())
    {
        return NULL;
    }
    return mem_buffer_malloc(g_tls_fileio_buffer, size);
}

void tls_fileio_free(void *ptr)
{
    if (!ptr || g_tls_fileio_buffer == NULL)
    {
        return;
    }
    mem_buffer_free(g_tls_fileio_buffer, ptr);
}
