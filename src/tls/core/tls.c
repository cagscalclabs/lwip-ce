#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "lwip/opt.h"
#include "../includes/tls.h"
#include "../includes/rsa.h"
#include "../includes/random.h"
#include "../../drivers/mem.h"

/* Temporary tls_init step tracing — prints a tag to the home screen and
 * waits for a key, so on hardware the last tag before a crash localizes
 * which init step faults. Set TLS_INIT_TRACE 0 to disable. */
#define TLS_INIT_TRACE 0
#if TLS_INIT_TRACE
#include <ti/screen.h>
#include <ti/getkey.h>
#define TLS_INIT_TRACE_STEP(msg) do { os_ClrHome(); os_PutStrFull("tls_init: " msg); \
                                      os_PutStrFull(" [key]"); os_GetKey(); } while (0)
#else
#define TLS_INIT_TRACE_STEP(msg) ((void)0)
#endif

/**
 * TLS Memory Module
 *
 * This module manages static memory allocation for TLS cryptographic operations.
 * All memory is allocated through unified allocator entry points from drivers/mem.
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
    TLS_INIT_TRACE_STEP("A enter");
    /* Check if already initialized */
    if (tls_ctx.initialized)
    {
        return true;
    }

    TLS_INIT_TRACE_STEP("B rsa scratch");
    /* Allocate RSA scratch buffer via unified allocator backend */
    tls_ctx.rsa_scratch = (uint8_t *)mem_buffer_custom_malloc(RSA_SCRATCH_SIZE);
    if (tls_ctx.rsa_scratch == NULL)
    {
        tls_cleanup(); /* Clean up any partial allocations */
        return false;
    }

    TLS_INIT_TRACE_STEP("C ecc scratch");
    /* Allocate ECC scratch buffer (reserved for future use) via unified allocator */
    tls_ctx.ecc_scratch = (uint8_t *)mem_buffer_custom_malloc(ECC_SCRATCH_SIZE);
    if (tls_ctx.ecc_scratch == NULL)
    {
        tls_cleanup(); /* Clean up any partial allocations */
        return false;
    }

    tls_ctx.initialized = true;
    TLS_INIT_TRACE_STEP("D rng start");
    tls_rng_start();

    /* Load and verify the SPKI trust store now that the RSA scratch exists
     * (tls_truststore_init verifies the store's own RSA-PSS signature, so
     * it must run after the scratch allocation above). A missing or invalid
     * store is NOT a bring-up failure: crypto context is up either way, and
     * certificate verification fail-closes later (tls_truststore_lookup
     * returns false unless the store validated). We record the status so
     * the handshake can surface it. */
    TLS_INIT_TRACE_STEP("E truststore");
    tls_ctx.truststore.status = tls_truststore_init();

    TLS_INIT_TRACE_STEP("F done");
    return true;
}

void tls_cleanup(void)
{
    tls_rng_cleanup();
    tls_rsa_padding_cleanup();

    if (g_tls_fileio_buffer != NULL)
    {
        mem_buffer_destroy(g_tls_fileio_buffer);
        g_tls_fileio_buffer = NULL;
    }

    if (tls_ctx.rsa_scratch != NULL)
    {
        mem_buffer_custom_free(tls_ctx.rsa_scratch);
        tls_ctx.rsa_scratch = NULL;
    }

    if (tls_ctx.ecc_scratch != NULL)
    {
        mem_buffer_custom_free(tls_ctx.ecc_scratch);
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
