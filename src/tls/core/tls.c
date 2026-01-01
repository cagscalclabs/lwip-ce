#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "lwip/mem.h"
#include "../includes/tls.h"
#include "../includes/rsa.h"

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
 * - ECC scratch buffer: 1KB (reserved for future P-256/X25519 operations)
 * - Total TLS overhead: ~2KB
 */

/* RSA scratch buffer sizing for 4096-bit (512 byte) modulus:
 * For OAEP decode: 1024 bytes (mgf1_digest[512] + tmp[512])
 * For PSS verify:  ~600 bytes (db_len[479] + tmp[72])
 * Use the larger requirement: 1024 bytes
 */
#define RSA_SCRATCH_SIZE (RSA_MODULUS_MAX_SUPPORTED * 2)

/* ECC scratch buffer (reserved for future P-256/X25519 operations) */
#define ECC_SCRATCH_SIZE 1024

/* TLS context structure */
struct tls_context
{
    uint8_t *rsa_scratch; /* RSA operations scratch buffer */
    uint8_t *ecc_scratch; /* ECC operations scratch buffer (future) */
    bool initialized;     /* Initialization flag */
};

/* Global TLS context (non-static so RSA/ECC code can access scratch buffers) */
struct tls_context tls_ctx = {
    .rsa_scratch = NULL,
    .ecc_scratch = NULL,
    .initialized = false};

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
    return true;
}

void tls_cleanup(void)
{
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
}
