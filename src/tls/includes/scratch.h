#ifndef TLS_SCRATCH_H
#define TLS_SCRATCH_H

#include <stddef.h>
#include <stdint.h>
#include "bytes.h"
#include "../../drivers/mem.h"

struct tls_hash_context;

/* Heap-allocates and initialises a hash context; NULL on failure. */
struct tls_hash_context *tls_hash_context_alloc(uint8_t algorithm);
/* Wipes and frees a context from tls_hash_context_alloc; NULL is a no-op. */
void tls_hash_context_free(struct tls_hash_context *ctx);

/* Short-lived TLS working buffers live on the lwIP heap, not the eZ80 stack.
 * The crypto guard only scrubs dead stack, so anything that held key material
 * must be wiped here before it goes back to the allocator. */
static inline void *tls_scratch_alloc(size_t len)
{
    return mem_buffer_custom_malloc(len);
}

static inline void tls_scratch_free(void *ptr, size_t len)
{
    if (ptr)
    {
        tls_secure_memzero(ptr, len);
        mem_buffer_custom_free(ptr);
    }
}

#endif
