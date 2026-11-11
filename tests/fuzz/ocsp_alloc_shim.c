#include <stddef.h>
#include <stdlib.h>

/* ocsp.c is a separate translation unit in the TLS fuzz target.  The
 * generated harness keeps its allocator mocks static, so expose matching
 * process-heap shims for OCSP's external allocator contract. */
void *tls_fileio_alloc(size_t size)
{
    return malloc(size);
}

void tls_fileio_free(void *ptr)
{
    free(ptr);
}
