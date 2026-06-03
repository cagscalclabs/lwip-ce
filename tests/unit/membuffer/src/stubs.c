#include <stddef.h>
#include <string.h>

void tls_secure_memzero(void *ptr, size_t len)
{
    if (ptr)
    {
        memset(ptr, 0, len);
    }
}
