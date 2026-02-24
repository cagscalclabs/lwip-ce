#ifndef TLS_KEYOBJECT_INTERNAL_H
#define TLS_KEYOBJECT_INTERNAL_H

#include <stddef.h>

void *tls_keyobject_alloc(size_t size);
void tls_keyobject_free(void *ptr);

#endif
