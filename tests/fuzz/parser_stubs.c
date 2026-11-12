/* Host fuzz build: the parsers allocate scratch through lwIP's heap. */
#include <stdlib.h>
#include "lwip/mem.h"

void *mem_malloc(mem_size_t size) { return malloc(size); }
void mem_free(void *mem) { free(mem); }
