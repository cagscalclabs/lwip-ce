#include "lwip/init.h"

#include <stddef.h>
#include <stdint.h>

extern uint8_t __low_bss;
extern uint8_t __len_bss;
extern uint8_t __init_array_count;
extern uint8_t __ctors_count;

extern void (*init_array[])(void) __asm__("init_array");
extern void (*ctors[])(void) __asm__("ctors");

void lwip_init_runtime(void) {
  uint8_t *bss = &__low_bss;
  size_t bss_len = (size_t)(uintptr_t)&__len_bss;
  size_t init_count = (size_t)(uintptr_t)&__init_array_count;
  size_t ctor_count = (size_t)(uintptr_t)&__ctors_count;

  for (size_t i = 0; i < bss_len; i++) {
    bss[i] = 0;
  }

  for (size_t i = 0; i < init_count; i++) {
    if (init_array[i]) {
      init_array[i]();
    }
  }

  for (size_t i = 0; i < ctor_count; i++) {
    if (ctors[i]) {
      ctors[i]();
    }
  }
}
