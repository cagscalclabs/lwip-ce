#ifndef LWIP_CC_H
#define LWIP_CC_H

#undef NDEBUG
#include <string.h>
#include <sys/lcd.h>
#include <debug.h>
#include <graphx.h>

#define LITTLE_ENDIAN 1234

#define LWIP_PLATFORM_DIAG(x) \
  do {                        \
  } while (0)

#define LWIP_PLATFORM_ASSERT(x) \
  do {                          \
  } while (0)

#endif // LWIP_CC_H

#define BYTE_ORDER LITTLE_ENDIAN
