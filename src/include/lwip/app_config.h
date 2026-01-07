#ifndef LWIP_APP_CONFIG_H
#define LWIP_APP_CONFIG_H

#include <stdint.h>

#define LWIP_CFG_VAR_NAME "lwIPCFG"
#define LWIP_CFG_VERSION 1u

#define LWIP_CFG_FLAG_TLS        (1u << 0)
#define LWIP_CFG_FLAG_NTP        (1u << 1)
#define LWIP_CFG_FLAG_DNS        (1u << 2)
#define LWIP_CFG_FLAG_HTTP_TEST  (1u << 3)

#define LWIP_CFG_DEFAULT_FLAGS (LWIP_CFG_FLAG_TLS | LWIP_CFG_FLAG_DNS)
#define LWIP_CFG_DEFAULT_MAX_HEAP (20u * 1024u)

#define LWIP_CFG_HEAP_STEP 1024u
#define LWIP_CFG_HEAP_MIN 4096u
#define LWIP_CFG_HEAP_MAX (48u * 1024u)

struct lwip_app_config
{
    uint16_t version;
    uint16_t flags;
    uint32_t max_heap;
};

#endif
