#ifndef LWIP_APP_CONFIG_H
#define LWIP_APP_CONFIG_H

#include <stdbool.h>
#include <stdint.h>

#define LWIP_CFG_APPVAR "lwIPCFG"
#define LWIP_CFG_VERSION 2u

#define LWIP_CFG_ENABLE_TLS        (1u << 0)
#define LWIP_CFG_AUTO_NTP          (1u << 2)
#define LWIP_CFG_DHCP              (1u << 3)
#define LWIP_CFG_TEST_HTTP         (1u << 4)
#define LWIP_CFG_CERT_CHECK_DATES  (1u << 5)
#define LWIP_CFG_CERT_CHECK_OWNER  (1u << 6)

typedef struct lwip_app_config {
    uint16_t version;
    uint16_t max_heap_bytes;
    uint8_t flags;
    uint8_t reserved;
    int16_t tz_offset_minutes;
    uint8_t dst_enabled;
    uint8_t reserved2;
    uint8_t ip_addr[4];
    uint8_t ip_gateway[4];
    uint8_t ip_netmask[4];
} lwip_app_config_t;

void lwip_app_config_defaults(lwip_app_config_t *cfg);
bool lwip_app_config_load(lwip_app_config_t *cfg);
bool lwip_app_config_save(const lwip_app_config_t *cfg);
const lwip_app_config_t *lwip_app_config_get(void);
bool lwip_app_config_refresh(void);

#endif
