#ifndef LWIP_APP_CONFIG_H
#define LWIP_APP_CONFIG_H

#include <stdbool.h>
#include <stdint.h>

#include "lwip/logging.h"

#define LWIP_CFG_APPVAR "lwIPCFG"

#define LWIP_CFG_HOSTNAME_MAX 16

#define LWIP_CFG_PCAP_SIZE_4K   (4u * 1024u)
#define LWIP_CFG_PCAP_SIZE_8K   (8u * 1024u)
#define LWIP_CFG_PCAP_SIZE_16K (16u * 1024u)
#define LWIP_CFG_PCAP_SIZE_32K (32u * 1024u)
#define LWIP_CFG_PCAP_SIZE_DEFAULT LWIP_CFG_PCAP_SIZE_4K

#define LWIP_CFG_DNS                  (1u << 0) /* legacy config bit */
#define LWIP_CFG_LOG_USB              (1u << 1) /* legacy config bit */
#define LWIP_CFG_AUTO_NTP             (1u << 2) /* legacy config bit */
#define LWIP_CFG_DHCP                 (1u << 3) /* legacy config bit */
#define LWIP_CFG_TEST_HTTP            (1u << 4)
/* Legacy TLS chain trust bit. The runtime policy is no longer user
 * configurable from the app wizard; CertificateVerify still runs for the
 * live leaf signature. */
#define LWIP_CFG_FULL_CHAIN_VERIFY    (1u << 5)
#define LWIP_CFG_LOG_TLS              (1u << 7) /* legacy config bit */

/* Legacy runtime fields retained for source compatibility. They are no longer
 * serialized into the settings AppVar. */
#define LWIP_TLS_FLOOR_BYTES        (24u * 1024u)
#define LWIP_MIN_FLOOR_BYTES        LWIP_TLS_FLOOR_BYTES
#define LWIP_CFG_MEM_CAP_DEF        (0xFFFFu)   /* uncapped: os_MemChk provides the real limit at init */
#define LWIP_CFG_MEM_CAP_STEP       1024u
/* Vestigial log-config fields. The appvar-backed log system was replaced by
 * the unified event callback (lwip_set_event_cb). */
#define LWIP_CFG_LOG_ENABLED_DEF    1u
#define LWIP_CFG_LOG_LEVEL_DEF      3u   /* was LWIP_LOG_LEVEL_ERROR */
#define LWIP_CFG_LOG_LEVEL_MIN      1u
#define LWIP_CFG_LOG_LEVEL_MAX      4u

typedef struct lwip_app_config {
    uint16_t lwip_mem_cap;
    uint8_t flags;
    uint8_t log_enabled;
    int16_t tz_offset_minutes;
    uint8_t dst_enabled;
    uint8_t log_min_level;
    /* Deprecated alias retained for source compatibility. */
    union {
        uint16_t pcap_max_bytes;
        uint16_t log_size_bytes; /* Deprecated alias. */
    };
    char hostname[LWIP_CFG_HOSTNAME_MAX];
    uint8_t tls_enabled;
} lwip_app_config_t;

void lwip_app_config_defaults(lwip_app_config_t *cfg);
bool lwip_app_config_load(lwip_app_config_t *cfg);
bool lwip_app_config_save(const lwip_app_config_t *cfg);
const lwip_app_config_t *lwip_app_config_get(void);
bool lwip_app_config_refresh(void);

#endif
