#ifndef LWIP_APP_CONFIG_H
#define LWIP_APP_CONFIG_H

#include <stdbool.h>
#include <stdint.h>

#define LWIP_CFG_APPVAR "lwIPCFG"
#define LWIP_CFG_VERSION 2u

#define LWIP_CFG_HOSTNAME_MAX 16

#define LWIP_CFG_ENABLE_TLS        (1u << 0)
#define LWIP_CFG_LOG_USB           (1u << 1)
#define LWIP_CFG_AUTO_NTP          (1u << 2)
#define LWIP_CFG_DHCP              (1u << 3)
#define LWIP_CFG_TEST_HTTP         (1u << 4)
#define LWIP_CFG_CERT_CHECK_DATES  (1u << 5)
#define LWIP_CFG_CERT_CHECK_OWNER  (1u << 6)
#define LWIP_CFG_LOG_TLS           (1u << 7)

/* Memory budgeting.  The user sets the total bytes given to the lwIP
 * global allocator (lwip_mem_cap).  At boot:
 *     mem_init(lwip_mem_cap, ...)
 * Everything in free RAM above that cap stays available to the host app:
 *     usermem_remaining = os_MemChk() - lwip_mem_cap
 *
 * lwIP needs a feature-dependent minimum working set:
 *   - Without TLS: LWIP_BASE_FLOOR_BYTES
 *   - With TLS:    LWIP_TLS_FLOOR_BYTES
 * The configurator clamps lwip_mem_cap to that floor.
 * The maximum is os_MemChk() at config time (leaving 0 for the host app).
 *
 * Step is 1 KiB; values are stored as raw byte counts.
 */
#define LWIP_BASE_FLOOR_BYTES       (12u * 1024u)
#define LWIP_TLS_FLOOR_BYTES        (24u * 1024u)
#define LWIP_MIN_FLOOR_BYTES        LWIP_TLS_FLOOR_BYTES
#define LWIP_CFG_MEM_CAP_DEF        (32u * 1024u)
#define LWIP_CFG_MEM_CAP_STEP       1024u

typedef struct lwip_app_config {
    uint16_t version;
    uint16_t lwip_mem_cap;        /* Total bytes given to the lwIP allocator. */
    uint8_t flags;
    uint8_t reserved;
    int16_t tz_offset_minutes;
    uint8_t dst_enabled;
    uint8_t reserved2;
    uint16_t log_size_bytes;
    uint8_t ip_addr[4];
    uint8_t ip_gateway[4];
    uint8_t ip_netmask[4];
    char hostname[LWIP_CFG_HOSTNAME_MAX];
} lwip_app_config_t;

void lwip_app_config_defaults(lwip_app_config_t *cfg);
bool lwip_app_config_load(lwip_app_config_t *cfg);
bool lwip_app_config_save(const lwip_app_config_t *cfg);
const lwip_app_config_t *lwip_app_config_get(void);
bool lwip_app_config_refresh(void);

#endif
