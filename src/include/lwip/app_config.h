#ifndef LWIP_APP_CONFIG_H
#define LWIP_APP_CONFIG_H

#include <stdbool.h>
#include <stdint.h>

#include "lwip/logging.h"

#define LWIP_CFG_APPVAR "lwIPCFG"
#define LWIP_CFG_VERSION 1u

#define LWIP_CFG_HOSTNAME_MAX 16

#define LWIP_CFG_DNS                  (1u << 0)
#define LWIP_CFG_LOG_USB              (1u << 1)
#define LWIP_CFG_AUTO_NTP             (1u << 2)
#define LWIP_CFG_DHCP                 (1u << 3)
#define LWIP_CFG_TEST_HTTP            (1u << 4)
/* TLS chain trust:
 *   bit clear  → SPKI-pin mode (default). Any cert in the chain whose
 *                 SPKI matches the truststore validates the chain.
 *                 Dates and owner-id checks run automatically when a
 *                 pin matches.
 *   bit set    → reserved for full-chain verify. This is currently
 *                 normalized back to SPKI-pin mode until cert-chain
 *                 signature verification is implemented.
 * Independent of this bit, the live CertificateVerify message is
 * always RSA-PSS verified against the leaf SPKI. */
#define LWIP_CFG_FULL_CHAIN_VERIFY    (1u << 5)
#define LWIP_CFG_LOG_TLS              (1u << 7)

/* Memory budgeting.  The user sets the total bytes visible to lwIP
 * accounting (lwip_mem_cap).  At boot the allocator splits that budget
 * into a fixed pbuf pool (LWIP_PBUF_POOL_BYTES) and a tracked non-pool
 * heap.  Callers that need protected heap while lwIP is running can reserve
 * it with mem_request/mem_resize/mem_release; those reservations reduce the
 * non-pool heap available to lwIP.
 *
 * lwIP-CE always ships with TLS available. The configurator clamps
 * lwip_mem_cap to the TLS-capable floor.
 * The maximum is os_MemChk() at config time (leaving 0 for the host app).
 *
 * Step is 1 KiB; values are stored as raw byte counts.
 */
#define LWIP_TLS_FLOOR_BYTES        (24u * 1024u)
#define LWIP_MIN_FLOOR_BYTES        LWIP_TLS_FLOOR_BYTES
#define LWIP_CFG_MEM_CAP_DEF        (50u * 1024u)
#define LWIP_CFG_MEM_CAP_STEP       1024u
/* Vestigial log-config fields. The appvar-backed log system was replaced by
 * the unified debug callback (lwip_set_debug); these fields are retained only
 * to keep the persisted config layout stable and are no longer consulted. */
#define LWIP_CFG_LOG_ENABLED_DEF    1u
#define LWIP_CFG_LOG_LEVEL_DEF      3u   /* was LWIP_LOG_LEVEL_ERROR */
#define LWIP_CFG_LOG_LEVEL_MIN      1u
#define LWIP_CFG_LOG_LEVEL_MAX      4u

typedef struct lwip_app_config {
    uint16_t version;
    uint16_t lwip_mem_cap;        /* Total bytes given to the lwIP allocator. */
    uint8_t flags;
    uint8_t log_enabled;
    int16_t tz_offset_minutes;
    uint8_t dst_enabled;
    uint8_t log_min_level;
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
