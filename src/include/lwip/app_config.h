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

/* Hard cap on each log file.  Not user-configurable; kept here for reference
 * by log_file.c and the config app. */
#define LWIP_CFG_LOG_FILE_MAX_BYTES  (16u * 1024u)

/* Range for the user-configurable archive slot count. */
#define LWIP_CFG_LOG_ARCHIVE_SLOTS_MIN     1u
#define LWIP_CFG_LOG_ARCHIVE_SLOTS_MAX     9u
#define LWIP_CFG_LOG_ARCHIVE_SLOTS_DEFAULT 2u

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

/* User-configurable verbosity gate (see lwip_log_verbosity_t). Persisted as
 * a plain uint8_t matching that enum's values. */
#define LWIP_CFG_LOG_VERBOSITY_DEFAULT LWIP_LOG_VERBOSITY_INFO
#define LWIP_CFG_LOG_VERBOSITY_MIN     LWIP_LOG_VERBOSITY_ERROR
#define LWIP_CFG_LOG_VERBOSITY_MAX     LWIP_LOG_VERBOSITY_DEBUG

typedef struct lwip_app_config {
    uint16_t lwip_mem_cap;
    uint8_t flags;
    uint8_t log_enabled;     /* vestigial; do not use */
    int16_t tz_offset_minutes;
    uint8_t dst_enabled;
    uint8_t log_verbosity;   /* lwip_log_verbosity_t: ERROR|WARNING|INFO|DEBUG */
    /* Deprecated alias retained for source compatibility. */
    union {
        uint16_t pcap_max_bytes;
        uint16_t log_size_bytes; /* Deprecated alias. */
    };
    char hostname[LWIP_CFG_HOSTNAME_MAX];
    uint8_t tls_enabled;
    uint8_t pcap_enabled;       /* User-persisted PCAP on/off toggle. */
    uint8_t file_log_enabled;   /* Route all events to lwIPLog appvar. */
    uint8_t log_archive_slots;  /* How many archive slots to keep (1-9). */
    uint8_t crypto_offload; /* hand X25519 and RSA checks to the Wi-Fi bridge */
    uint8_t bridge_rng;     /* seed every random byte from the bridge TRNG */
} lwip_app_config_t;

void lwip_app_config_defaults(lwip_app_config_t *cfg);
bool lwip_app_config_load(lwip_app_config_t *cfg);
bool lwip_app_config_save(const lwip_app_config_t *cfg);
const lwip_app_config_t *lwip_app_config_get(void);
bool lwip_app_config_refresh(void);

#endif
