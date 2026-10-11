#include <string.h>

#include "lwip/app_config.h"
#include "lwip-imports.h"

#define LWIP_DBG_FILE_ID LWIP_FILE_APP_CONFIG
#define LWIP_DBG_MODULE  LWIP_DBG_MOD_LWIP
#include "lwip/logging.h"

#define LWIP_CFG_FORMAT_VERSION 1u
#define LWIP_CFG_HEADER_SIZE    8u
#define LWIP_CFG_SERIALIZED_MAX 128u

/* Wire format:
 *   "LWCF" | format:u8 | header-size:u8 | payload-size:u16le
 *   repeated { setting-id:u8 | value-size:u8 | value[value-size] }
 *
 * The format version describes this envelope, not the set of settings.
 * Setting IDs are stable and independently optional, so schema additions do
 * not require a version bump or shift any existing value. */
enum lwip_cfg_setting_id {
    LWIP_CFG_ID_FLAGS = 1,
    LWIP_CFG_ID_TZ_OFFSET,
    LWIP_CFG_ID_DST_ENABLED,
    LWIP_CFG_ID_PCAP_MAX_BYTES,
    LWIP_CFG_ID_HOSTNAME,
    LWIP_CFG_ID_TLS_ENABLED,
};

static const uint8_t lwip_cfg_magic[4] = {'L', 'W', 'C', 'F'};
static lwip_app_config_t g_cfg;
static bool g_cfg_loaded = false;

/* Raw-struct formats written before settings became tagged. These are read
 * only for migration and are never written. */
typedef struct lwip_app_config_v1 {
    uint16_t version;
    uint16_t lwip_mem_cap;
    uint8_t flags;
    uint8_t log_enabled;
    int16_t tz_offset_minutes;
    uint8_t dst_enabled;
    uint8_t log_min_level;
    uint16_t pcap_max_bytes;
    uint8_t ip_addr[4];
    uint8_t ip_gateway[4];
    uint8_t ip_netmask[4];
    char hostname[LWIP_CFG_HOSTNAME_MAX];
    uint8_t tls_enabled;
} lwip_app_config_v1_t;

typedef struct lwip_app_config_v2 {
    uint16_t version;
    uint16_t lwip_mem_cap;
    uint8_t flags;
    uint8_t log_enabled;
    int16_t tz_offset_minutes;
    uint8_t dst_enabled;
    uint8_t log_min_level;
    uint16_t pcap_max_bytes;
    char hostname[LWIP_CFG_HOSTNAME_MAX];
    uint8_t tls_enabled;
} lwip_app_config_v2_t;

static uint16_t read_u16_le(const uint8_t *p)
{
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static void write_u16_le(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
}

static bool append_setting(uint8_t *out, size_t capacity, size_t *used,
                           uint8_t id, const void *value, uint8_t length)
{
    if (!out || !used || !value || *used > capacity ||
        (size_t)length + 2u > capacity - *used)
    {
        return false;
    }
    out[(*used)++] = id;
    out[(*used)++] = length;
    memcpy(out + *used, value, length);
    *used += length;
    return true;
}

static void lwip_app_config_normalize(lwip_app_config_t *cfg)
{
    /* These bits formerly controlled stack-owned services/security policy. */
    cfg->flags &= (uint8_t)~(LWIP_CFG_DNS |
                            LWIP_CFG_LOG_USB |
                            LWIP_CFG_AUTO_NTP |
                            LWIP_CFG_DHCP |
                            LWIP_CFG_FULL_CHAIN_VERIFY |
                            LWIP_CFG_LOG_TLS);

    cfg->lwip_mem_cap = LWIP_CFG_MEM_CAP_DEF;
    cfg->log_enabled = LWIP_CFG_LOG_ENABLED_DEF;
    cfg->log_min_level = LWIP_CFG_LOG_LEVEL_DEF;
    cfg->dst_enabled = cfg->dst_enabled ? 1u : 0u;
    cfg->tls_enabled = cfg->tls_enabled ? 1u : 0u;

    switch (cfg->pcap_max_bytes)
    {
    case LWIP_CFG_PCAP_SIZE_4K:
    case LWIP_CFG_PCAP_SIZE_8K:
    case LWIP_CFG_PCAP_SIZE_16K:
    case LWIP_CFG_PCAP_SIZE_32K:
        break;
    default:
        cfg->pcap_max_bytes = LWIP_CFG_PCAP_SIZE_DEFAULT;
        break;
    }
    cfg->hostname[LWIP_CFG_HOSTNAME_MAX - 1] = '\0';
}

void lwip_app_config_defaults(lwip_app_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->lwip_mem_cap = LWIP_CFG_MEM_CAP_DEF;
    cfg->flags = 0;
    cfg->log_enabled = LWIP_CFG_LOG_ENABLED_DEF;
    cfg->tz_offset_minutes = 0;
    cfg->dst_enabled = 0;
    cfg->log_min_level = LWIP_CFG_LOG_LEVEL_DEF;
    cfg->pcap_max_bytes = LWIP_CFG_PCAP_SIZE_DEFAULT;
    strncpy(cfg->hostname, "ti84plusce", LWIP_CFG_HOSTNAME_MAX - 1);
    cfg->hostname[LWIP_CFG_HOSTNAME_MAX - 1] = '\0';
    cfg->tls_enabled = 1;
}

static bool parse_serialized_config(lwip_app_config_t *cfg,
                                    const uint8_t *data, size_t size)
{
    uint32_t seen = 0;
    size_t pos;

    if (size < LWIP_CFG_HEADER_SIZE ||
        memcmp(data, lwip_cfg_magic, sizeof(lwip_cfg_magic)) != 0 ||
        data[4] != LWIP_CFG_FORMAT_VERSION ||
        data[5] != LWIP_CFG_HEADER_SIZE ||
        read_u16_le(data + 6) != size - LWIP_CFG_HEADER_SIZE)
    {
        return false;
    }

    lwip_app_config_defaults(cfg);
    pos = LWIP_CFG_HEADER_SIZE;
    while (pos < size)
    {
        uint8_t id;
        uint8_t length;
        uint32_t bit = 0;

        if (size - pos < 2u)
            return false;
        id = data[pos++];
        length = data[pos++];
        if ((size_t)length > size - pos || id == 0u)
            return false;
        if (id < 32u)
        {
            bit = (uint32_t)1u << id;
            if ((seen & bit) != 0u)
                return false;
        }

        switch (id)
        {
        case LWIP_CFG_ID_FLAGS:
            if (length != 1u) return false;
            cfg->flags = data[pos];
            break;
        case LWIP_CFG_ID_TZ_OFFSET:
            if (length != 2u) return false;
            cfg->tz_offset_minutes = (int16_t)read_u16_le(data + pos);
            break;
        case LWIP_CFG_ID_DST_ENABLED:
            if (length != 1u) return false;
            cfg->dst_enabled = data[pos];
            break;
        case LWIP_CFG_ID_PCAP_MAX_BYTES:
            if (length != 2u) return false;
            cfg->pcap_max_bytes = read_u16_le(data + pos);
            break;
        case LWIP_CFG_ID_HOSTNAME:
            if (length >= LWIP_CFG_HOSTNAME_MAX) return false;
            memcpy(cfg->hostname, data + pos, length);
            cfg->hostname[length] = '\0';
            break;
        case LWIP_CFG_ID_TLS_ENABLED:
            if (length != 1u) return false;
            cfg->tls_enabled = data[pos];
            break;
        default:
            /* Forward-compatible setting: retain framing, ignore value. */
            break;
        }

        if (bit != 0u)
            seen |= bit;
        pos += length;
    }

    lwip_app_config_normalize(cfg);
    return true;
}

static void migrate_common(lwip_app_config_t *cfg, uint8_t flags,
                           int16_t tz_offset_minutes, uint8_t dst_enabled,
                           uint16_t pcap_max_bytes, const char *hostname,
                           uint8_t tls_enabled)
{
    lwip_app_config_defaults(cfg);
    cfg->flags = flags;
    cfg->tz_offset_minutes = tz_offset_minutes;
    cfg->dst_enabled = dst_enabled;
    cfg->pcap_max_bytes = pcap_max_bytes;
    memcpy(cfg->hostname, hostname, sizeof(cfg->hostname));
    cfg->hostname[sizeof(cfg->hostname) - 1] = '\0';
    cfg->tls_enabled = tls_enabled;
    lwip_app_config_normalize(cfg);
}

static bool parse_legacy_config(lwip_app_config_t *cfg,
                                const uint8_t *data, size_t size)
{
    uint16_t version;

    if (size < sizeof(uint16_t))
        return false;
    version = read_u16_le(data);

    if (version == 1u && size >= sizeof(lwip_app_config_v1_t))
    {
        lwip_app_config_v1_t stored;
        memcpy(&stored, data, sizeof(stored));
        migrate_common(cfg, stored.flags, stored.tz_offset_minutes,
                       stored.dst_enabled, stored.pcap_max_bytes,
                       stored.hostname, stored.tls_enabled);
        return true;
    }
    if (version == 2u && size >= sizeof(lwip_app_config_v2_t))
    {
        lwip_app_config_v2_t stored;
        memcpy(&stored, data, sizeof(stored));
        migrate_common(cfg, stored.flags, stored.tz_offset_minutes,
                       stored.dst_enabled, stored.pcap_max_bytes,
                       stored.hostname, stored.tls_enabled);
        return true;
    }
    return false;
}

bool lwip_app_config_load(lwip_app_config_t *cfg)
{
    uint8_t serialized[LWIP_CFG_SERIALIZED_MAX];
    uint8_t h;
    uint16_t size;
    bool valid;

    if (!cfg)
        return false;
    h = file_fn.ti_open(LWIP_CFG_APPVAR, "r");
    if (!h)
    {
        WARN();
        lwip_app_config_defaults(cfg);
        return false;
    }
    size = file_fn.ti_getsize(h);
    if (size == 0u || size > sizeof(serialized) ||
        file_fn.ti_read(serialized, size, 1, h) != 1u)
    {
        ERROR_CODE(size);
        file_fn.ti_close(h);
        lwip_app_config_defaults(cfg);
        return false;
    }
    file_fn.ti_close(h);
    IO_FILE(LWIP_IO_READ, LWIP_CFG_APPVAR, size);

    valid = parse_serialized_config(cfg, serialized, size) ||
            parse_legacy_config(cfg, serialized, size);
    if (!valid)
    {
        WARN();
        lwip_app_config_defaults(cfg);
    }
    return valid;
}

bool lwip_app_config_save(const lwip_app_config_t *cfg)
{
    uint8_t serialized[LWIP_CFG_SERIALIZED_MAX] = {0};
    uint8_t scalar[2];
    uint8_t h;
    size_t hostname_len = 0;
    size_t used = LWIP_CFG_HEADER_SIZE;
    lwip_app_config_t normalized;

    if (!cfg)
    {
        ERROR();
        return false;
    }
    normalized = *cfg;
    lwip_app_config_normalize(&normalized);
    while (hostname_len < LWIP_CFG_HOSTNAME_MAX - 1u &&
           normalized.hostname[hostname_len] != '\0')
    {
        hostname_len++;
    }

    memcpy(serialized, lwip_cfg_magic, sizeof(lwip_cfg_magic));
    serialized[4] = LWIP_CFG_FORMAT_VERSION;
    serialized[5] = LWIP_CFG_HEADER_SIZE;

    if (!append_setting(serialized, sizeof(serialized), &used,
                        LWIP_CFG_ID_FLAGS, &normalized.flags, 1u))
        return false;
    write_u16_le(scalar, (uint16_t)normalized.tz_offset_minutes);
    if (!append_setting(serialized, sizeof(serialized), &used,
                        LWIP_CFG_ID_TZ_OFFSET, scalar, sizeof(scalar)) ||
        !append_setting(serialized, sizeof(serialized), &used,
                        LWIP_CFG_ID_DST_ENABLED, &normalized.dst_enabled, 1u))
        return false;
    write_u16_le(scalar, normalized.pcap_max_bytes);
    if (!append_setting(serialized, sizeof(serialized), &used,
                        LWIP_CFG_ID_PCAP_MAX_BYTES, scalar, sizeof(scalar)) ||
        !append_setting(serialized, sizeof(serialized), &used,
                        LWIP_CFG_ID_HOSTNAME, normalized.hostname,
                        (uint8_t)hostname_len) ||
        !append_setting(serialized, sizeof(serialized), &used,
                        LWIP_CFG_ID_TLS_ENABLED, &normalized.tls_enabled, 1u))
        return false;

    write_u16_le(serialized + 6, (uint16_t)(used - LWIP_CFG_HEADER_SIZE));
    file_fn.ti_delete(LWIP_CFG_APPVAR);
    h = file_fn.ti_open(LWIP_CFG_APPVAR, "w");
    if (!h)
    {
        ERROR();
        return false;
    }
    if (file_fn.ti_resize(used, h) != (int)used ||
        file_fn.ti_write(serialized, used, 1, h) != 1u)
    {
        ERROR();
        file_fn.ti_close(h);
        return false;
    }
    file_fn.ti_setarchivestatus(1, h);
    file_fn.ti_close(h);
    IO_FILE(LWIP_IO_WRITE, LWIP_CFG_APPVAR, used);
    return true;
}

const lwip_app_config_t *lwip_app_config_get(void)
{
    if (!g_cfg_loaded)
    {
        lwip_app_config_load(&g_cfg);
        g_cfg_loaded = true;
    }
    return &g_cfg;
}

bool lwip_app_config_refresh(void)
{
    g_cfg_loaded = lwip_app_config_load(&g_cfg);
    return g_cfg_loaded;
}
