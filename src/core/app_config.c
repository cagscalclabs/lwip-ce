#include <string.h>

#include "lwip/app_config.h"
#include "lwip-imports.h"

#define LWIP_DBG_FILE_ID LWIP_FILE_APP_CONFIG
#define LWIP_DBG_MODULE  LWIP_DBG_MOD_LWIP
#include "lwip/logging.h"

static lwip_app_config_t g_cfg;
static bool g_cfg_loaded = false;

static void lwip_app_config_normalize(lwip_app_config_t *cfg)
{
    /* These persisted bits were formerly wizard-controlled services or
     * security/logging toggles. The stack now owns service startup and TLS
     * policy, so old appvars must not re-enable them. */
    cfg->flags &= (uint8_t)~(LWIP_CFG_DNS |
                            LWIP_CFG_LOG_USB |
                            LWIP_CFG_AUTO_NTP |
                            LWIP_CFG_DHCP |
                            LWIP_CFG_FULL_CHAIN_VERIFY |
                            LWIP_CFG_LOG_TLS);

    /* lwip_mem_cap is a legacy wizard field; the real cap comes from
     * os_MemChk at init time. Reset any stale stored value so old appvars
     * don't silently cap the heap below what the device actually has free. */
    cfg->lwip_mem_cap = LWIP_CFG_MEM_CAP_DEF;

    if (cfg->log_min_level < LWIP_CFG_LOG_LEVEL_MIN ||
        cfg->log_min_level > LWIP_CFG_LOG_LEVEL_MAX)
    {
        cfg->log_min_level = LWIP_CFG_LOG_LEVEL_DEF;
        cfg->log_enabled = LWIP_CFG_LOG_ENABLED_DEF;
    }
    if (cfg->log_enabled > 1u)
    {
        cfg->log_enabled = LWIP_CFG_LOG_ENABLED_DEF;
    }
    if (cfg->tls_enabled > 1u)
    {
        cfg->tls_enabled = 1;
    }
}

void lwip_app_config_defaults(lwip_app_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->version = LWIP_CFG_VERSION;
    cfg->lwip_mem_cap = LWIP_CFG_MEM_CAP_DEF;
    cfg->flags = 0;
    cfg->log_enabled = LWIP_CFG_LOG_ENABLED_DEF;
    cfg->tz_offset_minutes = 0;
    cfg->dst_enabled = 0;
    cfg->log_min_level = LWIP_CFG_LOG_LEVEL_DEF;
    cfg->log_size_bytes = 4096u;
    strncpy(cfg->hostname, "ti84plusce", LWIP_CFG_HOSTNAME_MAX - 1);
    cfg->hostname[LWIP_CFG_HOSTNAME_MAX - 1] = '\0';
    cfg->tls_enabled = 1;
}

bool lwip_app_config_load(lwip_app_config_t *cfg)
{
    uint8_t h = file_fn.ti_open(LWIP_CFG_APPVAR, "r");
    if (!h)
    {
        WARN();
        lwip_app_config_defaults(cfg);
        return false;
    }
    uint16_t size = file_fn.ti_getsize(h);
    if (size < sizeof(*cfg))
    {
        ERROR_CODE(size);
        file_fn.ti_close(h);
        lwip_app_config_defaults(cfg);
        return false;
    }
    IO_FILE(LWIP_IO_READ, LWIP_CFG_APPVAR, size);
    lwip_app_config_t stored;
    file_fn.ti_read(&stored, sizeof(stored), 1, h);
    file_fn.ti_close(h);
    if (stored.version == LWIP_CFG_VERSION)
    {
        memcpy(cfg, &stored, sizeof(*cfg));
        lwip_app_config_normalize(cfg);
        return true;
    }
    WARN_CODE(stored.version);
    lwip_app_config_defaults(cfg);
    return false;
}

bool lwip_app_config_save(const lwip_app_config_t *cfg)
{
    if (!cfg)
    {
        ERROR();
        return false;
    }

    file_fn.ti_delete(LWIP_CFG_APPVAR);
    uint8_t h = file_fn.ti_open(LWIP_CFG_APPVAR, "w");
    if (!h)
    {
        ERROR();
        return false;
    }
    file_fn.ti_resize(sizeof(*cfg), h);
    file_fn.ti_write(cfg, sizeof(*cfg), 1, h);
    file_fn.ti_setarchivestatus(1, h);
    file_fn.ti_close(h);
    IO_FILE(LWIP_IO_WRITE, LWIP_CFG_APPVAR, sizeof(*cfg));
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
