#include <string.h>

#include <ti/vars.h>
#include <fileioc.h>

#include "lwip/app_config.h"

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
}

bool lwip_app_config_load(lwip_app_config_t *cfg)
{
    int archived = 0;
    var_t *var = os_GetAppVarData(LWIP_CFG_APPVAR, &archived);
    if (!var)
    {
        lwip_app_config_defaults(cfg);
        return false;
    }
    uint16_t size = *((uint16_t *)var);
    if (size < sizeof(uint16_t))
    {
        lwip_app_config_defaults(cfg);
        return false;
    }
    const uint8_t *data = (const uint8_t *)var + 2;
    const lwip_app_config_t *stored = (const lwip_app_config_t *)data;
    if (stored->version == LWIP_CFG_VERSION && size >= sizeof(*cfg))
    {
        memcpy(cfg, stored, sizeof(*cfg));
        lwip_app_config_normalize(cfg);
        return true;
    }
    lwip_app_config_defaults(cfg);
    return false;
}

bool lwip_app_config_save(const lwip_app_config_t *cfg)
{
    uint8_t handle = ti_Open(LWIP_CFG_APPVAR, "w");
    if (!handle)
    {
        return false;
    }
    ti_SetArchiveStatus(false, handle);
    ti_Write(cfg, sizeof(*cfg), 1, handle);
    ti_SetArchiveStatus(true, handle);
    ti_Close(handle);
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
