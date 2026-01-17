#include <string.h>

#include <ti/vars.h>
#include <fileioc.h>

#include "lwip/app_config.h"

typedef struct lwip_app_config_v1 {
    uint16_t version;
    uint16_t max_heap_bytes;
    uint8_t flags;
    uint8_t reserved;
    uint8_t ip_addr[4];
    uint8_t ip_gateway[4];
    uint8_t ip_netmask[4];
} lwip_app_config_v1_t;

static lwip_app_config_t g_cfg;
static bool g_cfg_loaded = false;

void lwip_app_config_defaults(lwip_app_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->version = LWIP_CFG_VERSION;
    cfg->max_heap_bytes = 32u * 1024u;
    cfg->flags = LWIP_CFG_ENABLE_TLS | LWIP_CFG_DHCP;
    cfg->tz_offset_minutes = 0;
    cfg->dst_enabled = 0;
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
    if (size < sizeof(lwip_app_config_v1_t))
    {
        lwip_app_config_defaults(cfg);
        return false;
    }
    const uint8_t *data = (const uint8_t *)var + 2;
    const lwip_app_config_t *stored = (const lwip_app_config_t *)data;
    if (stored->version == LWIP_CFG_VERSION && size >= sizeof(*cfg))
    {
        memcpy(cfg, stored, sizeof(*cfg));
        return true;
    }
    if (stored->version == 1u && size >= sizeof(lwip_app_config_v1_t))
    {
        const lwip_app_config_v1_t *stored_v1 = (const lwip_app_config_v1_t *)data;
        lwip_app_config_defaults(cfg);
        cfg->max_heap_bytes = stored_v1->max_heap_bytes;
        cfg->flags = stored_v1->flags;
        memcpy(cfg->ip_addr, stored_v1->ip_addr, sizeof(stored_v1->ip_addr));
        memcpy(cfg->ip_gateway, stored_v1->ip_gateway, sizeof(stored_v1->ip_gateway));
        memcpy(cfg->ip_netmask, stored_v1->ip_netmask, sizeof(stored_v1->ip_netmask));
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
