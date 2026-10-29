#include <stdbool.h>

#include <ti/getcsc.h>

#include <lwip.h>

static bool app_start(void)
{
    /* Configure application networking here. */
    return true;
}

static void app_tick(void)
{
    /* Handle application state here. */
}

static void app_stop(void)
{
    /* Release application resources here. */
}

int main(void)
{
    if (!lwip_start() || !lwip_network_up())
        return 1;
    if (!app_start())
    {
        lwip_stop();
        return 1;
    }

    while (os_GetCSC() != sk_Clear)
    {
        lwip_service_events();
        app_tick();
    }

    app_stop();
    lwip_stop();
    return 0;
}

