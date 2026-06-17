#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include <lwip.h>

#include "../../common/lwip_example.h"

#define NTP_TIMEOUT_SECONDS 60

/* CEmu debugger trap: write 2 to 0xFFFFFF to break into the debugger. */
#define CEMU_BREAK() do { *(volatile uint8_t *)0xFFFFFF = 2; } while (0)

static volatile bool g_sntp_ready = false;

static void ntp_service_cb(struct netif *n, void *arg, uint8_t svc,
                            lwip_netif_service_status_t st)
{
    (void)n; (void)arg; (void)svc;
    if (st == LWIP_NETIF_SERVICE_UP)
        g_sntp_ready = true;
}

int main(void)
{
    uint32_t unix_time;
    uint32_t start;
    lwip_error_t err;

    CEMU_BREAK();

    if (!lwip_example_stack_start())
    {
        return 1;
    }

    lwip_sntp_reset_flag();

    lwip_example_show("NTP", "starting");
    err = lwip_netif_request_services(NULL,
                                      LWIP_SOCKET_SVC_DNS | LWIP_SOCKET_SVC_SNTP,
                                      ntp_service_cb, NULL);
    if (err != LWIP_OK)
    {
        lwip_example_clear();
        lwip_example_linef("NTP svc err:%u", (unsigned)err);
        lwip_example_wait_key();
        return lwip_example_finish(1);
    }

    /* Wait for the service tick to confirm SNTP is up before polling for time. */
    lwip_example_show("NTP", "waiting for svc");
    while (!g_sntp_ready)
    {
        if (lwip_example_cancelled())
            return lwip_example_finish(0);
        lwip_service_events();
        lwip_example_mem_stats_tick();
    }

    lwip_example_show("NTP", "waiting");
    start = lwip_example_now_ms();
    unix_time = 0;

    while (!lwip_example_timed_out(start, NTP_TIMEOUT_SECONDS))
    {
        if (lwip_example_cancelled())
        {
            break;
        }

        lwip_service_events();
        lwip_example_mem_stats_tick();

        if (lwip_sntp_time_was_set())
        {
            unix_time = lwip_sntp_get_unix_time();
            break;
        }
    }

    if (!unix_time)
    {
        lwip_example_clear();
        lwip_example_line("NTP timeout");
        lwip_example_wait_key();
        return lwip_example_finish(1);
    }

    lwip_example_clear();
    lwip_example_line("NTP OK");
    lwip_example_linef("Unix: %lu", (unsigned long)unix_time);
    lwip_example_wait_key();

    return lwip_example_finish(0);
}
