#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include <lwip.h>

#include "common/lwip_example.h"

#define NTP_TIMEOUT_SECONDS 60

int main(void)
{
    struct lwip_conn conn = {0};
    uint32_t unix_time;
    clock_t start;
    lwip_error_t err;

    if (!lwip_example_stack_start())
    {
        return 1;
    }

    lwip_sntp_reset_flag();

    err = lwip_conn_create(&conn, NULL, LWIP_PROTO_UDP,
                           LWIP_CONN_SVC_DHCP | LWIP_CONN_SVC_SNTP);
    if (err != LWIP_OK)
    {
        lwip_example_show_conn_error("NTP create", &conn, err);
        lwip_conn_destroy(&conn);
        return lwip_example_finish(1);
    }

    lwip_example_show("NTP", "waiting");
    start = clock();
    unix_time = 0;

    while (!lwip_example_timed_out(start, NTP_TIMEOUT_SECONDS))
    {
        if (lwip_example_cancelled())
        {
            break;
        }

        lwip_poll_network_events();
        lwip_example_mem_stats_tick();

        if (lwip_sntp_time_was_set())
        {
            unix_time = lwip_sntp_get_unix_time();
            break;
        }
    }

    if (!unix_time)
    {
        lwip_example_show_conn_error("NTP timeout", &conn, conn.last_error);
        lwip_conn_destroy(&conn);
        return lwip_example_finish(1);
    }

    lwip_example_clear();
    lwip_example_line("NTP OK");
    lwip_example_linef("Unix: %lu", (unsigned long)unix_time);
    lwip_example_wait_key();

    lwip_conn_destroy(&conn);
    return lwip_example_finish(0);
}
