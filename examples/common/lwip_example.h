#ifndef LWIP_EXAMPLE_H
#define LWIP_EXAMPLE_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include <ti/getcsc.h>
#include <ti/getkey.h>
#include <ti/screen.h>

#include <lwip/core.h>
#include <lwip/conn.h>

static void lwip_example_wait_key(void)
{
    printf("\n\nPress any key");
    os_GetKey();
}

static void lwip_example_show(const char *line1, const char *line2)
{
    os_ClrHome();
    printf("%s", line1);
    if (line2)
    {
        printf("\n%s", line2);
    }
}

static void lwip_example_show_and_wait(const char *line1, const char *line2)
{
    lwip_example_show(line1, line2);
    lwip_example_wait_key();
}

static void lwip_example_print_ipv4(const uint8_t ip[4])
{
    printf("%u.%u.%u.%u",
           (unsigned)ip[0], (unsigned)ip[1],
           (unsigned)ip[2], (unsigned)ip[3]);
}

static void lwip_example_show_conn_error(const char *label,
                                         const struct lwip_conn *conn,
                                         lwip_error_t err)
{
    lwip_netif_info_t info = {0};

    os_ClrHome();
    printf("%s\nst:%u err:%u", label,
           conn ? (unsigned)conn->status : 0u,
           err ? (unsigned)err : (conn ? (unsigned)conn->last_error : 0u));
    if (lwip_default_netif_info(&info))
    {
        printf("\nu:%u l:%u dh:%u",
               (unsigned)info.up,
               (unsigned)info.link_up,
               (unsigned)info.dhcp_state);
        printf("\nip:%u gw:%u",
               (unsigned)info.has_ipv4,
               (unsigned)info.has_ipv4_gateway);
        printf("\nIP ");
        lwip_example_print_ipv4(info.ipv4_addr);
        printf("\nGW ");
        lwip_example_print_ipv4(info.ipv4_gateway);
    }
    else
    {
        printf("\nno netif");
    }
    lwip_example_wait_key();
}

static bool lwip_example_timed_out(clock_t start, uint16_t seconds);
static bool lwip_example_cancelled(void);

static bool lwip_example_stack_running = false;

static void lwip_example_stack_stop(void)
{
    if (lwip_example_stack_running)
    {
        lwip_example_stack_running = false;
        lwip_stop();
    }
}

static bool lwip_example_stack_start(void)
{
    os_ClrHome();
    printf("lwIP runtime");

    if (!lwip_init_runtime())
    {
        switch (lwip_runtime_last_error())
        {
        case 1:
            lwip_example_show_and_wait("lwIP failed", "app missing");
            break;
        case 2:
            lwip_example_show_and_wait("lwIP failed", "runtime table");
            break;
        case 3:
            lwip_example_show_and_wait("lwIP failed", "runtime count");
            break;
        default:
            lwip_example_show_and_wait("lwIP failed", "runtime init");
            break;
        }
        return false;
    }

    os_ClrHome();
    printf("lwIP start");

    if (!lwip_start())
    {
        switch (lwip_start_last_error())
        {
        case 1:
            lwip_example_show_and_wait("lwIP failed", "start init");
            break;
        case 2:
            lwip_example_show_and_wait("lwIP failed", "start usb");
            break;
        default:
            lwip_example_show_and_wait("lwIP failed", "start");
            break;
        }
        return false;
    }

    lwip_example_stack_running = true;
    return true;
}

static int lwip_example_finish(int code)
{
    lwip_example_stack_stop();
    return code;
}

static bool lwip_example_timed_out(clock_t start, uint16_t seconds)
{
    return (clock_t)(clock() - start) >= (clock_t)seconds * CLOCKS_PER_SEC;
}

static bool lwip_example_cancelled(void)
{
    return os_GetCSC() == sk_Clear;
}

#endif /* LWIP_EXAMPLE_H */
