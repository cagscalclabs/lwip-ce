#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <fileioc.h>
#include <sys/rtc.h>
#include <sys/timers.h>
#include <time.h>
#include <ti/getcsc.h>
#include <ti/screen.h>

#include <lwip.h>

#define LEASE_TIMEOUT_MS 45000
#define PING_COUNT 4
#define PING_TIMEOUT_MS 2000
#define PING_ID 0x5754
#define SERVE_MS 60000

static uint8_t usb_setups;
static uint8_t usb_configures;
static bool reply_seen;
static uint16_t reply_seq;

static bool quit;

static bool quit_pressed(void)
{
    if (!quit && os_GetCSC() == sk_Clear)
        quit = true;
    return quit;
}

static char screen[10][27];

static void put_line(uint8_t row, const char *text)
{
    snprintf(screen[row], sizeof screen[row], "%-26s", text);
    os_SetCursorPos(row, 0);
    os_PutStrFull(screen[row]);
}

static void save_log(uint32_t rtc_start, uint32_t ms_start, clock_t clock_start)
{
    uint8_t handle = ti_Open("WNLOG", "w");
    char line[40];

    if (!handle)
        return;
    for (uint8_t row = 0; row < 10; row++)
    {
        ti_Write(screen[row], strlen(screen[row]), 1, handle);
        ti_Write("\n", 1, 1, handle);
    }
    snprintf(line, sizeof line, "rtc %lu ms %lu clk %lu ctl %04X\n",
             (unsigned long)(rtc_Time() - rtc_start), (unsigned long)(lwip_now_ms() - ms_start),
             (unsigned long)(clock() - clock_start), timer_Control);
    ti_Write(line, strlen(line), 1, handle);
    ti_Close(handle);
}

static usb_error_t count_usb(usb_event_t event, void *event_data, usb_callback_data_t *data)
{
    (void)event_data;
    (void)data;

    if (event == USB_DEFAULT_SETUP_EVENT)
        usb_setups++;
    else if (event == USB_HOST_CONFIGURE_EVENT)
        usb_configures++;

    return USB_SUCCESS;
}

static u8_t ping_recv(void *arg, struct raw_pcb *pcb, struct pbuf *p, const ip_addr_t *addr)
{
    struct ip_hdr iph;
    struct icmp_echo_hdr echo;
    uint16_t offset;

    (void)arg;
    (void)pcb;
    (void)addr;

    if (pbuf_copy_partial(p, &iph, sizeof iph, 0) != sizeof iph)
        return 0;
    offset = IPH_HL_BYTES(&iph);
    if (pbuf_copy_partial(p, &echo, sizeof echo, offset) != sizeof echo)
        return 0;
    if (echo.type != ICMP_ER || echo.id != PP_HTONS(PING_ID))
        return 0;

    reply_seen = true;
    reply_seq = PP_HTONS(echo.seqno);
    pbuf_free(p);
    return 1;
}

static bool ping_send(struct raw_pcb *pcb, const ip_addr_t *target, uint16_t seq)
{
    struct pbuf *p = pbuf_alloc(PBUF_IP, sizeof(struct icmp_echo_hdr) + 32, PBUF_RAM);
    struct icmp_echo_hdr *echo;
    err_t err;

    if (!p)
        return false;

    echo = p->payload;
    echo->type = ICMP_ECHO;
    echo->code = 0;
    echo->chksum = 0;
    echo->id = PP_HTONS(PING_ID);
    echo->seqno = PP_HTONS(seq);
    for (uint8_t i = 0; i < 32; i++)
        ((uint8_t *)(echo + 1))[i] = (uint8_t)('a' + i % 26);
    echo->chksum = inet_chksum(echo, p->len);

    err = raw_sendto(pcb, p, target);
    pbuf_free(p);
    return err == ERR_OK;
}

static void show_usb(void)
{
    char line[27];

    snprintf(line, sizeof line, "usb setup %u cfg %u if %02X", usb_setups, usb_configures,
             eth_get_interfaces());
    put_line(1, line);
}

static int run(void)
{
    lwip_netif_info_t info;
    struct raw_pcb *pcb;
    ip_addr_t gateway;
    char line[27];
    uint32_t start;
    uint8_t replies = 0;

    os_ClrHome();
    put_line(0, "LWPING");

    if (!lwip_start() || !lwip_network_up())
    {
        snprintf(line, sizeof line, "FAIL start %u", lwip_start_last_error());
        put_line(9, line);
        return 1;
    }

    lwip_attach_usb_callback(count_usb);

    start = lwip_now_ms();
    for (;;)
    {
        lwip_service_events();
        show_usb();
        if (lwip_default_netif_info(&info) && info.has_ipv4 && info.has_ipv4_gateway)
            break;
        if (quit_pressed() || lwip_now_ms() - start > LEASE_TIMEOUT_MS)
        {
            put_line(9, "FAIL no lease");
            lwip_stop();
            return 1;
        }
    }

    snprintf(line, sizeof line, "ip %u.%u.%u.%u", info.ipv4_addr[0], info.ipv4_addr[1],
             info.ipv4_addr[2], info.ipv4_addr[3]);
    put_line(2, line);
    snprintf(line, sizeof line, "gw %u.%u.%u.%u", info.ipv4_gateway[0], info.ipv4_gateway[1],
             info.ipv4_gateway[2], info.ipv4_gateway[3]);
    put_line(3, line);

    IP_ADDR4(&gateway, info.ipv4_gateway[0], info.ipv4_gateway[1], info.ipv4_gateway[2],
             info.ipv4_gateway[3]);

    pcb = raw_new(IP_PROTO_ICMP);
    if (!pcb)
    {
        put_line(9, "FAIL raw_new");
        lwip_stop();
        return 1;
    }
    raw_recv(pcb, ping_recv, NULL);

    for (uint16_t seq = 1; seq <= PING_COUNT && !quit_pressed(); seq++)
    {
        uint32_t sent;
        bool ok = false;
        bool queued;

        reply_seen = false;
        sent = lwip_now_ms();
        queued = ping_send(pcb, &gateway, seq);
        if (queued)
        {
            while (lwip_now_ms() - sent < PING_TIMEOUT_MS && !quit_pressed())
            {
                lwip_service_events();
                if (reply_seen && reply_seq == seq)
                {
                    ok = true;
                    break;
                }
            }
        }

        if (ok)
        {
            replies++;
            snprintf(line, sizeof line, "seq %u reply %lu ms", seq,
                     (unsigned long)(lwip_now_ms() - sent));
        }
        else
        {
            snprintf(line, sizeof line, "seq %u %s %lu ms", seq, queued ? "timeout" : "send fail",
                     (unsigned long)(lwip_now_ms() - sent));
        }
        put_line((uint8_t)(3 + seq), line);
        show_usb();

        start = lwip_now_ms();
        while (lwip_now_ms() - start < 500 && !quit_pressed())
            lwip_service_events();
    }

    raw_remove(pcb);
    snprintf(line, sizeof line, "%s %u/%u", replies == PING_COUNT ? "PASS" : "FAIL", replies,
             PING_COUNT);
    put_line(9, line);
    put_line(8, "up 60 s, clear quits");

    start = lwip_now_ms();
    while (lwip_now_ms() - start < SERVE_MS && !quit_pressed())
        lwip_service_events();
    lwip_stop();
    return replies == PING_COUNT ? 0 : 1;
}

int main(void)
{
    uint32_t rtc_start = rtc_Time();
    uint32_t ms_start = lwip_now_ms();
    clock_t clock_start = clock();
    int result = run();

    save_log(rtc_start, ms_start, clock_start);
    return result;
}
