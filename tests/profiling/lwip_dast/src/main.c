/* lwIP-CE DAST calc-side harness.
 *
 * Pairs with build-tools/dast/lwip-dast.py. The script drives the calc
 * over a UDP control channel (port 9997) — no manual keypress needed to
 * advance tests. The calc opens the appropriate listener for each test,
 * waits for probe traffic, then waits for the script to send NEXT/DONE.
 *
 *   DAST_STATE_IDLE        nothing app-side; ARP/ICMP/IP/closed-port handled
 *                          passively by the stack.
 *   DAST_STATE_UDP_RECV    a UDP PCB bound to the test port, counting datagrams
 *                          that reach its recv callback.
 *   DAST_STATE_TCP_LISTEN  a listening TCP PCB; counts accepts and bytes read
 *                          (recv copy is bounded — overflow attempts must not
 *                          overrun this fixed buffer).
 *
 * Control protocol (UDP port 9997):
 *   Script → calc  "NEXT"  advance to the next test
 *   Script → calc  "DONE"  all tests complete, calc exits cleanly
 *   Script → calc  "ABRT"  abort run, calc exits
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <lwip.h>

#include "common/lwip_example.h"
#include "dast_tests.h"

#define DAST_RECV_CAP      128
#define DAST_TCP_ACTIVE_MAX  4
#define DAST_CTRL_PORT      9997

static volatile uint16_t dast_events;
static volatile uint16_t dast_accepts;
static volatile uint16_t dast_last_len;
static char dast_recv_buf[DAST_RECV_CAP];

static struct udp_pcb *dast_udp;
static struct tcp_pcb *dast_tcp_listen;
static struct tcp_pcb *dast_tcp_active[DAST_TCP_ACTIVE_MAX];

/* Control channel state — set by the control PCB recv callback. */
#define DAST_CTRL_NONE  0
#define DAST_CTRL_NEXT  1
#define DAST_CTRL_DONE  2
#define DAST_CTRL_ABRT  3
static volatile uint8_t dast_ctrl_signal = DAST_CTRL_NONE;
static struct udp_pcb *dast_ctrl_pcb = NULL;

static ip_addr_t dast_ip_any(void)
{
    ip_addr_t any;
    IP_ADDR4(&any, 0, 0, 0, 0);
    return any;
}

/* ---- Control channel ---------------------------------------------------- */

static void dast_ctrl_recv(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                           const ip_addr_t *addr, u16_t port)
{
    (void)arg; (void)pcb; (void)addr; (void)port;
    if (!p)
        return;
    char buf[8] = {0};
    pbuf_copy_partial(p, buf, sizeof(buf) - 1, 0);
    pbuf_free(p);

    if (strncmp(buf, "NEXT", 4) == 0)
        dast_ctrl_signal = DAST_CTRL_NEXT;
    else if (strncmp(buf, "DONE", 4) == 0)
        dast_ctrl_signal = DAST_CTRL_DONE;
    else if (strncmp(buf, "ABRT", 4) == 0)
        dast_ctrl_signal = DAST_CTRL_ABRT;
}

static bool dast_ctrl_open(void)
{
    ip_addr_t any = dast_ip_any();
    dast_ctrl_pcb = udp_new();
    if (!dast_ctrl_pcb)
        return false;
    if (udp_bind(dast_ctrl_pcb, &any, DAST_CTRL_PORT) != ERR_OK)
    {
        udp_remove(dast_ctrl_pcb);
        dast_ctrl_pcb = NULL;
        return false;
    }
    udp_recv(dast_ctrl_pcb, dast_ctrl_recv, NULL);
    return true;
}

static void dast_ctrl_close(void)
{
    if (dast_ctrl_pcb)
    {
        udp_remove(dast_ctrl_pcb);
        dast_ctrl_pcb = NULL;
    }
}

/* ---- UDP listener ------------------------------------------------------- */

static void dast_udp_recv(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                          const ip_addr_t *addr, u16_t port)
{
    (void)arg; (void)pcb; (void)addr; (void)port;
    if (p)
    {
        u16_t n = pbuf_copy_partial(p, dast_recv_buf,
                                    (u16_t)(p->tot_len < DAST_RECV_CAP
                                            ? p->tot_len : DAST_RECV_CAP),
                                    0);
        dast_last_len = n;
        dast_events++;
        pbuf_free(p);
    }
}

static bool dast_udp_open(uint16_t port)
{
    ip_addr_t any = dast_ip_any();
    dast_udp = udp_new();
    if (!dast_udp)
        return false;
    if (udp_bind(dast_udp, &any, port) != ERR_OK)
    {
        udp_remove(dast_udp);
        dast_udp = NULL;
        return false;
    }
    udp_recv(dast_udp, dast_udp_recv, NULL);
    return true;
}

static void dast_udp_close(void)
{
    if (dast_udp)
    {
        udp_remove(dast_udp);
        dast_udp = NULL;
    }
}

/* ---- TCP listener ------------------------------------------------------- */

static bool dast_tcp_track(struct tcp_pcb *pcb)
{
    for (uint8_t i = 0; i < DAST_TCP_ACTIVE_MAX; i++)
    {
        if (!dast_tcp_active[i])
        {
            dast_tcp_active[i] = pcb;
            return true;
        }
    }
    return false;
}

static void dast_tcp_untrack(struct tcp_pcb *pcb)
{
    for (uint8_t i = 0; i < DAST_TCP_ACTIVE_MAX; i++)
    {
        if (dast_tcp_active[i] == pcb)
        {
            dast_tcp_active[i] = NULL;
            return;
        }
    }
}

static void dast_tcp_err(void *arg, err_t err)
{
    (void)err;
    dast_tcp_untrack((struct tcp_pcb *)arg);
}

static err_t dast_tcp_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p,
                           err_t err)
{
    (void)arg;
    if (err != ERR_OK)
    {
        if (p) pbuf_free(p);
        return err;
    }
    if (!p)
    {
        dast_tcp_untrack(tpcb);
        tcp_arg(tpcb, NULL);
        tcp_recv(tpcb, NULL);
        tcp_err(tpcb, NULL);
        tcp_close(tpcb);
        return ERR_OK;
    }
    u16_t n = pbuf_copy_partial(p, dast_recv_buf,
                                (u16_t)(p->tot_len < DAST_RECV_CAP
                                        ? p->tot_len : DAST_RECV_CAP),
                                0);
    dast_last_len = n;
    dast_events++;
    tcp_recved(tpcb, p->tot_len);
    pbuf_free(p);
    return ERR_OK;
}

static err_t dast_tcp_accept(void *arg, struct tcp_pcb *newpcb, err_t err)
{
    (void)arg;
    if (err != ERR_OK || !newpcb)
        return ERR_VAL;
    dast_accepts++;
    if (!dast_tcp_track(newpcb))
    {
        tcp_abort(newpcb);
        return ERR_ABRT;
    }
    tcp_arg(newpcb, newpcb);
    tcp_recv(newpcb, dast_tcp_recv);
    tcp_err(newpcb, dast_tcp_err);
    return ERR_OK;
}

static bool dast_tcp_open(uint16_t port)
{
    ip_addr_t any = dast_ip_any();
    struct tcp_pcb *pcb = tcp_new();
    if (!pcb)
        return false;
    if (tcp_bind(pcb, &any, port) != ERR_OK)
    {
        tcp_abort(pcb);
        return false;
    }
    dast_tcp_listen = tcp_listen_with_backlog(pcb, 2);
    if (!dast_tcp_listen)
    {
        tcp_abort(pcb);
        return false;
    }
    tcp_accept(dast_tcp_listen, dast_tcp_accept);
    return true;
}

static void dast_tcp_close(void)
{
    if (dast_tcp_listen)
    {
        struct tcp_pcb *pcb = dast_tcp_listen;
        dast_tcp_listen = NULL;
        tcp_accept(pcb, NULL);
        if (tcp_close(pcb) != ERR_OK)
            tcp_abort(pcb);
    }
    for (uint8_t i = 0; i < DAST_TCP_ACTIVE_MAX; i++)
    {
        struct tcp_pcb *pcb = dast_tcp_active[i];
        if (!pcb)
            continue;
        dast_tcp_active[i] = NULL;
        tcp_arg(pcb, NULL);
        tcp_recv(pcb, NULL);
        tcp_sent(pcb, NULL);
        tcp_err(pcb, NULL);
        tcp_poll(pcb, NULL, pcb->pollinterval);
        tcp_abort(pcb);
    }
}

/* ---- state lifecycle ---------------------------------------------------- */

static bool dast_enter_state(const dast_test_t *t)
{
    dast_events = 0;
    dast_accepts = 0;
    dast_last_len = 0;
    switch (t->state)
    {
    case DAST_STATE_UDP_RECV:
        return dast_udp_open(t->port);
    case DAST_STATE_TCP_LISTEN:
        return dast_tcp_open(t->port);
    case DAST_STATE_IDLE:
    case DAST_STATE_RAW_RECV:
    default:
        return true;
    }
}

static void dast_leave_state(const dast_test_t *t)
{
    switch (t->state)
    {
    case DAST_STATE_UDP_RECV:
        dast_udp_close();
        break;
    case DAST_STATE_TCP_LISTEN:
        dast_tcp_close();
        break;
    default:
        break;
    }
}

static void dast_close_all(void)
{
    dast_udp_close();
    dast_tcp_close();
    dast_ctrl_close();
}

/* ---- display ------------------------------------------------------------ */

static const char *dast_state_name(dast_state_t s)
{
    switch (s)
    {
    case DAST_STATE_UDP_RECV:   return "udp_recv";
    case DAST_STATE_TCP_LISTEN: return "tcp_listen";
    case DAST_STATE_RAW_RECV:   return "raw_recv";
    case DAST_STATE_IDLE:
    default:                    return "idle";
    }
}

static void dast_draw_test(int idx, const dast_test_t *t, bool open_ok)
{
    lwip_example_clear();
    lwip_example_linef("DAST %d/%d", idx + 1, DAST_TEST_COUNT);
    lwip_example_line(t->name);
    if (t->port)
        lwip_example_linef("state: %s:%u", dast_state_name(t->state), t->port);
    else
        lwip_example_linef("state: %s", dast_state_name(t->state));
    if (!open_ok)
        lwip_example_line("!! listener open FAILED");
    lwip_example_line(t->intent);
    lwip_example_line("");
    lwip_example_line("waiting for probe...");
}

static uint8_t dast_line_y(uint8_t row)
{
    return (uint8_t)(LWIP_EXAMPLE_TOP + (row * lwip_example_line_h()));
}

static void dast_status_line(uint8_t row, const char *text)
{
    uint8_t y = dast_line_y(row);
    os_FontSelect(os_SmallFont);
    os_FontDrawText("                                                ",
                    LWIP_EXAMPLE_LEFT, y);
    os_FontDrawText(text ? text : "", LWIP_EXAMPLE_LEFT, y);
}

static void dast_draw_counter(const dast_test_t *t)
{
    char line[40];
    if (t->state == DAST_STATE_TCP_LISTEN)
        snprintf(line, sizeof(line), "acc:%u evt:%u len:%u",
                 (unsigned)dast_accepts, (unsigned)dast_events,
                 (unsigned)dast_last_len);
    else
        snprintf(line, sizeof(line), "evt:%u len:%u",
                 (unsigned)dast_events, (unsigned)dast_last_len);
    dast_status_line(7, line);
}

static bool dast_network_ready(const lwip_netif_info_t *info)
{
    return info && info->has_netif && info->up && info->link_up &&
           info->has_ipv4;
}

static void dast_draw_start(const lwip_netif_info_t *info)
{
    char line[44];

    lwip_example_clear();
    lwip_example_line("lwIP DAST harness");

    if (!info || !info->has_netif || !info->has_ipv4)
    {
        lwip_example_line("waiting for IP...");
    }
    else
    {
        snprintf(line, sizeof(line), "IP:%u.%u.%u.%u",
                 info->ipv4_addr[0], info->ipv4_addr[1],
                 info->ipv4_addr[2], info->ipv4_addr[3]);
        lwip_example_line(line);
        snprintf(line, sizeof(line), "GW:%u.%u.%u.%u",
                 info->ipv4_gateway[0], info->ipv4_gateway[1],
                 info->ipv4_gateway[2], info->ipv4_gateway[3]);
        lwip_example_line(line);
    }

    lwip_example_line("");
    lwip_example_linef("%d tests. ctrl port: %u", DAST_TEST_COUNT, DAST_CTRL_PORT);
    lwip_example_line("run: lwip-dast.sh --ip <above>");
    lwip_example_line("[clear] quit");
}

static bool dast_wait_for_network(lwip_netif_info_t *info)
{
    uint8_t status_ticks = 0;

    memset(info, 0, sizeof(*info));
    (void)lwip_default_netif_info(info);
    dast_draw_start(info);
    lwip_example_draw_mem_stats();

    while (!dast_network_ready(info))
    {
        lwip_poll_network_events();
        lwip_example_mem_stats_tick();

        if (++status_ticks >= 32)
        {
            lwip_netif_info_t next = {0};
            status_ticks = 0;
            (void)lwip_default_netif_info(&next);
            if (memcmp(info, &next, sizeof(*info)) != 0)
            {
                *info = next;
                dast_draw_start(info);
                lwip_example_draw_mem_stats();
            }
        }

        uint8_t key = os_GetCSC();
        if (key == sk_Clear)
        {
            dast_close_all();
            return false;
        }
    }

    dast_draw_start(info);
    lwip_example_draw_mem_stats();
    return true;
}

/* Pump the stack until the script sends NEXT (or DONE/ABRT).
 * Returns DAST_CTRL_NEXT, DAST_CTRL_DONE, or DAST_CTRL_ABRT. */
static uint8_t dast_run_test(int idx, const dast_test_t *t)
{
    bool open_ok = dast_enter_state(t);
    dast_draw_test(idx, t, open_ok);
    lwip_example_draw_mem_stats();

    uint16_t last_drawn = 0xFFFF;
    dast_ctrl_signal = DAST_CTRL_NONE;

    while (dast_ctrl_signal == DAST_CTRL_NONE)
    {
        lwip_poll_network_events();
        lwip_example_mem_stats_tick();

        if (dast_events != last_drawn)
        {
            dast_draw_counter(t);
            last_drawn = dast_events;
        }

        /* Still allow [clear] on the calc as an emergency abort. */
        if (os_GetCSC() == sk_Clear)
        {
            dast_leave_state(t);
            return DAST_CTRL_ABRT;
        }
    }

    dast_leave_state(t);
    return dast_ctrl_signal;
}

int main(void)
{
    if (!lwip_example_stack_start())
        return 1;

    lwip_netif_info_t info = {0};
    if (!dast_wait_for_network(&info))
    {
        dast_close_all();
        return lwip_example_finish(0);
    }

    if (!dast_ctrl_open())
    {
        lwip_example_show_and_wait("DAST failed", "ctrl port open");
        return lwip_example_finish(1);
    }

    /* Show IP and wait for the script to send the first NEXT. */
    dast_draw_start(&info);
    lwip_example_draw_mem_stats();

    /* Pump until script sends NEXT to kick off test 1, or [clear] to abort. */
    dast_ctrl_signal = DAST_CTRL_NONE;
    while (dast_ctrl_signal == DAST_CTRL_NONE)
    {
        lwip_poll_network_events();
        lwip_example_mem_stats_tick();
        if (os_GetCSC() == sk_Clear)
        {
            dast_close_all();
            return lwip_example_finish(0);
        }
    }
    if (dast_ctrl_signal != DAST_CTRL_NEXT)
    {
        dast_close_all();
        return lwip_example_finish(0);
    }

    for (int i = 0; i < DAST_TEST_COUNT; i++)
    {
        uint8_t sig = dast_run_test(i, &dast_tests[i]);
        if (sig == DAST_CTRL_ABRT || sig == DAST_CTRL_DONE)
            break;
    }

    lwip_example_show_and_wait("DAST complete", "see host report");
    dast_close_all();
    return lwip_example_finish(0);
}
