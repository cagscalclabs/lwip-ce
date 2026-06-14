/* lwIP-CE DAST calc-side harness.
 *
 * Pairs with build-tools/dast/lwip-dast.py. Walks the shared test list
 * (dast_tests.h, generated from tests/profiling/lwip_dast/dast_tests.json),
 * placing the stack into each test's listener state so the off-calc probe
 * runner can poke a meaningful surface:
 *
 *   DAST_STATE_IDLE        nothing app-side; ARP/ICMP/IP/closed-port handled
 *                          passively by the stack.
 *   DAST_STATE_UDP_RECV    a UDP PCB bound to the test port, counting datagrams
 *                          that reach its recv callback.
 *   DAST_STATE_TCP_LISTEN  a listening TCP PCB; counts accepts and bytes read
 *                          (recv copy is bounded — overflow attempts must not
 *                          overrun this fixed buffer).
 *
 * For each test the screen shows the id/name/intent and a live event counter
 * that updates as probe packets arrive. The operator runs the matching probe
 * on the host, watches what the calc does, then presses [enter] to advance
 * (or [clear] to quit). The host script prompts for the observed outcome.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <lwip.h>

#include "common/lwip_example.h"
#include "dast_tests.h"

/* Bounded recv buffer shared by the UDP/TCP listeners. Deliberately small so
 * oversized probes exercise the bounded-copy path rather than an overrun. */
#define DAST_RECV_CAP 128

static volatile uint16_t dast_events;     /* packets/segments seen this test */
static volatile uint16_t dast_accepts;    /* TCP accepts this test */
static volatile uint16_t dast_last_len;   /* length of last payload handled */
static char dast_recv_buf[DAST_RECV_CAP];

static struct udp_pcb *dast_udp;
static struct tcp_pcb *dast_tcp_listen;

/* 0.0.0.0 = bind to any address. Built locally because the dylib's
 * ip_addr_any global is not exported through libload. */
static ip_addr_t dast_ip_any(void)
{
    ip_addr_t any;
    IP_ADDR4(&any, 0, 0, 0, 0);
    return any;
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
        /* Remote closed. */
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
    tcp_recv(newpcb, dast_tcp_recv);
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
        tcp_close(dast_tcp_listen);
        dast_tcp_listen = NULL;
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
    case DAST_STATE_RAW_RECV:   /* RAW reserved; idle handling suffices today */
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

/* ---- per-test screen + pump loop ---------------------------------------- */

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
    lwip_example_line("[enter] next  [clear] quit");
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

static void dast_draw_start_frame(void)
{
    lwip_example_clear();
    lwip_example_line("lwIP DAST harness");
    lwip_example_line("");
    lwip_example_line("");
    lwip_example_line("");
    lwip_example_line("");
    lwip_example_linef("%d tests. Run host:", DAST_TEST_COUNT);
    lwip_example_line("lwip-dast.sh --ip <above>");
    lwip_example_line("[enter] begin  [clear] quit");
}

static void dast_update_start_status(const lwip_netif_info_t *info,
                                     const char *svc_status)
{
    char line[44];

    if (!info || !info->has_netif)
    {
        dast_status_line(1, "IP: waiting for netif");
        dast_status_line(2, "u:0 l:0 ip:0 gw:0");
        dast_status_line(3, "dh:0 st:0");
    }
    else if (info->has_ipv4)
    {
        snprintf(line, sizeof(line), "IP:%u.%u.%u.%u",
                 info->ipv4_addr[0], info->ipv4_addr[1],
                 info->ipv4_addr[2], info->ipv4_addr[3]);
        dast_status_line(1, line);

        snprintf(line, sizeof(line), "GW:%u.%u.%u.%u",
                 info->ipv4_gateway[0], info->ipv4_gateway[1],
                 info->ipv4_gateway[2], info->ipv4_gateway[3]);
        dast_status_line(2, line);

        snprintf(line, sizeof(line), "u:%u l:%u dh:%u st:%u",
                 (unsigned)info->up,
                 (unsigned)info->link_up,
                 (unsigned)info->dhcp_running,
                 (unsigned)info->dhcp_state);
        dast_status_line(3, line);
    }
    else
    {
        dast_status_line(1, "IP: waiting for DHCP");
        snprintf(line, sizeof(line), "u:%u l:%u ip:%u gw:%u",
                 (unsigned)info->up,
                 (unsigned)info->link_up,
                 (unsigned)info->has_ipv4,
                 (unsigned)info->has_ipv4_gateway);
        dast_status_line(2, line);
        snprintf(line, sizeof(line), "dh:%u st:%u",
                 (unsigned)info->dhcp_running,
                 (unsigned)info->dhcp_state);
        dast_status_line(3, line);
    }

    dast_status_line(4, svc_status ? svc_status : "");
}

static void dast_draw_start(const lwip_netif_info_t *info,
                            const char *svc_status)
{
    dast_draw_start_frame();
    dast_update_start_status(info, svc_status);
}

static bool dast_netif_changed(const lwip_netif_info_t *a,
                               const lwip_netif_info_t *b)
{
    return !a || !b ||
           a->has_netif != b->has_netif ||
           a->up != b->up ||
           a->link_up != b->link_up ||
           a->dhcp_running != b->dhcp_running ||
           a->dhcp_state != b->dhcp_state ||
           a->has_ipv4 != b->has_ipv4 ||
           a->has_ipv4_gateway != b->has_ipv4_gateway ||
           memcmp(a->ipv4_addr, b->ipv4_addr, sizeof(a->ipv4_addr)) != 0 ||
           memcmp(a->ipv4_gateway, b->ipv4_gateway,
                  sizeof(a->ipv4_gateway)) != 0;
}

static bool dast_wait_for_network(lwip_netif_info_t *info)
{
    struct lwip_conn svc = {0};
    bool svc_live = false;
    const char *svc_status = NULL;
    uint8_t status_ticks = 0;
    lwip_netif_info_t last_info = {0};

    if (lwip_conn_create(&svc, NULL, LWIP_PROTO_UDP, LWIP_CONN_SVC_DHCP) == LWIP_OK)
    {
        svc_live = true;
        svc_status = "DHCP requested";
    }
    else
    {
        svc_status = "DHCP request failed";
    }

    memset(info, 0, sizeof(*info));
    (void)lwip_default_netif_info(info);
    dast_draw_start(info, svc_status);
    last_info = *info;

    while (!dast_network_ready(info))
    {
        lwip_poll_network_events();

        if (++status_ticks >= 32)
        {
            lwip_netif_info_t next = {0};
            status_ticks = 0;
            memset(info, 0, sizeof(*info));
            (void)lwip_default_netif_info(info);
            next = *info;
            if (dast_netif_changed(&last_info, &next))
            {
                dast_update_start_status(info, svc_status);
                last_info = next;
            }
        }

        uint8_t key = os_GetCSC();
        if (key == sk_Clear)
        {
            if (svc_live)
            {
                lwip_conn_destroy(&svc);
            }
            return false;
        }
    }

    if (svc_live)
    {
        lwip_conn_destroy(&svc);
    }
    dast_draw_start(info, NULL);
    return true;
}

/* Pump the stack until the operator advances. Returns false on [clear]. */
static bool dast_run_test(int idx, const dast_test_t *t)
{
    bool open_ok = dast_enter_state(t);
    dast_draw_test(idx, t, open_ok);

    uint16_t last_drawn = 0xFFFF;
    bool keep_going = true;
    while (true)
    {
        lwip_poll_network_events();

        if (dast_events != last_drawn)
        {
            dast_draw_counter(t);
            last_drawn = dast_events;
        }

        uint8_t key = os_GetCSC();
        if (key == sk_Enter)
            break;
        if (key == sk_Clear)
        {
            keep_going = false;
            break;
        }
    }

    dast_leave_state(t);
    return keep_going;
}

int main(void)
{
    if (!lwip_example_stack_start())
        return 1;

    /* Show the calc's address so the operator can pass it to --ip. */
    lwip_netif_info_t info = {0};
    if (!dast_wait_for_network(&info))
    {
        return lwip_example_finish(0);
    }

    /* Wait for begin while still pumping the stack. */
    while (true)
    {
        lwip_poll_network_events();
        uint8_t key = os_GetCSC();
        if (key == sk_Enter)
            break;
        if (key == sk_Clear)
            return lwip_example_finish(0);
    }

    for (int i = 0; i < DAST_TEST_COUNT; i++)
    {
        if (!dast_run_test(i, &dast_tests[i]))
            break;
    }

    lwip_example_show_and_wait("DAST complete", "see host report");
    return lwip_example_finish(0);
}
