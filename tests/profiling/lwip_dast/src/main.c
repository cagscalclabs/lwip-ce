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
 *   DAST_STATE_TLS_CLIENT  active TLS client; connects back to the host runner
 *                          and echoes encrypted application data.
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
#define DAST_TLS_HOST_CAP 48
#define DAST_TLS_TIMEOUT_MS 45000u
#define DAST_TLS_RX_MAX 1024u

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
#define DAST_CTRL_START 4
static volatile uint8_t dast_ctrl_signal = DAST_CTRL_NONE;
static struct udp_pcb *dast_ctrl_pcb = NULL;
static ip_addr_t dast_ctrl_peer;
static bool dast_ctrl_peer_valid = false;

static struct lwip_socket dast_tls_sock;
static bool dast_tls_live = false;
static char dast_tls_host[DAST_TLS_HOST_CAP];
static volatile uint16_t dast_tls_err;
static volatile int dast_tls_raw;
static volatile uint8_t dast_tls_status;

/* Set by dast_dhcp_service_cb once lwip_netif_request_services() resolves
 * the DHCP request (success, failure, or timeout). Using the callback form
 * (rather than the bare lwip_request_services(), which has no callback and
 * therefore never registers a retry entry -- see main()) gets us the same
 * re-polling-until-netif-exists behavior the socket-connect path relies on. */
static volatile lwip_netif_service_status_t dast_dhcp_status = (lwip_netif_service_status_t)0xFF;

static void dast_dhcp_service_cb(struct netif *netif, void *arg,
                                 uint8_t service_id,
                                 lwip_netif_service_status_t status)
{
    (void)netif;
    (void)arg;
    if (service_id == LWIP_SOCKET_SVC_DHCP)
    {
        dast_dhcp_status = status;
    }
}

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
    (void)arg;
    (void)pcb;
    (void)port;
    if (!p)
        return;
    char buf[8] = {0};
    pbuf_copy_partial(p, buf, sizeof(buf) - 1, 0);
    pbuf_free(p);

    if (addr)
    {
        ip_addr_copy(dast_ctrl_peer, *addr);
        dast_ctrl_peer_valid = true;
    }

    if (strncmp(buf, "NEXT", 4) == 0)
        dast_ctrl_signal = DAST_CTRL_NEXT;
    else if (strncmp(buf, "DONE", 4) == 0)
        dast_ctrl_signal = DAST_CTRL_DONE;
    else if (strncmp(buf, "ABRT", 4) == 0)
        dast_ctrl_signal = DAST_CTRL_ABRT;
    else if (strncmp(buf, "START", 5) == 0)
        dast_ctrl_signal = DAST_CTRL_START;
}

/* Sends READY back to whichever host last sent us a control message.
 * Used to ack START (before the test loop begins) and to ack completion
 * of each test (before the host's next NEXT can be acted on). */
static void dast_ctrl_send_ready(void)
{
    if (!dast_ctrl_pcb || !dast_ctrl_peer_valid)
        return;
    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, 5, PBUF_RAM);
    if (!p)
        return;
    memcpy(p->payload, "READY", 5);
    udp_sendto(dast_ctrl_pcb, p, &dast_ctrl_peer, DAST_CTRL_PORT);
    pbuf_free(p);
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

/* ---- TLS client --------------------------------------------------------- */

static void dast_tls_event(struct lwip_socket *sock,
                           lwip_socket_event_type_t type,
                           const void *ev_data,
                           void *arg)
{
    (void)arg;
    if (type == LWIP_SOCKET_EV_STATE_CHANGE)
    {
        const lwip_socket_state_data_t *st =
            (const lwip_socket_state_data_t *)ev_data;
        if (st)
        {
            dast_tls_status = (uint8_t)st->current;
            if (st->current == LWIP_STATUS_CONNECTED)
            {
                dast_accepts++;
                dast_events++;
            }
        }
        return;
    }
    if (type == LWIP_SOCKET_EV_ERROR)
    {
        const lwip_socket_error_data_t *err =
            (const lwip_socket_error_data_t *)ev_data;
        dast_tls_err = err ? (uint16_t)err->err : (uint16_t)sock->last_error;
        dast_tls_raw = err ? err->raw_error : 0;
        dast_tls_status = (uint8_t)sock->status;
        dast_events++;
    }
}

static bool dast_tls_open(uint16_t port)
{
    lwip_error_t err;

    if (!dast_ctrl_peer_valid)
        return false;

    memset(&dast_tls_sock, 0, sizeof(dast_tls_sock));
    memset(dast_tls_host, 0, sizeof(dast_tls_host));
    if (!ipaddr_ntoa_r(&dast_ctrl_peer, dast_tls_host, sizeof(dast_tls_host)))
        return false;

    err = lwip_socket_create_ex(&dast_tls_sock, LWIP_SOCKET_ALTCP_TLS,
                                LWIP_NETIF_EXT, NULL,
                                DAST_TLS_TIMEOUT_MS, DAST_TLS_RX_MAX);
    if (err != LWIP_OK)
    {
        dast_tls_err = (uint16_t)err;
        dast_tls_status = (uint8_t)dast_tls_sock.status;
        return false;
    }

    lwip_socket_on_event(&dast_tls_sock, LWIP_SOCKET_EVENTF_ALL,
                         dast_tls_event, NULL);
    dast_tls_live = true;
    dast_tls_status = (uint8_t)dast_tls_sock.status;

    err = lwip_socket_connect(&dast_tls_sock, dast_tls_host, port);
    if (err != LWIP_OK)
    {
        dast_tls_err = (uint16_t)err;
        dast_tls_status = (uint8_t)dast_tls_sock.status;
        lwip_socket_destroy(&dast_tls_sock);
        dast_tls_live = false;
        return false;
    }
    return true;
}

static void dast_tls_pump_rx(void)
{
    if (!dast_tls_live)
        return;

    dast_tls_status = (uint8_t)lwip_socket_status(&dast_tls_sock);

    size_t avail = lwip_socket_available(&dast_tls_sock);
    while (avail > 0)
    {
        size_t take = avail < DAST_RECV_CAP ? avail : DAST_RECV_CAP;
        size_t got = lwip_socket_read(&dast_tls_sock,
                                      (uint8_t *)dast_recv_buf, take);
        if (!got)
            break;
        dast_last_len = (uint16_t)got;
        dast_events++;
        if (lwip_socket_write(&dast_tls_sock, (const uint8_t *)dast_recv_buf,
                              got) != LWIP_OK)
        {
            lwip_socket_abort(&dast_tls_sock);
            break;
        }
        avail = lwip_socket_available(&dast_tls_sock);
    }
}

static void dast_tls_close(void)
{
    if (!dast_tls_live)
        return;

    if (lwip_socket_is_active(&dast_tls_sock))
    {
        uint32_t start;
        (void)lwip_socket_close(&dast_tls_sock);
        start = lwip_now_ms();
        while (lwip_socket_is_active(&dast_tls_sock) &&
               (uint32_t)(lwip_now_ms() - start) < 3000u)
        {
            lwip_service_events();
        }
    }

    lwip_socket_destroy(&dast_tls_sock);
    dast_tls_live = false;
}

/* ---- state lifecycle ---------------------------------------------------- */

static bool dast_enter_state(const dast_test_t *t)
{
    dast_events = 0;
    dast_accepts = 0;
    dast_last_len = 0;
    dast_tls_err = 0;
    dast_tls_raw = 0;
    dast_tls_status = 0;
    switch (t->state)
    {
    case DAST_STATE_UDP_RECV:
        return dast_udp_open(t->port);
    case DAST_STATE_TCP_LISTEN:
        return dast_tcp_open(t->port);
    case DAST_STATE_TLS_CLIENT:
        return dast_tls_open(t->port);
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
    case DAST_STATE_TLS_CLIENT:
        dast_tls_close();
        break;
    default:
        break;
    }
}

static void dast_close_all(void)
{
    dast_udp_close();
    dast_tcp_close();
    dast_tls_close();
    dast_ctrl_close();
}

/* ---- display ------------------------------------------------------------ */

static const char *dast_state_name(dast_state_t s)
{
    switch (s)
    {
    case DAST_STATE_UDP_RECV:   return "udp_recv";
    case DAST_STATE_TCP_LISTEN: return "tcp_listen";
    case DAST_STATE_TLS_CLIENT:
        return "tls_client";
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
    lwip_example_line_wrapped(t->intent);
    lwip_example_line("");
    lwip_example_line("waiting for probe...");

    /* Force an immediate blit -- see dast_draw_start()'s comment. Without
     * this, the test-transition screen can sit stale on whatever was drawn
     * before (e.g. the IP screen) even though the calc has already moved
     * on and is correctly waiting for the probe; the periodic blit timer
     * alone isn't reliably catching these transition redraws in time. */
    lwip_example_present();
}

static uint8_t dast_line_y(uint8_t row)
{
    return (uint8_t)(LWIP_EXAMPLE_TOP + (row * lwip_example_line_h()));
}

static void dast_status_line(uint8_t row, const char *text)
{
    uint8_t y = dast_line_y(row);
    gfx_SetColor(LWIP_EXAMPLE_COLOR_BG);
    gfx_FillRectangle(LWIP_EXAMPLE_LEFT, y,
                      LWIP_EXAMPLE_LCD_W - LWIP_EXAMPLE_LEFT,
                      lwip_example_line_h());
    gfx_SetTextFGColor(LWIP_EXAMPLE_COLOR_FG);
    gfx_PrintStringXY(text ? text : "", LWIP_EXAMPLE_LEFT, y);
}

static void dast_draw_counter(const dast_test_t *t)
{
    char line[48];
    if (t->state == DAST_STATE_TLS_CLIENT)
        snprintf(line, sizeof(line), "st:%u evt:%u len:%u e:%u r:%d",
                 (unsigned)dast_tls_status, (unsigned)dast_events,
                 (unsigned)dast_last_len, (unsigned)dast_tls_err,
                 dast_tls_raw);
    else if (t->state == DAST_STATE_TCP_LISTEN)
        snprintf(line, sizeof(line), "acc:%u evt:%u len:%u",
                 (unsigned)dast_accepts, (unsigned)dast_events,
                 (unsigned)dast_last_len);
    else
        snprintf(line, sizeof(line), "evt:%u len:%u",
                 (unsigned)dast_events, (unsigned)dast_last_len);
    dast_status_line(7, line);
}

static void dast_draw_start(const lwip_netif_info_t *info)
{
    char line[44];

    lwip_example_clear();
    lwip_example_line("lwIP DAST harness");

    if (!info || !info->has_netif || !info->has_ipv4)
    {
        lwip_example_line("waiting for IP...");
        /* TEMP diagnostic: which precondition is actually missing. */
        snprintf(line, sizeof(line), "netif:%d up:%d link:%d",
                 info ? info->has_netif : -1,
                 info ? info->up : -1,
                 info ? info->link_up : -1);
        lwip_example_line(line);
        snprintf(line, sizeof(line), "dhcp_run:%d dhcp_st:%u",
                 info ? info->dhcp_running : -1,
                 info ? (unsigned)info->dhcp_state : 0u);
        lwip_example_line(line);
        snprintf(line, sizeof(line), "svc_cb:%u",
                 (unsigned)dast_dhcp_status);
        lwip_example_line(line);
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

    /* Force an immediate blit rather than relying on the periodic
     * sys_timeout-driven one (see lwip_example_present()'s comment) --
     * removes any doubt about whether this screen is actually reaching
     * the display promptly while diagnosing the DHCP hang. */
    lwip_example_present();
}

/* Pump the stack until the script sends NEXT (or DONE/ABRT).
 * Returns DAST_CTRL_NEXT, DAST_CTRL_DONE, or DAST_CTRL_ABRT. */
static uint8_t dast_run_test(int idx, const dast_test_t *t)
{
    bool open_ok = dast_enter_state(t);
    dast_draw_test(idx, t, open_ok);
    lwip_example_draw_mem_stats();

    /* Tell the host this test's listener is open and ready for its probe.
     * The host blocks on this before dispatching, so the probe never races
     * against the listener still being set up. */
    dast_ctrl_send_ready();

    uint16_t last_drawn = 0xFFFF;
    dast_ctrl_signal = DAST_CTRL_NONE;

    while (dast_ctrl_signal == DAST_CTRL_NONE)
    {
        uint8_t key;
        lwip_service_events();
        if (t->state == DAST_STATE_TLS_CLIENT)
            dast_tls_pump_rx();

        key = os_GetCSC();
        lwip_example_mem_stats_tick(key);

        if (dast_events != last_drawn)
        {
            dast_draw_counter(t);
            last_drawn = dast_events;
        }

        /* Still allow [clear] on the calc as an emergency abort. */
        if (key == sk_Clear)
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

    /* Open the control port immediately and proceed reactively, the same
     * way the IRC example doesn't block on network readiness up front --
     * udp_bind(any, PORT) doesn't require a routable address yet, so this
     * is safe before DHCP completes. Blocking here on link_up/has_ipv4
     * (the old dast_wait_for_network) could hang indefinitely if USB
     * enumeration or DHCP took longer than expected, with no way to see
     * what was actually happening. */
    if (!dast_ctrl_open())
    {
        lwip_example_show_and_wait("DAST failed", "ctrl port open");
        return lwip_example_finish(1);
    }

    lwip_netif_info_t info = {0};
    (void)lwip_default_netif_info(&info);
    dast_draw_start(&info);
    lwip_example_draw_mem_stats();

    /* DHCP is normally requested implicitly by lwip_socket_connect() (see
     * apply_service_flags()/LWIP_SOCKET_SVC_DHCP in lwIP.c) -- that's how
     * examples like irc_chat get an IP without ever calling this API
     * directly. DAST never calls lwip_socket_connect() for its control
     * channel or most test states (they bind raw udp/tcp PCBs directly),
     * so DHCP must be requested explicitly. Use the callback form
     * (lwip_netif_request_services, not the bare lwip_request_services)
     * so the request registers into g_netif_service_requests[] and gets
     * re-polled by netif_services_dispatch() every 100ms -- including
     * re-resolving the netif via find_external_netif() on each tick --
     * until USB enumeration has actually created the netif and DHCP can
     * start. The callback-less form resolves the netif once and silently
     * no-ops if it doesn't exist yet, with nothing left to retry it. */
    (void)lwip_netif_request_services(NULL, LWIP_SOCKET_SVC_DHCP,
                                      dast_dhcp_service_cb, NULL);

    /* Pump until script sends START, or [clear] to abort. Network status
     * (IP/gateway) is redrawn as it changes so the operator can see DHCP
     * progress live instead of a static "waiting" screen. This screen
     * never advances on its own -- the host script must explicitly send
     * START once it has the calc's IP and is ready to begin, at which
     * point the calc acks with READY and only then starts waiting for
     * the first NEXT. */
    uint8_t status_ticks = 0;
    dast_ctrl_signal = DAST_CTRL_NONE;
    while (dast_ctrl_signal == DAST_CTRL_NONE)
    {
        uint8_t key;
        lwip_service_events();
        key = os_GetCSC();
        // lwip_example_mem_stats_tick(key);

        if (++status_ticks >= 32)
        {
            lwip_netif_info_t next = {0};
            status_ticks = 0;
            (void)lwip_default_netif_info(&next);
            if (memcmp(&info, &next, sizeof(info)) != 0)
            {
                info = next;
                dast_draw_start(&info);
                lwip_example_draw_mem_stats();
            }
        }

        if (key == sk_Clear)
        {
            dast_close_all();
            return lwip_example_finish(0);
        }
    }
    if (dast_ctrl_signal != DAST_CTRL_START)
    {
        dast_close_all();
        return lwip_example_finish(0);
    }
    /* dast_run_test() sends READY itself once it opens the first test's
     * listener -- that doubles as the ack for START, so nothing to send
     * here. */

    for (int i = 0; i < DAST_TEST_COUNT; i++)
    {
        uint8_t sig = dast_run_test(i, &dast_tests[i]);
        if (sig == DAST_CTRL_ABRT || sig == DAST_CTRL_DONE)
            break;
        dast_ctrl_send_ready();
    }

    lwip_example_show_and_wait("DAST complete", "see host report");
    dast_close_all();
    return lwip_example_finish(0);
}
