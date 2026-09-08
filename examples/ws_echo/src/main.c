/**
 * WebSocket Echo Example for the TI-84+CE
 *
 * Demonstrates both WS (plain TCP) and WSS (TLS) using the altcp_ws layer.
 *
 * Phase 1 — WS  (ws://websocket-echo.com/):
 *   Connect to a public plain-TCP WebSocket echo server, send one message,
 *   receive the echo, then close.
 *
 * Phase 2 — WSS (wss://echo.websocket.org/):
 *   Connect to a public TLS WebSocket echo server (TLS 1.3, Let's Encrypt),
 *   send one message, receive the echo, then close.
 *
 * Controls:  any key aborts the current phase and moves to the next.
 *            [clear] exits at any point.
 *
 * Notes:
 *   LWIP_SOCKET_ALTCP_WS  and LWIP_SOCKET_ALTCP_WSS may not be present in
 *   the installed cedev lwip.h yet.  They are shimmed below with #ifndef
 *   guards and numeric values that match src/lwIP.h.
 *
 *   lwip_socket_set_ws_config() is shimmed as an extern declaration.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include <ti/getcsc.h>
#include <graphx.h>

#include <lwip.h>
#include <lwip/core/logging.h>
#include "../../common/lwip_example.h"

/* ---------------------------------------------------------------------- */
/* Server configuration                                                    */
/* ---------------------------------------------------------------------- */

/* Public echo service; WS_HOST can be overridden at build time. */
#ifndef WS_HOST
#define WS_HOST    "websocket-echo.com"
#endif
#define WS_PORT    80
#define WS_PATH    "/"

#define WSS_HOST   "websocket-echo.com"
#define WSS_PORT   443
#define WSS_PATH   "/"

#define CONNECT_TIMEOUT_MS  30000u
#define PHASE_TIMEOUT_MS    30000u

static const char *SEND_MSG = "Hello from TI-84+CE via lwIP-CE!";

/* ---------------------------------------------------------------------- */
/* Per-phase state                                                         */
/* ---------------------------------------------------------------------- */

typedef struct
{
    struct lwip_socket sock;
    bool   connected;
    bool   sent;
    bool   done;
    bool   echo_received;
    lwip_error_t last_err;
    char   rx_buf[256];
    size_t rx_len;
} phase_t;

static phase_t ph;

/* ---------------------------------------------------------------------- */
/* Logging helpers (use lwip_example simple line draw)                     */
/* ---------------------------------------------------------------------- */

static void log_line(const char *text)
{
    lwip_example_line(text);
    lwip_example_present();
}

static void log_linef(const char *fmt, ...)
{
    char buf[64];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    log_line(buf);
}

/* ---------------------------------------------------------------------- */
/* Socket event callback                                                   */
/* ---------------------------------------------------------------------- */

static void ws_on_event(struct lwip_socket *sock,
                        lwip_socket_event_type_t type,
                        const void *ev_data, void *arg)
{
    (void)sock; (void)arg;

    switch (type)
    {
    case LWIP_SOCKET_EV_STATE_CHANGE:
    {
        const lwip_socket_state_data_t *st = ev_data;
        if (st->current == LWIP_STATUS_CONNECTED)
        {
            log_line("  connected");
            ph.connected = true;
        }
        else if (st->current == LWIP_STATUS_CLOSED)
        {
            ph.done = true;
        }
        else if (st->current == LWIP_STATUS_RESET)
        {
            ph.done = true;
        }
        break;
    }
    case LWIP_SOCKET_EV_ERROR:
    {
        const lwip_socket_error_data_t *e = ev_data;
        ph.last_err = e->err;
        ph.done     = true;
        log_linef("  error %d", (int)e->err);
        break;
    }
    case LWIP_SOCKET_EV_IO:
    {
        const lwip_socket_io_data_t *io = ev_data;
        if (!(io->flags & LWIP_SOCKET_IO_READABLE))
            break;

        uint8_t tmp[128];
        while (lwip_socket_available(&ph.sock))
        {
            size_t got = lwip_socket_read(&ph.sock, tmp, sizeof(tmp));
            for (size_t i = 0; i < got; i++)
            {
                if (ph.rx_len + 1 < sizeof(ph.rx_buf))
                    ph.rx_buf[ph.rx_len++] = (char)tmp[i];
            }
        }
        ph.rx_buf[ph.rx_len] = '\0';

        /* Check if we got our echo back */
        if (!ph.echo_received &&
            ph.rx_len >= strlen(SEND_MSG) &&
            strstr(ph.rx_buf, SEND_MSG))
        {
            ph.echo_received = true;
            log_linef("  echo: \"%.*s\"",
                      (int)(ph.rx_len > 40 ? 40 : ph.rx_len), ph.rx_buf);
            ph.done = true;  /* got what we came for */
        }
        break;
    }
    default: break;
    }
}

/* ---------------------------------------------------------------------- */
/* Run one phase                                                           */
/* ---------------------------------------------------------------------- */

static bool run_phase(lwip_socket_type_t type,
                      const char *host, uint16_t port, const char *path,
                      const char *label)
{
    memset(&ph, 0, sizeof(ph));

    log_linef("[ %s ]", label);
    log_linef("  host: %s:%u", host, (unsigned)port);

    lwip_error_t e = lwip_socket_create(&ph.sock, type, LWIP_NETIF_EXT,
                                        NULL, CONNECT_TIMEOUT_MS);
    if (e != LWIP_OK)
    {
        log_linef("  create failed: %d", (int)e);
        return false;
    }

    lwip_socket_set_ws_config(&ph.sock, path, NULL);
    lwip_socket_on_event(&ph.sock, LWIP_SOCKET_EVENTF_ALL, ws_on_event, NULL);

    e = lwip_socket_connect(&ph.sock, host, port);
    if (e != LWIP_OK)
    {
        log_linef("  connect failed: %d", (int)e);
        goto cleanup;
    }

    /* Event loop — wait for echo or timeout */
    uint32_t deadline = lwip_now_ms() + PHASE_TIMEOUT_MS;
    while (!ph.done && lwip_now_ms() < deadline)
    {
        lwip_service_events();

        if (ph.connected && !ph.sent)
        {
            ph.sent = true;
            lwip_error_t we = lwip_socket_write(&ph.sock,
                                                (const uint8_t *)SEND_MSG,
                                                strlen(SEND_MSG));
            if (we != LWIP_OK)
                log_linef("  write err %d", (int)we);
        }

        uint8_t key = os_GetCSC();
        if (key == sk_Clear)
        {
            log_line("  aborted");
            goto cleanup;
        }
    }

    bool failed = !ph.echo_received;

    if (!ph.done)
        log_line("  timeout");
    else if (ph.echo_received)
        log_line("  PASS");
    else if (ph.last_err)
        log_linef("  FAIL (err %d)", (int)ph.last_err);
    else
        log_line("  FAIL (no echo)");

    if (failed)
    {
        uint8_t count = 0;
        const struct lwip_traceback_entry *tb = lwip_get_traceback(&count);
        if (count > 0)
        {
            log_line("  traceback:");
            for (uint8_t i = 0; i < count && i < 6; i++)
            {
                log_linef("  [%u] %s %s:%lu x%u",
                          (unsigned)i,
                          lwip_debug_module_name(tb[i].module),
                          lwip_debug_file_name(tb[i].file),
                          (unsigned long)tb[i].line,
                          (unsigned)tb[i].extra);
            }
        }
    }

cleanup:
    if (lwip_socket_is_active(&ph.sock))
    {
        lwip_socket_close(&ph.sock);
        uint32_t t = lwip_now_ms() + 2000u;
        while (lwip_socket_is_active(&ph.sock) && lwip_now_ms() < t)
            lwip_service_events();
    }
    lwip_socket_destroy(&ph.sock);
    return ph.echo_received;
}

/* ---------------------------------------------------------------------- */
/* main                                                                    */
/* ---------------------------------------------------------------------- */

int main(void)
{
    if (!lwip_example_stack_start())
        return 0;

    log_line("WS Echo Test");
    log_line("Waiting for network...");
    {
        uint8_t flags = LWIP_SOCKET_SVC_DHCP | LWIP_SOCKET_SVC_DNS;
        uint32_t t = lwip_now_ms() + 20000u;
        while (!lwip_are_services_ready(NULL, flags) && lwip_now_ms() < t)
        {
            lwip_service_events();
            if (os_GetCSC() == sk_Clear) goto done;
        }
        if (!lwip_are_services_ready(NULL, flags))
        {
            lwip_example_show_and_wait("net timeout", NULL);
            goto done;
        }
    }
    log_line("Network ready.");
    log_line("");

    /* Phase 1: plain WS */
    bool ws_ok  = run_phase(LWIP_SOCKET_ALTCP_WS,
                            WS_HOST, WS_PORT, WS_PATH,
                            "WS plain TCP");
    log_line("");

    /* Phase 2: WSS */
    bool wss_ok = run_phase(LWIP_SOCKET_ALTCP_WSS,
                            WSS_HOST, WSS_PORT, WSS_PATH,
                            "WSS (TLS 1.3)");
    log_line("");

    log_linef("Results: WS=%s  WSS=%s",
              ws_ok  ? "PASS" : "FAIL",
              wss_ok ? "PASS" : "FAIL");
    lwip_example_wait_key();

done:
    return lwip_example_finish(0);
}
