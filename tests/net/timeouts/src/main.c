/* NETTMO: socket inactivity timeouts are per socket (issue #93).
 *
 * The watchdog used to be extended by any frame on the interface, so a silent
 * or hung socket never timed out while anything else was on the wire. Three
 * checks, each of which the old behaviour fails:
 *
 *   1. a connect to a host that never answers fails at its own window while
 *      the host is sending unrelated ICMP traffic;
 *   2. a connected socket that goes quiet fails at its window under the same
 *      traffic;
 *   3. a socket making progress is never killed by the watchdog.
 */
#include <string.h>

#include "net.h"

#define IDLE_MS        3000u
#define PING_SECONDS   "10"
#define BLACKHOLE      "192.0.2.1"   /* TEST-NET-1: routed at the gateway, never answers */
#define BLACKHOLE_PORT 80

static uint32_t now_ms(void)
{
    return lwip_now_ms();
}

static bool start_unrelated_traffic(void)
{
    /* host_call() already fails unless the host acknowledged with OK; the
     * acknowledgement carries no payload, so there is nothing to inspect. */
    return host_call("pingburst " PING_SECONDS, NULL, 0, 5000);
}

static void test_connect_timeout_under_traffic(void)
{
    struct lwip_socket *s;
    uint32_t t0, elapsed;

    check("connect: unrelated traffic started", start_unrelated_traffic());

    s = lwip_socket_create(LWIP_SOCKET_TCP, LWIP_NETIF_EXT, NULL, IDLE_MS);
    if (!check("connect: socket created", s != NULL))
        return;

    t0 = now_ms();
    if (lwip_socket_connect(s, BLACKHOLE, BLACKHOLE_PORT) != LWIP_OK)
    {
        check("connect: connect accepted", false);
        lwip_socket_destroy(s);
        return;
    }
    pump(not_connecting, s, 20000);
    elapsed = now_ms() - t0;
    metric("connect_timeout_ms", elapsed, "ms");

    check("connect: silent socket failed", lwip_socket_status(s) == LWIP_STATUS_ERROR);
    check("connect: failed near its window (2-9 s)", elapsed >= 2000 && elapsed <= 9000);
    lwip_socket_destroy(s);
}

static void test_idle_connected_socket_under_traffic(void)
{
    struct lwip_socket *s;
    uint32_t t0, elapsed;

    s = open_socket(LWIP_SOCKET_TCP, HOST, PORT_ECHO, NULL, IDLE_MS);
    if (!check("idle: echo socket connected", s != NULL))
        return;

    check("idle: unrelated traffic started", start_unrelated_traffic());
    t0 = now_ms();
    pump(not_active, s, 20000);
    elapsed = now_ms() - t0;
    metric("idle_timeout_ms", elapsed, "ms");

    check("idle: quiet socket failed", lwip_socket_status(s) == LWIP_STATUS_ERROR);
    check("idle: failed near its window (2-9 s)", elapsed >= 2000 && elapsed <= 9000);
    lwip_socket_destroy(s);
}

static void test_progress_keeps_socket_alive(void)
{
    struct lwip_socket *s;
    uint8_t out[16];
    uint8_t in[16];
    bool ok = true;

    s = open_socket(LWIP_SOCKET_TCP, HOST, PORT_ECHO, NULL, IDLE_MS);
    if (!check("progress: echo socket connected", s != NULL))
        return;

    /* Four seconds of regular traffic against a three second window: each
     * exchange re-arms the deadline, so the watchdog must never fire. */
    for (uint8_t i = 0; i < 8 && ok; i++)
    {
        memset(out, (int)pattern(i), sizeof(out));
        settle(400);
        ok = write_all(s, out, sizeof(out)) &&
             read_exact(s, in, sizeof(in), 2000) == sizeof(in) &&
             memcmp(in, out, sizeof(in)) == 0;
        settle(200);
    }
    check("progress: socket stayed alive", ok);
    check("progress: still connected after 4.8 s",
          lwip_socket_status(s) == LWIP_STATUS_CONNECTED);
    close_socket(s);
}

int main(void)
{
    if (net_begin("timeouts"))
    {
        test_connect_timeout_under_traffic();
        test_idle_connected_socket_under_traffic();
        test_progress_keeps_socket_alive();
    }
    return net_end();
}
