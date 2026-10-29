#!/usr/bin/env python3
"""Keep socket listener callback setup away from invalid TCP poll APIs."""

from pathlib import Path
import re
import subprocess
import tempfile


source = (Path(__file__).resolve().parents[3] / "src/lwIP.c").read_text()


def function(name: str) -> str:
    match = re.search(
        r"^static void " + name + r"\([^;]*?\)\s*\{", source, re.M
    )
    assert match, name
    pos = match.end()
    depth = 1
    while depth:
        depth += (source[pos] == "{") - (source[pos] == "}")
        pos += 1
    return source[match.start():pos] + "\n"


c_test = r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define LWIP_TCP 1
#define LWIP_SOCKET_TCP 1
#define LWIP_SOCKET_UDP 2
#define LWIP_SOCKET_ALTCP 3
#define LWIP_SOCKET_ALTCP_TLS 4
#define LWIP_SOCKET_ALTCP_WS 5
#define LWIP_SOCKET_ALTCP_WSS 6

typedef int lwip_socket_type_t;
struct altcp_pcb { uint8_t pollinterval; };
struct tcp_pcb { uint8_t pollinterval; };
struct udp_pcb { unsigned unused; };
struct lwip_socket {
    int protocol;
    bool is_listen;
    union {
        struct altcp_pcb *altcp;
        struct tcp_pcb *tcp;
        struct udp_pcb *udp;
    } pcb;
};

#define conn_altcp_recv_cb ((void *)1)
#define conn_altcp_sent_cb ((void *)2)
#define conn_altcp_err_cb ((void *)3)
#define conn_altcp_poll_cb ((void *)4)
#define socket_altcp_accept_cb ((void *)5)
#define conn_tcp_recv_cb ((void *)6)
#define conn_tcp_sent_cb ((void *)7)
#define conn_tcp_err_cb ((void *)8)
#define conn_tcp_poll_cb ((void *)9)
#define socket_tcp_accept_cb ((void *)10)
#define conn_udp_recv_cb ((void *)11)

static unsigned arg_calls, accept_calls, recv_calls, sent_calls;
static unsigned err_calls, poll_calls, udp_calls;
static void reset_calls(void)
{
    arg_calls = accept_calls = recv_calls = sent_calls = 0;
    err_calls = poll_calls = udp_calls = 0;
}
static void altcp_arg(struct altcp_pcb *p, void *fn) { (void)p; (void)fn; arg_calls++; }
static void altcp_accept(struct altcp_pcb *p, void *fn) { (void)p; (void)fn; accept_calls++; }
static void altcp_recv(struct altcp_pcb *p, void *fn) { (void)p; (void)fn; recv_calls++; }
static void altcp_sent(struct altcp_pcb *p, void *fn) { (void)p; (void)fn; sent_calls++; }
static void altcp_err(struct altcp_pcb *p, void *fn) { (void)p; (void)fn; err_calls++; }
static void altcp_poll(struct altcp_pcb *p, void *fn, uint8_t interval)
{ (void)p; (void)fn; (void)interval; poll_calls++; }
static void tcp_arg(struct tcp_pcb *p, void *fn) { (void)p; (void)fn; arg_calls++; }
static void tcp_accept(struct tcp_pcb *p, void *fn) { (void)p; (void)fn; accept_calls++; }
static void tcp_recv(struct tcp_pcb *p, void *fn) { (void)p; (void)fn; recv_calls++; }
static void tcp_sent(struct tcp_pcb *p, void *fn) { (void)p; (void)fn; sent_calls++; }
static void tcp_err(struct tcp_pcb *p, void *fn) { (void)p; (void)fn; err_calls++; }
static void tcp_poll(struct tcp_pcb *p, void *fn, uint8_t interval)
{ (void)p; (void)fn; (void)interval; poll_calls++; }
static void udp_recv(struct udp_pcb *p, void *fn, void *arg)
{ (void)p; (void)fn; (void)arg; udp_calls++; }
'''
c_test += function("rebind_pcb_callbacks")
c_test += function("lwip_socket_detach_pcb_callbacks")
c_test += r'''
int main(void)
{
    struct altcp_pcb altcp = {.pollinterval = 4};
    struct tcp_pcb tcp = {.pollinterval = 4};
    struct lwip_socket socket = {
        .protocol = LWIP_SOCKET_ALTCP_TLS,
        .is_listen = true,
        .pcb.altcp = &altcp,
    };

    rebind_pcb_callbacks(&socket);
    assert(arg_calls == 1 && accept_calls == 1);
    assert(recv_calls == 0 && sent_calls == 0 && err_calls == 0 && poll_calls == 0);
    reset_calls();
    lwip_socket_detach_pcb_callbacks(&socket);
    assert(arg_calls == 1 && accept_calls == 1 && poll_calls == 0);

    socket.is_listen = false;
    reset_calls();
    rebind_pcb_callbacks(&socket);
    assert(arg_calls == 1 && accept_calls == 0);
    assert(recv_calls == 1 && sent_calls == 1 && err_calls == 1 && poll_calls == 1);
    reset_calls();
    lwip_socket_detach_pcb_callbacks(&socket);
    assert(arg_calls == 1 && accept_calls == 0);
    assert(recv_calls == 1 && sent_calls == 1 && err_calls == 1 && poll_calls == 1);

    socket.protocol = LWIP_SOCKET_TCP;
    socket.is_listen = true;
    socket.pcb.tcp = &tcp;
    reset_calls();
    rebind_pcb_callbacks(&socket);
    assert(arg_calls == 1 && accept_calls == 1 && poll_calls == 0);
    reset_calls();
    lwip_socket_detach_pcb_callbacks(&socket);
    assert(arg_calls == 1 && accept_calls == 1 && poll_calls == 0);
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix="socket-listener-callbacks-") as tmp:
    tmp = Path(tmp)
    unit = tmp / "test.c"
    binary = tmp / "test"
    unit.write_text(c_test)
    subprocess.run(
        ["cc", "-std=c99", "-Wall", "-Wextra", "-Werror",
         "-fsanitize=address,undefined", str(unit), "-o", str(binary)],
        check=True,
    )
    subprocess.run([str(binary)], check=True)

print("Socket listener callback lifecycle: PASS")
