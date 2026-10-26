/* Shared harness for the networked lwIP-CE suites in tests/net.
 *
 * Each suite logs PASS/FAIL/METRIC lines to the NETLOG appvar and ends on a
 * solid green or red screen. tests/net/run.py serves the host endpoints and
 * answers control requests sent with host_call(). */
#ifndef NET_TEST_H
#define NET_TEST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <lwip.h>

#define HOST           "192.168.84.1"
#define CALC_IP_BYTES  {192, 168, 84, 2}
#define HOST_IP_BYTES  {192, 168, 84, 1}
#define PORT_CONTROL   7000
#define PORT_ECHO      7001
#define PORT_UDP       7002
#define PORT_SERVER    7003
#define PORT_WS        7004
#define PORT_TLS_BAD   7005
#define PORT_BULK      7006
#define PORT_SINK      7007
#define PORT_HOLD      7008
#define PORT_PSK       7100
#define PORT_CLOSED    7999
#define BULK_BYTES     262144ul

extern uint8_t buf[2048];
extern char line[96];

/* Starts graphics, the log, the stack and DHCP + DNS. False if the stack or
 * the lease could not be brought up (already logged as failures). */
bool net_begin(const char *suite);
/* Logs the verdict, stops the stack, paints the verdict screen and waits for
 * a key. Returns the program exit code. */
int net_end(void);

void note(const char *fmt, ...);
bool check(const char *name, bool ok);
void metric(const char *name, unsigned long value, const char *unit);
/* Logs the newest `max` entries of lwIP-CE's error traceback. */
void note_traceback(uint8_t max);

bool pump(bool (*done)(void *), void *arg, uint32_t timeout_ms);
void settle(uint32_t ms);
uint8_t pattern(uint32_t i);
size_t heap_used(void);

/* Sends `cmd` to the host control server and waits for its reply. The reply
 * text after "OK " is copied to `reply`. False on ERR or timeout. */
bool host_call(const char *cmd, char *reply, size_t reply_len, uint32_t timeout_ms);

bool not_connecting(void *sock);
bool not_active(void *sock);
struct lwip_socket *open_socket(lwip_socket_type_t type, const char *host, uint16_t port,
                                const char *ws_path, uint32_t timeout_ms);
bool write_all(struct lwip_socket *sock, const uint8_t *data, size_t len);
size_t read_exact(struct lwip_socket *sock, uint8_t *dst, size_t len, uint32_t timeout_ms);
void close_socket(struct lwip_socket *sock);

#endif
