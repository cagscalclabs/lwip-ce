#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define LWIP_UDP 1
#define LWIP_DHCP 0
#define LWIP_DNS 0
#define LWIP_NSC_NETIF_REMOVED 2
#define LWIP_NETIF_SERVICE_REQUEST_MAX 4
#define LWIP_NETIF_LOOP 1
#define LWIP_SOCKET_SVC_DHCP 1
#define LWIP_SOCKET_SVC_DNS 2
#define LWIP_SOCKET_SVC_SNTP 4
#define LWIP_SOCKET_ALTCP_TLS 3
#define LWIP_SOCKET_ALTCP_WSS 4
#define LWIP_STATUS_INIT 0
#define LWIP_STATUS_WAITING_SERVICES 1
#define LWIP_STATUS_CONNECTING 2
#define LWIP_STATUS_ERROR 3
#define LWIP_OK 0
#define LWIP_ERR_SERVICES 7
#define LWIP_DISPATCH_CONN_SERVICES 0
typedef int lwip_error_t;
typedef int lwip_socket_bind_descriptor_t;
typedef unsigned netif_nsc_reason_t;
typedef int netif_ext_callback_args_t;
struct netif { bool up, link, address, loop; unsigned ready; };
struct lwip_socket {
    struct lwip_socket *registry_next;
    struct netif *netif;
    bool static_applied, has_addrinfo;
    int status, bind_descriptor, protocol;
    uint32_t connect_deadline;
    uint8_t pending_svc_flags;
    uint16_t pending_port;
    char *pending_host;
};
static struct { struct netif *netif; } g_netif_service_requests[4];
static struct lwip_socket *g_conn_registry;
static bool g_services_dirty, g_lwip_stopping;
static struct netif *available;
static uint32_t now;
static unsigned connects, starts, period_sets;
static uint16_t period;
static int apply_error;
static bool netif_is_loop_network(const struct netif *n) { return n && n->loop; }
static bool host_requires_dns(const char *h) { return h && !strcmp(h,"example.com"); }
static bool netif_is_up(const struct netif *n) { return n->up; }
static bool netif_is_link_up(const struct netif *n) { return n->link; }
static bool netif_address_configuration_ready(const struct netif *n) { return n->address; }
static bool sntp_running, sntp_synced;
static bool netif_has_usable_ipv4(const struct netif *n) { return n->address; }
static bool netif_has_usable_gateway(const struct netif *n) { return n->address; }
static int sntp_enabled(void) { return sntp_running; }
static bool lwip_sntp_time_was_set(void) { return sntp_synced; }
static bool lwip_are_services_ready(struct netif *n, unsigned f) { return n && (n->ready & f)==f; }
static struct netif *socket_find_qualifying_netif(int bind) { return available && (!bind || available->loop) ? available : NULL; }
static void socket_bind_netif(struct lwip_socket *c,struct netif *n) { c->netif=n; }
static bool lwip_socket_services_timed_out(uint32_t n,uint32_t d) { return (int32_t)(n-d)>=0; }
static void lwip_socket_set_pending_host(struct lwip_socket *c,const char *h) { assert(!h); free(c->pending_host);c->pending_host=NULL; }
static void lwip_socket_fail(struct lwip_socket *c,int err) { assert(err); c->status=LWIP_STATUS_ERROR; }
static int apply_service_flags(struct netif *n,unsigned f) { (void)n;(void)f; return apply_error; }
static void lwip_socket_connect_now(struct lwip_socket *c,const char *h,unsigned p) { assert(h && p==80); c->status=LWIP_STATUS_CONNECTING; connects++; }
#define mem_free free
static bool netif_service_requests_active(void) { return false; }
static void netif_services_dispatch(uint32_t n) { (void)n; }
static uint32_t sys_now(void) { return now; }
static void lwip_dispatch_set_period(int id,uint16_t p) { (void)id;period=p;period_sets++; }
static uint16_t lwip_dispatch_get_period(int id) { (void)id;return period; }
static uint16_t lwip_dispatch_period_from_ms(unsigned ms) { return ms/10; }
static void lwip_dispatch_attach(int id,void (*fn)(void)) { (void)id;(void)fn; }
static void lwip_dispatch_start(void) { starts++; }
