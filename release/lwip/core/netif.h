/**
 * @file
 * netif API (to be used from TCPIP thread)
 */

/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Adam Dunkels <adam@sics.se>
 *
 */
#ifndef LWIP_HDR_NETIF_H
#define LWIP_HDR_NETIF_H

#include "arch.h"

#define ENABLE_LOOPBACK (LWIP_NETIF_LOOPBACK || LWIP_HAVE_LOOPIF)

#include "err.h"

#include "ip_addr.h"

#include "def.h"
#include "pbuf.h"
#include "stats.h"

#define LWIP_AUTOIP (LWIP_DHCP)
#define LWIP_DHCP LWIP_UDP
#define LWIP_HAVE_LOOPIF 1
#define LWIP_IGMP LWIP_IPV4
#define LWIP_IPV6_DHCP6 0
#define LWIP_IPV6_MLD LWIP_IPV6
#define LWIP_IPV6_NUM_ADDRESSES 3
#define LWIP_NETIF_LOOPBACK 1
#define LWIP_NETIF_LOOPBACK_MULTITHREADING (!NO_SYS)
#define LWIP_NUM_NETIF_CLIENT_DATA (LWIP_MDNS_RESPONDER)
#define NULL ((void *)0)
#define LWIP_UDP 1
#define LWIP_IPV4 1
#define LWIP_IPV6 1
#define NO_SYS 1
#define LWIP_MDNS_RESPONDER LWIP_UDP

#ifdef __cplusplus
extern "C" {
#endif

/* Throughout this file, IP addresses are expected to be in
 * the same byte order as in IP_PCB. */

/** Must be the maximum of all used hardware address lengths
    across all types of interfaces in use.
    This does not have to be changed, normally. */
#ifndef NETIF_MAX_HWADDR_LEN
#define NETIF_MAX_HWADDR_LEN 6U
#endif

/** The size of a fully constructed netif name which the
 * netif can be identified by in APIs. Composed of
 * 2 chars, 3 (max) digits, and 1 \0
 */
#define NETIF_NAMESIZE 6

/**
 * @defgroup netif_flags Flags
 * @ingroup netif
 * @{
 */

/** Whether the network interface is 'up'. This is
 * a software flag used to control whether this network
 * interface is enabled and processes traffic.
 * It must be set by the startup code before this netif can be used
 * (also for dhcp/autoip).
 */
#define NETIF_FLAG_UP           0x01U
/** If set, the netif has broadcast capability.
 * Set by the netif driver in its init function. */
#define NETIF_FLAG_BROADCAST    0x02U
/** If set, the interface has an active link
 *  (set by the network interface driver).
 * Either set by the netif driver in its init function (if the link
 * is up at that time) or at a later point once the link comes up
 * (if link detection is supported by the hardware). */
#define NETIF_FLAG_LINK_UP      0x04U
/** If set, the netif is an ethernet device using ARP.
 * Set by the netif driver in its init function.
 * Used to check input packet types and use of DHCP. */
#define NETIF_FLAG_ETHARP       0x08U
/** If set, the netif is an ethernet device. It might not use
 * ARP or TCP/IP if it is used for PPPoE only.
 */
#define NETIF_FLAG_ETHERNET     0x10U
/** If set, the netif has IGMP capability.
 * Set by the netif driver in its init function. */
#define NETIF_FLAG_IGMP         0x20U
/** If set, the netif has MLD6 capability.
 * Set by the netif driver in its init function. */
#define NETIF_FLAG_MLD6         0x40U

/**
 * @}
 */

enum lwip_internal_netif_client_data_index
{
   LWIP_NETIF_CLIENT_DATA_INDEX_DHCP,
#if LWIP_AUTOIP
   LWIP_NETIF_CLIENT_DATA_INDEX_AUTOIP,
#endif
   LWIP_NETIF_CLIENT_DATA_INDEX_ACD,
   LWIP_NETIF_CLIENT_DATA_INDEX_IGMP,
   LWIP_NETIF_CLIENT_DATA_INDEX_MLD6,
   LWIP_NETIF_CLIENT_DATA_INDEX_MAX
};

struct netif;

/** MAC Filter Actions, these are passed to a netif's igmp_mac_filter or
 * mld_mac_filter callback function. */
enum netif_mac_filter_action {
  /** Delete a filter entry */
  NETIF_DEL_MAC_FILTER = 0,
  /** Add a filter entry */
  NETIF_ADD_MAC_FILTER = 1
};

/** Function prototype for netif init functions. Set up flags and output/linkoutput
 * callback functions in this function.
 *
 * @param netif The netif to initialize
 */
typedef err_t (*netif_init_fn)(struct netif *netif);
/** Function prototype for netif->input functions. This function is saved as 'input'
 * callback function in the netif struct. Call it when a packet has been received.
 *
 * @param p The received packet, copied into a pbuf
 * @param inp The netif which received the packet
 * @return ERR_OK if the packet was handled
 *         != ERR_OK is the packet was NOT handled, in this case, the caller has
 *                   to free the pbuf
 */
typedef err_t (*netif_input_fn)(struct pbuf *p, struct netif *inp);

/** Function prototype for netif->output functions. Called by lwIP when a packet
 * shall be sent. For ethernet netif, set this to 'etharp_output' and set
 * 'linkoutput'.
 *
 * @param netif The netif which shall send a packet
 * @param p The packet to send (p->payload points to IP header)
 * @param ipaddr The IP address to which the packet shall be sent
 */
typedef err_t (*netif_output_fn)(struct netif *netif, struct pbuf *p,
       const ip4_addr_t *ipaddr);

/** Function prototype for netif->output_ip6 functions. Called by lwIP when a packet
 * shall be sent. For ethernet netif, set this to 'ethip6_output' and set
 * 'linkoutput'.
 *
 * @param netif The netif which shall send a packet
 * @param p The packet to send (p->payload points to IP header)
 * @param ipaddr The IPv6 address to which the packet shall be sent
 */
typedef err_t (*netif_output_ip6_fn)(struct netif *netif, struct pbuf *p,
       const ip6_addr_t *ipaddr);

/** Function prototype for netif->linkoutput functions. Only used for ethernet
 * netifs. This function is called by ARP when a packet shall be sent.
 *
 * @param netif The netif which shall send a packet
 * @param p The packet to send (raw ethernet packet)
 */
typedef err_t (*netif_linkoutput_fn)(struct netif *netif, struct pbuf *p);
/** Function prototype for netif status- or link-callback functions. */
typedef void (*netif_status_callback_fn)(struct netif *netif);
/** Function prototype for netif igmp_mac_filter functions */
typedef err_t (*netif_igmp_mac_filter_fn)(struct netif *netif,
       const ip4_addr_t *group, enum netif_mac_filter_action action);
/** Function prototype for netif mld_mac_filter functions */
typedef err_t (*netif_mld_mac_filter_fn)(struct netif *netif,
       const ip6_addr_t *group, enum netif_mac_filter_action action);

#if LWIP_DHCP || LWIP_AUTOIP || LWIP_IGMP || LWIP_IPV6_MLD || LWIP_IPV6_DHCP6 || (LWIP_NUM_NETIF_CLIENT_DATA > 0)
#if LWIP_NUM_NETIF_CLIENT_DATA > 0
u8_t netif_alloc_client_data_id(void);
#endif
/** @ingroup netif_cd
 * Set client data. Obtain ID from netif_alloc_client_data_id().
 */
#define netif_set_client_data(netif, id, data) netif_get_client_data(netif, id) = (data)
/** @ingroup netif_cd
 * Get client data. Obtain ID from netif_alloc_client_data_id().
 */
#define netif_get_client_data(netif, id)       (netif)->client_data[(id)]
#endif

typedef u8_t netif_addr_idx_t;
#define NETIF_ADDR_IDX_MAX 0x7F

 #define LWIP_NETIF_USE_HINTS              0

/** Generic data structure used for all lwIP network interfaces.
 *  The following fields should be filled in by the initialization
 *  function for the device driver: hwaddr_len, hwaddr[], mtu, flags */
struct netif {
  /** pointer to next in linked list */
  struct netif *next;

  /** IP address configuration in network byte order */
  ip_addr_t ip_addr;
  ip_addr_t netmask;
  ip_addr_t gw;
  /** Array of IPv6 addresses for this netif. */
  ip_addr_t ip6_addr[LWIP_IPV6_NUM_ADDRESSES];
  /** The state of each IPv6 address (Tentative, Preferred, etc).
   * @see ip6_addr.h */
  u8_t ip6_addr_state[LWIP_IPV6_NUM_ADDRESSES];
  /** Remaining valid and preferred lifetime of each IPv6 address, in seconds.
   * For valid lifetimes, the special value of IP6_ADDR_LIFE_STATIC (0)
   * indicates the address is static and has no lifetimes. */
  u32_t ip6_addr_valid_life[LWIP_IPV6_NUM_ADDRESSES];
  u32_t ip6_addr_pref_life[LWIP_IPV6_NUM_ADDRESSES];
  /** This function is called by the network device driver
   *  to pass a packet up the TCP/IP stack. */
  netif_input_fn input;
  /** This function is called by the IP module when it wants
   *  to send a packet on the interface. This function typically
   *  first resolves the hardware address, then sends the packet.
   *  For ethernet physical layer, this is usually etharp_output() */
  netif_output_fn output;
  /** This function is called by ethernet_output() when it wants
   *  to send a packet on the interface. This function outputs
   *  the pbuf as-is on the link medium. */
  netif_linkoutput_fn linkoutput;
  /** This function is called by the IPv6 module when it wants
   *  to send a packet on the interface. This function typically
   *  first resolves the hardware address, then sends the packet.
   *  For ethernet physical layer, this is usually ethip6_output() */
  netif_output_ip6_fn output_ip6;
  /** This function is called when the netif state is set to up or down
   */
  netif_status_callback_fn status_callback;
  /** This function is called when the netif link is set to up or down
   */
  netif_status_callback_fn link_callback;
  /** This function is called when the netif has been removed */
  netif_status_callback_fn remove_callback;
  /** This field can be set by the device driver and could point
   *  to state information for the device. */
  void *state;
#ifdef netif_get_client_data
  void* client_data[LWIP_NETIF_CLIENT_DATA_INDEX_MAX + LWIP_NUM_NETIF_CLIENT_DATA];
#endif
  /* the hostname for this netif, NULL is a valid value */
  const char*  hostname;
  /** maximum transfer unit (in bytes) */
  u16_t mtu;
  /** maximum transfer unit (in bytes), updated by RA */
  u16_t mtu6;
  /** link level hardware address of this interface */
  u8_t hwaddr[NETIF_MAX_HWADDR_LEN];
  /** number of bytes used in hwaddr */
  u8_t hwaddr_len;
  /** flags (@see @ref netif_flags) */
  u8_t flags;
  /** descriptive abbreviation */
  char name[2];
  /** number of this interface. Used for @ref if_api and @ref netifapi_netif,
   * as well as for IPv6 zones */
  u8_t num;
  /** is this netif enabled for IPv6 autoconfiguration */
  u8_t ip6_autoconfig_enabled;
  /** Number of Router Solicitation messages that remain to be sent. */
  u8_t rs_count;
  /** This function could be called to add or delete an entry in the multicast
      filter table of the ethernet MAC.*/
  netif_igmp_mac_filter_fn igmp_mac_filter;
  /** This function could be called to add or delete an entry in the IPv6 multicast
      filter table of the ethernet MAC. */
  netif_mld_mac_filter_fn mld_mac_filter;
  struct acd *acd_list;
#if LWIP_NETIF_USE_HINTS
  struct netif_hint *hints;
#endif /* LWIP_NETIF_USE_HINTS */
#if ENABLE_LOOPBACK
  /* List of packets to be queued for ourselves. */
  struct pbuf *loop_first;
  struct pbuf *loop_last;
  u16_t loop_cnt_current;
#if LWIP_NETIF_LOOPBACK_MULTITHREADING
  /* Used if the original scheduling failed. */
  u8_t reschedule_poll;
#endif /* LWIP_NETIF_LOOPBACK_MULTITHREADING */
#endif /* ENABLE_LOOPBACK */
};

#define NETIF_CHECKSUM_ENABLED(netif, chksumflag) 0
#define NETIF_SET_CHECKSUM_CTRL(netif, chksumflags)
#define IF__NETIF_CHECKSUM_ENABLED(netif, chksumflag)

/** The list of network interfaces. */
extern struct netif *netif_list;
#define NETIF_FOREACH(netif) for ((netif) = netif_list; (netif) != NULL; (netif) = (netif)->next)
/** The default network interface. */
extern struct netif *netif_default;

struct netif *netif_add_noaddr(struct netif *netif, void *state, netif_init_fn init, netif_input_fn input);

struct netif *netif_add(struct netif *netif,
                            const ip4_addr_t *ipaddr, const ip4_addr_t *netmask, const ip4_addr_t *gw,
                            void *state, netif_init_fn init, netif_input_fn input);
void netif_set_addr(struct netif *netif, const ip4_addr_t *ipaddr, const ip4_addr_t *netmask,
                    const ip4_addr_t *gw);
void netif_remove(struct netif * netif);

/* Returns a network interface given its name. The name is of the form
   "et0", where the first two letters are the "name" field in the
   netif structure, and the digit is in the num field in the same
   structure. */
struct netif *netif_find(const char *name);

void netif_set_default(struct netif *netif);

void netif_set_ipaddr(struct netif *netif, const ip4_addr_t *ipaddr);
void netif_set_netmask(struct netif *netif, const ip4_addr_t *netmask);
void netif_set_gw(struct netif *netif, const ip4_addr_t *gw);
/** @ingroup netif_ip4 */
#define netif_ip4_addr(netif)    ((const ip4_addr_t*)ip_2_ip4(&((netif)->ip_addr)))
/** @ingroup netif_ip4 */
#define netif_ip4_netmask(netif) ((const ip4_addr_t*)ip_2_ip4(&((netif)->netmask)))
/** @ingroup netif_ip4 */
#define netif_ip4_gw(netif)      ((const ip4_addr_t*)ip_2_ip4(&((netif)->gw)))
/** @ingroup netif_ip4 */
#define netif_ip_addr4(netif)    ((const ip_addr_t*)&((netif)->ip_addr))
/** @ingroup netif_ip4 */
#define netif_ip_netmask4(netif) ((const ip_addr_t*)&((netif)->netmask))
/** @ingroup netif_ip4 */
#define netif_ip_gw4(netif)      ((const ip_addr_t*)&((netif)->gw))

#define netif_set_flags(netif, set_flags)     do { (netif)->flags = (u8_t)((netif)->flags |  (set_flags)); } while(0)
#define netif_clear_flags(netif, clr_flags)   do { (netif)->flags = (u8_t)((netif)->flags & (u8_t)(~(clr_flags) & 0xff)); } while(0)
#define netif_is_flag_set(netif, flag)        (((netif)->flags & (flag)) != 0)

void netif_set_up(struct netif *netif);
void netif_set_down(struct netif *netif);
/** @ingroup netif
 * Ask if an interface is up
 */
#define netif_is_up(netif) (((netif)->flags & NETIF_FLAG_UP) ? (u8_t)1 : (u8_t)0)

void netif_set_status_callback(struct netif *netif, netif_status_callback_fn status_callback);
void netif_set_remove_callback(struct netif *netif, netif_status_callback_fn remove_callback);

void netif_set_link_up(struct netif *netif);
void netif_set_link_down(struct netif *netif);
/** Ask if a link is up */
#define netif_is_link_up(netif) (((netif)->flags & NETIF_FLAG_LINK_UP) ? (u8_t)1 : (u8_t)0)

void netif_set_link_callback(struct netif *netif, netif_status_callback_fn link_callback);

/** @ingroup netif */
#define netif_set_hostname(netif, name) do { if((netif) != NULL) { (netif)->hostname = name; }}while(0)
/** @ingroup netif */
#define netif_get_hostname(netif) (((netif) != NULL) ? ((netif)->hostname) : NULL)

/** @ingroup netif
 * Set igmp mac filter function for a netif. */
#define netif_set_igmp_mac_filter(netif, function) do { if((netif) != NULL) { (netif)->igmp_mac_filter = function; }}while(0)
/** Get the igmp mac filter function for a netif. */
#define netif_get_igmp_mac_filter(netif) (((netif) != NULL) ? ((netif)->igmp_mac_filter) : NULL)

/** @ingroup netif
 * Set mld mac filter function for a netif. */
#define netif_set_mld_mac_filter(netif, function) do { if((netif) != NULL) { (netif)->mld_mac_filter = function; }}while(0)
/** Get the mld mac filter function for a netif. */
#define netif_get_mld_mac_filter(netif) (((netif) != NULL) ? ((netif)->mld_mac_filter) : NULL)
#define netif_mld_mac_filter(netif, addr, action) do { if((netif) && (netif)->mld_mac_filter) { (netif)->mld_mac_filter((netif), (addr), (action)); }}while(0)

#if ENABLE_LOOPBACK
err_t netif_loop_output(struct netif *netif, struct pbuf *p);
void netif_poll(struct netif *netif);
#if !LWIP_NETIF_LOOPBACK_MULTITHREADING
void netif_poll_all(void);
#endif /* !LWIP_NETIF_LOOPBACK_MULTITHREADING */
#endif /* ENABLE_LOOPBACK */

err_t netif_input(struct pbuf *p, struct netif *inp);

/** @ingroup netif_ip6 */
#define netif_ip_addr6(netif, i)  ((const ip_addr_t*)(&((netif)->ip6_addr[i])))
/** @ingroup netif_ip6 */
#define netif_ip6_addr(netif, i)  ((const ip6_addr_t*)ip_2_ip6(&((netif)->ip6_addr[i])))
void netif_ip6_addr_set(struct netif *netif, s8_t addr_idx, const ip6_addr_t *addr6);
void netif_ip6_addr_set_parts(struct netif *netif, s8_t addr_idx, u32_t i0, u32_t i1, u32_t i2, u32_t i3);
#define netif_ip6_addr_state(netif, i)  ((netif)->ip6_addr_state[i])
void netif_ip6_addr_set_state(struct netif* netif, s8_t addr_idx, u8_t state);
s8_t netif_get_ip6_addr_match(struct netif *netif, const ip6_addr_t *ip6addr);
void netif_create_ip6_linklocal_address(struct netif *netif, u8_t from_mac_48bit);
err_t netif_add_ip6_address(struct netif *netif, const ip6_addr_t *ip6addr, s8_t *chosen_idx);
#define netif_set_ip6_autoconfig_enabled(netif, action) do { if(netif) { (netif)->ip6_autoconfig_enabled = (action); }}while(0)
#define netif_ip6_addr_valid_life(netif, i)  \
    (((netif) != NULL) ? ((netif)->ip6_addr_valid_life[i]) : IP6_ADDR_LIFE_STATIC)
#define netif_ip6_addr_set_valid_life(netif, i, secs) \
    do { if (netif != NULL) { (netif)->ip6_addr_valid_life[i] = (secs); }} while (0)
#define netif_ip6_addr_pref_life(netif, i)  \
    (((netif) != NULL) ? ((netif)->ip6_addr_pref_life[i]) : IP6_ADDR_LIFE_STATIC)
#define netif_ip6_addr_set_pref_life(netif, i, secs) \
    do { if (netif != NULL) { (netif)->ip6_addr_pref_life[i] = (secs); }} while (0)
#define netif_ip6_addr_isstatic(netif, i)  \
    (netif_ip6_addr_valid_life((netif), (i)) == IP6_ADDR_LIFE_STATIC)
#define netif_mtu6(netif) ((netif)->mtu6)

#if LWIP_NETIF_USE_HINTS
#define NETIF_SET_HINTS(netif, netifhint)  (netif)->hints = (netifhint)
#define NETIF_RESET_HINTS(netif)      (netif)->hints = NULL
#else /* LWIP_NETIF_USE_HINTS */
#define NETIF_SET_HINTS(netif, netifhint)
#define NETIF_RESET_HINTS(netif)
#endif /* LWIP_NETIF_USE_HINTS */

u8_t netif_name_to_index(const char *name);
char * netif_index_to_name(u8_t idx, char *name);
struct netif* netif_get_by_index(u8_t idx);

/* Interface indexes always start at 1 per RFC 3493, section 4, num starts at 0 (internal index is 0..254)*/
#define netif_get_index(netif)      ((u8_t)((netif)->num + 1))
#define NETIF_NO_INDEX              (0)

/**
 * @ingroup netif
 * Extended netif status callback (NSC) reasons flags.
 * May be extended in the future!
 */
typedef u16_t netif_nsc_reason_t;

/* used for initialization only */
#define LWIP_NSC_NONE                     0x0000
/** netif was added. arg: NULL. Called AFTER netif was added. */
#define LWIP_NSC_NETIF_ADDED              0x0001
/** netif was removed. arg: NULL. Called BEFORE netif is removed. */
#define LWIP_NSC_NETIF_REMOVED            0x0002
/** link changed */
#define LWIP_NSC_LINK_CHANGED             0x0004
/** netif administrative status changed.<br>
  * up is called AFTER netif is set up.<br>
  * down is called BEFORE the netif is actually set down. */
#define LWIP_NSC_STATUS_CHANGED           0x0008
/** IPv4 address has changed */
#define LWIP_NSC_IPV4_ADDRESS_CHANGED     0x0010
/** IPv4 gateway has changed */
#define LWIP_NSC_IPV4_GATEWAY_CHANGED     0x0020
/** IPv4 netmask has changed */
#define LWIP_NSC_IPV4_NETMASK_CHANGED     0x0040
/** called AFTER IPv4 address/gateway/netmask changes have been applied */
#define LWIP_NSC_IPV4_SETTINGS_CHANGED    0x0080
/** IPv6 address was added */
#define LWIP_NSC_IPV6_SET                 0x0100
/** IPv6 address state has changed */
#define LWIP_NSC_IPV6_ADDR_STATE_CHANGED  0x0200
/** IPv4 settings: valid address set, application may start to communicate */
#define LWIP_NSC_IPV4_ADDR_VALID          0x0400

/** @ingroup netif
 * Argument supplied to netif_ext_callback_fn.
 */
typedef union
{
  /** Args to LWIP_NSC_LINK_CHANGED callback */
  struct link_changed_s
  {
    /** 1: up; 0: down */
    u8_t state;
  } link_changed;
  /** Args to LWIP_NSC_STATUS_CHANGED callback */
  struct status_changed_s
  {
    /** 1: up; 0: down */
    u8_t state;
  } status_changed;
  /** Args to LWIP_NSC_IPV4_ADDRESS_CHANGED|LWIP_NSC_IPV4_GATEWAY_CHANGED|LWIP_NSC_IPV4_NETMASK_CHANGED|LWIP_NSC_IPV4_SETTINGS_CHANGED callback */
  struct ipv4_changed_s
  {
    /** Old IPv4 address */
    const ip_addr_t* old_address;
    const ip_addr_t* old_netmask;
    const ip_addr_t* old_gw;
  } ipv4_changed;
  /** Args to LWIP_NSC_IPV6_SET callback */
  struct ipv6_set_s
  {
    /** Index of changed IPv6 address */
    s8_t addr_index;
    /** Old IPv6 address */
    const ip_addr_t* old_address;
  } ipv6_set;
  /** Args to LWIP_NSC_IPV6_ADDR_STATE_CHANGED callback */
  struct ipv6_addr_state_changed_s
  {
    /** Index of affected IPv6 address */
    s8_t addr_index;
    /** Old IPv6 address state */
    u8_t old_state;
    /** Affected IPv6 address */
    const ip_addr_t* address;
  } ipv6_addr_state_changed;
} netif_ext_callback_args_t;

/**
 * @ingroup netif
 * Function used for extended netif status callbacks
 * Note: When parsing reason argument, keep in mind that more reasons may be added in the future!
 * @param netif netif that is affected by change
 * @param reason change reason
 * @param args depends on reason, see reason description
 */
typedef void (*netif_ext_callback_fn)(struct netif* netif, netif_nsc_reason_t reason, const netif_ext_callback_args_t* args);

struct netif_ext_callback;
typedef struct netif_ext_callback
{
  netif_ext_callback_fn callback_fn;
  struct netif_ext_callback* next;
} netif_ext_callback_t;

#define NETIF_DECLARE_EXT_CALLBACK(name) static netif_ext_callback_t name;
void netif_add_ext_callback(netif_ext_callback_t* callback, netif_ext_callback_fn fn);
void netif_remove_ext_callback(netif_ext_callback_t* callback);

#ifdef __cplusplus
}
#endif

#endif /* LWIP_HDR_NETIF_H */
