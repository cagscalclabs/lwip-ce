#ifndef LWIP_LWIPOPTS_H
#define LWIP_LWIPOPTS_H

#include <stdint.h>

#include "ti/getkey.h"
#include "lwip/sntp_time.h"
#define LWIP_DEBUG 0
#define LWIP_NOASSERT 1

#define LWIP_IPV4 1
#define LWIP_IPV6 1

#define NO_SYS 1
#define LWIP_TIMERS 1
#define LWIP_ETHERNET 1
#define LWIP_CALLBACK_API 1
#define LWIP_SOCKET 0
#define LWIP_NETCONN 0
#define LWIP_NETIF_API 0
#define LWIP_NETIF_HOSTNAME 1
#define LWIP_NETIF_REMOVE_CALLBACK 1

#define LWIP_CHKSUM_ALGORITHM 1 // todo: does this do anything?

#define LWIP_IGMP LWIP_IPV4
#define LWIP_ICMP LWIP_IPV4

#define LWIP_SNMP 0
#define MIB2_STATS 0
#ifdef LWIP_HAVE_MBEDTLS
#define LWIP_SNMP_V3 (LWIP_SNMP)
#endif

#define LWIP_DNS LWIP_UDP
#define LWIP_MDNS_RESPONDER LWIP_UDP
#define LWIP_DHCP_GET_NTP_SRV 1
#define SNTP_GET_SERVERS_FROM_DHCP 1

#define SNTP_SET_SYSTEM_TIME(sec) lwip_sntp_set_time((uint32_t)(sec))

#define LWIP_NUM_NETIF_CLIENT_DATA (LWIP_MDNS_RESPONDER)

#define LWIP_HAVE_LOOPIF 1
#define LWIP_NETIF_LOOPBACK 1
#define LWIP_LOOPBACK_MAX_PBUFS 5

#define TCP_LISTEN_BACKLOG 1

#define LWIP_COMPAT_SOCKETS 1
#define LWIP_SO_RCVTIMEO 1
#define LWIP_SO_RCVBUF 1

#define LWIP_TCPIP_CORE_LOCKING 1

#define LWIP_NETIF_LINK_CALLBACK 1
#define LWIP_NETIF_STATUS_CALLBACK 1
#define LWIP_NETIF_EXT_STATUS_CALLBACK 1

#ifdef LWIP_DEBUG
#define LWIP_DBG_MIN_LEVEL 0
#define ETH_DEBUG LWIP_DBG_ON
#define PPP_DEBUG LWIP_DBG_OFF
#define MEM_DEBUG LWIP_DBG_OFF
#define MEMP_DEBUG LWIP_DBG_OFF
#define PBUF_DEBUG LWIP_DBG_OFF
#define API_LIB_DEBUG LWIP_DBG_OFF
#define API_MSG_DEBUG LWIP_DBG_OFF
#define TCPIP_DEBUG LWIP_DBG_OFF
#define NETIF_DEBUG LWIP_DBG_OFF
#define SOCKETS_DEBUG LWIP_DBG_OFF
#define DNS_DEBUG LWIP_DBG_OFF
#define AUTOIP_DEBUG LWIP_DBG_OFF
#define ACD_DEBUG LWIP_DBG_OFF
#define DHCP_DEBUG LWIP_DBG_OFF
#define IP_DEBUG LWIP_DBG_OFF
#define IP_REASS_DEBUG LWIP_DBG_OFF
#define ICMP_DEBUG LWIP_DBG_OFF
#define IGMP_DEBUG LWIP_DBG_OFF
#define UDP_DEBUG LWIP_DBG_OFF
#define TCP_DEBUG LWIP_DBG_OFF
#define TCP_INPUT_DEBUG LWIP_DBG_OFF
#define TCP_OUTPUT_DEBUG LWIP_DBG_OFF
#define TCP_RTO_DEBUG LWIP_DBG_OFF
#define TCP_CWND_DEBUG LWIP_DBG_OFF
#define TCP_WND_DEBUG LWIP_DBG_OFF
#define TCP_FR_DEBUG LWIP_DBG_OFF
#define TCP_QLEN_DEBUG LWIP_DBG_OFF
#define TCP_RST_DEBUG LWIP_DBG_OFF
#endif

#define LWIP_DBG_TYPES_ON (LWIP_DBG_ON | LWIP_DBG_TRACE | LWIP_DBG_STATE | LWIP_DBG_FRESH | LWIP_DBG_HALT)

/* ---------- Memory options ---------- */
// Disable using pools entirely, use user malloc
#define MEM_USE_POOLS   0
#define MEM_CUSTOM_ALLOCATOR 1
#define MEMP_MEM_MALLOC 1
#if MEM_CUSTOM_ALLOCATOR==1
#define MEM_CUSTOM_FREE                 mem_buffer_custom_free
#define MEM_CUSTOM_MALLOC               mem_buffer_custom_malloc
#define MEM_CUSTOM_CALLOC               mem_buffer_custom_calloc

#endif

#define MAX_HEAP_USAGE 24576

/* MEM_ALIGNMENT: should be set to the alignment of the CPU for which
   lwIP is compiled. 4 byte alignment -> define MEM_ALIGNMENT to 4, 2
   byte alignment -> define MEM_ALIGNMENT to 2. */
/* MSVC port: intel processors don't need 4-byte alignment,
   but are faster that way! */
#define MEM_ALIGNMENT 1U

/* MEM_SIZE: the size of the heap memory. If the application will send
a lot of data that needs to be copied, this should be set high. */
#define MEM_SIZE (MAX_HEAP_USAGE / 2)

/* MEMP_NUM_PBUF: the number of memp struct pbufs. If the application
   sends a lot of data out of ROM (or other static memory), this
   should be set high. */
#define MEMP_NUM_PBUF 8
/* MEMP_NUM_RAW_PCB: the number of UDP protocol control blocks. One
   per active RAW "connection". */
#define MEMP_NUM_RAW_PCB 1
/* MEMP_NUM_UDP_PCB: the number of UDP protocol control blocks. One
   per active UDP "connection". */
#define MEMP_NUM_UDP_PCB 4
/* MEMP_NUM_TCP_PCB: the number of simulatenously active TCP
   connections. */
#define MEMP_NUM_TCP_PCB 16
/* MEMP_NUM_TCP_PCB_LISTEN: the number of listening TCP
   connections. */
#define MEMP_NUM_TCP_PCB_LISTEN 4
/* MEMP_NUM_TCP_SEG: the number of simultaneously queued TCP
   segments. */
#define MEMP_NUM_TCP_SEG 32
/* MEMP_NUM_SYS_TIMEOUT: the number of simulateously active
   timeouts. */
#define MEMP_NUM_SYS_TIMEOUT 32

/* The following four are used only with the sequential API and can be
   set to 0 if the application only will use the raw API. */
/* MEMP_NUM_NETBUF: the number of struct netbufs. */
#define MEMP_NUM_NETBUF 0
/* MEMP_NUM_NETCONN: the number of struct netconns. */
#define MEMP_NUM_NETCONN 0
/* MEMP_NUM_TCPIP_MSG_*: the number of struct tcpip_msg, which is used
   for sequential API communication and incoming packets. Used in
   src/api/tcpip.c. */
#define MEMP_NUM_TCPIP_MSG_API 0
#define MEMP_NUM_TCPIP_MSG_INPKT 0

/* ---------- Pbuf options ---------- */

/* PBUF_POOL_BUFSIZE: the size of each pbuf in the pbuf pool. */
#define PBUF_POOL_BUFSIZE 256

/* PBUF_POOL_SIZE: the number of buffers in the pbuf pool. */
#define PBUF_POOL_SIZE ((MAX_HEAP_USAGE / 2) / PBUF_POOL_BUFSIZE)

/* ---------- Custom mem_buffer pool sizing ---------- */
#define LWIP_MEMPOOL_SMALL_BLOCK 64
#define LWIP_MEMPOOL_SMALL_COUNT 96
#define LWIP_MEMPOOL_MEDIUM_BLOCK PBUF_POOL_BUFSIZE
#define LWIP_MEMPOOL_MEDIUM_COUNT PBUF_POOL_SIZE
#define LWIP_MEMPOOL_LARGE_BLOCK 512
#define LWIP_MEMPOOL_LARGE_COUNT 8
#define LWIP_MEMBUF_GROW_STEP 256
#define LWIP_MEMBUF_SHRINK_STEP 256
#define LWIP_MEMBUF_GROW_THRESHOLD 85
#define LWIP_MEMBUF_SHRINK_THRESHOLD 30
#define LWIP_MEMBUF_SHRINK_HOLD 1
#ifndef LWIP_MEM_PRESSURE_CLEAR_PCT
#define LWIP_MEM_PRESSURE_CLEAR_PCT 70
#endif

/** SYS_LIGHTWEIGHT_PROT
 * define SYS_LIGHTWEIGHT_PROT in lwipopts.h if you want inter-task protection
 * for certain critical regions during buffer allocation, deallocation and memory
 * allocation and deallocation.
 */
#define SYS_LIGHTWEIGHT_PROT (NO_SYS == 0)

/* ---------- TCP options ---------- */
#define LWIP_TCP 1
#define TCP_TTL 255

#define LWIP_ALTCP (LWIP_TCP)
// #define LWIP_HAVE_MBEDTLS (LWIP_TCP)
#ifdef LWIP_HAVE_MBEDTLS
#define LWIP_ALTCP_TLS (LWIP_TCP)
#define LWIP_ALTCP_TLS_MBEDTLS (LWIP_TCP)
#endif

/* Controls if TCP should queue segments that arrive out of
   order. Define to 0 if your device is low on memory. */
#define TCP_QUEUE_OOSEQ 1

/* TCP Maximum segment size. */
#define TCP_MSS 512

#define TCP_OVERSIZE TCP_MSS

/* TCP sender buffer space (bytes). */
#define TCP_SND_BUF (8 * TCP_MSS)

/* TCP sender buffer space (pbufs). This must be at least = 2 *
   TCP_SND_BUF/TCP_MSS for things to work. */
#define TCP_SND_QUEUELEN ((4 * (TCP_SND_BUF) + (TCP_MSS - 1)) / (TCP_MSS))

/* TCP writable space (bytes). This must be less than or equal
   to TCP_SND_BUF. It is the amount of space which must be
   available in the tcp snd_buf for select to return writable */
#define TCP_SNDLOWAT (TCP_SND_BUF / 2)

/* TCP receive window. */
#define TCP_WND (16 * TCP_MSS)

/* TCP Maximum Segment Lifetime in milliseconds.
   TIME_WAIT lasts 2*MSL. Default is 60000 (60s), set to 15000 for 30s TIME_WAIT. */
#define TCP_MSL 15000UL

/* Maximum number of retransmissions of data segments. */
#define TCP_MAXRTX 6

/* Maximum number of retransmissions of SYN segments. */
#define TCP_SYNMAXRTX 2

/* ---------- ARP options ---------- */
#define LWIP_ARP 1
#define ARP_TABLE_SIZE 10
#define ARP_QUEUEING 1

/* ---------- IP options ---------- */
/* Define IP_FORWARD to 1 if you wish to have the ability to forward
   IP packets across network interfaces. If you are going to run lwIP
   on a device with only one network interface, define this to 0. */
#define IP_FORWARD 1

/* IP reassembly and segmentation.These are orthogonal even
 * if they both deal with IP fragments */
#define IP_REASSEMBLY 1
#define IP_REASS_MAX_PBUFS (10 * ((1500 + PBUF_POOL_BUFSIZE - 1) / PBUF_POOL_BUFSIZE))
#define MEMP_NUM_REASSDATA IP_REASS_MAX_PBUFS
#define IP_FRAG 1
#define IPV6_FRAG_COPYHEADER 1

/* ---------- ICMP options ---------- */
#define ICMP_TTL 255

/* ---------- DHCP options ---------- */
/* Define LWIP_DHCP to 1 if you want DHCP configuration of
   interfaces. */
#define LWIP_DHCP LWIP_UDP
#define LWIP_DHCP_PROVIDE_DNS_SERVERS 1
/* 1 if you want to do an ARP check on the offered address
   (recommended). */
#define DHCP_DOES_ARP_CHECK (LWIP_DHCP)
#define LWIP_DHCP_DOES_ACD_CHECK 0
#define LWIP_ACD 1

/* ---------- AUTOIP options ------- */
#define LWIP_AUTOIP (LWIP_DHCP)
#define LWIP_DHCP_AUTOIP_COOP (LWIP_DHCP && LWIP_AUTOIP)

/* ---------- UDP options ---------- */
#define LWIP_UDP 1
#define LWIP_UDPLITE LWIP_UDP
#define LWIP_UDPLITE LWIP_UDP
#define UDP_TTL 255

/* ---------- RAW options ---------- */
#define LWIP_RAW 1

/* ---------- Statistics options ---------- */

#define LWIP_STATS 0
#define LWIP_STATS_DISPLAY 0

#if LWIP_STATS
#define LINK_STATS 1
#define IP_STATS 1
#define ICMP_STATS 1
#define IGMP_STATS 1
#define IPFRAG_STATS 1
#define UDP_STATS 1
#define TCP_STATS 1
#define MEM_STATS 1
#define MEMP_STATS 1
#define PBUF_STATS 1
#define SYS_STATS 1
#endif /* LWIP_STATS */

/* ---------- NETBIOS options ---------- */
#define LWIP_NETBIOS_RESPOND_NAME_QUERY 1

/* ---------- PPP options ---------- */

#define PPP_SUPPORT 0 /* Set > 0 for PPP */

#if PPP_SUPPORT

#define NUM_PPP 1 /* Max PPP sessions. */

/* Select modules to enable.  Ideally these would be set in the makefile but
 * we're limited by the command line length so you need to modify the settings
 * in this file.
 */
#define PPPOE_SUPPORT 1
#define PPPOS_SUPPORT 1

#define PAP_SUPPORT 1    /* Set > 0 for PAP. */
#define CHAP_SUPPORT 1   /* Set > 0 for CHAP. */
#define MSCHAP_SUPPORT 0 /* Set > 0 for MSCHAP */
#define CBCP_SUPPORT 0   /* Set > 0 for CBCP (NOT FUNCTIONAL!) */
#define CCP_SUPPORT 0    /* Set > 0 for CCP */
#define VJ_SUPPORT 0     /* Set > 0 for VJ header compression. */
#define MD5_SUPPORT 1    /* Set > 0 for MD5 (see also CHAP) */

#endif /* PPP_SUPPORT */

/* miscellanous */
#define HTTPD_SERVER_PORT 80
#define LWIP_RAND rand

#endif // LWIP_LWIPOPTS_H
