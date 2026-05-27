core/
=====

``core/`` contains lwIP core includes curated and modified for the CE build.

.. list-table::
   :header-rows: 1
   :widths: 28 72

   * - Header
     - Purpose
   * - :doc:`acd.h <core/acd>`
     - Address conflict detection support.
   * - :doc:`altcp.h <core/altcp>`
     - Application-layer TCP abstraction.
   * - :doc:`altcp_tls.h <core/altcp_tls>`
     - ALTCP TLS integration for the CE TLS layer.
   * - :doc:`altcp_tls_mbedtls_opts.h <core/altcp_tls_mbedtls_opts>`
     - TLS/ALTCP compatibility options used by the release headers.
   * - :doc:`arch.h <core/arch>`
     - lwIP architecture types and platform definitions for CE.
   * - :doc:`autoip.h <core/autoip>`
     - IPv4 AutoIP address configuration.
   * - :doc:`cc.h <core/cc>`
     - Compiler and platform compatibility macros.
   * - :doc:`def.h <core/def>`
     - Common lwIP definitions, byte order helpers, and packed-structure helpers.
   * - :doc:`dhcp.h <core/dhcp>`
     - DHCP client API.
   * - :doc:`dns.h <core/dns>`
     - DNS resolver API.
   * - :doc:`drivers_mem.h <core/drivers_mem>`
     - Driver memory helper definitions.
   * - :doc:`err.h <core/err>`
     - lwIP error code definitions.
   * - :doc:`etharp.h <core/etharp>`
     - Ethernet ARP support for IPv4.
   * - :doc:`ethernet.h <core/ethernet>`
     - Ethernet frame definitions and input helpers.
   * - :doc:`icmp.h <core/icmp>`
     - IPv4 ICMP support.
   * - :doc:`icmp6.h <core/icmp6>`
     - IPv6 ICMP support.
   * - :doc:`ieee.h <core/ieee>`
     - IEEE-format helper definitions used by lwIP.
   * - :doc:`igmp.h <core/igmp>`
     - IPv4 multicast group management.
   * - :doc:`inet_chksum.h <core/inet_chksum>`
     - Internet checksum helpers.
   * - :doc:`init.h <core/init>`
     - lwIP stack initialization.
   * - :doc:`ip.h <core/ip>`
     - Shared IP-layer definitions.
   * - :doc:`ip4.h <core/ip4>`
     - IPv4 core API.
   * - :doc:`ip4_addr.h <core/ip4_addr>`
     - IPv4 address helpers.
   * - :doc:`ip4_frag.h <core/ip4_frag>`
     - IPv4 fragmentation and reassembly.
   * - :doc:`ip6.h <core/ip6>`
     - IPv6 core API.
   * - :doc:`ip6_addr.h <core/ip6_addr>`
     - IPv6 address helpers.
   * - :doc:`ip6_frag.h <core/ip6_frag>`
     - IPv6 fragmentation and reassembly.
   * - :doc:`ip6_zone.h <core/ip6_zone>`
     - IPv6 scope-zone helpers.
   * - :doc:`ip_addr.h <core/ip_addr>`
     - Dual-stack IP address helpers.
   * - :doc:`mem.h <core/mem>`
     - lwIP heap and memory allocator API.
   * - :doc:`mem_priv.h <core/mem_priv>`
     - Memory allocator internals required by curated release headers.
   * - :doc:`memp.h <core/memp>`
     - lwIP memory pool API.
   * - :doc:`memp_priv.h <core/memp_priv>`
     - Memory pool internals required by curated release headers.
   * - :doc:`memp_std.h <core/memp_std>`
     - Default memory pool declarations.
   * - :doc:`mld6.h <core/mld6>`
     - IPv6 multicast listener discovery.
   * - :doc:`nd6.h <core/nd6>`
     - IPv6 neighbor discovery.
   * - :doc:`netif.h <core/netif>`
     - Network interface model, status flags, and callbacks.
   * - :doc:`pbuf.h <core/pbuf>`
     - Packet buffer API.
   * - :doc:`prot_acd.h <core/prot_acd>`
     - Address conflict detection wire-format definitions.
   * - :doc:`prot_etharp.h <core/prot_etharp>`
     - ARP wire-format definitions.
   * - :doc:`prot_ethernet.h <core/prot_ethernet>`
     - Ethernet wire-format definitions.
   * - :doc:`prot_icmp.h <core/prot_icmp>`
     - IPv4 ICMP wire-format definitions.
   * - :doc:`prot_icmp6.h <core/prot_icmp6>`
     - IPv6 ICMP wire-format definitions.
   * - :doc:`prot_ip.h <core/prot_ip>`
     - Shared IP wire-format definitions.
   * - :doc:`prot_ip4.h <core/prot_ip4>`
     - IPv4 wire-format definitions.
   * - :doc:`prot_ip6.h <core/prot_ip6>`
     - IPv6 wire-format definitions.
   * - :doc:`prot_udp.h <core/prot_udp>`
     - UDP wire-format definitions.
   * - :doc:`raw.h <core/raw>`
     - Raw PCB API.
   * - :doc:`sntp_time.h <core/sntp_time>`
     - RTC-backed Unix timestamp helper.
   * - :doc:`stats.h <core/stats>`
     - lwIP statistics structures and macros.
   * - :doc:`sys.h <core/sys>`
     - NO_SYS/system abstraction definitions.
   * - :doc:`tcp.h <core/tcp>`
     - TCP raw API.
   * - :doc:`tcpbase.h <core/tcpbase>`
     - Common TCP constants and flags.
   * - :doc:`timeouts.h <core/timeouts>`
     - Timer registration and timeout processing.
   * - :doc:`udp.h <core/udp>`
     - UDP raw API.
   * - :doc:`usb_ethernet.h <core/usb_ethernet>`
     - USB Ethernet driver callback entry point.

.. toctree::
   :hidden:

   core/acd
   core/altcp
   core/altcp_tls
   core/altcp_tls_mbedtls_opts
   core/arch
   core/autoip
   core/cc
   core/def
   core/dhcp
   core/dns
   core/drivers_mem
   core/err
   core/etharp
   core/ethernet
   core/icmp
   core/icmp6
   core/ieee
   core/igmp
   core/inet_chksum
   core/init
   core/ip
   core/ip4
   core/ip4_addr
   core/ip4_frag
   core/ip6
   core/ip6_addr
   core/ip6_frag
   core/ip6_zone
   core/ip_addr
   core/mem
   core/mem_priv
   core/memp
   core/memp_priv
   core/memp_std
   core/mld6
   core/nd6
   core/netif
   core/pbuf
   core/prot_acd
   core/prot_etharp
   core/prot_ethernet
   core/prot_icmp
   core/prot_icmp6
   core/prot_ip
   core/prot_ip4
   core/prot_ip6
   core/prot_udp
   core/raw
   core/sntp_time
   core/stats
   core/sys
   core/tcp
   core/tcpbase
   core/timeouts
   core/udp
   core/usb_ethernet
