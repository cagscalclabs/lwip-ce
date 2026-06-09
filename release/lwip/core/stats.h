/**
 * @file
 * Statistics API (to be used from TCPIP thread)
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
#ifndef LWIP_HDR_STATS_H
#define LWIP_HDR_STATS_H

#include "arch.h"

#include "mem.h"
#include "memp.h"

#ifdef __cplusplus
extern "C" {
#endif

#define stats_init()
#define STATS_INC(x)
#define STATS_DEC(x)
#define STATS_INC_USED(x, y, type)

#define TCP_STATS_INC(x)
#define TCP_STATS_DISPLAY()

#define UDP_STATS_INC(x)
#define UDP_STATS_DISPLAY()

#define ICMP_STATS_INC(x)
#define ICMP_STATS_DISPLAY()

#define IGMP_STATS_INC(x)
#define IGMP_STATS_DISPLAY()

#define IP_STATS_INC(x)
#define IP_STATS_DISPLAY()

#define IPFRAG_STATS_INC(x)
#define IPFRAG_STATS_DISPLAY()

#define ETHARP_STATS_INC(x)
#define ETHARP_STATS_DISPLAY()

#define LINK_STATS_INC(x)
#define LINK_STATS_DISPLAY()

#define MEM_STATS_AVAIL(x, y)
#define MEM_STATS_INC(x)
#define MEM_STATS_INC_USED(x, y)
#define MEM_STATS_DEC_USED(x, y)
#define MEM_STATS_DISPLAY()

#define MEMP_STATS_DEC(x, i)
#define MEMP_STATS_DISPLAY(i)
#define MEMP_STATS_GET(x, i) 0

#define SYS_STATS_INC(x)
#define SYS_STATS_DEC(x)
#define SYS_STATS_INC_USED(x)
#define SYS_STATS_DISPLAY()

#define IP6_STATS_INC(x)
#define IP6_STATS_DISPLAY()

#define ICMP6_STATS_INC(x)
#define ICMP6_STATS_DISPLAY()

#define IP6_FRAG_STATS_INC(x)
#define IP6_FRAG_STATS_DISPLAY()

#define MLD6_STATS_INC(x)
#define MLD6_STATS_DISPLAY()

#define ND6_STATS_INC(x)
#define ND6_STATS_DISPLAY()

#define MIB2_STATS_INC(x)

/* Display of statistics */
#define stats_display()
#define stats_display_proto(proto, name)
#define stats_display_igmp(igmp, name)
#define stats_display_mem(mem, name)
#define stats_display_memp(mem, index)
#define stats_display_sys(sys)

#ifdef __cplusplus
}
#endif

#endif /* LWIP_HDR_STATS_H */
