/*
 * File: init.h
 * Author: Adam Dunkels <adam@sics.se>, Anthony Cagliano, Simon Goldschmidt, Dirk Ziegelmeier, goldsimon, sg, Sylvain Rochet, kieranm, fbernon
 * Description: lwIP initialization API
 * Generated: 2026-05-26T14:35:13Z
 */
/**
 * @file
 * lwIP initialization API
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
#ifndef LWIP_PUBLIC_CORE_INIT_H
#define LWIP_PUBLIC_CORE_INIT_H

#include "lwip/opt.h"
#include "lwip/err.h"
#include "drivers/usb_ethernet.h"
#include <stdlib.h>  /* malloc, free, realloc — needed by LWIP_CONFIGURATOR_INIT */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup lwip_version Version
 * @ingroup lwip
 * @{
 */

/** X.x.x: Major version of the stack */
#define LWIP_VERSION_MAJOR      2
/** x.X.x: Minor version of the stack */
#define LWIP_VERSION_MINOR      2
/** x.x.X: Revision of the stack */
#define LWIP_VERSION_REVISION   2
/** For release candidates, this is set to 1..254
  * For official releases, this is set to 255 (LWIP_RC_RELEASE)
  * For development versions (Git), this is set to 0 (LWIP_RC_DEVELOPMENT) */
#define LWIP_VERSION_RC         LWIP_RC_DEVELOPMENT

/** LWIP_VERSION_RC is set to LWIP_RC_RELEASE for official releases */
#define LWIP_RC_RELEASE         255
/** LWIP_VERSION_RC is set to LWIP_RC_DEVELOPMENT for Git versions */
#define LWIP_RC_DEVELOPMENT     0

#define LWIP_VERSION_IS_RELEASE     (LWIP_VERSION_RC == LWIP_RC_RELEASE)
#define LWIP_VERSION_IS_DEVELOPMENT (LWIP_VERSION_RC == LWIP_RC_DEVELOPMENT)
#define LWIP_VERSION_IS_RC          ((LWIP_VERSION_RC != LWIP_RC_RELEASE) && (LWIP_VERSION_RC != LWIP_RC_DEVELOPMENT))

/* Some helper defines to get a version string */
#define LWIP_VERSTR2(x) #x
#define LWIP_VERSTR(x) LWIP_VERSTR2(x)
#if LWIP_VERSION_IS_RELEASE
#define LWIP_VERSION_STRING_SUFFIX ""
#elif LWIP_VERSION_IS_DEVELOPMENT
#define LWIP_VERSION_STRING_SUFFIX "d"
#else
#define LWIP_VERSION_STRING_SUFFIX "rc" LWIP_VERSTR(LWIP_VERSION_RC)
#endif

/** Provides the version of the stack */
#define LWIP_VERSION   ((LWIP_VERSION_MAJOR) << 24   | (LWIP_VERSION_MINOR) << 16 | \
                        (LWIP_VERSION_REVISION) << 8 | (LWIP_VERSION_RC))
/** Provides the version of the stack as string */
#define LWIP_VERSION_STRING     LWIP_VERSTR(LWIP_VERSION_MAJOR) "." LWIP_VERSTR(LWIP_VERSION_MINOR) "." LWIP_VERSTR(LWIP_VERSION_REVISION) LWIP_VERSION_STRING_SUFFIX

/**
 * @}
 */

struct lwip_configurator {
    uint24_t version;
    struct usb_configurator usb_conf;
    struct {
        void* (*caller_malloc)(size_t);
        void  (*caller_free)(void*);
        void* (*caller_realloc)(void*, size_t);
    } malloc_conf;
};
#define LWIP_CONFIGURATOR_V1 sizeof(struct lwip_configurator)

/**
 * Designated initializer for lwip_configurator.
 *
 * The shipped lwip header defines this macro so that when the *caller*
 * includes it and writes:
 *
 *   static struct lwip_configurator conf = LWIP_CONFIGURATOR_INIT;
 *
 * the struct is built into the caller's translation unit, which means
 * malloc/free/realloc resolve to the *caller's* CRT — not lwip-ce's.
 * This keeps all lwip heap traffic inside the caller's allocator and
 * avoids any cross-program heap conflict.
 *
 * After this, the caller only needs to fill in the usb_conf fields
 * before calling lwip_init().
 */
#define LWIP_CONFIGURATOR_INIT \
    { \
        .version        = LWIP_CONFIGURATOR_V1, \
        .usb_conf       = {0}, \
        .malloc_conf    = { malloc, free, realloc } \
    }

/* Modules initialization */
err_t lwip_init(struct lwip_configurator *conf);


#ifdef __cplusplus
}
#endif

#endif /* LWIP_PUBLIC_CORE_INIT_H */
