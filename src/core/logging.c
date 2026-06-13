#include <stdlib.h>

#include "lwip/logging.h"

/* Unified debug sink. A single callback, shared by the whole stack. No file
 * I/O: persistence/console/log is entirely the caller's choice inside its
 * callback. See lwip/logging.h. */

static lwip_debug_fn g_debug_fn = NULL;
static uint8_t g_debug_mode = LWIP_DBG_INFO;
static uint8_t g_debug_depth = LWIP_DBG_DEPTH_MILESTONE;
static bool g_in_fatal = false;
static void (*g_fatal_cleanup)(void) = NULL;

void lwip_debug_set_fatal_cleanup(void (*cleanup)(void))
{
    g_fatal_cleanup = cleanup;
}

void lwip_set_debug(lwip_debug_fn debug_fn, uint8_t debug_mode,
                    uint8_t debug_depth)
{
    g_debug_fn = debug_fn;
    /* Default to delivering everything if no usable mode bit is set. */
    if ((debug_mode & (LWIP_DBG_INFO | LWIP_DBG_ERROR)) == 0)
    {
        debug_mode = LWIP_DBG_INFO;
    }
    g_debug_mode = debug_mode;
    g_debug_depth = debug_depth;
}

void lwip_debug_emit_at(uint16_t module, uint16_t module_state, int errnum,
                        uint16_t line, uint8_t depth)
{
    if (!g_debug_fn)
    {
        return;
    }
    /* LWIP_DBG_INFO delivers everything; LWIP_DBG_ERROR delivers only events
     * with a non-zero errnum. (Both set behaves like INFO.) */
    if (!(g_debug_mode & LWIP_DBG_INFO) && errnum == 0)
    {
        return;
    }
    /* Drop emits deeper than the configured verbosity — but errors always
     * surface, no matter how deep they were raised. */
    if (depth > g_debug_depth && errnum == 0)
    {
        return;
    }

    struct lwip_debug_info info;
    info.module = module;
    info.module_state = module_state;
    info.errnum = errnum;
    info.line = line;
    info.depth = depth;
    g_debug_fn(&info);
}

void lwip_debug_emit(uint16_t module, uint16_t module_state, int errnum,
                     uint16_t line)
{
    lwip_debug_emit_at(module, module_state, errnum, line,
                       LWIP_DBG_DEPTH_MILESTONE);
}

void lwip_debug_fatal(uint16_t module, uint16_t module_state, int errnum,
                      uint16_t line)
{
    /* Guard against re-entrancy if the callback itself trips a fatal. */
    if (g_in_fatal)
    {
        exit(1);
    }
    g_in_fatal = true;
    /* A fatal is always an error; force a non-zero errnum so it is delivered
     * even in LWIP_DBG_ERROR mode. */
    if (errnum == 0)
    {
        errnum = -1;
    }
    if (g_debug_fn)
    {
        struct lwip_debug_info info;
        info.module = module;
        info.module_state = module_state;
        info.errnum = errnum;
        info.line = line;
        info.depth = LWIP_DBG_DEPTH_MILESTONE;
        g_debug_fn(&info);
    }
    if (g_fatal_cleanup)
    {
        g_fatal_cleanup();
    }
    exit(1);
}

/* Compatibility entry points for the lwIP core macros (debug.h). */
void lwip_log_event_at(uint16_t module, uint16_t module_state, uint16_t line)
{
    lwip_debug_emit(module, module_state, -1, line);
}

void lwip_log_fatal_at(uint16_t module, uint16_t module_state, uint16_t line)
{
    lwip_debug_fatal(module, module_state, -1, line);
}

const char *lwip_debug_module_name(uint16_t module)
{
    switch (module)
    {
    case LWIP_DBG_MOD_LWIP: return "lwip";
    case LWIP_DBG_MOD_USB:  return "usb";
    case LWIP_DBG_MOD_TCP:  return "tcp";
    case LWIP_DBG_MOD_UDP:  return "udp";
    case LWIP_DBG_MOD_TLS:  return "tls";
    default:                return "?";
    }
}

const char *lwip_debug_state_name(uint16_t module_state)
{
    switch (module_state)
    {
    case LWIP_DBG_LWIP_ASSERT:             return "assert";
    case LWIP_DBG_LWIP_ERROR:              return "error";

    case LWIP_DBG_USB_ENDPOINT_STALL:      return "ep_stall";
    case LWIP_DBG_USB_ENDPOINT_NO_DEVICE:  return "ep_no_device";
    case LWIP_DBG_USB_ENDPOINT_ERROR:      return "ep_error";
    case LWIP_DBG_USB_FATAL_RETRY:         return "fatal_retry";
    case LWIP_DBG_USB_RX_DRAIN_SHORT:      return "rx_drain_short";
    case LWIP_DBG_USB_RX_DRAIN_FATAL:      return "rx_drain_fatal";

    case LWIP_DBG_TLS_INIT_START:          return "tls_init started";
    case LWIP_DBG_TLS_TRUSTSTORE_INIT:     return "tls_truststore init";
    case LWIP_DBG_TLS_TRUSTSTORE_VERIFIED: return "tls_truststore verified";
    case LWIP_DBG_TLS_INIT_DONE:           return "tls_init done";

    case LWIP_DBG_TLS_HANDSHAKE_BEGIN:     return "handshake_begin";
    case LWIP_DBG_TLS_CLIENT_HELLO:        return "client_hello";
    case LWIP_DBG_TLS_SERVER_HELLO:        return "server_hello";
    case LWIP_DBG_TLS_KEY_EXCHANGE:        return "key_exchange";
    case LWIP_DBG_TLS_DERIVE_HS_KEYS:      return "derive_hs_keys";
    case LWIP_DBG_TLS_ENCRYPTED_EXT:       return "encrypted_extensions";
    case LWIP_DBG_TLS_CERTIFICATE:         return "certificate";
    case LWIP_DBG_TLS_CERTIFICATE_VERIFY:  return "certificate_verify";
    case LWIP_DBG_TLS_DERIVE_APP_KEYS:     return "derive_app_keys";
    case LWIP_DBG_TLS_FINISHED:            return "finished";
    case LWIP_DBG_TLS_HANDSHAKE_END:       return "handshake_end";

    case LWIP_DBG_TLS_FATAL_ALERT:         return "fatal_alert";
    case LWIP_DBG_TLS_TRUSTSTORE_FAIL:     return "truststore_fail";
    case LWIP_DBG_TLS_CERTVERIFY_FAIL:     return "certverify_fail";

    case LWIP_DBG_TLS_REC_RX:              return "rec_rx";
    case LWIP_DBG_TLS_REC_PARTIAL:         return "rec_partial";
    case LWIP_DBG_TLS_DERIVE_HS_KEYS_V:    return "derive_hs_keys";
    case LWIP_DBG_TLS_DECRYPT:             return "decrypt";
    case LWIP_DBG_TLS_DECRYPT_NOMEM:       return "decrypt_nomem";
    case LWIP_DBG_TLS_PROCESS_INNER:       return "process_inner";
    case LWIP_DBG_TLS_CERT_WALK:           return "cert_walk";

    default:                               return "?";
    }
}
