#include <stdlib.h>

#include "lwip/logging.h"

/* Unified event sink. A single callback, shared by the whole stack. No file
 * I/O: persistence/console/log is entirely the caller's choice inside its
 * callback. See lwip/logging.h. */

#define LWIP_TRACEBACK_DEPTH 16u

static lwip_event_fn g_event_fn = NULL;
static uint32_t g_last_debug_loc = 0xFFFFFFFFu; /* no event has this value */
static bool g_in_fatal = false;
static void (*g_fatal_cleanup)(void) = NULL;
static struct lwip_traceback_entry g_traceback[LWIP_TRACEBACK_DEPTH];
static struct lwip_traceback_entry g_traceback_ordered[LWIP_TRACEBACK_DEPTH];
static uint8_t g_traceback_next = 0;
static uint8_t g_traceback_count = 0;

static void lwip_traceback_push(const struct lwip_traceback_entry *entry)
{
    if (!entry)
    {
        return;
    }
    g_traceback[g_traceback_next] = *entry;
    g_traceback_next = (uint8_t)((g_traceback_next + 1u) % LWIP_TRACEBACK_DEPTH);
    if (g_traceback_count < LWIP_TRACEBACK_DEPTH)
    {
        g_traceback_count++;
    }
}

static void lwip_traceback_push_code(uint8_t module, uint8_t kind,
                                     uint32_t loc, uint16_t extra)
{
    struct lwip_traceback_entry entry;

    entry.module = module;
    entry.kind = kind;
    entry.file = LWIP_EVENT_CODE_FILE(loc);
    entry.line = LWIP_EVENT_CODE_LINE(loc);
    entry.extra = extra;
    entry.component = 0;
    entry.operation = 0;
    entry.raw_error = 0;
    entry.mapped_error = 0;
    entry.status = 0;
    lwip_traceback_push(&entry);
}

void lwip_debug_set_fatal_cleanup(void (*cleanup)(void))
{
    g_fatal_cleanup = cleanup;
}

void lwip_set_event_cb(lwip_event_fn event_fn)
{
    g_event_fn = event_fn;
    g_last_debug_loc = 0xFFFFFFFFu;
}

const struct lwip_traceback_entry *lwip_get_traceback(uint8_t *count)
{
    for (uint8_t i = 0; i < g_traceback_count; i++)
    {
        uint8_t idx = (uint8_t)((g_traceback_next + LWIP_TRACEBACK_DEPTH - 1u - i) %
                                LWIP_TRACEBACK_DEPTH);
        g_traceback_ordered[i] = g_traceback[idx];
    }
    if (count)
    {
        *count = g_traceback_count;
    }
    return g_traceback_ordered;
}

void lwip_event_emit_code(uint8_t module, uint8_t kind, uint32_t loc, uint16_t extra)
{
    if (kind == LWIP_EV_DEBUG)
    {
        /* DEBUG only fires when the call site changes from the last one. */
        if (loc == g_last_debug_loc)
        {
            return;
        }
        g_last_debug_loc = loc;
    }

    if (kind == LWIP_EV_WARN || kind == LWIP_EV_ERROR)
    {
        lwip_traceback_push_code(module, kind, loc, extra);
    }

    if (!g_event_fn)
    {
        return;
    }

    struct lwip_event ev;
    ev.module = module;
    ev.kind = kind;
    ev.data.code.loc = loc;
    ev.data.code.extra = extra;
    g_event_fn(&ev);
}

void lwip_traceback_push_socket(uint16_t component, uint16_t operation,
                                int raw_error, uint16_t mapped_error,
                                uint16_t status)
{
    struct lwip_traceback_entry entry;

    entry.module = LWIP_DBG_MOD_LWIP;
    entry.kind = LWIP_EV_ERROR;
    entry.file = LWIP_FILE_NONE;
    entry.line = 0;
    entry.extra = 0;
    entry.component = component;
    entry.operation = operation;
    entry.raw_error = raw_error;
    entry.mapped_error = mapped_error;
    entry.status = status;
    lwip_traceback_push(&entry);
}

void lwip_event_emit_info(uint8_t module, const char *msg)
{
    if (!g_event_fn)
    {
        return;
    }
    struct lwip_event ev;
    ev.module = module;
    ev.kind = LWIP_EV_INFO;
    ev.data.msg = msg;
    g_event_fn(&ev);
}

void lwip_event_emit_state(uint8_t module, void *owner, uint16_t change_event)
{
    if (!g_event_fn)
    {
        return;
    }
    struct lwip_event ev;
    ev.module = module;
    ev.kind = LWIP_EV_STATE_CHG;
    ev.data.state.owner = owner;
    ev.data.state.change_event = change_event;
    g_event_fn(&ev);
}

void lwip_event_emit_io_file(uint8_t module, uint8_t dir, const char *name, uint32_t bytes)
{
    if (!g_event_fn)
    {
        return;
    }
    struct lwip_event ev;
    ev.module = module;
    ev.kind = LWIP_EV_IO_FILE;
    ev.data.file.dir = dir;
    ev.data.file.name = name;
    ev.data.file.bytes = bytes;
    g_event_fn(&ev);
}

void lwip_event_emit_io_eth(uint8_t module, uint8_t dir, uint32_t bytes)
{
    if (!g_event_fn)
    {
        return;
    }
    struct lwip_event ev;
    ev.module = module;
    ev.kind = LWIP_EV_IO_ETH;
    ev.data.eth.dir = dir;
    ev.data.eth.bytes = bytes;
    g_event_fn(&ev);
}

void lwip_event_emit_power(uint8_t module, uint8_t subtype, uint8_t charging)
{
    if (!g_event_fn)
    {
        return;
    }
    struct lwip_event ev;
    ev.module = module;
    ev.kind = LWIP_EV_POWER;
    ev.data.power.subtype = subtype;
    ev.data.power.charging = charging;
    g_event_fn(&ev);
}

/* Compatibility entry points for the lwIP core LWIP_ASSERT/LWIP_ERROR macros
 * (debug.h), which have no file_id of their own: routed as ERROR events with
 * LWIP_FILE_NONE, exact line preserved. */
void lwip_log_event_at(uint16_t module, uint16_t module_state, uint16_t line)
{
    (void)module_state;
    lwip_event_emit_code((uint8_t)module, LWIP_EV_ERROR,
                         LWIP_EVENT_CODE(LWIP_FILE_NONE, line), 0);
}

void lwip_log_fatal_at(uint16_t module, uint16_t module_state, uint16_t line)
{
    if (g_in_fatal)
    {
        exit(1);
    }
    g_in_fatal = true;
    lwip_log_event_at(module, module_state, line);
    if (g_fatal_cleanup)
    {
        g_fatal_cleanup();
    }
    exit(1);
}

const char *lwip_debug_module_name(uint16_t module)
{
    switch (module)
    {
    case LWIP_DBG_MOD_LWIP: return "lwip";
    case LWIP_DBG_MOD_USB:  return "usb";
    case LWIP_DBG_MOD_MEM:  return "mem";
    case LWIP_DBG_MOD_TLS:  return "tls";
    default:                return "?";
    }
}

const char *lwip_debug_file_name(uint8_t file_id)
{
    switch (file_id)
    {
    case LWIP_FILE_TLS:                  return "tls.c";
    case LWIP_FILE_HANDSHAKE:            return "handshake.c";
    case LWIP_FILE_TRUSTSTORE:           return "truststore.c";
    case LWIP_FILE_AES:                  return "aes.c";
    case LWIP_FILE_ASN1:                 return "asn1.c";
    case LWIP_FILE_BASE64:               return "base64.c";
    case LWIP_FILE_HASH:                 return "hash.c";
    case LWIP_FILE_HKDF:                 return "hkdf.c";
    case LWIP_FILE_HMAC:                 return "hmac.c";
    case LWIP_FILE_KEYOBJECT:            return "keyobject.c";
    case LWIP_FILE_PASSWORDS:            return "passwords.c";
    case LWIP_FILE_PKCS8:                return "pkcs8.c";
    case LWIP_FILE_RANDOM:               return "random.c";
    case LWIP_FILE_RSA:                  return "rsa.c";
    case LWIP_FILE_X509:                 return "x509.c";
    case LWIP_FILE_ALTCP_TLS_CE:         return "altcp_tls_ce.c";
    case LWIP_FILE_ALTCP_TLS_CE_EXAMPLE: return "altcp_tls_ce_example.c";
    case LWIP_FILE_USB_ETHERNET:         return "usb_ethernet.c";
    case LWIP_FILE_MEM:                  return "mem.c";
    case LWIP_FILE_LWIP_CE:              return "lwIP.c";
    case LWIP_FILE_APP_CONFIG:           return "app_config.c";
    case LWIP_FILE_LWIP_RUNTIME:         return "lwip_runtime.c";
    case LWIP_FILE_DISPATCH:             return "dispatch.c";
    case LWIP_FILE_TEARDOWN:             return "teardown.c";
    case LWIP_FILE_LOGGING:              return "logging.c";
    case LWIP_FILE_MAIN:                 return "main.c";
    default:                             return "?";
    }
}

const char *lwip_debug_state_change_name(uint16_t change_event)
{
    switch (change_event)
    {
    case LWIP_STATE_LINK_UP:               return "link_up";
    case LWIP_STATE_LINK_DOWN:             return "link_down";
    case LWIP_STATE_IP_ACQUIRED:           return "ip_acquired";
    case LWIP_STATE_IP_LOST:               return "ip_lost";
    case LWIP_STATE_CONN_CONNECTING:       return "conn_connecting";
    case LWIP_STATE_CONN_ESTABLISHED:      return "conn_established";
    case LWIP_STATE_CONN_CLOSED:           return "conn_closed";
    case LWIP_STATE_CONN_FAILED:           return "conn_failed";
    case LWIP_STATE_TLS_HANDSHAKE_BEGIN:   return "tls_handshake_begin";
    case LWIP_STATE_TLS_HANDSHAKE_DONE:    return "tls_handshake_done";
    case LWIP_STATE_TLS_HANDSHAKE_FAILED:  return "tls_handshake_failed";
    default:                               return "?";
    }
}
