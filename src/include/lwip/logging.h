#ifndef LWIP_LOGGING_H
#define LWIP_LOGGING_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Unified lwIP event system.
 *
 * Every module (USB, TLS, the custom allocator, the lwIP-CE glue layer)
 * routes notable events through a single callback. The library performs no
 * I/O of its own. If the caller wants a log, persistence, or an on-screen
 * console, it does that inside its callback.
 *
 * Each .c file that emits events defines, once near the top, which file and
 * module it is:
 *
 *   #define LWIP_DBG_FILE_ID  LWIP_FILE_TRUSTSTORE
 *   #define LWIP_DBG_MODULE   LWIP_DBG_MOD_TLS
 *   #include "lwip/logging.h"
 *
 * Then, at any fallible call site:
 *
 *   if (status != OK) { ERROR(); ...handle... }
 *   if (degraded)      { WARN(); }
 *   DEBUG();                          // fires only when the {file,line} changes
 *   ERROR_CODE(status);               // ERROR + a caller-supplied uint16_t
 *   WARN_CODE(bitmask);
 *   INFO("sent ClientHello");         // milestone, payload is the string itself
 *   STATE_CHG(conn, LWIP_STATE_CONN_ESTABLISHED);
 *   IO_FILE(LWIP_IO_READ, "lwIPTS", n);
 *   IO_ETH(LWIP_IO_RX, n);
 *
 * Set the callback once with lwip_set_event_cb(); it is shared by the whole
 * stack. Pass NULL to disable.
 */

/** Which component emitted an event. */
typedef enum lwip_debug_module
{
    LWIP_DBG_MOD_NONE = 0,
    LWIP_DBG_MOD_LWIP,   /* lwIP-CE glue (conn/socket layer, dispatch, netif) */
    LWIP_DBG_MOD_USB,    /* USB ethernet driver                       */
    LWIP_DBG_MOD_MEM,    /* custom allocator                          */
    LWIP_DBG_MOD_TLS     /* TLS handshake / record layer / crypto     */
} lwip_debug_module_t;

/**
 * File registry. One entry per .c file that emits events. Assigned by hand;
 * stable across builds. 0 is reserved/invalid. Fits in the top byte of an
 * event code (file_id << 24 | line).
 */
typedef enum lwip_debug_file_id
{
    LWIP_FILE_NONE = 0,

    /* ---- TLS core / crypto ---- */
    LWIP_FILE_TLS,                  /* tls/core/tls.c            */
    LWIP_FILE_HANDSHAKE,            /* tls/core/handshake.c      */
    LWIP_FILE_TRUSTSTORE,           /* tls/core/truststore.c     */
    LWIP_FILE_AES,                  /* tls/core/aes.c            */
    LWIP_FILE_ASN1,                 /* tls/core/asn1.c           */
    LWIP_FILE_BASE64,               /* tls/core/base64.c         */
    LWIP_FILE_HASH,                 /* tls/core/hash.c           */
    LWIP_FILE_HKDF,                 /* tls/core/hkdf.c           */
    LWIP_FILE_HMAC,                 /* tls/core/hmac.c           */
    LWIP_FILE_KEYOBJECT,            /* tls/core/keyobject.c      */
    LWIP_FILE_PASSWORDS,            /* tls/core/passwords.c      */
    LWIP_FILE_PKCS8,                /* tls/core/pkcs8.c          */
    LWIP_FILE_RANDOM,                /* tls/core/random.c         */
    LWIP_FILE_RSA,                  /* tls/core/rsa.c            */
    LWIP_FILE_X509,                 /* tls/core/x509.c           */

    /* ---- altcp / TLS integration ---- */
    LWIP_FILE_ALTCP_TLS_CE,         /* apps/altcp_tls/altcp_tls_ce.c         */
    LWIP_FILE_ALTCP_TLS_CE_EXAMPLE, /* apps/altcp_tls/altcp_tls_ce_example.c */

    /* ---- USB driver ---- */
    LWIP_FILE_USB_ETHERNET,         /* drivers/usb_ethernet.c    */

    /* ---- custom allocator ---- */
    LWIP_FILE_MEM,                  /* drivers/mem.c             */

    /* ---- lwIP-CE glue ---- */
    LWIP_FILE_LWIP_CE,              /* lwIP.c                    */
    LWIP_FILE_APP_CONFIG,           /* core/app_config.c         */
    LWIP_FILE_LWIP_RUNTIME,         /* core/lwip_runtime.c       */
    LWIP_FILE_DISPATCH,             /* core/dispatch.c           */
    LWIP_FILE_TEARDOWN,             /* core/teardown.c           */
    LWIP_FILE_LOGGING,              /* core/logging.c            */
    LWIP_FILE_MAIN,                 /* main.c (config app)       */

    LWIP_FILE_MAX
} lwip_debug_file_id_t;

/** Kind of event (lwip_event.kind). */
typedef enum lwip_event_kind
{
    LWIP_EV_INFO = 0,     /* milestone; data.msg is a literal string         */
    LWIP_EV_DEBUG,        /* trace point; data.code, deduped by {file,line}  */
    LWIP_EV_WARN,         /* tolerated problem; data.code                   */
    LWIP_EV_ERROR,        /* hard failure; data.code                        */
    LWIP_EV_STATE_CHG,    /* meaningful state transition; data.state         */
    LWIP_EV_IO_FILE,      /* appvar/flash read or write; data.file           */
    LWIP_EV_IO_ETH        /* network bytes rx/tx; data.eth                   */
} lwip_event_kind_t;

/** I/O direction for IO_FILE. */
enum lwip_io_file_dir { LWIP_IO_READ = 0, LWIP_IO_WRITE = 1 };

/** I/O direction for IO_ETH. */
enum lwip_io_eth_dir { LWIP_IO_RX = 0, LWIP_IO_TX = 1 };

/**
 * Meaningful state transitions worth surfacing on their own, independent of
 * the object whose state changed (lwip_event.data.state.owner identifies
 * which object). Kept small and curated on purpose — not a code per struct
 * field, just the handful of transitions a console/UI actually cares about.
 */
typedef enum lwip_state_change
{
    LWIP_STATE_NONE = 0,

    LWIP_STATE_LINK_UP,
    LWIP_STATE_LINK_DOWN,
    LWIP_STATE_IP_ACQUIRED,
    LWIP_STATE_IP_LOST,

    LWIP_STATE_CONN_CONNECTING,
    LWIP_STATE_CONN_ESTABLISHED,
    LWIP_STATE_CONN_CLOSED,
    LWIP_STATE_CONN_FAILED,

    LWIP_STATE_TLS_HANDSHAKE_BEGIN,
    LWIP_STATE_TLS_HANDSHAKE_DONE,
    LWIP_STATE_TLS_HANDSHAKE_FAILED
} lwip_state_change_t;

/**
 * A code identifying exactly where an ERROR/WARN/DEBUG event was raised:
 * file_id in the top byte, source line in the low 24 bits. Use
 * LWIP_EVENT_CODE_FILE/LINE to decode.
 */
#define LWIP_EVENT_CODE(file_id, line) \
    (((uint32_t)(file_id) << 24) | ((uint32_t)(line) & 0x00FFFFFFu))
#define LWIP_EVENT_CODE_FILE(code) ((uint8_t)((code) >> 24))
#define LWIP_EVENT_CODE_LINE(code) ((uint32_t)(code) & 0x00FFFFFFu)

/** One event handed to the callback. */
struct lwip_event
{
    uint8_t module;  /* lwip_debug_module_t */
    uint8_t kind;    /* lwip_event_kind_t   */
    union
    {
        const char *msg;        /* INFO: literal message               */
        struct
        {
            uint32_t loc;        /* LWIP_EVENT_CODE(file_id, line)      */
            uint16_t extra;      /* 0 for bare ERROR()/WARN()/DEBUG()    */
        } code;                  /* DEBUG / WARN / ERROR                 */
        struct
        {
            void    *owner;       /* object whose state changed          */
            uint16_t change_event; /* lwip_state_change_t                */
        } state;                 /* STATE_CHG                            */
        struct
        {
            uint8_t     dir;      /* lwip_io_file_dir                    */
            const char *name;     /* appvar name                         */
            uint32_t    bytes;
        } file;                  /* IO_FILE                              */
        struct
        {
            uint8_t  dir;         /* lwip_io_eth_dir                     */
            uint32_t bytes;
        } eth;                   /* IO_ETH                               */
    } data;
};

/** One captured traceback entry, newest-first from lwip_get_traceback().
 *
 * For WARN/ERROR entries, module/kind/file/line/extra identify the emitting
 * call site. DEBUG events stay callback-only and do not occupy traceback
 * slots. For socket-wrapper error entries, component/operation, raw_error,
 * mapped_error, and status carry the same fields exposed through
 * lwip_socket_error_data_t; file/line are zero because the causal call site is
 * expected to be one of the preceding code entries.
 */
struct lwip_traceback_entry
{
    uint8_t  module;       /* lwip_debug_module_t */
    uint8_t  kind;         /* lwip_event_kind_t */
    uint8_t  file;         /* lwip_debug_file_id_t */
    uint32_t line;         /* source line, or 0 for socket entries */
    uint16_t extra;        /* ERROR_CODE/WARN_CODE extra */
    uint16_t component;    /* lwip_socket_error_component_t, or 0 */
    uint16_t operation;    /* lwip_socket_error_operation_t, or 0 */
    int      raw_error;    /* raw err_t/module code, or 0 */
    uint16_t mapped_error; /* lwip_error_t, or 0 */
    uint16_t status;       /* lwip_status_t, or 0 */
};

/** The shared event callback. */
typedef void (*lwip_event_fn)(const struct lwip_event *ev);

/**
 * Install the stack-wide event callback. NULL disables. There is no mode or
 * depth filter any more — every emitted event reaches the callback (DEBUG is
 * already self-throttling: it only fires when the {file,line} it's raised at
 * changes from the previous DEBUG emit).
 */
void lwip_set_event_cb(lwip_event_fn event_fn);

/** Return recent WARN/ERROR/socket-error trace entries, newest first.
 *  The returned pointer is owned by lwIP and remains valid until the next call
 *  to lwip_get_traceback() or until another trace entry is pushed. */
const struct lwip_traceback_entry *lwip_get_traceback(uint8_t *count);

/** Human-readable label for a module (e.g. "tls"). */
const char *lwip_debug_module_name(uint16_t module);

/** Human-readable label for a file_id (e.g. "truststore.c"). */
const char *lwip_debug_file_name(uint8_t file_id);

/** Human-readable label for a state_change (e.g. "conn_established"). */
const char *lwip_debug_state_change_name(uint16_t change_event);

/* ----------------------------------------------------------------------
 * Internal emit entry points. Use the ERROR()/WARN()/DEBUG()/... macros
 * below instead of calling these directly.
 * -------------------------------------------------------------------- */
void lwip_event_emit_code(uint8_t module, uint8_t kind, uint32_t loc, uint16_t extra);
void lwip_event_emit_info(uint8_t module, const char *msg);
void lwip_event_emit_state(uint8_t module, void *owner, uint16_t change_event);
void lwip_event_emit_io_file(uint8_t module, uint8_t dir, const char *name, uint32_t bytes);
void lwip_event_emit_io_eth(uint8_t module, uint8_t dir, uint32_t bytes);
void lwip_traceback_push_socket(uint16_t component, uint16_t operation,
                                int raw_error, uint16_t mapped_error,
                                uint16_t status);

/* ----------------------------------------------------------------------
 * Call-site macros. Each .c file using these must first define:
 *   #define LWIP_DBG_FILE_ID  <one of lwip_debug_file_id_t>
 *   #define LWIP_DBG_MODULE   <one of lwip_debug_module_t>
 * -------------------------------------------------------------------- */
#define ERROR() \
    lwip_event_emit_code(LWIP_DBG_MODULE, LWIP_EV_ERROR, \
                         LWIP_EVENT_CODE(LWIP_DBG_FILE_ID, __LINE__), 0)

#define ERROR_CODE(extra) \
    lwip_event_emit_code(LWIP_DBG_MODULE, LWIP_EV_ERROR, \
                         LWIP_EVENT_CODE(LWIP_DBG_FILE_ID, __LINE__), (uint16_t)(extra))

#define WARN() \
    lwip_event_emit_code(LWIP_DBG_MODULE, LWIP_EV_WARN, \
                         LWIP_EVENT_CODE(LWIP_DBG_FILE_ID, __LINE__), 0)

#define WARN_CODE(extra) \
    lwip_event_emit_code(LWIP_DBG_MODULE, LWIP_EV_WARN, \
                         LWIP_EVENT_CODE(LWIP_DBG_FILE_ID, __LINE__), (uint16_t)(extra))

#define DEBUG() \
    lwip_event_emit_code(LWIP_DBG_MODULE, LWIP_EV_DEBUG, \
                         LWIP_EVENT_CODE(LWIP_DBG_FILE_ID, __LINE__), 0)

#define INFO(str) \
    lwip_event_emit_info(LWIP_DBG_MODULE, (str))

#define STATE_CHG(owner, change_event) \
    lwip_event_emit_state(LWIP_DBG_MODULE, (void *)(owner), (uint16_t)(change_event))

#define IO_FILE(dir, name, bytes) \
    lwip_event_emit_io_file(LWIP_DBG_MODULE, (uint8_t)(dir), (name), (uint32_t)(bytes))

#define IO_ETH(dir, bytes) \
    lwip_event_emit_io_eth(LWIP_DBG_MODULE, (uint8_t)(dir), (uint32_t)(bytes))

/* ----------------------------------------------------------------------
 * Compatibility shim for the lwIP core LWIP_ASSERT/LWIP_ERROR macros in
 * debug.h, which have no file_id of their own. Routed onto the new event
 * system as ERROR-kind events with LWIP_FILE_NONE; the line number is still
 * exact. Used by vendored upstream code (mem.c, altcp_tls_mbedtls*.c) and by
 * altcp_tls_ce.c.
 * -------------------------------------------------------------------- */
#define LWIP_LOG_TYPE_LWIP   LWIP_DBG_MOD_LWIP
#define LWIP_LOG_LWIP_ASSERT 1
#define LWIP_LOG_LWIP_ERROR  2

void lwip_log_event_at(uint16_t module, uint16_t module_state, uint16_t line);
void lwip_log_fatal_at(uint16_t module, uint16_t module_state, uint16_t line)
    __attribute__((noreturn));

/**
 * Register a cleanup routine run on a fatal LWIP_ASSERT, after the event
 * callback and before exit(). NULL clears it.
 */
void lwip_debug_set_fatal_cleanup(void (*cleanup)(void));

#ifdef __cplusplus
}
#endif

#endif /* LWIP_LOGGING_H */
