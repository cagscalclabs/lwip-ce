#ifndef LWIP_LOGGING_H
#define LWIP_LOGGING_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Unified lwIP debug/event system.
 *
 * Every module (USB, TLS, TCP, UDP, the lwIP core) routes notable events —
 * progress milestones, errors, and fatal asserts — through a single debug
 * callback. The library performs no I/O of its own: it does NOT write a log
 * file. If the caller wants a log, persistence, or an on-screen console, it
 * does that inside its callback.
 *
 * Set the callback once with lwip_set_debug(); it is shared by the whole
 * stack. Pass NULL to disable.
 */

/** Which component emitted an event (lwip_debug_info.module). */
typedef enum lwip_debug_module
{
    LWIP_DBG_MOD_NONE = 0,
    LWIP_DBG_MOD_LWIP,   /* lwIP core (assert/error, dispatch, netif) */
    LWIP_DBG_MOD_USB,    /* USB ethernet driver                       */
    LWIP_DBG_MOD_TCP,
    LWIP_DBG_MOD_UDP,
    LWIP_DBG_MOD_TLS     /* TLS handshake / record layer              */
} lwip_debug_module_t;

/**
 * Where in the code the event was raised (lwip_debug_info.module_state). The
 * value space is shared across modules; read it together with `module`.
 * Grouped in blocks per module so ranges stay readable.
 */
typedef enum lwip_debug_state
{
    LWIP_DBG_STATE_NONE = 0,

    /* ---- lwIP core (0x100..) ---- */
    LWIP_DBG_LWIP_ASSERT = 0x100,
    LWIP_DBG_LWIP_ERROR,

    /* ---- USB (0x200..) ---- */
    LWIP_DBG_USB_ENDPOINT_STALL = 0x200,
    LWIP_DBG_USB_ENDPOINT_NO_DEVICE,
    LWIP_DBG_USB_ENDPOINT_ERROR,
    LWIP_DBG_USB_FATAL_RETRY,
    LWIP_DBG_USB_RX_DRAIN_SHORT,
    LWIP_DBG_USB_RX_DRAIN_FATAL,

    /* ---- TLS init / trust store (0x300..) ---- */
    LWIP_DBG_TLS_INIT_START = 0x300,
    LWIP_DBG_TLS_TRUSTSTORE_INIT,
    LWIP_DBG_TLS_TRUSTSTORE_VERIFIED,
    LWIP_DBG_TLS_INIT_DONE,

    /* ---- TLS handshake steps (0x320..) ---- */
    LWIP_DBG_TLS_HANDSHAKE_BEGIN = 0x320,
    LWIP_DBG_TLS_CLIENT_HELLO,
    LWIP_DBG_TLS_SERVER_HELLO,
    LWIP_DBG_TLS_KEY_EXCHANGE,
    LWIP_DBG_TLS_DERIVE_HS_KEYS,
    LWIP_DBG_TLS_ENCRYPTED_EXT,
    LWIP_DBG_TLS_CERTIFICATE,
    LWIP_DBG_TLS_CERTIFICATE_VERIFY,
    LWIP_DBG_TLS_DERIVE_APP_KEYS,
    LWIP_DBG_TLS_FINISHED,
    LWIP_DBG_TLS_HANDSHAKE_END,

    /* ---- TLS errors (0x340..) ---- */
    LWIP_DBG_TLS_FATAL_ALERT = 0x340,
    LWIP_DBG_TLS_TRUSTSTORE_FAIL,
    LWIP_DBG_TLS_CERTVERIFY_FAIL,

    /* ---- TLS verbose record/decrypt path (0x360..), depth 1 ---- */
    LWIP_DBG_TLS_REC_RX = 0x360,        /* encrypted record seen            */
    LWIP_DBG_TLS_REC_PARTIAL,           /* record split across TCP segments */
    LWIP_DBG_TLS_DERIVE_HS_KEYS_V,      /* deriving handshake keys          */
    LWIP_DBG_TLS_DECRYPT,               /* decrypting a record              */
    LWIP_DBG_TLS_DECRYPT_NOMEM,         /* decrypt scratch alloc deferred   */
    LWIP_DBG_TLS_PROCESS_INNER,         /* feeding plaintext to handshake   */
    LWIP_DBG_TLS_CERT_WALK              /* cert walker processing a chunk   */
} lwip_debug_state_t;

/**
 * One debug event handed to the callback.
 *  - module:        which component raised it (lwip_debug_module_t)
 *  - module_state:  identifier of where in the code (lwip_debug_state_t)
 *  - errnum:        0 = ok / informational; non-zero = an error code
 *  - line:          __LINE__ at the emit site (0 if not applicable)
 */
struct lwip_debug_info
{
    uint16_t module;        /* lwip_debug_module_t */
    uint16_t module_state;  /* lwip_debug_state_t  */
    int      errnum;        /* 0 = ok, else error  */
    uint16_t line;
    uint8_t  depth;         /* verbosity depth of this emit (lwip_debug_depth) */
};

/** Debug delivery mode (bit flags). */
enum lwip_debug_mode
{
    LWIP_DBG_INFO  = 1u, /* deliver every emit (informational + errors) */
    LWIP_DBG_ERROR = 2u  /* deliver only emits with errnum != 0         */
};

/**
 * Verbosity depth. Each emit is tagged with the depth at which it becomes
 * relevant; the callback only receives emits whose depth <= the configured
 * depth (errors are always delivered regardless of depth).
 *
 *   depth 0  — milestones only: per-step state progress + success/error.
 *              Right for a simple "what's happening" display.
 *   depth 1+ — verbose: additional in-flight detail within a step
 *              (fn entry, intermediate actions, ...). Use for deep tracing.
 *
 * A module may define finer sub-states/error numbers and emit them at higher
 * depths; depth 0 stays a clean high-level progress view.
 */
enum lwip_debug_depth
{
    LWIP_DBG_DEPTH_MILESTONE = 0, /* state progress + success/error */
    LWIP_DBG_DEPTH_VERBOSE   = 1  /* in-flight detail within a step */
};

/** The shared debug callback. */
typedef void (*lwip_debug_fn)(const struct lwip_debug_info *info);

/**
 * Install the stack-wide debug callback.
 *
 * @param debug_fn    Callback invoked for matching events (NULL disables).
 * @param debug_mode  Bit-OR of LWIP_DBG_INFO / LWIP_DBG_ERROR. LWIP_DBG_INFO
 *                    delivers all events; LWIP_DBG_ERROR delivers only events
 *                    whose errnum != 0. Passing both is equivalent to
 *                    LWIP_DBG_INFO.
 * @param debug_depth Maximum verbosity depth to deliver (see
 *                    lwip_debug_depth). 0 = milestones only; higher = more
 *                    verbose. Emits above this depth are dropped, except
 *                    error emits, which are always delivered.
 */
void lwip_set_debug(lwip_debug_fn debug_fn, uint8_t debug_mode,
                    uint8_t debug_depth);

/** Human-readable label for a module (e.g. "TLS"). */
const char *lwip_debug_module_name(uint16_t module);

/** Human-readable label for a module_state (e.g. "certificate"). */
const char *lwip_debug_state_name(uint16_t module_state);

/**
 * Emit a debug event at a given verbosity depth. Internal entry point used by
 * every module. Delivered to the callback subject to the configured mode and
 * depth (an error — errnum != 0 — is always delivered regardless of depth).
 * `errnum` of 0 is informational.
 */
void lwip_debug_emit_at(uint16_t module, uint16_t module_state, int errnum,
                        uint16_t line, uint8_t depth);

/** Emit at milestone depth (depth 0). Convenience wrapper. */
void lwip_debug_emit(uint16_t module, uint16_t module_state, int errnum,
                     uint16_t line);

/**
 * Emit a fatal event then terminate the program (does not return). The
 * callback (if any) is invoked first so the caller can record/flush.
 */
void lwip_debug_fatal(uint16_t module, uint16_t module_state, int errnum,
                      uint16_t line) __attribute__((noreturn));

/**
 * Register an internal cleanup routine run on a fatal event, after the debug
 * callback and before exit(). Used by the stack to tear down resources on an
 * assert/fatal. NULL clears it. Not part of the app-facing debug API.
 */
void lwip_debug_set_fatal_cleanup(void (*cleanup)(void));

/* ----------------------------------------------------------------------
 * Compatibility shim for the lwIP core macros in debug.h, which expand to
 * lwip_log_*_at(LWIP_LOG_TYPE_LWIP, LWIP_LOG_LWIP_*, __LINE__). Mapped onto
 * the unified module/module_state space so those macros need no edits.
 * -------------------------------------------------------------------- */
#define LWIP_LOG_TYPE_LWIP   LWIP_DBG_MOD_LWIP
#define LWIP_LOG_LWIP_ASSERT LWIP_DBG_LWIP_ASSERT
#define LWIP_LOG_LWIP_ERROR  LWIP_DBG_LWIP_ERROR

void lwip_log_event_at(uint16_t module, uint16_t module_state, uint16_t line);
void lwip_log_fatal_at(uint16_t module, uint16_t module_state, uint16_t line)
    __attribute__((noreturn));

#ifdef __cplusplus
}
#endif

#endif /* LWIP_LOGGING_H */
