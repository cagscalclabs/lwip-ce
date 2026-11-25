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
     * Then, at any fallible call site. Every ERROR/WARN-class site takes a stable
     * error ID (LWIP_EXXXX, see lwip_error_id_t below) as its first argument:
     *
     *   if (status != OK) { ERROR(LWIP_E0001); ...handle... }
     *   if (degraded)      { WARN(LWIP_E0002); }
     *   DEBUG();                          // fires only when the {file,line} changes
     *   ERROR_CODE(LWIP_E0003, status);   // ERROR + a caller-supplied uint16_t
     *   ERROR_INFO(LWIP_E0004, "named failure"); // textual ERROR without traceback entry
     *   WARN_CODE(LWIP_E0005, bitmask);
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
        LWIP_DBG_MOD_LWIP, /* lwIP-CE glue (conn/socket layer, dispatch, netif) */
        LWIP_DBG_MOD_USB,  /* USB ethernet driver                       */
        LWIP_DBG_MOD_MEM,  /* custom allocator                          */
        LWIP_DBG_MOD_TLS,  /* TLS handshake / record layer / crypto     */
        LWIP_DBG_MOD_WS    /* WebSocket framing layer (RFC 6455)        */
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
    LWIP_FILE_AES,                  /* tls/core/primitives/aes.c */
    LWIP_FILE_ASN1,                 /* tls/core/asn1.c           */
    LWIP_FILE_BASE64,               /* tls/core/base64.c         */
    LWIP_FILE_HASH,                 /* tls/core/hash.c           */
    LWIP_FILE_HKDF,                 /* tls/core/hkdf.c           */
    LWIP_FILE_HMAC,                 /* tls/core/hmac.c */
    LWIP_FILE_KEYOBJECT,            /* tls/core/keyobject.c      */
    LWIP_FILE_PASSWORDS,            /* tls/core/passwords.c      */
    LWIP_FILE_PKCS8,                /* tls/core/pkcs8.c          */
    LWIP_FILE_RANDOM,                /* tls/core/random.c         */
    LWIP_FILE_RSA,                  /* tls/core/rsa.c            */
    LWIP_FILE_X509,                 /* tls/core/x509.c           */

    /* ---- altcp / TLS integration ---- */
    LWIP_FILE_ALTCP_TLS_CE,         /* apps/altcp_tls/altcp_tls_ce.c         */
    LWIP_FILE_ALTCP_TLS_CE_EXAMPLE, /* apps/altcp_tls/altcp_tls_ce_example.c */
    LWIP_FILE_ALTCP_WS,             /* apps/altcp_ws/altcp_ws.c              */

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
    LWIP_FILE_LOG_FILE,             /* core/log_file.c           */

    /* Appended to preserve existing traceback IDs. */
    LWIP_FILE_OCSP,                 /* tls/core/ocsp.c           */
    LWIP_FILE_DNS,
    LWIP_FILE_UDP,
    LWIP_FILE_IP4,
    LWIP_FILE_ETHARP,
    LWIP_FILE_ETHERNET,

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
    LWIP_EV_IO_ETH,       /* network bytes rx/tx; data.eth                   */
    LWIP_EV_POWER,        /* USB/calc power state change; data.power         */
    /* Appended to preserve existing event-kind values. */
    LWIP_EV_ERROR_MSG     /* named error detail; data.msg                    */
} lwip_event_kind_t;

/**
 * User-configurable verbosity gate. Each level admits itself and every level
 * above it: ERROR admits only ERROR; WARNING admits WARNING+ERROR; INFO adds
 * INFO; DEBUG admits everything, including self-throttled DEBUG trace points
 * and STATE_CHG/IO_FILE/IO_ETH/POWER events. Applied once, centrally, in
 * lwip_event_emit_*() before the event reaches the callback — individual
 * call sites never need to check it themselves.
 */
typedef enum lwip_log_verbosity
{
    LWIP_LOG_VERBOSITY_ERROR = 0,
    LWIP_LOG_VERBOSITY_WARNING,
    LWIP_LOG_VERBOSITY_INFO,
    LWIP_LOG_VERBOSITY_DEBUG
} lwip_log_verbosity_t;

/** Install the verbosity gate. Events below the configured level are dropped
 *  before reaching the event callback. Default is LWIP_LOG_VERBOSITY_INFO. */
void lwip_set_log_verbosity(lwip_log_verbosity_t level);

/** Return the currently configured verbosity gate. */
lwip_log_verbosity_t lwip_get_log_verbosity(void);

/**
 * Power event subtypes for LWIP_EV_POWER events (lwip_event.data.power.subtype).
 *
 *   LWIP_POWER_DEVICE_SELF_POWERED  -- a USB device reported self-powered status
 *                                       (not drawing bus power from the calc).
 *   LWIP_POWER_HUB_GOOD             -- a USB hub switched to its own power supply
 *                                       (USB_HUB_LOCAL_POWER_GOOD_EVENT).
 *   LWIP_POWER_HUB_LOST             -- a USB hub lost its own power supply and
 *                                       started drawing bus power from the calc
 *                                       (USB_HUB_LOCAL_POWER_LOST_EVENT).
 *   LWIP_POWER_CALC_CHARGING        -- calc battery is charging (USB supply present).
 *   LWIP_POWER_BATT_LOW             -- calc battery level is low.
 */
typedef enum lwip_power_event
{
    LWIP_POWER_DEVICE_SELF_POWERED = 0,
    LWIP_POWER_HUB_GOOD,
    LWIP_POWER_HUB_LOST,
    LWIP_POWER_CALC_CHARGING,
    LWIP_POWER_BATT_LOW
} lwip_power_event_t;

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
 * Error IDs. Every ERROR/WARN-class call site passes exactly one of these as
 * its first argument, and the log writer prints it as eXXXX (lowercase hex)
 * on TBK and "EVT: ERR:" lines. Unlike {file,line}, an ID survives edits, so
 * a log from any build can be explained by looking the ID up here at that
 * build's revision (the cagscalclabs bug reporter does this automatically).
 *
 * Rules, enforced by `tools/error_ids/error_ids.py check` in CI:
 *   - Append-only. Never renumber, reuse, or delete an ID. When a call site
 *     goes away, keep its line and put RETIRED in the description.
 *   - One ID per call site, one call site per ID.
 *   - One line per ID: `LWIP_EXXXX = 0xXXXX, // meaning. Trigger: condition @cat:NN`.
 *     The text after // is what the bug reporter shows; "Trigger:" splits it
 *     into its own column.
 *
 * New call sites can be written with a placeholder (e.g. ERROR() or
 * ERROR_CODE(x)) and given IDs by `tools/error_ids/error_ids.py assign`,
 * which also drafts a description tagged [auto]. Replace [auto] drafts with
 * a hand-written description when you know the real cause.
 *
 * LWIP_E0000 means "no ID": DEBUG trace points and the vendored lwIP
 * LWIP_ASSERT/LWIP_ERROR shim.
 *
 * Evidence tags. Each line ends with one or more `@category:NN` tags: how
 * strongly this error, seen on its own, points at that category of bug
 * (NN = confidence %, 1-100). The bug reporter combines the tags of every
 * distinct ID in a log into one score per category (noisy-OR), so tag what
 * the error proves, not everything it could be near. `@propagate` marks a
 * site that only forwards a callee's failure; the callee's own ID is the real
 * evidence, so such sites carry low weights. `tools/error_ids/error_ids.py
 * tag` drafts tags; check rejects categories not listed here.
 *
 * error-categories:begin
 *   memory     Heap, pool, or buffer exhausted; an allocation failed.
 *   api        The application called lwIP-CE incorrectly (bad argument, wrong state).
 *   config     Missing or invalid configuration (settings, TLS config, routes).
 *   peer       The remote end sent malformed, unexpected, or unacceptable data.
 *   tls        TLS handshake, record layer, or key schedule failure.
 *   cert       Certificate parsing, chain building, trust store, hostname, or validity.
 *   crypto     Cryptographic primitive or RNG failure.
 *   ws         WebSocket upgrade or framing failure.
 *   dns        Name resolution failure.
 *   transport  TCP/UDP/socket/connection layer failure.
 *   wire       IP, ARP, or Ethernet framing problem; routing or link-layer reachability.
 *   usb        USB Ethernet driver or device failure.
 *   storage    Reading or writing calculator files (appvars, logs).
 *   logic      Internal invariant violated or unexpected internal state (likely an lwIP-CE bug).
 * error-categories:end
 */
typedef enum lwip_error_id
{
    /* error-ids:begin (one entry per line; maintained by tools/error_ids/error_ids.py) */
    LWIP_E0000 = 0x0000, // No error ID: DEBUG trace points and vendored lwIP asserts. Generally not evidence of anything.
    LWIP_E0001 = 0x0001, // altcp_tls_ce_record_aead_init(): The suite fixes the AEAD key length (RFC 8446 Appendix B.4); refuse a mismatched key_len rather than initializing an AEAD with the wrong key size. Trigger: `ctx->key_len != 16 (case TLS_AES_128_CCM_SHA256)` @tls:55
    LWIP_E0002 = 0x0002, // altcp_tls_ce_record_aead_init(): The suite fixes the AEAD key length (RFC 8446 Appendix B.4); refuse a mismatched key_len rather than initializing an AEAD with the wrong key size. Trigger: `ctx->key_len != 16 (case TLS_AES_128_GCM_SHA256)` @tls:55
    LWIP_E0003 = 0x0003, // altcp_tls_ce_record_aead_init(): The suite fixes the AEAD key length (RFC 8446 Appendix B.4); refuse a mismatched key_len rather than initializing an AEAD with the wrong key size. Trigger: `ctx->key_len != 32 (case TLS_AES_256_GCM_SHA384)` @tls:55
    LWIP_E0004 = 0x0004, // altcp_tls_ce_record_aead_init(): fails and returns false. Trigger: `default` @tls:55
    LWIP_E0005 = 0x0005, // altcp_tls_ce_transport_write(): fails and returns false. Trigger: `!state || !state->conn || !state->conn->inner_conn || !data || len == 0` @tls:55
    LWIP_E0006 = 0x0006, // altcp_tls_ce_transport_write(): fails and returns false. Trigger: `err != ERR_OK` @tls:55
    LWIP_E0007 = 0x0007, // altcp_tls_ce_create_config_psk_client(): fails and returns NULL. Trigger: `conf == NULL` @memory:85 @tls:20
    LWIP_E0008 = 0x0008, // altcp_tls_ce_create_config_psk_server(): fails and returns NULL. Trigger: `conf == NULL` @memory:85 @tls:20
    LWIP_E0009 = 0x0009, // altcp_tls_ce_create_config_client_ecdhe(): fails and returns NULL. Trigger: `conf == NULL` @memory:85 @tls:20
    LWIP_E000A = 0x000A, // load_cert_identity(): fails. Trigger: `rc != TLS_KEY_IMPORT_OK` @cert:65
    LWIP_E000B = 0x000B, // altcp_tls_ce_lower_accept(): fails and returns ERR_MEM. Trigger: `new_conn == NULL` @memory:85 @tls:20
    LWIP_E000C = 0x000C, // altcp_tls_ce_lower_accept(): fails and returns listen_conn->accept(listen_conn->arg, new_conn, err). Trigger: `listen_conn && listen_conn->state && listen_conn->accept` @tls:55 @logic:45
    LWIP_E000D = 0x000D, // altcp_tls_ce_lower_accept(): fails and returns ERR_ARG. @api:60 @tls:25
    LWIP_E000E = 0x000E, // altcp_tls_ce_lower_connected(): Upper connected callback called after handshake completes. Trigger: `err != ERR_OK` @tls:55
    LWIP_E000F = 0x000F, // altcp_tls_ce_lower_connected(): Upper connected callback called after handshake completes. Trigger: `conn->connected` @tls:55
    LWIP_E0010 = 0x0010, // altcp_tls_ce_lower_connected(): propagates a failure from altcp_tls_ce_lower_recv_process(). Trigger: `altcp_tls_ce_lower_recv_process(conn, state) returned an error` @tls:20 @propagate
    LWIP_E0011 = 0x0011, // altcp_tls_ce_lower_connected(): fails and returns ERR_VAL. @tls:55
    LWIP_E0012 = 0x0012, // altcp_tls_ce_lower_recv(): fails. Trigger: `!conn` @memory:85 @tls:20
    LWIP_E0013 = 0x0013, // altcp_tls_ce_lower_recv(): Our wrapper is gone (or never wired); fall back to abort if the orderly close can't go out. Trigger: `altcp_close(inner_conn) != ERR_OK` @tls:35
    LWIP_E0014 = 0x0014, // altcp_tls_ce_lower_recv(): fails. Trigger: `!state` @tls:55
    LWIP_E0015 = 0x0015, // altcp_tls_ce_lower_recv(): fails. Trigger: `altcp_close(inner_conn) != ERR_OK` @tls:35
    LWIP_E0016 = 0x0016, // altcp_tls_ce_lower_recv(): Handle NULL pbuf (connection closed). Trigger: `else branch` @tls:55
    LWIP_E0017 = 0x0017, // altcp_tls_ce_lower_recv(): fails. Trigger: `altcp_close(conn) != ERR_OK` @tls:35
    LWIP_E0018 = 0x0018, // altcp_tls_ce_send_client_hello(): Generate the ClientHello exactly once per attempt. Trigger: `settle_err != ERR_OK` @tls:55
    LWIP_E0019 = 0x0019, // altcp_tls_ce_send_client_hello(): Query the exact serialized size first. Trigger: `!tls_send_client_hello(&state->tls_ctx, NULL, 0, &client_hello_len) || client_hello_len > ALTCP_TLS_CE_MAX_RECORD_PLAINTEXT || client_hello_len > UINT16_MAX -…` @tls:55
    LWIP_E001A = 0x001A, // altcp_tls_ce_send_client_hello(): Generate the ClientHello exactly once per attempt. Trigger: `state->pending_chello == NULL` @memory:85 @tls:20
    LWIP_E001B = 0x001B, // altcp_tls_ce_send_client_hello(): Generate the ClientHello exactly once per attempt. Trigger: `!chello_ok` @tls:55
    LWIP_E001C = 0x001C, // altcp_tls_ce_send_client_hello(): fails and returns ERR_ABRT. Trigger: `write_err != ERR_OK` @tls:55
    LWIP_E001D = 0x001D, // altcp_tls_ce_cert_job_dispatch(): fails and returns. Trigger: `!tls_cert_jobs_step_ocsp(&state->tls_ctx, &query)` @cert:45
    LWIP_E001E = 0x001E, // altcp_tls_ce_cert_job_dispatch(): fails. Trigger: `!altcp_tls_ocsp_start(query, state, altcp_tls_ce_ocsp_done, state)` @cert:45
    LWIP_E001F = 0x001F, // altcp_tls_ce_ocsp_done(): fails and returns. Trigger: `!tls_ocsp_job_done(&state->tls_ctx, status)` @cert:45 @tls:35
    LWIP_E0020 = 0x0020, // altcp_tls_ce_keyshare_dispatch(): fails. Trigger: `conn` @tls:55
    LWIP_E0021 = 0x0021, // altcp_tls_ce_server_process(): fails and returns ERR_ABRT. Trigger: `rec_len == 0 || rec_len > ALTCP_TLS_CE_MAX_RECORD_PLAINTEXT + 256u` @peer:60 @tls:55
    LWIP_E0022 = 0x0022, // altcp_tls_ce_server_process(): fails and returns ERR_ABRT. Trigger: `!ok` @tls:55
    LWIP_E0023 = 0x0023, // altcp_tls_ce_server_process(): fails and returns ERR_ABRT. Trigger: `err != ERR_OK` @peer:60 @tls:55
    LWIP_E0024 = 0x0024, // altcp_tls_ce_server_process(): fails and returns ERR_ABRT. Trigger: `!ok` @tls:55
    LWIP_E0025 = 0x0025, // altcp_tls_ce_server_process(): fails and returns ERR_ABRT. Trigger: `while state->rx != NULL && state->rx->tot_len >= 5 && !(state->flags & ALTCP_TLS_CE_FLAGS_HANDSHAKE_DONE)` @tls:55 @logic:45
    LWIP_E0026 = 0x0026, // altcp_tls_ce_lower_recv_process(): Client: process complete TLS records. Trigger: `pbuf_copy_partial(state->rx, header, sizeof(header), 0) != sizeof(header)` @tls:35
    LWIP_E0027 = 0x0027, // altcp_tls_ce_lower_recv_process(): Client: process complete TLS records. Trigger: `rec_len > record_limit || total_len > 0xFFFF` @peer:60 @tls:55
    LWIP_E0028 = 0x0028, // altcp_tls_ce_lower_recv_process(): RFC 8446 5.1: legacy_record_version is ignored. Trigger: `rec_len == 0` @peer:60 @tls:55
    LWIP_E0029 = 0x0029, // altcp_tls_ce_lower_recv_process(): Derive handshake keys exactly once, right after ServerHello, so we can decrypt the subsequent encrypted handshake records. Trigger: `settle_err != ERR_OK` @peer:60 @tls:55
    LWIP_E002A = 0x002A, // altcp_tls_ce_lower_recv_process(): Derive handshake keys exactly once, right after ServerHello, so we can decrypt the subsequent encrypted handshake records. Trigger: `!derive_ok` @tls:55
    LWIP_E002B = 0x002B, // altcp_tls_ce_lower_recv_process(): fails and returns ERR_ABRT. Trigger: `!use_hs_keys` @tls:55
    LWIP_E002C = 0x002C, // altcp_tls_ce_lower_recv_process(): Scratch alloc deferred — the record stays in state->rx and we retry on the next recv. Trigger: `dec_err == ERR_MEM` @memory:50 @tls:10
    LWIP_E002D = 0x002D, // altcp_tls_ce_lower_recv_process(): fails and returns ERR_ABRT. Trigger: `dec_err != ERR_OK` @peer:60 @tls:55
    LWIP_E002E = 0x002E, // altcp_tls_ce_lower_recv_process(): fails and returns ERR_ABRT. Trigger: `!tls_process_inner_plaintext_pbuf(&state->tls_ctx, inner_type, dec_pbuf, dec_len)` @tls:35
    LWIP_E002F = 0x002F, // altcp_tls_ce_lower_recv_process(): fails and returns ERR_ABRT. Trigger: `pbuf_copy_partial(state->rx, tmp, (u16_t)total_len, 0) != total_len` @tls:35
    LWIP_E0030 = 0x0030, // altcp_tls_ce_lower_recv_process(): fails. Trigger: `else branch` @tls:55
    LWIP_E0031 = 0x0031, // altcp_tls_ce_lower_recv_process(): fails. Trigger: `else branch` @tls:55
    LWIP_E0032 = 0x0032, // altcp_tls_ce_lower_recv_process(): fails and returns ERR_ABRT. Trigger: `!plaintext_ok` @tls:55
    LWIP_E0033 = 0x0033, // altcp_tls_ce_lower_recv_process(): Check if server Finished received — time to send client Finished. Trigger: `settle_err != ERR_OK` @peer:60 @tls:55
    LWIP_E0034 = 0x0034, // altcp_tls_ce_lower_recv_process(): Check if server Finished received — time to send client Finished. Trigger: `!derive_app_ok` @tls:55
    LWIP_E0035 = 0x0035, // altcp_tls_ce_lower_recv_process(): fails and returns ERR_ABRT. Trigger: `cert_cap > UINT16_MAX || der_len > UINT16_MAX - cert_cap - 5u` @peer:60 @tls:55
    LWIP_E0036 = 0x0036, // altcp_tls_ce_lower_recv_process(): fails and returns ERR_ABRT. Trigger: `write_err != ERR_OK` @peer:60 @tls:55
    LWIP_E0037 = 0x0037, // altcp_tls_ce_lower_recv_process(): fails and returns ERR_ABRT. Trigger: `!cert_ok` @tls:55
    LWIP_E0038 = 0x0038, // altcp_tls_ce_lower_recv_process(): Check if server Finished received — time to send client Finished. Trigger: `!finished_hs` @memory:85 @tls:20
    LWIP_E0039 = 0x0039, // altcp_tls_ce_lower_recv_process(): Check if server Finished received — time to send client Finished. Trigger: `!send_finished_ok` @tls:55
    LWIP_E003A = 0x003A, // altcp_tls_ce_lower_recv_process(): Check if server Finished received — time to send client Finished. Trigger: `!altcp_tls_ce_encrypt_record_stream(&state->tls_ctx, true, TLS_CONTENT_TYPE_HANDSHAKE, finished_hs, finished_hs_len, enc_finished, ENC_FINISHED_MAX, &enc_finis…` @peer:60 @tls:55
    LWIP_E003B = 0x003B, // altcp_tls_ce_lower_recv_process(): Check if server Finished received — time to send client Finished. Trigger: `write_err != ERR_OK` @peer:60 @tls:55
    LWIP_E003C = 0x003C, // altcp_tls_ce_pass_rx_data(): fails and returns ERR_ABRT. Trigger: `err == ERR_ABRT` @tls:55
    LWIP_E003D = 0x003D, // altcp_tls_ce_handle_rx_appldata_impl(): Process available TLS records. Trigger: `rec_payload_len > ALTCP_TLS_CE_MAX_RECORD_PLAINTEXT + 256u` @peer:60 @tls:55
    LWIP_E003E = 0x003E, // altcp_tls_ce_handle_rx_appldata_impl(): Process available TLS records. Trigger: `header[0] != TLS_CONTENT_TYPE_APPLICATION_DATA || rec_payload_len == 0` @peer:60 @tls:55
    LWIP_E003F = 0x003F, // altcp_tls_ce_handle_rx_appldata_impl(): Process available TLS records. Trigger: `dec_err != ERR_OK` @peer:60 @tls:55
    LWIP_E0040 = 0x0040, // altcp_tls_ce_handle_rx_appldata_impl(): Post-handshake handshake messages (NewSessionTicket, KeyUpdate, etc.) flow through the same reassembly dispatcher we use during the handshake. Trigger: `!tls_process_inner_plaintext_pbuf(&state->tls_ctx, inner_type, dec_pbuf, dec_len)` @tls:35
    LWIP_E0041 = 0x0041, // altcp_tls_ce_handle_rx_appldata_impl(): fails and returns ERR_ABRT. Trigger: `dec_len != 2` @peer:60 @tls:55
    LWIP_E0042 = 0x0042, // altcp_tls_ce_handle_rx_appldata_impl(): fails. Trigger: `else branch` @tls:55
    LWIP_E0043 = 0x0043, // altcp_tls_ce_handle_rx_appldata_impl(): fails and returns ERR_ABRT. Trigger: `else branch` @tls:55
    LWIP_E0044 = 0x0044, // altcp_tls_ce_handle_rx_appldata_impl(): Process available TLS records. Trigger: `else branch` @tls:55
    LWIP_E0045 = 0x0045, // altcp_tls_ce_handle_rx_appldata_impl(): fails and returns ERR_ABRT. Trigger: `err == ERR_ABRT` @tls:55
    LWIP_E0046 = 0x0046, // altcp_tls_ce_lower_err(): fails. @tls:55
    LWIP_E0047 = 0x0047, // altcp_tls_ce_setup(): lwip_start() deliberately survives a TLS-only initialization failure. Trigger: `!conf || !tls_ctx.initialized` @tls:55
    LWIP_E0048 = 0x0048, // altcp_tls_ce_setup(): fails and returns ERR_MEM. Trigger: `state == NULL` @memory:85 @tls:20
    LWIP_E0049 = 0x0049, // altcp_tls_ce_wrap(): fails and returns NULL. Trigger: `inner_pcb == NULL` @api:75 @tls:20
    LWIP_E004A = 0x004A, // altcp_tls_ce_wrap(): fails and returns NULL. Trigger: `ret == NULL` @memory:85 @tls:20
    LWIP_E004B = 0x004B, // altcp_tls_ce_new(): fails and returns NULL. Trigger: `inner_pcb == NULL` @tls:55
    LWIP_E004C = 0x004C, // altcp_tls_ce_connect(): fails and returns ERR_VAL. Trigger: `conn == NULL || ipaddr == NULL` @api:75 @tls:20
    LWIP_E004D = 0x004D, // altcp_tls_ce_connect(): fails and returns ERR_VAL. Trigger: `state == NULL` @tls:55
    LWIP_E004E = 0x004E, // altcp_tls_ce_connect(): fails and returns ERR_ABRT. Trigger: `state->tls_ctx.keyshare_state == TLS_KEYSHARE_STATE_ERROR` @tls:55
    LWIP_E004F = 0x004F, // altcp_tls_ce_connect(): propagates a failure from altcp_tls_ce_start_lower_connect(). Trigger: `altcp_tls_ce_start_lower_connect(state) returned an error` @tls:20 @propagate
    LWIP_E0050 = 0x0050, // altcp_tls_ce_listen(): fails and returns NULL. Trigger: `conn == NULL` @api:75 @tls:20
    LWIP_E0051 = 0x0051, // altcp_tls_ce_listen(): fails and returns NULL. @tls:55
    LWIP_E0052 = 0x0052, // altcp_tls_ce_close(): fails and returns ERR_VAL. Trigger: `conn == NULL` @api:75 @tls:20
    LWIP_E0053 = 0x0053, // altcp_tls_ce_close(): fails and returns err. Trigger: `err != ERR_OK` @tls:55
    LWIP_E0054 = 0x0054, // altcp_tls_ce_write(): fails and returns ERR_VAL. Trigger: `conn == NULL` @api:75 @tls:20
    LWIP_E0055 = 0x0055, // altcp_tls_ce_write(): fails and returns ERR_ARG. Trigger: `state == NULL` @tls:55
    LWIP_E0056 = 0x0056, // altcp_tls_ce_write(): fails and returns ERR_VAL. Trigger: `!(state->flags & ALTCP_TLS_CE_FLAGS_HANDSHAKE_DONE)` @tls:55 @logic:45
    LWIP_E0057 = 0x0057, // altcp_tls_ce_write(): fails and returns ERR_MEM. Trigger: `!tls_update_write_keys_if_needed(&state->tls_ctx)` @memory:85 @tls:20
    LWIP_E0058 = 0x0058, // altcp_tls_ce_write(): fails and returns ERR_MEM. Trigger: `!ciphertext` @memory:85 @tls:20
    LWIP_E0059 = 0x0059, // altcp_tls_ce_write(): Encrypt data as a TLS record (includes 5-byte header + ciphertext + tag). Trigger: `!altcp_tls_ce_encrypt_record_stream(&state->tls_ctx, false, TLS_CONTENT_TYPE_APPLICATION_DATA, (const uint8_t *)dataptr, len, ciphertext, ct_buf_size, &ciphert…` @tls:55
    LWIP_E005A = 0x005A, // altcp_tls_ce_write(): fails and returns err. Trigger: `err != ERR_OK && err != ERR_MEM` @memory:85 @tls:20
    LWIP_E005B = 0x005B, // altcp_tls_create_config_server(): Server config requires PSK, use altcp_tls_ce_create_config_psk_server directly. @tls:55
    LWIP_E005C = 0x005C, // altcp_tls_config_server_add_privkey_cert(): Certificate-based auth not yet supported on CE. @cert:65
    LWIP_E005D = 0x005D, // altcp_tls_create_config_server_privkey_cert(): Certificate-based auth not yet supported on CE. @cert:65
    LWIP_E005E = 0x005E, // altcp_tls_create_config_client(): This API has no hostname parameter, so it cannot create a configuration that performs RFC 9525 service-identity verification. @tls:55
    LWIP_E005F = 0x005F, // altcp_tls_create_config_client_2wayauth(): fails and returns NULL. @tls:55
    LWIP_E0060 = 0x0060, // altcp_tls_configure_alpn_protocols(): fails and returns -1. Trigger: `!ce_conf` @tls:55
    LWIP_E0061 = 0x0061, // altcp_tls_configure_alpn_protocols(): fails and returns -1. Trigger: `protocol_len == 0 || protocol_len > TLS_ALPN_PROTOCOL_NAME_MAX || encoded_len > 0xFFFFu - protocol_len - 1u` @tls:55
    LWIP_E0062 = 0x0062, // altcp_tls_configure_alpn_protocols(): fails and returns -1. Trigger: `!encoded` @memory:85 @tls:20
    LWIP_E0063 = 0x0063, // altcp_tls_get_session(): fails and returns ERR_ARG. Trigger: `!dest` @api:75 @tls:20
    LWIP_E0064 = 0x0064, // altcp_tls_get_session(): No live conn / no in-flight session: can't safely load without knowing the target hostname. @tls:55
    LWIP_E0065 = 0x0065, // altcp_tls_set_session(): fails and returns ERR_ARG. Trigger: `!from || !from->valid || from->identity.identity_len == 0 || from->identity.identity_len > sizeof(from->identity.identity)` @tls:55
    LWIP_E0066 = 0x0066, // altcp_ws_send_upgrade_request(): fails and returns ERR_VAL. Trigger: `tls_random_bytes(key_raw, sizeof(key_raw)) == NULL` @crypto:40 @ws:35
    LWIP_E0067 = 0x0067, // altcp_ws_send_upgrade_request(): fails and returns ERR_MEM. Trigger: `!t` @memory:85 @ws:20
    LWIP_E0068 = 0x0068, // altcp_ws_send_upgrade_request(): fails and returns ERR_VAL. Trigger: `n <= 0 || (size_t)n >= sizeof(t->buf)` @ws:60
    LWIP_E0069 = 0x0069, // altcp_ws_send_upgrade_request(): fails and returns e. Trigger: `e != ERR_OK` @ws:60
    LWIP_E006A = 0x006A, // altcp_ws_lower_recv_process(): fails and returns ERR_ABRT. Trigger: `tot >= WS_RX_LIMIT` @peer:60 @ws:60
    LWIP_E006B = 0x006B, // altcp_ws_lower_recv_process(): ---- Phase 1: HTTP upgrade handshake ----. Trigger: `memcmp(status, , 12) != 0 || status[12] !=` @peer:60 @ws:60
    LWIP_E006C = 0x006C, // altcp_ws_lower_recv_process(): fails and returns ERR_ABRT. Trigger: `!hdr_buf` @memory:85 @ws:20
    LWIP_E006D = 0x006D, // altcp_ws_lower_recv_process(): fails and returns ERR_ABRT. Trigger: `!found_upgrade || !found_connection` @ws:60
    LWIP_E006E = 0x006E, // altcp_ws_lower_recv_process(): Only handle payloads that fit u16_t. Trigger: `ext[0] || ext[1] || ext[2] || ext[3] || ext[4] || ext[5] || (((uint32_t)ext[6] << 8u) | ext[7]) > 0xFFFFu` @peer:60 @ws:60
    LWIP_E006F = 0x006F, // altcp_ws_lower_recv_process(): ---- Phase 2: WebSocket frame parsing ----. Trigger: `masked || (hdr[0] & 0x70u) || payload_len + hdr_size > WS_RX_LIMIT || (opcode >= WS_OP_CLOSE && (!fin || payload_len > 125u)) || (opcode == WS_OP_CLOSE && payl…` @peer:60 @ws:60
    LWIP_E0070 = 0x0070, // altcp_ws_lower_recv_process(): RFC 6455 §5.5: control frames must not be fragmented and must have payload ≤ 125 bytes. Trigger: `!fin || payload_len > 125u (case WS_OP_CLOSE)` @peer:60 @ws:60
    LWIP_E0071 = 0x0071, // altcp_ws_lower_recv_process(): RFC 6455 §5.5: control frames must not be fragmented and must have payload ≤ 125 bytes. Trigger: `!fin || payload_len > 125u (case WS_OP_PING)` @peer:60 @ws:60
    LWIP_E0072 = 0x0072, // altcp_ws_lower_recv_process(): wait for rest of frame. Trigger: `!fin || payload_len > 125u (case WS_OP_PONG)` @peer:60 @ws:60
    LWIP_E0073 = 0x0073, // altcp_ws_lower_recv_process(): fails and returns ERR_ABRT. Trigger: `default` @peer:60 @ws:60
    LWIP_E0074 = 0x0074, // altcp_ws_lower_recv_process(): Deliver complete message to upper layer. Trigger: `e == ERR_ABRT` @ws:60
    LWIP_E0075 = 0x0075, // altcp_ws_lower_err(): fails. @ws:60
    LWIP_E0076 = 0x0076, // altcp_ws_lower_connected(): fails. Trigger: `err != ERR_OK` @ws:60
    LWIP_E0077 = 0x0077, // altcp_ws_lower_connected(): fails and returns ERR_ABRT. Trigger: `e != ERR_OK` @ws:60
    LWIP_E0078 = 0x0078, // altcp_ws_setup(): fails and returns ERR_MEM. Trigger: `!state` @memory:85 @ws:20
    LWIP_E0079 = 0x0079, // altcp_ws_wrap(): fails and returns NULL. Trigger: `!conn` @memory:85 @ws:20
    LWIP_E007A = 0x007A, // altcp_ws_new(): fails and returns NULL. Trigger: `!inner` @ws:60
    LWIP_E007B = 0x007B, // altcp_ws_new_tls(): fails and returns NULL. Trigger: `!tls_pcb` @memory:85 @ws:20
    LWIP_E007C = 0x007C, // lwip_app_config_load(): warns. Trigger: `!h` @config:35
    LWIP_E007D = 0x007D, // lwip_app_config_load(): fails. Trigger: `size == 0u || size > sizeof(g_cfg_io.serialized) || file_fn.ti_read(serialized, size, 1, h) != 1u` @config:60
    LWIP_E007E = 0x007E, // lwip_app_config_load(): warns. Trigger: `!valid` @config:35
    LWIP_E007F = 0x007F, // lwip_app_config_save(): fails and returns false. Trigger: `!cfg` @api:75 @config:20
    LWIP_E0080 = 0x0080, // lwip_app_config_save(): fails and returns false. Trigger: `!h` @config:60
    LWIP_E0081 = 0x0081, // lwip_app_config_save(): fails. Trigger: `file_fn.ti_resize(used, h) != (int)used || file_fn.ti_write(serialized, used, 1, h) != 1u` @config:60
    LWIP_E0082 = 0x0082, // lwip_dispatch_attach(): fails and returns. Trigger: `(unsigned)id >= LWIP_DISPATCH_COUNT` @logic:45
    LWIP_E0083 = 0x0083, // lwip_dispatch_set_period(): fails and returns. Trigger: `(unsigned)id >= LWIP_DISPATCH_COUNT` @logic:45
    LWIP_E0084 = 0x0084, // lwip_dispatch_get_period(): fails and returns 0. Trigger: `(unsigned)id >= LWIP_DISPATCH_COUNT` @logic:45
    LWIP_E0085 = 0x0085, // dns_local_addhost(): fails and returns ERR_MEM. Trigger: `entry == NULL` @memory:85 @dns:20
    LWIP_E0086 = 0x0086, // dns_send(): warns. Trigger: `else branch` @dns:40
    LWIP_E0087 = 0x0087, // dns_send(): fails and returns err. @dns:70
    LWIP_E0088 = 0x0088, // dns_send(): fails and returns ERR_VAL. @dns:70
    LWIP_E0089 = 0x0089, // dns_enqueue(): if we don't have found an unused entry, use the oldest completed one. Trigger: `(lseqi >= DNS_TABLE_SIZE) || (dns_table[lseqi].state != DNS_STATE_DONE)` @dns:70 @logic:45
    LWIP_E008A = 0x008A, // dns_enqueue(): fails and returns ERR_MEM. Trigger: `req == NULL` @memory:85 @dns:20
    LWIP_E008B = 0x008B, // dns_enqueue(): fails and returns ERR_MEM. Trigger: `entry->pcb_idx >= DNS_MAX_SOURCE_PORTS` @memory:85 @dns:20
    LWIP_E008C = 0x008C, // dns_gethostbyname_addrtype(): prevent calling found callback if no server is set, return error instead. Trigger: `ip_addr_isany_val(dns_servers[0])` @dns:35
    LWIP_E008D = 0x008D, // etharp_update_arp_entry(): non-unicast address?. Trigger: `ip4_addr_isany(ipaddr) || ip4_addr_isbroadcast(ipaddr, netif) || ip4_addr_ismulticast(ipaddr)` @wire:35
    LWIP_E008E = 0x008E, // etharp_update_arp_entry(): found entry is a static type, don't overwrite it. Trigger: `arp_table[i].state == ETHARP_STATE_STATIC` @wire:50
    LWIP_E008F = 0x008F, // etharp_update_arp_entry(): fails and returns ERR_RTE. Trigger: `netif == NULL` @api:75 @wire:20
    LWIP_E0090 = 0x0090, // etharp_update_arp_entry(): propagates a failure from etharp_update_arp_entry(). Trigger: `etharp_update_arp_entry(netif, ipaddr, ethaddr, ETHARP_FLAG_TRY_HARD | ETHARP_FLAG_STATIC_ENTRY) returned an error` @wire:20 @propagate
    LWIP_E0091 = 0x0091, // etharp_update_arp_entry(): entry wasn't a static entry, cannot remove it. Trigger: `arp_table[i].state != ETHARP_STATE_STATIC` @wire:50 @logic:45
    LWIP_E0092 = 0x0092, // etharp_update_arp_entry(): propagates a failure from ethernet_output(). Trigger: `ethernet_output(netif, q, (struct eth_addr *)(netif->hwaddr), &arp_table[arp_idx].ethaddr, ETHTYPE_IP) returned an error` @wire:20 @propagate
    LWIP_E0093 = 0x0093, // etharp_update_arp_entry(): no route to destination error (default gateway missing). Trigger: `else branch` @wire:60 @config:40
    LWIP_E0094 = 0x0094, // etharp_update_arp_entry(): propagates a failure from etharp_output_to_arp_index(). Trigger: `etharp_output_to_arp_index(netif, q, etharp_cached_entry) returned an error` @wire:20 @propagate
    LWIP_E0095 = 0x0095, // etharp_update_arp_entry(): propagates a failure from etharp_output_to_arp_index(). Trigger: `etharp_output_to_arp_index(netif, q, i) returned an error` @wire:20 @propagate
    LWIP_E0096 = 0x0096, // etharp_update_arp_entry(): propagates a failure from etharp_query(). Trigger: `etharp_query(netif, dst_addr, q) returned an error` @wire:20 @propagate
    LWIP_E0097 = 0x0097, // etharp_update_arp_entry(): propagates a failure from ethernet_output(). Trigger: `ethernet_output(netif, q, (struct eth_addr *)(netif->hwaddr), dest, ETHTYPE_IP) returned an error` @wire:20 @propagate
    LWIP_E0098 = 0x0098, // etharp_update_arp_entry(): non-unicast address?. Trigger: `ip4_addr_isany(ipaddr) || ip4_addr_isbroadcast(ipaddr, netif) || ip4_addr_ismulticast(ipaddr)` @wire:35
    LWIP_E0099 = 0x0099, // etharp_update_arp_entry(): could not find or create entry?. Trigger: `i_err < 0` @wire:50
    LWIP_E009A = 0x009A, // etharp_update_arp_entry(): do we have a new entry?. Trigger: `q == NULL` @wire:50
    LWIP_E009B = 0x009B, // etharp_update_arp_entry(): packet could be taken over?. Trigger: `else branch` @wire:50
    LWIP_E009C = 0x009C, // etharp_update_arp_entry(): fails. Trigger: `else branch` @wire:50
    LWIP_E009D = 0x009D, // etharp_update_arp_entry(): fails and returns result. @wire:50
    LWIP_E009E = 0x009E, // etharp_update_arp_entry(): could allocate a pbuf for an ARP request?. Trigger: `p == NULL` @memory:85 @wire:20
    LWIP_E009F = 0x009F, // etharp_update_arp_entry(): could not allocate pbuf for ARP request. @memory:85 @wire:20
    LWIP_E00A0 = 0x00A0, // etharp_update_arp_entry(): propagates a failure from etharp_raw(). Trigger: `etharp_raw(netif, (struct eth_addr *)netif->hwaddr, hw_dst_addr, (struct eth_addr *)netif->hwaddr, netif_ip4_addr(netif), &ethzero, ipaddr, ARP_REQUEST) returned an error` @wire:20 @propagate
    LWIP_E00A1 = 0x00A1, // etharp_update_arp_entry(): propagates a failure from etharp_request_dst(). Trigger: `etharp_request_dst(netif, ipaddr, &ethbroadcast) returned an error` @wire:20 @propagate
    LWIP_E00A2 = 0x00A2, // etharp_update_arp_entry(): propagates a failure from etharp_raw(). Trigger: `etharp_raw(netif, (struct eth_addr *)netif->hwaddr, &ethbroadcast, (struct eth_addr *)netif->hwaddr, IP4_ADDR_ANY4, &ethzero, ipaddr, ARP_REQUEST) returned an error` @wire:20 @propagate
    LWIP_E00A3 = 0x00A3, // etharp_update_arp_entry(): propagates a failure from etharp_raw(). Trigger: `etharp_raw(netif, (struct eth_addr *)netif->hwaddr, &ethbroadcast, (struct eth_addr *)netif->hwaddr, ipaddr, &ethzero, ipaddr, ARP_REQUEST) returned an error` @wire:20 @propagate
    LWIP_E00A4 = 0x00A4, // ip4_input(): propagates a failure from ip4_output_if_opt(). Trigger: `ip4_output_if_opt(p, src, dest, ttl, tos, proto, netif, NULL, 0) returned an error` @wire:20 @propagate
    LWIP_E00A5 = 0x00A5, // ip4_input(): propagates a failure from ip4_output_if_opt_src(). Trigger: `ip4_output_if_opt_src(p, src_used, dest, ttl, tos, proto, netif, ip_options, optlen) returned an error` @wire:20 @propagate
    LWIP_E00A6 = 0x00A6, // ip4_input(): propagates a failure from ip4_output_if_src(). Trigger: `ip4_output_if_src(p, src_used, dest, ttl, tos, proto, netif) returned an error` @wire:20 @propagate
    LWIP_E00A7 = 0x00A7, // ip4_input(): propagates a failure from ip4_output_if_opt_src(). Trigger: `ip4_output_if_opt_src(p, src, dest, ttl, tos, proto, netif, NULL, 0) returned an error` @wire:20 @propagate
    LWIP_E00A8 = 0x00A8, // ip4_input(): fails and returns ERR_VAL. Trigger: `optlen > (IP_HLEN_MAX - IP_HLEN)` @wire:50 @peer:45
    LWIP_E00A9 = 0x00A9, // ip4_input(): First write in the IP options. Trigger: `pbuf_add_header(p, optlen_aligned)` @wire:35
    LWIP_E00AA = 0x00AA, // ip4_input(): generate IP header. Trigger: `pbuf_add_header(p, IP_HLEN)` @wire:35
    LWIP_E00AB = 0x00AB, // ip4_input(): IP header already included in p. Trigger: `p->len < IP_HLEN` @wire:50 @peer:45
    LWIP_E00AC = 0x00AC, // ip4_input(): propagates a failure from netif_loop_output(). Trigger: `netif_loop_output(netif, p) returned an error` @wire:20 @propagate
    LWIP_E00AD = 0x00AD, // ip4_input(): propagates a failure from ip4_frag(). Trigger: `ip4_frag(p, netif, dest) returned an error` @wire:20 @propagate
    LWIP_E00AE = 0x00AE, // ip4_input(): fails and returns netif->output(netif, p, dest). @wire:50
    LWIP_E00AF = 0x00AF, // ip4_input(): fails and returns ERR_RTE. Trigger: `(netif = ip4_route_src(src, dest)) == NULL` @wire:60 @config:40
    LWIP_E00B0 = 0x00B0, // ip4_input(): propagates a failure from ip4_output_if(). Trigger: `ip4_output_if(p, src, dest, ttl, tos, proto, netif) returned an error` @wire:20 @propagate
    LWIP_E00B1 = 0x00B1, // ip4_input(): fails and returns ERR_RTE. Trigger: `(netif = ip4_route_src(src, dest)) == NULL` @wire:60 @config:40
    LWIP_E00B2 = 0x00B2, // ip4_input(): fails and returns err. @wire:50
    LWIP_E00B3 = 0x00B3, // udp_send(): fails and returns ERR_ARG. @api:60 @transport:25
    LWIP_E00B4 = 0x00B4, // udp_send(): fails and returns ERR_ARG. @api:60 @transport:25
    LWIP_E00B5 = 0x00B5, // udp_send(): fails and returns ERR_VAL. Trigger: `IP_IS_ANY_TYPE_VAL(pcb->remote_ip)` @transport:35
    LWIP_E00B6 = 0x00B6, // udp_send(): propagates a failure from udp_sendto(). Trigger: `udp_sendto(pcb, p, &pcb->remote_ip, pcb->remote_port) returned an error` @transport:20 @propagate
    LWIP_E00B7 = 0x00B7, // udp_send_chksum(): fails and returns ERR_ARG. @api:60 @transport:25
    LWIP_E00B8 = 0x00B8, // udp_send_chksum(): fails and returns ERR_ARG. @api:60 @transport:25
    LWIP_E00B9 = 0x00B9, // udp_send_chksum(): fails and returns ERR_VAL. Trigger: `IP_IS_ANY_TYPE_VAL(pcb->remote_ip)` @transport:35
    LWIP_E00BA = 0x00BA, // udp_send_chksum(): propagates a failure from udp_sendto_chksum(). Trigger: `udp_sendto_chksum(pcb, p, &pcb->remote_ip, pcb->remote_port, have_chksum, chksum) returned an error` @transport:20 @propagate
    LWIP_E00BB = 0x00BB, // udp_sendto(): propagates a failure from udp_sendto_chksum(). Trigger: `udp_sendto_chksum(pcb, p, dst_ip, dst_port, 0, 0) returned an error` @transport:20 @propagate
    LWIP_E00BC = 0x00BC, // udp_sendto_chksum(): fails and returns ERR_ARG. @api:60 @transport:25
    LWIP_E00BD = 0x00BD, // udp_sendto_chksum(): fails and returns ERR_ARG. @api:60 @transport:25
    LWIP_E00BE = 0x00BE, // udp_sendto_chksum(): fails and returns ERR_ARG. @api:60 @transport:25
    LWIP_E00BF = 0x00BF, // udp_sendto_chksum(): fails and returns ERR_VAL. Trigger: `!IP_ADDR_PCB_VERSION_MATCH(pcb, dst_ip)` @transport:35
    LWIP_E00C0 = 0x00C0, // udp_sendto_chksum(): no outgoing network interface could be found?. Trigger: `netif == NULL` @transport:50
    LWIP_E00C1 = 0x00C1, // udp_sendto_chksum(): propagates a failure from udp_sendto_if_chksum(). Trigger: `udp_sendto_if_chksum(pcb, p, dst_ip, dst_port, netif, have_chksum, chksum) returned an error` @transport:20 @propagate
    LWIP_E00C2 = 0x00C2, // udp_sendto_chksum(): propagates a failure from udp_sendto_if(). Trigger: `udp_sendto_if(pcb, p, dst_ip, dst_port, netif) returned an error` @transport:20 @propagate
    LWIP_E00C3 = 0x00C3, // udp_sendto_if(): propagates a failure from udp_sendto_if_chksum(). Trigger: `udp_sendto_if_chksum(pcb, p, dst_ip, dst_port, netif, 0, 0) returned an error` @transport:20 @propagate
    LWIP_E00C4 = 0x00C4, // udp_sendto_if_chksum(): fails and returns ERR_ARG. @api:60 @transport:25
    LWIP_E00C5 = 0x00C5, // udp_sendto_if_chksum(): fails and returns ERR_ARG. @api:60 @transport:25
    LWIP_E00C6 = 0x00C6, // udp_sendto_if_chksum(): fails and returns ERR_ARG. @api:60 @transport:25
    LWIP_E00C7 = 0x00C7, // udp_sendto_if_chksum(): fails and returns ERR_ARG. @api:60 @transport:25
    LWIP_E00C8 = 0x00C8, // udp_sendto_if_chksum(): fails and returns ERR_VAL. Trigger: `!IP_ADDR_PCB_VERSION_MATCH(pcb, dst_ip)` @transport:35
    LWIP_E00C9 = 0x00C9, // udp_sendto_if_chksum(): No suitable source address was found. Trigger: `src_ip == NULL` @transport:50
    LWIP_E00CA = 0x00CA, // udp_sendto_if_chksum(): Address isn't valid anymore. Trigger: `netif_get_ip6_addr_match(netif, ip_2_ip6(&pcb->local_ip)) < 0` @transport:50
    LWIP_E00CB = 0x00CB, // udp_sendto_if_chksum(): local_ip doesn't match, drop the packet. Trigger: `!ip4_addr_eq(ip_2_ip4(&(pcb->local_ip)), netif_ip4_addr(netif))` @transport:35
    LWIP_E00CC = 0x00CC, // udp_sendto_if_chksum(): propagates a failure from udp_sendto_if_src_chksum(). Trigger: `udp_sendto_if_src_chksum(pcb, p, dst_ip, dst_port, netif, have_chksum, chksum, src_ip) returned an error` @transport:20 @propagate
    LWIP_E00CD = 0x00CD, // udp_sendto_if_chksum(): propagates a failure from udp_sendto_if_src(). Trigger: `udp_sendto_if_src(pcb, p, dst_ip, dst_port, netif, src_ip) returned an error` @transport:20 @propagate
    LWIP_E00CE = 0x00CE, // udp_sendto_if_src(): propagates a failure from udp_sendto_if_src_chksum(). Trigger: `udp_sendto_if_src_chksum(pcb, p, dst_ip, dst_port, netif, 0, 0, src_ip) returned an error` @transport:20 @propagate
    LWIP_E00CF = 0x00CF, // udp_sendto_if_src_chksum(): fails and returns ERR_ARG. @api:60 @transport:25
    LWIP_E00D0 = 0x00D0, // udp_sendto_if_src_chksum(): fails and returns ERR_ARG. @api:60 @transport:25
    LWIP_E00D1 = 0x00D1, // udp_sendto_if_src_chksum(): fails and returns ERR_ARG. @api:60 @transport:25
    LWIP_E00D2 = 0x00D2, // udp_sendto_if_src_chksum(): fails and returns ERR_ARG. @api:60 @transport:25
    LWIP_E00D3 = 0x00D3, // udp_sendto_if_src_chksum(): fails and returns ERR_ARG. @api:60 @transport:25
    LWIP_E00D4 = 0x00D4, // udp_sendto_if_src_chksum(): fails and returns ERR_VAL. Trigger: `!IP_ADDR_PCB_VERSION_MATCH(pcb, src_ip) || !IP_ADDR_PCB_VERSION_MATCH(pcb, dst_ip)` @transport:35
    LWIP_E00D5 = 0x00D5, // udp_sendto_if_src_chksum(): broadcast filter?. Trigger: `!ip_get_option(pcb, SOF_BROADCAST) && IP_IS_V4(dst_ip) && ip_addr_isbroadcast(dst_ip, netif)` @transport:35
    LWIP_E00D6 = 0x00D6, // udp_sendto_if_src_chksum(): if the PCB is not yet bound to a port, bind it here. Trigger: `err != ERR_OK` @transport:50
    LWIP_E00D7 = 0x00D7, // udp_sendto_if_src_chksum(): packet too large to add a UDP header without causing an overflow?. Trigger: `(u16_t)(p->tot_len + UDP_HLEN) < p->tot_len` @transport:50
    LWIP_E00D8 = 0x00D8, // udp_sendto_if_src_chksum(): new header pbuf could not be allocated?. Trigger: `q == NULL` @memory:85 @transport:20
    LWIP_E00D9 = 0x00D9, // udp_sendto_if_src_chksum(): fails and returns err. @transport:50
    LWIP_E00DA = 0x00DA, // udp_bind(): fails and returns ERR_ARG. @api:60 @transport:25
    LWIP_E00DB = 0x00DB, // udp_bind(): fails and returns ERR_ARG. @api:60 @transport:25
    LWIP_E00DC = 0x00DC, // udp_bind(): no port specified?. Trigger: `port == 0` @api:75 @transport:20
    LWIP_E00DD = 0x00DD, // udp_bind(): port matches that of PCB in list and REUSEADDR not set -> reject. Trigger: `(ipcb->local_port == port) && (((IP_GET_TYPE(&ipcb->local_ip) == IP_GET_TYPE(ipaddr)) && (ip_addr_eq(&ipcb->local_ip, ipaddr) || ip_addr_isany(ipaddr) || ip_ad…` @transport:50
    LWIP_E00DE = 0x00DE, // udp_connect(): fails and returns ERR_ARG. @api:60 @transport:25
    LWIP_E00DF = 0x00DF, // udp_connect(): fails and returns ERR_ARG. @api:60 @transport:25
    LWIP_E00E0 = 0x00E0, // udp_connect(): fails and returns err. Trigger: `err != ERR_OK` @transport:50
    LWIP_E00E1 = 0x00E1, // udp_new(): fails. Trigger: `pcb == NULL` @memory:85 @transport:20
    LWIP_E00E2 = 0x00E2, // udp_new_ip_type(): fails. Trigger: `pcb == NULL` @memory:85 @transport:20
    LWIP_E00E3 = 0x00E3, // mem_init_dynamic(): fails and returns false. Trigger: `!malloc_fn || !free_fn` @api:75 @memory:20
    LWIP_E00E4 = 0x00E4, // mem_init_static(): fails and returns false. Trigger: `!buffer || buffer_size < (sizeof(struct mem_static_block) + MEM_STATIC_ALIGN)` @memory:70
    LWIP_E00E5 = 0x00E5, // mem_init_static(): fails and returns false. Trigger: `!g_mem_static.ready` @memory:70
    LWIP_E00E6 = 0x00E6, // mem_buffer_create(): fails and returns NULL. Trigger: `!g_mem_cfg_ready` @memory:70
    LWIP_E00E7 = 0x00E7, // mem_buffer_create(): fails and returns NULL. Trigger: `(initial_size == 0 && type != MEM_BUFFER_FILE) || !g_mem_cfg.malloc_fn || !g_mem_cfg.free_fn` @memory:70
    LWIP_E00E8 = 0x00E8, // mem_buffer_create(): fails and returns NULL. Trigger: `!mem_buffer_charge(sizeof(struct mem_buffer) + initial_size)` @memory:70
    LWIP_E00E9 = 0x00E9, // mem_buffer_create(): fails. Trigger: `!rb` @memory:70
    LWIP_E00EA = 0x00EA, // mem_buffer_create(): fails. Trigger: `!rb->buf` @memory:70
    LWIP_E00EB = 0x00EB, // mem_buffer_create(): fails. Trigger: `!rb->u.file.slots` @memory:70
    LWIP_E00EC = 0x00EC, // mem_buffer_create(): fails. Trigger: `rb->current_size < block_size` @memory:70
    LWIP_E00ED = 0x00ED, // mem_buffer_create(): fails. Trigger: `!mem_buffer_charge(rb->u.pool.pool_bitmap_bytes)` @memory:70
    LWIP_E00EE = 0x00EE, // mem_buffer_create(): fails. Trigger: `!rb->u.pool.pool_bitmap` @memory:70
    LWIP_E00EF = 0x00EF, // mem_buffer_notify_pressure(): Only notify on level changes. Trigger: `level != old_level && level == MEM_PRESSURE_CRITICAL` @memory:70
    LWIP_E00F0 = 0x00F0, // mem_buffer_free(): fails and returns. Trigger: `base < rb->buf || base >= (rb->buf + rb->current_size)` @memory:70
    LWIP_E00F1 = 0x00F1, // mem_buffer_free(): fails and returns. Trigger: `(offset % rb->u.pool.pool_block_size) != 0` @memory:70
    LWIP_E00F2 = 0x00F2, // mem_buffer_free(): fails and returns. Trigger: `blocks == 0 || start + blocks > rb->u.pool.pool_block_count` @memory:70
    LWIP_E00F3 = 0x00F3, // mem_direct_alloc(): fails and returns NULL. Trigger: `!mem_user_charge(raw_size)` @memory:70
    LWIP_E00F4 = 0x00F4, // mem_direct_alloc(): fails and returns NULL. Trigger: `!mem_buffer_charge(raw_size)` @memory:70
    LWIP_E00F5 = 0x00F5, // mem_direct_alloc(): fails. Trigger: `!hdr` @memory:70
    LWIP_E00F6 = 0x00F6, // mem_direct_header_from_ptr(): fails and returns NULL. Trigger: `hdr->magic != MEM_DIRECT_MAGIC` @memory:70
    LWIP_E00F7 = 0x00F7, // log_usb_transfer_status(): warns. Trigger: `status & USB_TRANSFER_NO_DEVICE` @usb:40
    LWIP_E00F8 = 0x00F8, // log_usb_transfer_status(): warns. Trigger: `status & USB_TRANSFER_STALLED` @usb:40
    LWIP_E00F9 = 0x00F9, // log_usb_transfer_status(): fails. Trigger: `status & (USB_TRANSFER_ERROR | USB_TRANSFER_HOST_ERROR | USB_TRANSFER_BUS_ERROR | USB_TRANSFER_OVERFLOW | USB_TRANSFER_FAILED)` @usb:70
    LWIP_E00FA = 0x00FA, // eth_rx_ring_drain(): Invariant violation: pbuf_alloc reported success but the chain couldn't hold all `len` bytes. Trigger: `remaining != 0` @usb:40
    LWIP_E00FB = 0x00FB, // eth_rx_ring_drain(): fails. Trigger: `++dev->rx_drain_errors >= ETH_RX_DRAIN_MAX_ERRORS` @usb:70
    LWIP_E00FC = 0x00FC, // eth_xmit_fatal_error(): fails. Trigger: `retries == ETH_USB_MAX_RETRIES` @usb:70
    LWIP_E00FD = 0x00FD, // ecm_bulk_transmit(): fails and returns ERR_IF. Trigger: `eth_is_shutting_down(dev)` @usb:35
    LWIP_E00FE = 0x00FE, // ecm_bulk_transmit(): fails and returns ERR_MEM. Trigger: `p->tot_len > ETHERNET_MTU` @memory:85 @usb:20
    LWIP_E00FF = 0x00FF, // ecm_bulk_transmit(): fails and returns ERR_MEM. Trigger: `tbuf == NULL` @memory:85 @usb:20
    LWIP_E0100 = 0x0100, // ecm_bulk_transmit(): fails and returns ERR_MEM. Trigger: `ctx == NULL` @memory:85 @usb:20
    LWIP_E0101 = 0x0101, // ecm_bulk_transmit(): fails and returns ERR_MEM. Trigger: `pbuf_copy_partial(p, out + prefix, p->tot_len, 0) != p->tot_len` @memory:85 @usb:20
    LWIP_E0102 = 0x0102, // ecm_bulk_transmit(): fails and returns ERR_IF. Trigger: `usb_fn.schedule_transfer(dev->tx.endpoint, tbuf->payload, tbuf->tot_len, bulk_transmit_callback, ctx) != USB_SUCCESS` @usb:70
    LWIP_E0103 = 0x0103, // ncm_bulk_transmit(): fails and returns ERR_IF. Trigger: `eth_is_shutting_down(dev) || dev->dead` @usb:70
    LWIP_E0104 = 0x0104, // ncm_bulk_transmit(): fails and returns ERR_MEM. Trigger: `p->tot_len > ETHERNET_MTU` @memory:85 @usb:20
    LWIP_E0105 = 0x0105, // ncm_bulk_transmit(): fails and returns ERR_MEM. Trigger: `obuf == NULL` @memory:85 @usb:20
    LWIP_E0106 = 0x0106, // ncm_bulk_transmit(): fails and returns ERR_MEM. Trigger: `ctx == NULL` @memory:85 @usb:20
    LWIP_E0107 = 0x0107, // ncm_bulk_transmit(): fails and returns ERR_IF. Trigger: `usb_fn.schedule_transfer(dev->tx.endpoint, obuf->payload, obuf->tot_len, bulk_transmit_callback, ctx) != USB_SUCCESS` @usb:70
    LWIP_E0108 = 0x0108, // init_ethernet_usb_device(): fails and returns false. Trigger: `!eth` @memory:85 @usb:20
    LWIP_E0109 = 0x0109, // device_attach(): fails and returns. Trigger: `!eth` @memory:85 @usb:20
    LWIP_E010A = 0x010A, // lwip_stack_init(): warns. Trigger: `g_lwip_cfg.tls_enabled && !tls_init()` @transport:30
    LWIP_E010B = 0x010B, // lwip_socket_rx_ring_create(): fails. Trigger: `!conn->rx_ring` @memory:85 @transport:20
    LWIP_E010C = 0x010C, // lwip_socket_take_stream(): fails and returns false. Trigger: `lwip_socket_rx_ring_create(conn) != LWIP_OK` @memory:70 @transport:35
    LWIP_E010D = 0x010D, // lwip_socket_buffer_pbuf(): fails and returns false. Trigger: `lwip_socket_rx_ring_create(conn) != LWIP_OK` @memory:70 @transport:35
    LWIP_E010E = 0x010E, // lwip_socket_buffer_pbuf(): fails. Trigger: `!mem_buffer_push(conn->rx_ring, (const uint8_t *)q->payload, q->len)` @transport:35
    LWIP_E010F = 0x010F, // lwip_socket_fail(): fails. @transport:50
    LWIP_E0110 = 0x0110, // conn_connect_fail_timeout(): fails. @transport:50
    LWIP_E0111 = 0x0111, // conn_altcp_err_cb(): fails. @transport:50
    LWIP_E0112 = 0x0112, // conn_altcp_connected_cb(): fails. Trigger: `err != ERR_OK` @transport:50
    LWIP_E0113 = 0x0113, // conn_tcp_err_cb(): fails. @transport:50
    LWIP_E0114 = 0x0114, // conn_tcp_connected_cb(): fails. Trigger: `err != ERR_OK` @transport:50
    LWIP_E0115 = 0x0115, // lwip_socket_create_ex(): fails. Trigger: `lwip_socket_rx_ring_create(conn) != LWIP_OK` @memory:70 @transport:35
    LWIP_E0116 = 0x0116, // lwip_socket_create_ex(): fails. @transport:50
    LWIP_E0117 = 0x0117, // conn_dns_found_cb(): fails. Trigger: `!ipaddr` @api:75 @dns:60 @transport:20
    LWIP_E0118 = 0x0118, // conn_dns_found_cb(): fails. Trigger: `err != ERR_OK` @dns:60 @transport:50
    LWIP_E0119 = 0x0119, // lwip_socket_connect_now(): IPv4 / IPv6 literal short-circuits DNS. Trigger: `err != ERR_OK` @transport:50
    LWIP_E011A = 0x011A, // lwip_socket_connect_now(): fails. Trigger: `err != ERR_OK` @transport:50
    LWIP_E011B = 0x011B, // lwip_socket_connect_now(): fails. @transport:50
    LWIP_E011C = 0x011C, // lwip_socket_connect_now(): fails. @transport:50
    LWIP_E011D = 0x011D, // socket_altcp_accept_cb(): fails and returns ERR_VAL. Trigger: `err != ERR_OK || !newpcb || !listener` @transport:50
    LWIP_E011E = 0x011E, // socket_altcp_accept_cb(): fails. Trigger: `!peer` @memory:85 @transport:20
    LWIP_E011F = 0x011F, // socket_altcp_accept_cb(): fails. Trigger: `lwip_socket_rx_ring_create(peer) != LWIP_OK` @memory:70 @transport:35
    LWIP_E0120 = 0x0120, // socket_tcp_accept_cb(): fails and returns ERR_VAL. Trigger: `err != ERR_OK || !newpcb || !listener` @transport:50
    LWIP_E0121 = 0x0121, // socket_tcp_accept_cb(): fails. Trigger: `!peer` @memory:85 @transport:20
    LWIP_E0122 = 0x0122, // socket_tcp_accept_cb(): fails. Trigger: `lwip_socket_rx_ring_create(peer) != LWIP_OK` @memory:70 @transport:35
    LWIP_E0123 = 0x0123, // lwip_socket_write(): fails. Trigger: `e != ERR_OK` @transport:50
    LWIP_E0124 = 0x0124, // ethernet_input(): send the packet. @wire:50
    LWIP_E0125 = 0x0125, // ethernet_input(): fails and returns ERR_BUF. @wire:50
    LWIP_E0126 = 0x0126, // transcript_hash_digest(): fails and returns false. Trigger: `!ctx_copy` @memory:85 @tls:20
    LWIP_E0127 = 0x0127, // tls_record_aead_init(): fails and returns false. Trigger: `!s || key_len != s->key_len` @tls:60
    LWIP_E0128 = 0x0128, // tls_hs_reasm_grow(): fails and returns false. Trigger: `need > TLS_HS_REASSEMBLY_MAX` @api:75 @tls:20
    LWIP_E0129 = 0x0129, // tls_hs_reasm_grow(): fails and returns false. Trigger: `!nb` @memory:85 @tls:20
    LWIP_E012A = 0x012A, // tls_cert_extract_sig_material(): fails and returns false. Trigger: `!tls_asn1_cursor_init(&top, der, der_len) || !tls_asn1_next(&top, &cert_seq) || tls_asn1_tag_number(cert_seq.tag) != ASN1_SEQUENCE || !tls_asn1_tag_constructed…` @cert:65
    LWIP_E012B = 0x012B, // tls_cert_extract_sig_material(): fails and returns false. Trigger: `!tls_asn1_child_cursor(&cert_seq, &items) || !tls_asn1_next(&items, &tbs) || !tls_asn1_next(&items, &sig_alg) || !tls_asn1_next(&items, &sig_val)` @peer:55 @cert:50
    LWIP_E012C = 0x012C, // tls_cert_extract_sig_material(): fails and returns false. Trigger: `!tls_asn1_tag_constructed(tbs.tag) || tls_asn1_tag_number(tbs.tag) != ASN1_SEQUENCE || tls_asn1_tag_number(sig_val.tag) != ASN1_BITSTRING` @peer:55 @cert:50
    LWIP_E012D = 0x012D, // tls_cert_extract_sig_material(): fails and returns false. Trigger: `!tls_x509_signature_algorithm(&sig_alg, sig_alg_out)` @cert:45
    LWIP_E012E = 0x012E, // tls_cert_extract_sig_material(): fails and returns false. Trigger: `!tls_asn1_child_cursor(&tbs, &body) || !tls_asn1_next(&body, &serial)` @peer:55 @cert:50
    LWIP_E012F = 0x012F, // tls_cert_extract_sig_material(): fails and returns false. Trigger: `serial.tag == 0xa0 && !tls_asn1_next(&body, &serial)` @cert:65
    LWIP_E0130 = 0x0130, // tls_cert_extract_sig_material(): fails and returns false. Trigger: `serial.tag != ASN1_INTEGER || !tls_asn1_next(&body, &inner_alg) || inner_alg.tag != sig_alg.tag || inner_alg.len != sig_alg.len || memcmp(inner_alg.value, sig_…` @cert:65
    LWIP_E0131 = 0x0131, // tls_cert_extract_sig_material(): signatureValue BIT STRING: first content byte is the unused-bits count (0 for a byte-aligned signature); the rest is the signature. Trigger: `sig_val.len < 2 || sig_val.value[0] != 0x00` @cert:65
    LWIP_E0132 = 0x0132, // tls_cert_anchor_root(): fails and returns false. Trigger: `w->topmost_authority_key_id_len == 0 || !tls_truststore_lookup_key_id(w->topmost_authority_key_id, w->topmost_authority_key_id_len, &root_entry) || !root_entry` @cert:65
    LWIP_E0133 = 0x0133, // tls_cert_anchor_root(): fails and returns false. Trigger: `memcmp(root_entry->subject, w->pending_issuer_name_digest, TLS_TRUSTSTORE_SUBJECT_LEN) != 0` @cert:35
    LWIP_E0134 = 0x0134, // tls_cert_anchor_root(): fails and returns false. Trigger: `tls_cert_verify_root_entry(ctx, w, root_entry, true) != TLS_KEY_OP_OK` @cert:45
    LWIP_E0135 = 0x0135, // tls_cert_anchor_root(): fails and returns false. Trigger: `w->pending_link` @cert:65
    LWIP_E0136 = 0x0136, // tls_cert_anchor_root(): No pending topmost link leaves nothing that can be anchored. @cert:65
    LWIP_E0137 = 0x0137, // tls_cert_job_run_head(): fails. Trigger: `ok && job->link.pending_ocsp_url[0] != && !tls_cert_job_root_ocsp_issuer(job, anchor)` @cert:65
    LWIP_E0138 = 0x0138, // tls_cert_job_run_head(): fails. Trigger: `!ok` @cert:65
    LWIP_E0139 = 0x0139, // tls_cert_job_enqueue(): The walker rejects chains longer than TLS_CERT_CHAIN_MAX, so a fuller queue is a logic error: fail closed. Trigger: `ctx->cert_jobs_count >= TLS_CERT_CHAIN_MAX` @cert:65
    LWIP_E013A = 0x013A, // tls_cert_job_enqueue(): fails and returns false. Trigger: `!job` @memory:85 @cert:20
    LWIP_E013B = 0x013B, // tls_cert_job_enqueue(): fails and returns false. Trigger: `issuer && !tls_cert_job_clone_key(job, issuer)` @cert:65
    LWIP_E013C = 0x013C, // tls_cert_chain_verify_one(): Step 1: if a prior cert is awaiting its issuer key, THIS cert is that issuer — verify the pending link now. Trigger: `!name_match` @cert:65
    LWIP_E013D = 0x013D, // tls_cert_chain_verify_one(): Step 1: if a prior cert is awaiting its issuer key, THIS cert is that issuer — verify the pending link now. Trigger: `w->link.pending_ocsp_url[0] != && (!cert->subject_pubkey_raw || cert->subject_pubkey_raw_len == 0 || !tls_ocsp_hash_issuer(cert->subject_name, cert->subject_na…` @cert:65 @peer:60
    LWIP_E013E = 0x013E, // tls_cert_chain_verify_one(): The signature check itself is deferred: it is queued as a job and run from the dispatch tick (see the job section above). Trigger: `!tls_cert_job_enqueue(w, &cert->pubkey)` @cert:45
    LWIP_E013F = 0x013F, // tls_cert_chain_verify_one(): Step 2: stash THIS cert's signature material so the next cert (its issuer) can verify it. Trigger: `!tls_cert_extract_sig_material(w->cert_buf, w->cert_buf_len, &tbs, &tbs_len, &sig_alg, &sig, &sig_len)` @cert:45
    LWIP_E0140 = 0x0140, // tls_cert_chain_verify_one(): fails and returns false. Trigger: `!tls_hash_context_init(w->cert_hash, tbs_hash)` @crypto:40 @cert:35
    LWIP_E0141 = 0x0141, // tls_cert_chain_verify_one(): Copy the signature (it lives in cert_buf, which is freed after this call returns). Trigger: `sig_len == 0` @cert:65 @peer:60
    LWIP_E0142 = 0x0142, // tls_cert_chain_verify_one(): fails and returns false. Trigger: `sig_alg != TLS_ALG_RSA_PKCS1_SHA256 && sig_alg != TLS_ALG_RSA_PSS_RSAE_SHA256` @cert:65 @peer:60
    LWIP_E0143 = 0x0143, // tls_cert_chain_verify_one(): fails and returns false. Trigger: `!w->link.pending_sig` @memory:85 @cert:20
    LWIP_E0144 = 0x0144, // tls_cert_walker_validate_one(): fails and returns false. Trigger: `!tls_x509_parse_certificate(w->cert_buf, w->cert_buf_len, &cert)` @peer:55 @cert:50
    LWIP_E0145 = 0x0145, // tls_cert_walker_validate_one(): fails and returns false. Trigger: `cert.pubkey.type == TLS_KEY_TYPE_UNKNOWN || ((cert.pubkey.type == TLS_KEY_TYPE_RSA) ? cert.pubkey.rsa.mod_len == 0 : cert.pubkey.ec.len == 0)` @cert:65
    LWIP_E0146 = 0x0146, // tls_cert_walker_validate_one(): Enforce RSA key size policy: 2048-4096 bits only. Trigger: `cert.pubkey.type == TLS_KEY_TYPE_RSA && (cert.pubkey.rsa.mod_len < RSA_MODULUS_MIN_SUPPORTED || cert.pubkey.rsa.mod_len > RSA_MODULUS_MAX_SUPPORTED)` @cert:65
    LWIP_E0147 = 0x0147, // tls_cert_walker_validate_one(): fails and returns false. Trigger: `now == 0 || !tls_x509_time_in_validity(&cert, now)` @cert:65
    LWIP_E0148 = 0x0148, // tls_cert_walker_validate_one(): Enforce leaf TLS usage and every issuer's CA/key/path constraints. Trigger: `!tls_x509_validate_path_extensions(&cert, !is_leaf, is_leaf ? 0 : w->non_self_issued_ca_count)` @cert:45
    LWIP_E0149 = 0x0149, // tls_cert_walker_validate_one(): An issuer's constraints apply to every subject/SAN name below it in the path. Trigger: `!is_leaf && !tls_x509_name_constraints_allow(&cert, w->subordinate_names, w->subordinate_names_len)` @cert:65
    LWIP_E014A = 0x014A, // tls_cert_walker_validate_one(): Hostname/SAN check: leaf only. Trigger: `!w->ctx || !w->ctx->hostname || !tls_x509_hostname_matches(cert.extensions, cert.extensions_len, cert.subject_cn, cert.subject_cn_len, w->ctx->hostname)` @cert:65
    LWIP_E014B = 0x014B, // tls_cert_walker_validate_one(): Capture the leaf public key for CertificateVerify. Trigger: `mat_len == 0` @cert:65
    LWIP_E014C = 0x014C, // tls_cert_walker_validate_one(): Capture the leaf public key for CertificateVerify. Trigger: `!mat` @memory:85 @cert:20
    LWIP_E014D = 0x014D, // tls_cert_walker_validate_one(): fails and returns false. Trigger: `!tls_cert_chain_verify_one(w, &cert, is_leaf)` @cert:45
    LWIP_E014E = 0x014E, // tls_cert_walker_validate_one(): fails and returns false. Trigger: `!tls_x509_get_ocsp_url(cert.extensions, cert.extensions_len, &url)` @cert:45
    LWIP_E014F = 0x014F, // tls_cert_walker_validate_one(): fails and returns false. Trigger: `url_len == 0 || url_len >= sizeof(w->link.pending_ocsp_url)` @cert:65
    LWIP_E0150 = 0x0150, // tls_cert_walker_validate_one(): Higher issuers constrain this certificate too, except that RFC 5280 4.2.1.10 exempts non-final self-issued rollover certificates. Trigger: `(is_leaf || !tls_cert_is_self_issued(&cert)) && !tls_cert_walker_append_constraint_names(w, &cert)` @cert:65
    LWIP_E0151 = 0x0151, // tls_cert_walker_feed(): fails. Trigger: `value != 0 (case CW_REQ_CTX_LEN)` @cert:65 @peer:60
    LWIP_E0152 = 0x0152, // tls_cert_walker_feed(): Deduct the 3-byte length field itself from chain_remaining, then deduct the cert body length. Trigger: `w->cert_index >= TLS_CERT_CHAIN_MAX (case CW_CERT_LEN)` @cert:65 @peer:60
    LWIP_E0153 = 0x0153, // tls_cert_walker_feed(): fails. Trigger: `value == 0 || value > SIZE_MAX - 3u || w->chain_remaining < 3u + value (case CW_CERT_LEN)` @cert:65 @peer:60
    LWIP_E0154 = 0x0154, // tls_cert_walker_feed(): fails. Trigger: `!w->cert_buf (case CW_CERT_LEN)` @memory:85 @cert:20
    LWIP_E0155 = 0x0155, // tls_cert_walker_feed(): Deduct the 2-byte ext_len field itself plus the ext body. Trigger: `value > 0xFFFF || w->chain_remaining < 2 + value (case CW_EXT_LEN)` @cert:65 @peer:60
    LWIP_E0156 = 0x0156, // tls_cert_walker_feed(): fails and returns false. Trigger: `w->cert_buf_len + take > w->cert_buf_cap` @cert:65 @peer:60
    LWIP_E0157 = 0x0157, // tls_cert_walker_feed(): fails and returns false. Trigger: `!ok` @cert:65
    LWIP_E0158 = 0x0158, // tls_cert_walker_feed(): fails and returns false. Trigger: `default` @cert:65 @peer:60
    LWIP_E0159 = 0x0159, // tls_cert_walker_feed(): No-progress guard: if a full switch pass consumed no input and left every framing counter unchanged, the walker is wedged (malformed framing or a… Trigger: `off == prev_off && w->state == prev_state && w->field_remaining == prev_field_remaining && w->chain_remaining == prev_chain_remaining && w->len_have == prev_le…` @cert:65 @logic:45
    LWIP_E015A = 0x015A, // tls_cert_walker_feed(): Bytes after the end of certificate_list are not part of the message. Trigger: `w->state == CW_DONE && off < len` @cert:65 @logic:45
    LWIP_E015B = 0x015B, // tls_feed_inflight_body(): fails and returns false. Trigger: `!ctx->cert_walker` @memory:85 @tls:20
    LWIP_E015C = 0x015C, // tls_feed_inflight_body(): fails and returns false. Trigger: `!tls_cert_walker_feed(ctx->cert_walker, bytes, take)` @cert:45 @tls:35
    LWIP_E015D = 0x015D, // tls_feed_inflight_body(): Non-Certificate: legacy flat append into hs_reasm_buf. Trigger: `!tls_hs_reasm_grow(ctx, ctx->hs_reasm_len + take)` @memory:70 @tls:35
    LWIP_E015E = 0x015E, // tls_dispatch_inflight(): cert_walker must exist: it is created lazily in tls_feed_inflight_body as soon as the first body byte arrives. Trigger: `!ctx->cert_walker` @memory:85 @tls:20
    LWIP_E015F = 0x015F, // tls_hs_defer_bytes(): fails and returns false. Trigger: `need > TLS_HS_DEFERRED_MAX` @tls:60
    LWIP_E0160 = 0x0160, // tls_hs_defer_bytes(): fails and returns false. Trigger: `!nb` @memory:85 @tls:20
    LWIP_E0161 = 0x0161, // tls_consume_handshake_buffer(): If we previously spilled a partial header (1-3 bytes) we don't yet know the full message size. Trigger: `body_len > SIZE_MAX - 4u` @peer:60 @tls:60
    LWIP_E0162 = 0x0162, // tls_consume_handshake_buffer(): If we previously spilled a partial header (1-3 bytes) we don't yet know the full message size. Trigger: `body_len == 0` @peer:60 @tls:60
    LWIP_E0163 = 0x0163, // tls_consume_handshake_buffer(): If we previously spilled a partial header (1-3 bytes) we don't yet know the full message size. Trigger: `ctx->hs_reasm_buf[0] != TLS_HANDSHAKE_CERTIFICATE && ctx->hs_reasm_expected > TLS_HS_REASSEMBLY_MAX` @peer:60 @tls:60
    LWIP_E0164 = 0x0164, // tls_consume_handshake_buffer(): fails and returns false. Trigger: `!tls_feed_inflight_body(ctx, msg_type, buf + off, take)` @tls:35
    LWIP_E0165 = 0x0165, // tls_consume_handshake_buffer(): If we were mid-reassembly, top up first. Trigger: `!tls_dispatch_inflight(ctx)` @tls:35
    LWIP_E0166 = 0x0166, // tls_consume_handshake_buffer(): RFC 8446 5.1: a key-changing message (Finished, KeyUpdate) must end its record; more handshake data here would be under the wrong keys. Trigger: `ctx->key_change_pending` @tls:60
    LWIP_E0167 = 0x0167, // tls_consume_handshake_buffer(): Drain complete messages from `buf`. Trigger: `body_len > SIZE_MAX - 4u` @peer:60 @tls:60
    LWIP_E0168 = 0x0168, // tls_consume_handshake_buffer(): Drain complete messages from `buf`. Trigger: `body_len == 0` @peer:60 @tls:60
    LWIP_E0169 = 0x0169, // tls_consume_handshake_buffer(): Non-Certificate parsers hold their message flat, so enforce the documented memory bound. Trigger: `msg_type != TLS_HANDSHAKE_CERTIFICATE && total > TLS_HS_REASSEMBLY_MAX` @peer:60 @tls:60
    LWIP_E016A = 0x016A, // tls_consume_handshake_buffer(): Certificate: install header, transcript-update the header, route body through walker. Trigger: `!tls_hs_reasm_grow(ctx, 4)` @memory:70 @tls:35
    LWIP_E016B = 0x016B, // tls_consume_handshake_buffer(): fails and returns false. Trigger: `!tls_feed_inflight_body(ctx, msg_type, buf + off, body_avail)` @tls:35
    LWIP_E016C = 0x016C, // tls_consume_handshake_buffer(): fails and returns false. Trigger: `!tls_dispatch_inflight(ctx)` @tls:35
    LWIP_E016D = 0x016D, // tls_consume_handshake_buffer(): Non-Certificate: legacy path. Trigger: `!tls_hs_reasm_grow(ctx, total)` @memory:70 @tls:35
    LWIP_E016E = 0x016E, // tls_consume_handshake_buffer(): Drain complete messages from `buf`. Trigger: `!tls_dispatch_inner_handshake(ctx, msg_type, buf + off, total)` @tls:35
    LWIP_E016F = 0x016F, // tls_consume_handshake_buffer(): We can't know the full size yet — stash and ask grow() for at least 4 bytes so a follow-up call can read the length. Trigger: `!tls_hs_reasm_grow(ctx, 4)` @memory:70 @tls:35
    LWIP_E0170 = 0x0170, // tls_dispatch_inner_handshake(): Certificate verification jobs must all have passed before any further handshake message is acted on. Trigger: `ctx->cert_jobs != NULL || ctx->ocsp_pending` @tls:60
    LWIP_E0171 = 0x0171, // tls_dispatch_inner_handshake(): fails. Trigger: `!ok` @tls:60
    LWIP_E0172 = 0x0172, // tls_process_inner_plaintext_pbuf(): fails and returns false. Trigger: `!ctx` @api:75 @tls:20
    LWIP_E0173 = 0x0173, // tls_process_inner_plaintext_pbuf(): fails and returns false. Trigger: `plaintext_len != 0 && !plaintext` @api:75 @tls:20
    LWIP_E0174 = 0x0174, // tls_process_inner_plaintext_pbuf(): fails and returns false. Trigger: `!q` @tls:60
    LWIP_E0175 = 0x0175, // tls_process_inner_plaintext_pbuf(): fails and returns false. Trigger: `!tls_consume_handshake_buffer(ctx, (const uint8_t *)q->payload, chunk)` @tls:35
    LWIP_E0176 = 0x0176, // tls_process_inner_plaintext_pbuf(): fails and returns false. Trigger: `plaintext_len != 2` @peer:60 @tls:60
    LWIP_E0177 = 0x0177, // tls_process_inner_plaintext_pbuf(): fails. Trigger: `inner_content_type == TLS_CONTENT_TYPE_ALERT` @tls:60
    LWIP_E0178 = 0x0178, // tls_process_inner_plaintext_pbuf(): fails and returns false. Trigger: `inner_content_type == TLS_CONTENT_TYPE_ALERT` @tls:60
    LWIP_E0179 = 0x0179, // tls_process_inner_plaintext_pbuf(): fails and returns false. @tls:60
    LWIP_E017A = 0x017A, // tls_handshake_init_common(): fails and returns false. Trigger: `!ctx` @api:75 @tls:20
    LWIP_E017B = 0x017B, // tls_handshake_init_common(): fails and returns false. Trigger: `tls_random_bytes_ex(ctx->client_random, sizeof(ctx->client_random), TLS_RNG_STRENGTH_128) == NULL` @crypto:40 @tls:35
    LWIP_E017C = 0x017C, // tls_handshake_init_common(): fails and returns false. Trigger: `!transcript_hash_init(ctx->transcript_hash, TLS_HASH_SHA256)` @crypto:40 @tls:35
    LWIP_E017D = 0x017D, // tls_handshake_init_common(): fails and returns false. Trigger: `tls_random_bytes_ex(ctx->ecdhe_private, sizeof(ctx->ecdhe_private), TLS_RNG_STRENGTH_128) == NULL` @crypto:40 @tls:35
    LWIP_E017E = 0x017E, // tls_handshake_init_common(): fails and returns false. Trigger: `tls_random_bytes_ex(ctx->p256_private, sizeof(ctx->p256_private), TLS_RNG_STRENGTH_128) == NULL` @crypto:40 @tls:35
    LWIP_E017F = 0x017F, // tls_handshake_keyshare_fail(): fails and returns -1. @tls:60
    LWIP_E0180 = 0x0180, // tls_handshake_keyshares_step(): fails and returns -1. Trigger: `ctx->keyshare_state != TLS_KEYSHARE_STATE_GENERATING` @tls:60
    LWIP_E0181 = 0x0181, // tls_handshake_init(): fails and returns false. Trigger: `!x25519_ok` @tls:60
    LWIP_E0182 = 0x0182, // tls_send_client_hello(): fails and returns false. Trigger: `!ctx || !written || (!out && out_len != 0)` @api:75 @tls:20
    LWIP_E0183 = 0x0183, // tls_send_client_hello(): fails and returns false. Trigger: `!is_hrr_retry && ctx->state != TLS_STATE_INIT` @tls:60 @logic:45
    LWIP_E0184 = 0x0184, // tls_send_client_hello(): fails and returns false. Trigger: `use_p256_share && !(ctx->keyshare_ready & TLS_KEYSHARE_P256_READY)` @tls:60
    LWIP_E0185 = 0x0185, // tls_send_client_hello(): fails and returns false. Trigger: `hostname_len > 0xFFFFu - 5u` @tls:60
    LWIP_E0186 = 0x0186, // tls_send_client_hello(): fails and returns false. Trigger: `ip_len < 0` @tls:60
    LWIP_E0187 = 0x0187, // tls_send_client_hello(): fails and returns false. Trigger: `ctx->psk_mode && (ctx->psk_identity.identity_len == 0 || ctx->psk_identity.identity_len > TLS_PSK_IDENTITY_MAX_LEN)` @tls:60
    LWIP_E0188 = 0x0188, // tls_send_client_hello(): fails and returns false. Trigger: `!ctx->alpn_protocols || ctx->alpn_protocols_len > 0xFFFFu` @tls:60
    LWIP_E0189 = 0x0189, // tls_send_client_hello(): fails and returns false. Trigger: `protocol_len == 0 || protocol_len > ctx->alpn_protocols_len - alpn_offset` @tls:60
    LWIP_E018A = 0x018A, // tls_send_client_hello(): fails and returns false. Trigger: `required_ext_len > 0xFFFFu` @tls:60
    LWIP_E018B = 0x018B, // tls_send_client_hello(): fails and returns false. Trigger: `required_len - 4 > 0xFFFFFFu` @tls:60
    LWIP_E018C = 0x018C, // tls_send_client_hello(): fails and returns false. Trigger: `required_len > out_len` @tls:60
    LWIP_E018D = 0x018D, // tls_send_client_hello(): fails and returns false. Trigger: `!psk_tmp` @memory:85 @tls:20
    LWIP_E018E = 0x018E, // tls_send_client_hello(): fails and aborts (goto psk_cleanup). Trigger: `offset + ctx->psk_identity.identity_len > out_len` @tls:60
    LWIP_E018F = 0x018F, // tls_send_client_hello(): Calculate PSK binder. Trigger: `!tls_hkdf_extract(TLS_HASH_SHA256, NULL, 0, ctx->psk, 32, psk_tmp->early_secret)` @crypto:40 @tls:35
    LWIP_E0190 = 0x0190, // tls_send_client_hello(): RFC 8446 derives binder_key with Derive-Secret(..., ""), so the HKDF context is Transcript-Hash(empty), not a zero-length context field. Trigger: `!tls_hash_context_init(&psk_tmp->hash_ctx, TLS_HASH_SHA256)` @crypto:40 @tls:35
    LWIP_E0191 = 0x0191, // tls_send_client_hello(): fails and aborts (goto psk_cleanup). Trigger: `!tls_hkdf_expand_label(TLS_HASH_SHA256, psk_tmp->early_secret, 32, binder_label, 10, psk_tmp->partial_hash, 32, psk_tmp->binder_key, 32)` @crypto:40 @tls:35
    LWIP_E0192 = 0x0192, // tls_send_client_hello(): fails and aborts (goto psk_cleanup). Trigger: `!tls_hkdf_expand_label(TLS_HASH_SHA256, psk_tmp->binder_key, 32, , 8, NULL, 0, psk_tmp->finished_key, 32)` @crypto:40 @tls:35
    LWIP_E0193 = 0x0193, // tls_send_client_hello(): fails and aborts (goto psk_cleanup). Trigger: `!tls_hash_context_init(&psk_tmp->hash_ctx, TLS_HASH_SHA256)` @crypto:40 @tls:35
    LWIP_E0194 = 0x0194, // tls_send_client_hello(): Compute binder = HMAC(finished_key, partial_hash). Trigger: `!tls_hmac_context_init(&psk_tmp->hmac_ctx, TLS_HASH_SHA256, psk_tmp->finished_key, 32)` @crypto:40 @tls:35
    LWIP_E0195 = 0x0195, // tls_send_client_hello(): Write binder value. Trigger: `offset + 32 > out_len` @tls:60
    LWIP_E0196 = 0x0196, // tls_recv_server_hello(): fails and returns false. Trigger: `!ctx || !data || ctx->state != TLS_STATE_CLIENT_HELLO_SENT` @tls:60 @logic:45
    LWIP_E0197 = 0x0197, // tls_recv_server_hello(): fails and returns false. Trigger: `offset == 0` @peer:60 @tls:60
    LWIP_E0198 = 0x0198, // tls_recv_server_hello(): Step 3: Verify legacy version (0x0303). Trigger: `offset + 2 > msg_end || data[offset] != 0x03 || data[offset + 1] != 0x03` @peer:60 @tls:60
    LWIP_E0199 = 0x0199, // tls_recv_server_hello(): Step 4: Extract server random. Trigger: `offset + 32 > msg_end` @peer:60 @tls:60
    LWIP_E019A = 0x019A, // tls_recv_server_hello(): Reject a second HRR — RFC 8446 §4.1.4 forbids it. Trigger: `ctx->hrr_done` @tls:60
    LWIP_E019B = 0x019B, // tls_recv_server_hello(): fails and returns false. Trigger: `hrr_offset >= msg_end` @peer:60 @tls:60
    LWIP_E019C = 0x019C, // tls_recv_server_hello(): fails and returns false. Trigger: `hrr_offset + sid_len > msg_end` @peer:60 @tls:60
    LWIP_E019D = 0x019D, // tls_recv_server_hello(): fails and returns false. Trigger: `sid_len != 0` @peer:60 @tls:60
    LWIP_E019E = 0x019E, // tls_recv_server_hello(): Skip cipher suite (2) + compression method (1). Trigger: `hrr_offset + 3 > msg_end` @peer:60 @tls:60
    LWIP_E019F = 0x019F, // tls_recv_server_hello(): fails and returns false. Trigger: `!tls_cipher_suite_offered(ctx, hrr_cipher_suite) || data[hrr_offset + 2] != 0` @peer:60 @tls:60
    LWIP_E01A0 = 0x01A0, // tls_recv_server_hello(): Extensions block. Trigger: `hrr_offset + 2 > msg_end` @peer:60 @tls:60
    LWIP_E01A1 = 0x01A1, // tls_recv_server_hello(): fails and returns false. Trigger: `hrr_ext_end != msg_end` @peer:60 @tls:60
    LWIP_E01A2 = 0x01A2, // tls_recv_server_hello(): fails and returns false. Trigger: `hrr_offset + elen > hrr_ext_end` @peer:60 @tls:60
    LWIP_E01A3 = 0x01A3, // tls_recv_server_hello(): HRR key_share extension body = 2-byte NamedGroup. Trigger: `hrr_key_share || elen != 2` @peer:60 @tls:60
    LWIP_E01A4 = 0x01A4, // tls_recv_server_hello(): Cookie body = 2-byte length + cookie bytes. Trigger: `hrr_cookie_seen || elen < 3` @peer:60 @tls:60
    LWIP_E01A5 = 0x01A5, // tls_recv_server_hello(): fails and returns false. Trigger: `(size_t)clen + 2u != elen` @peer:60 @tls:60
    LWIP_E01A6 = 0x01A6, // tls_recv_server_hello(): fails and returns false. Trigger: `hrr_version || elen != 2 || data[hrr_offset] != 0x03 || data[hrr_offset + 1] != 0x04` @peer:60 @tls:60
    LWIP_E01A7 = 0x01A7, // tls_recv_server_hello(): fails and returns false. Trigger: `hrr_offset != hrr_ext_end || !hrr_version || (!hrr_key_share && !hrr_cookie_seen)` @peer:60 @tls:60
    LWIP_E01A8 = 0x01A8, // tls_recv_server_hello(): ClientHello1 sent X25519 and advertised X25519 + P-256. Trigger: `hrr_requested_group != TLS_NAMED_GROUP_SECP256R1` @peer:60 @tls:60
    LWIP_E01A9 = 0x01A9, // tls_recv_server_hello(): fails and returns false. Trigger: `!synth` @memory:85 @tls:20
    LWIP_E01AA = 0x01AA, // tls_recv_server_hello(): The suite hash is known from the HRR, so rebuild the CH1 transcript under it when it differs from SHA-256. Trigger: `!ctx->client_hello_buf || ctx->client_hello_len == 0 || !tls_hash_context_init(ctx->transcript_hash, algorithm)` @peer:60 @tls:60
    LWIP_E01AB = 0x01AB, // tls_recv_server_hello(): Re-initialise the transcript hash. Trigger: `!transcript_hash_init(ctx->transcript_hash, algorithm)` @crypto:40 @tls:35
    LWIP_E01AC = 0x01AC, // tls_recv_server_hello(): fails and returns false. Trigger: `!ctx->hrr_cookie` @memory:85 @tls:20
    LWIP_E01AD = 0x01AD, // tls_recv_server_hello(): Step 5: Skip session ID. Trigger: `offset >= msg_end` @peer:60 @tls:60
    LWIP_E01AE = 0x01AE, // tls_recv_server_hello(): fails and returns false. Trigger: `session_id_len != 0 || offset + session_id_len > msg_end` @peer:60 @tls:60
    LWIP_E01AF = 0x01AF, // tls_recv_server_hello(): Step 6: Parse cipher suite. Trigger: `offset + 2 > msg_end` @peer:60 @tls:60
    LWIP_E01B0 = 0x01B0, // tls_recv_server_hello(): fails and returns false. Trigger: `!tls_cipher_suite_offered(ctx, cipher_suite) || (ctx->hrr_done && cipher_suite != ctx->cipher_suite)` @peer:60 @tls:60
    LWIP_E01B1 = 0x01B1, // tls_recv_server_hello(): Step 7: Verify compression method. Trigger: `offset >= msg_end || data[offset++] != 0x00` @peer:60 @tls:60
    LWIP_E01B2 = 0x01B2, // tls_recv_server_hello(): Step 8: Parse extensions. Trigger: `offset + 2 > msg_end` @peer:60 @tls:60
    LWIP_E01B3 = 0x01B3, // tls_recv_server_hello(): fails and returns false. Trigger: `ext_end != msg_end` @peer:60 @tls:60
    LWIP_E01B4 = 0x01B4, // tls_recv_server_hello(): fails and returns false. Trigger: `offset + 4 > ext_end` @peer:60 @tls:60
    LWIP_E01B5 = 0x01B5, // tls_recv_server_hello(): fails and returns false. Trigger: `offset + ext_data_len > ext_end` @peer:60 @tls:60
    LWIP_E01B6 = 0x01B6, // tls_recv_server_hello(): Verify TLS 1.3 (0x0304). Trigger: `found_supported_versions || ext_data_len != 2 (case TLS_EXT_SUPPORTED_VERSIONS)` @peer:60 @tls:60
    LWIP_E01B7 = 0x01B7, // tls_recv_server_hello(): fails and returns false. Trigger: `data[offset] != 0x03 || data[offset + 1] != 0x04 (case TLS_EXT_SUPPORTED_VERSIONS)` @peer:60 @tls:60
    LWIP_E01B8 = 0x01B8, // tls_recv_server_hello(): ServerHello key_share: named_group (2) + key_exchange_length (2) + key_exchange. Trigger: `ctx->ecdhe_negotiated || ext_data_len < 4` @peer:60 @tls:60
    LWIP_E01B9 = 0x01B9, // tls_recv_server_hello(): fails and returns false. Trigger: `ext_data_len != (size_t)(4 + ke_len)` @peer:60 @tls:60
    LWIP_E01BA = 0x01BA, // tls_recv_server_hello(): After an HRR selecting P-256, ClientHello2 contains only P-256, so the server may no longer select X25519. Trigger: `(ctx->hrr_done && ctx->hrr_requested_group == TLS_NAMED_GROUP_SECP256R1) || ke_len != 32` @peer:60 @tls:60
    LWIP_E01BB = 0x01BB, // tls_recv_server_hello(): fails. Trigger: `!x25519_ok` @tls:60
    LWIP_E01BC = 0x01BC, // tls_recv_server_hello(): fails and returns false. Trigger: `!x25519_ok` @tls:60
    LWIP_E01BD = 0x01BD, // tls_recv_server_hello(): P-256 was not present in ClientHello1. Trigger: `!ctx->hrr_done || ctx->hrr_requested_group != TLS_NAMED_GROUP_SECP256R1 || !(ctx->keyshare_ready & TLS_KEYSHARE_P256_READY)` @peer:60 @tls:60
    LWIP_E01BE = 0x01BE, // tls_recv_server_hello(): P-256 uncompressed point: 0x04 || x(32) || y(32) = 65 bytes. Trigger: `ke_len != 65 || data[offset + 4] != 0x04` @peer:60 @tls:60
    LWIP_E01BF = 0x01BF, // tls_recv_server_hello(): fails. Trigger: `!p256_ok` @tls:60
    LWIP_E01C0 = 0x01C0, // tls_recv_server_hello(): fails and returns false. Trigger: `!p256_ok` @tls:60
    LWIP_E01C1 = 0x01C1, // tls_recv_server_hello(): fails and returns false. Trigger: `else branch` @tls:60
    LWIP_E01C2 = 0x01C2, // tls_recv_server_hello(): fails and returns false. Trigger: `found_psk || !ctx->psk_mode` @tls:60
    LWIP_E01C3 = 0x01C3, // tls_recv_server_hello(): Extract selected PSK identity (2 bytes, should be 0 for first PSK). Trigger: `ext_data_len != 2` @peer:60 @tls:60
    LWIP_E01C4 = 0x01C4, // tls_recv_server_hello(): fails and returns false. Trigger: `selected_identity != 0` @peer:60 @tls:60
    LWIP_E01C5 = 0x01C5, // tls_recv_server_hello(): Verify required extensions were present. Trigger: `!found_supported_versions || (!found_psk && !ctx->ecdhe_negotiated)` @tls:60
    LWIP_E01C6 = 0x01C6, // tls_recv_server_hello(): Step 9: Update transcript hash with ServerHello. Trigger: `!tls_transcript_select_suite_hash(ctx)` @crypto:40 @tls:35
    LWIP_E01C7 = 0x01C7, // tls_recv_certificate_streamed(): fails and returns false. Trigger: `!ctx || !w` @api:75 @cert:20
    LWIP_E01C8 = 0x01C8, // tls_recv_certificate_streamed(): fails and returns false. Trigger: `ctx->state != TLS_STATE_ENCRYPTED_EXTENSIONS_RECEIVED` @cert:65 @logic:45
    LWIP_E01C9 = 0x01C9, // tls_recv_certificate_streamed(): PSK-authenticated handshakes, including PSK+DHE, MUST NOT send Certificate. Trigger: `ctx->psk_mode` @cert:65
    LWIP_E01CA = 0x01CA, // tls_recv_certificate_streamed(): fails and returns false. Trigger: `w->state != CW_DONE` @cert:65 @logic:45
    LWIP_E01CB = 0x01CB, // tls_recv_certificate_streamed(): fails and returns false. Trigger: `!w->chain_validated` @api:75 @cert:20
    LWIP_E01CC = 0x01CC, // tls_recv_certificate_streamed(): Anchoring the topmost certificate in the truststore is queued behind the chain-link jobs. Trigger: `!tls_cert_job_enqueue(w, NULL)` @cert:45
    LWIP_E01CD = 0x01CD, // tls_recv_encrypted_extensions(): fails and returns false. Trigger: `!ctx || !data || data_len < 6` @api:75 @tls:20
    LWIP_E01CE = 0x01CE, // tls_recv_encrypted_extensions(): fails and returns false. Trigger: `ctx->state != TLS_STATE_HANDSHAKE_KEYS_DERIVED` @tls:60 @logic:45
    LWIP_E01CF = 0x01CF, // tls_recv_encrypted_extensions(): fails and returns false. Trigger: `offset == 0` @peer:60 @tls:60
    LWIP_E01D0 = 0x01D0, // tls_recv_encrypted_extensions(): Parse extensions length (2 bytes). Trigger: `offset + 2 > data_len` @peer:60 @tls:60
    LWIP_E01D1 = 0x01D1, // tls_recv_encrypted_extensions(): Verify extensions fit in message. Trigger: `offset + ext_len != data_len || ext_len != msg_len - 2u` @peer:60 @tls:60
    LWIP_E01D2 = 0x01D2, // tls_recv_encrypted_extensions(): fails and returns false. Trigger: `ext_offset + ext_data_len > ext_len` @peer:60 @tls:60
    LWIP_E01D3 = 0x01D3, // tls_recv_encrypted_extensions(): RFC 6066 3: the server may only acknowledge an SNI we sent. Trigger: `!ctx->sni_sent` @api:75 @tls:20
    LWIP_E01D4 = 0x01D4, // tls_recv_encrypted_extensions(): fails and returns false. Trigger: `seen_server_name || ext_data_len != 0` @peer:60 @tls:60
    LWIP_E01D5 = 0x01D5, // tls_recv_encrypted_extensions(): RFC 8449 §4: server echoes the limit we sent (4096 = 0x1000). Trigger: `seen_record_size_limit || ext_data_len != 2` @peer:60 @tls:60
    LWIP_E01D6 = 0x01D6, // tls_recv_encrypted_extensions(): fails and returns false. Trigger: `server_limit > 4096u` @peer:60 @tls:60
    LWIP_E01D7 = 0x01D7, // tls_recv_encrypted_extensions(): A server ALPN response contains exactly one non-empty name. Trigger: `selected_len == 0 || list_len != (uint16_t)(selected_len + 1u) || ext_data_len != (uint16_t)(list_len + 2u)` @peer:60 @tls:60
    LWIP_E01D8 = 0x01D8, // tls_recv_encrypted_extensions(): fails and returns false. Trigger: `offered_len == 0 || offered_len > ctx->alpn_protocols_len - offered_offset` @peer:60 @tls:60
    LWIP_E01D9 = 0x01D9, // tls_recv_encrypted_extensions(): fails and returns false. Trigger: `seen_groups || ext_data_len < 4` @peer:60 @tls:60
    LWIP_E01DA = 0x01DA, // tls_recv_encrypted_extensions(): fails and returns false. Trigger: `groups_len < 2 || (groups_len & 1u) != 0 || groups_len != (uint16_t)(ext_data_len - 2u)` @peer:60 @tls:60
    LWIP_E01DB = 0x01DB, // tls_recv_encrypted_extensions(): fails and returns false. Trigger: `previous_group == group` @tls:60
    LWIP_E01DC = 0x01DC, // tls_recv_encrypted_extensions(): fails and returns false. Trigger: `ext_offset != ext_len` @peer:60 @tls:60
    LWIP_E01DD = 0x01DD, // tls_recv_certificate_request(): fails and returns false. Trigger: `!ctx || !data || data_len < 7` @api:75 @cert:20
    LWIP_E01DE = 0x01DE, // tls_recv_certificate_request(): fails and returns false. Trigger: `ctx->state != TLS_STATE_ENCRYPTED_EXTENSIONS_RECEIVED || ctx->client_certificate_requested` @cert:65 @logic:45
    LWIP_E01DF = 0x01DF, // tls_recv_certificate_request(): A server authenticating this main handshake with a selected PSK is not permitted to request a client certificate (RFC 8446 §4.3.2). Trigger: `ctx->psk_mode` @cert:65
    LWIP_E01E0 = 0x01E0, // tls_recv_certificate_request(): fails and returns false. Trigger: `offset == 0` @cert:65 @peer:60
    LWIP_E01E1 = 0x01E1, // tls_recv_certificate_request(): fails and returns false. Trigger: `msg_end != data_len` @cert:65 @peer:60
    LWIP_E01E2 = 0x01E2, // tls_recv_certificate_request(): fails and returns false. Trigger: `offset + 1 > msg_end` @cert:65 @peer:60
    LWIP_E01E3 = 0x01E3, // tls_recv_certificate_request(): fails and returns false. Trigger: `offset + request_context_len > msg_end` @cert:65 @peer:60
    LWIP_E01E4 = 0x01E4, // tls_recv_certificate_request(): A CertificateRequest sent in the main handshake has an empty context. Trigger: `request_context_len != 0` @cert:65 @peer:60
    LWIP_E01E5 = 0x01E5, // tls_recv_certificate_request(): fails and returns false. Trigger: `offset + 2 > msg_end` @cert:65 @peer:60
    LWIP_E01E6 = 0x01E6, // tls_recv_certificate_request(): fails and returns false. Trigger: `offset + ext_len != msg_end` @cert:65 @peer:60
    LWIP_E01E7 = 0x01E7, // tls_recv_certificate_request(): fails and returns false. Trigger: `ext_offset + ext_data_len > ext_len` @cert:65 @peer:60
    LWIP_E01E8 = 0x01E8, // tls_recv_certificate_request(): RFC 8446 §4.2 forbids duplicate extensions in any extension block, including types that this client otherwise ignores. Trigger: `previous_type == ext_type` @cert:65
    LWIP_E01E9 = 0x01E9, // tls_recv_certificate_request(): fails and returns false. Trigger: `ext_data_len < 4` @cert:65 @peer:60
    LWIP_E01EA = 0x01EA, // tls_recv_certificate_request(): fails and returns false. Trigger: `algorithms_len < 2 || (algorithms_len & 1u) != 0 || algorithms_len != (uint16_t)(ext_data_len - 2u)` @cert:65 @peer:60
    LWIP_E01EB = 0x01EB, // tls_recv_certificate_request(): fails and returns false. Trigger: `ext_data_len < 5` @cert:65 @peer:60
    LWIP_E01EC = 0x01EC, // tls_recv_certificate_request(): fails and returns false. Trigger: `names_len < 3 || names_len != (uint16_t)(ext_data_len - 2u)` @cert:65 @peer:60
    LWIP_E01ED = 0x01ED, // tls_recv_certificate_request(): fails and returns false. Trigger: `ext_offset != ext_len` @cert:65 @peer:60
    LWIP_E01EE = 0x01EE, // tls_recv_certificate_request(): signature_algorithms is mandatory in a TLS 1.3 CertificateRequest. Trigger: `!found_signature_algorithms` @cert:65
    LWIP_E01EF = 0x01EF, // tls_certverify_rsa_pss_sha256(): fails and returns false. Trigger: `!ctx || ctx->leaf_pubkey.type != TLS_KEY_TYPE_RSA || !sig || sig_len == 0` @cert:65 @peer:60
    LWIP_E01F0 = 0x01F0, // tls_certverify_rsa_pss_sha256(): fails and returns false. Trigger: `!rsa->modulus || rsa->mod_len == 0` @cert:65 @peer:60
    LWIP_E01F1 = 0x01F1, // tls_certverify_rsa_pss_sha256(): TLS 1.3 PSS uses salt length == hash length, so the signature must exactly match the modulus size in bytes. Trigger: `sig_len != rsa->mod_len` @cert:65 @peer:60
    LWIP_E01F2 = 0x01F2, // tls_certverify_rsa_pss_sha256(): Build the signed-content digest. Trigger: `!ctx->transcript_hash || (ctx->hash_len != TLS_SHA256_DIGEST_LEN && ctx->hash_len != TLS_SHA384_DIGEST_LEN)` @cert:65 @peer:60
    LWIP_E01F3 = 0x01F3, // tls_certverify_rsa_pss_sha256(): RSA decrypt the signature, then run the PSS padding check. Trigger: `rsa->mod_len > RSA_TRANSIENT_SIZE || rsa->mod_len < RSA_MODULUS_MIN_SUPPORTED` @cert:65 @peer:60
    LWIP_E01F4 = 0x01F4, // tls_certverify_rsa_pss_sha256(): fails and returns false. Trigger: `!cv` @memory:85 @cert:20
    LWIP_E01F5 = 0x01F5, // tls_certverify_rsa_pss_sha256(): fails and aborts (goto cleanup). Trigger: `!transcript_hash_digest(ctx->transcript_hash, cv->transcript) || !tls_hash_context_init(&cv->hash_ctx, TLS_HASH_SHA256)` @crypto:40 @cert:35
    LWIP_E01F6 = 0x01F6, // tls_certverify_ecdsa_p256_sha256(): fails and returns false. Trigger: `!ctx || ctx->leaf_pubkey.type != TLS_KEY_TYPE_EC_P256 || !sig || sig_len == 0` @cert:65 @peer:60
    LWIP_E01F7 = 0x01F7, // tls_certverify_ecdsa_p256_sha256(): fails and returns false. Trigger: `!ctx->leaf_pubkey.ec.pub || ctx->leaf_pubkey.ec.len != 65` @cert:65 @peer:60
    LWIP_E01F8 = 0x01F8, // tls_certverify_ecdsa_p256_sha256(): Build the signed-content digest. Trigger: `!ctx->transcript_hash || (ctx->hash_len != TLS_SHA256_DIGEST_LEN && ctx->hash_len != TLS_SHA384_DIGEST_LEN)` @cert:65 @peer:60
    LWIP_E01F9 = 0x01F9, // tls_certverify_ecdsa_p256_sha256(): fails and returns false. Trigger: `!cv` @memory:85 @cert:20
    LWIP_E01FA = 0x01FA, // tls_certverify_ecdsa_p256_sha256(): fails and aborts (goto done). Trigger: `!transcript_hash_digest(ctx->transcript_hash, cv->transcript) || !tls_hash_context_init(&cv->hash_ctx, TLS_HASH_SHA256)` @crypto:40 @cert:35
    LWIP_E01FB = 0x01FB, // tls_certverify_ecdsa_p256_sha256(): Parse DER SEQUENCE { INTEGER r, INTEGER s } → flat 64-byte r||s. Trigger: `!tls_ecdsa_sig_rs(sig, sig_len, cv->rs)` @cert:35
    LWIP_E01FC = 0x01FC, // tls_certverify_ecdsa_p384_sha384(): fails and returns false. Trigger: `!ctx || ctx->leaf_pubkey.type != TLS_KEY_TYPE_EC_P384 || !sig || sig_len == 0` @cert:65 @peer:60
    LWIP_E01FD = 0x01FD, // tls_certverify_ecdsa_p384_sha384(): fails and returns false. Trigger: `!ctx->leaf_pubkey.ec.pub || ctx->leaf_pubkey.ec.len != 97` @cert:65 @peer:60
    LWIP_E01FE = 0x01FE, // tls_certverify_ecdsa_p384_sha384(): fails and returns false. Trigger: `!ctx->transcript_hash || (ctx->hash_len != TLS_SHA256_DIGEST_LEN && ctx->hash_len != TLS_SHA384_DIGEST_LEN)` @cert:65 @peer:60
    LWIP_E01FF = 0x01FF, // tls_certverify_ecdsa_p384_sha384(): fails and returns false. Trigger: `!cv` @memory:85 @cert:20
    LWIP_E0200 = 0x0200, // tls_certverify_ecdsa_p384_sha384(): fails and aborts (goto done). Trigger: `!transcript_hash_digest(ctx->transcript_hash, cv->transcript) || !tls_hash_context_init(&cv->hash_ctx, TLS_HASH_SHA384)` @crypto:40 @cert:35
    LWIP_E0201 = 0x0201, // tls_certverify_ecdsa_p384_sha384(): fails and aborts (goto done). Trigger: `!tls_ecdsa_sig_rs96(sig, sig_len, cv->rs)` @cert:35
    LWIP_E0202 = 0x0202, // tls_recv_certificate_verify(): fails and returns false. Trigger: `!ctx || !data || data_len < 8` @api:75 @cert:20
    LWIP_E0203 = 0x0203, // tls_recv_certificate_verify(): fails and returns false. Trigger: `ctx->state != TLS_STATE_CERTIFICATE_RECEIVED` @cert:65 @logic:45
    LWIP_E0204 = 0x0204, // tls_recv_certificate_verify(): fails and returns false. Trigger: `offset == 0` @cert:65 @peer:60
    LWIP_E0205 = 0x0205, // tls_recv_certificate_verify(): Signature algorithm (2 bytes). Trigger: `offset + 2 > data_len` @cert:65 @peer:60
    LWIP_E0206 = 0x0206, // tls_recv_certificate_verify(): Signature length (2 bytes) and bounds. Trigger: `offset + 2 > data_len` @cert:65 @peer:60
    LWIP_E0207 = 0x0207, // tls_recv_certificate_verify(): fails and returns false. Trigger: `offset + sig_len > data_len || offset + sig_len != 4 + msg_len` @cert:65 @peer:60
    LWIP_E0208 = 0x0208, // tls_recv_certificate_verify(): No leaf cert in hand (e.g. Trigger: `ctx->leaf_pubkey.type == TLS_KEY_TYPE_UNKNOWN` @cert:65
    LWIP_E0209 = 0x0209, // tls_recv_certificate_verify(): fails. Trigger: `!sig_ok` @cert:65
    LWIP_E020A = 0x020A, // tls_recv_certificate_verify(): fails and returns false. Trigger: `!sig_ok` @cert:65
    LWIP_E020B = 0x020B, // tls_derive_handshake_keys(): fails and returns false. Trigger: `!ctx || ctx->state != TLS_STATE_SERVER_HELLO_RECEIVED` @tls:60 @logic:45
    LWIP_E020C = 0x020C, // tls_derive_handshake_keys(): fails and returns false. Trigger: `(hash_alg != TLS_HASH_SHA256 && hash_alg != TLS_HASH_SHA384) || (hlen != TLS_SHA256_DIGEST_LEN && hlen != TLS_SHA384_DIGEST_LEN) || (klen != 16 && klen != 32)…` @tls:60
    LWIP_E020D = 0x020D, // tls_derive_handshake_keys(): fails and returns false. Trigger: `!sec` @memory:85 @tls:20
    LWIP_E020E = 0x020E, // tls_derive_handshake_keys(): fails and returns false. Trigger: `!tls_hkdf_extract(hash_alg, NULL, 0, psk_ikm, psk_len, sec->early_secret)` @crypto:40 @tls:35
    LWIP_E020F = 0x020F, // tls_derive_handshake_keys(): Step 2: Compute empty hash for "derived" secret. Trigger: `!tls_hash_context_init(&sec->hash_ctx, hash_alg)` @crypto:40 @tls:35
    LWIP_E0210 = 0x0210, // tls_derive_handshake_keys(): Step 3: Derive "derived" secret from early_secret derived = Derive-Secret(early_secret, "derived", empty_hash). Trigger: `!tls_derive_secret(hash_alg, sec->early_secret, hlen, , 7, sec->empty_hash, hlen, sec->derived_secret)` @tls:35
    LWIP_E0211 = 0x0211, // tls_derive_handshake_keys(): fails and returns false. Trigger: `!tls_hkdf_extract(hash_alg, sec->derived_secret, hlen, ecdhe_ikm, ecdhe_len, sec->handshake_secret)` @crypto:40 @tls:35
    LWIP_E0212 = 0x0212, // tls_derive_handshake_keys(): Step 5: Get transcript hash (ClientHello...ServerHello). Trigger: `!ctx->transcript_hash || ctx->transcript_hash->digestlen != hlen || !transcript_hash_digest(ctx->transcript_hash, sec->transcript_hash)` @tls:60
    LWIP_E0213 = 0x0213, // tls_derive_handshake_keys(): Step 6: Derive client handshake traffic secret client_handshake_traffic_secret = Derive-Secret(handshake_secret, "c hs traffic", transcript_hash). Trigger: `!tls_derive_secret(hash_alg, sec->handshake_secret, hlen, , 12, sec->transcript_hash, hlen, ctx->keys.client_handshake_traffic_secret)` @tls:35
    LWIP_E0214 = 0x0214, // tls_derive_handshake_keys(): Step 7: Derive server handshake traffic secret server_handshake_traffic_secret = Derive-Secret(handshake_secret, "s hs traffic", transcript_hash). Trigger: `!tls_derive_secret(hash_alg, sec->handshake_secret, hlen, , 12, sec->transcript_hash, hlen, ctx->keys.server_handshake_traffic_secret)` @tls:35
    LWIP_E0215 = 0x0215, // tls_derive_handshake_keys(): fails and returns false. Trigger: `!tls_hkdf_expand_label(hash_alg, ctx->keys.client_handshake_traffic_secret, hlen, , 3, NULL, 0, ctx->keys.client_handshake_key, klen)` @crypto:40 @tls:35
    LWIP_E0216 = 0x0216, // tls_derive_handshake_keys(): fails and returns false. Trigger: `!tls_hkdf_expand_label(hash_alg, ctx->keys.client_handshake_traffic_secret, hlen, , 2, NULL, 0, ctx->keys.client_handshake_iv, 12)` @crypto:40 @tls:35
    LWIP_E0217 = 0x0217, // tls_derive_handshake_keys(): Step 9: Derive server handshake key and IV. Trigger: `!tls_hkdf_expand_label(hash_alg, ctx->keys.server_handshake_traffic_secret, hlen, , 3, NULL, 0, ctx->keys.server_handshake_key, klen)` @crypto:40 @tls:35
    LWIP_E0218 = 0x0218, // tls_derive_handshake_keys(): fails and returns false. Trigger: `!tls_hkdf_expand_label(hash_alg, ctx->keys.server_handshake_traffic_secret, hlen, , 2, NULL, 0, ctx->keys.server_handshake_iv, 12)` @crypto:40 @tls:35
    LWIP_E0219 = 0x0219, // tls_derive_application_keys(): fails and returns false. Trigger: `!ctx` @api:75 @tls:20
    LWIP_E021A = 0x021A, // tls_derive_application_keys(): fails and returns false. Trigger: `(hash_alg != TLS_HASH_SHA256 && hash_alg != TLS_HASH_SHA384) || (hlen != TLS_SHA256_DIGEST_LEN && hlen != TLS_SHA384_DIGEST_LEN) || (klen != 16 && klen != 32)` @tls:60
    LWIP_E021B = 0x021B, // tls_derive_application_keys(): fails and returns false. Trigger: `!sec` @memory:85 @tls:20
    LWIP_E021C = 0x021C, // tls_derive_application_keys(): Step 1: Compute empty hash for "derived" secret. Trigger: `!tls_hash_context_init(&sec->hash_ctx, hash_alg)` @crypto:40 @tls:35
    LWIP_E021D = 0x021D, // tls_derive_application_keys(): Step 2: Derive "derived" secret from handshake_secret derived = Derive-Secret(handshake_secret, "derived", empty_hash). Trigger: `!tls_derive_secret(hash_alg, ctx->keys.handshake_secret, hlen, , 7, sec->empty_hash, hlen, sec->derived_secret)` @tls:35
    LWIP_E021E = 0x021E, // tls_derive_application_keys(): Step 3: Compute master_secret master_secret = HKDF-Extract(salt=derived, IKM=0) ikm=NULL tells hkdf_extract to use hash-length zero bytes. Trigger: `!tls_hkdf_extract(hash_alg, sec->derived_secret, hlen, NULL, hlen, sec->master_secret)` @crypto:40 @tls:35
    LWIP_E021F = 0x021F, // tls_derive_application_keys(): Step 4: Get transcript hash (ClientHello...server Finished). Trigger: `!ctx->transcript_hash || ctx->transcript_hash->digestlen != hlen || !transcript_hash_digest(ctx->transcript_hash, sec->transcript_hash)` @tls:60
    LWIP_E0220 = 0x0220, // tls_derive_application_keys(): Step 5: Derive client application traffic secret client_application_traffic_secret = Derive-Secret(master_secret, "c ap traffic", transcript_hash). Trigger: `!tls_derive_secret(hash_alg, sec->master_secret, hlen, , 12, sec->transcript_hash, hlen, ctx->keys.client_application_traffic_secret)` @tls:35
    LWIP_E0221 = 0x0221, // tls_derive_application_keys(): Step 6: Derive server application traffic secret server_application_traffic_secret = Derive-Secret(master_secret, "s ap traffic", transcript_hash). Trigger: `!tls_derive_secret(hash_alg, sec->master_secret, hlen, , 12, sec->transcript_hash, hlen, ctx->keys.server_application_traffic_secret)` @tls:35
    LWIP_E0222 = 0x0222, // tls_derive_application_keys(): Step 7: Derive client application key and IV key = HKDF-Expand-Label(secret, "key", "", key_len) iv = HKDF-Expand-Label(secret, "iv", "", 12). Trigger: `!tls_hkdf_expand_label(hash_alg, ctx->keys.client_application_traffic_secret, hlen, , 3, NULL, 0, ctx->keys.client_application_key, klen)` @crypto:40 @tls:35
    LWIP_E0223 = 0x0223, // tls_derive_application_keys(): fails and returns false. Trigger: `!tls_hkdf_expand_label(hash_alg, ctx->keys.client_application_traffic_secret, hlen, , 2, NULL, 0, ctx->keys.client_application_iv, 12)` @crypto:40 @tls:35
    LWIP_E0224 = 0x0224, // tls_derive_application_keys(): Step 8: Derive server application key and IV. Trigger: `!tls_hkdf_expand_label(hash_alg, ctx->keys.server_application_traffic_secret, hlen, , 3, NULL, 0, ctx->keys.server_application_key, klen)` @crypto:40 @tls:35
    LWIP_E0225 = 0x0225, // tls_derive_application_keys(): fails and returns false. Trigger: `!tls_hkdf_expand_label(hash_alg, ctx->keys.server_application_traffic_secret, hlen, , 2, NULL, 0, ctx->keys.server_application_iv, 12)` @crypto:40 @tls:35
    LWIP_E0226 = 0x0226, // tls_send_finished(): fails and returns false. Trigger: `!ctx || !out || !written` @api:75 @tls:20
    LWIP_E0227 = 0x0227, // tls_send_finished(): fails and returns false. Trigger: `(hash_alg != TLS_HASH_SHA256 && hash_alg != TLS_HASH_SHA384) || (hlen != TLS_SHA256_DIGEST_LEN && hlen != TLS_SHA384_DIGEST_LEN)` @tls:60
    LWIP_E0228 = 0x0228, // tls_send_finished(): fails and returns false. Trigger: `out_len < 4 + hlen` @tls:60
    LWIP_E0229 = 0x0229, // tls_send_finished(): fails and returns false. Trigger: `!sec` @memory:85 @tls:20
    LWIP_E022A = 0x022A, // tls_send_finished(): Step 2: Derive finished_key finished_key = HKDF-Expand-Label(traffic_secret, "finished", "", Hash.length). Trigger: `!tls_hkdf_expand_label(hash_alg, traffic_secret, hlen, , 8, NULL, 0, sec->finished_key, hlen)` @crypto:40 @tls:35
    LWIP_E022B = 0x022B, // tls_send_finished(): Step 3: Get transcript hash up to this point. Trigger: `!ctx->transcript_hash || ctx->transcript_hash->digestlen != hlen || !transcript_hash_digest(ctx->transcript_hash, sec->transcript_hash)` @tls:60
    LWIP_E022C = 0x022C, // tls_send_finished(): Step 4: Compute verify_data = HMAC(finished_key, transcript_hash). Trigger: `!tls_hmac_context_init(&sec->hmac_ctx, hash_alg, sec->finished_key, hlen)` @crypto:40 @tls:35
    LWIP_E022D = 0x022D, // tls_send_finished(): Client Finished completes transcript needed for resumption master secret. Trigger: `!transcript_hash_full || !transcript_hash_digest(ctx->transcript_hash, transcript_hash_full) || !tls_derive_secret(hash_alg, ctx->keys.master_secret, hlen, , 1…` @tls:60
    LWIP_E022E = 0x022E, // tls_send_empty_certificate(): fails and returns false. Trigger: `!ctx || !out || !written` @api:75 @cert:20
    LWIP_E022F = 0x022F, // tls_send_empty_certificate(): fails and returns false. Trigger: `!ctx->client_certificate_requested || ctx->state != TLS_STATE_SERVER_FINISHED_RECEIVED` @cert:65 @logic:45
    LWIP_E0230 = 0x0230, // tls_send_empty_certificate(): fails and returns false. Trigger: `out_len < sizeof(empty_certificate)` @cert:65
    LWIP_E0231 = 0x0231, // tls_recv_finished(): fails and returns false. Trigger: `!ctx || !data || data_len < 4` @api:75 @tls:20
    LWIP_E0232 = 0x0232, // tls_recv_finished(): fails and returns false. Trigger: `(hash_alg != TLS_HASH_SHA256 && hash_alg != TLS_HASH_SHA384) || (hlen != TLS_SHA256_DIGEST_LEN && hlen != TLS_SHA384_DIGEST_LEN)` @peer:60 @tls:60
    LWIP_E0233 = 0x0233, // tls_recv_finished(): fails and returns false. Trigger: `ctx->state != required_state` @tls:60 @logic:45
    LWIP_E0234 = 0x0234, // tls_recv_finished(): fails and returns false. Trigger: `!sec` @memory:85 @tls:20
    LWIP_E0235 = 0x0235, // tls_recv_finished(): fails and returns false. Trigger: `offset == 0 || msg_len != hlen || offset + hlen != data_len` @peer:60 @tls:60
    LWIP_E0236 = 0x0236, // tls_recv_finished(): Derive finished_key. Trigger: `!tls_hkdf_expand_label(hash_alg, traffic_secret, hlen, , 8, NULL, 0, sec->finished_key, hlen)` @crypto:40 @tls:35
    LWIP_E0237 = 0x0237, // tls_recv_finished(): Get transcript hash (before this Finished message). Trigger: `!ctx->transcript_hash || ctx->transcript_hash->digestlen != hlen || !transcript_hash_digest(ctx->transcript_hash, sec->transcript_hash)` @peer:60 @tls:60
    LWIP_E0238 = 0x0238, // tls_recv_finished(): Compute expected verify_data. Trigger: `!tls_hmac_context_init(&sec->hmac_ctx, hash_alg, sec->finished_key, hlen)` @crypto:40 @tls:35
    LWIP_E0239 = 0x0239, // tls_recv_finished(): fails. Trigger: `diff != 0` @peer:60 @tls:60
    LWIP_E023A = 0x023A, // tls_server_recv_client_hello(): fails and returns false. Trigger: `!ctx || !msg || !out || !written || (ctx->state != TLS_STATE_INIT && ctx->state != TLS_STATE_HRR_RECEIVED) || !ctx->transcript_hash || ctx->ecdhe_job != 0` @tls:60 @logic:45
    LWIP_E023B = 0x023B, // tls_server_recv_client_hello(): fails. @tls:60
    LWIP_E023C = 0x023C, // tls_send_client_certificate(): fails and returns false. Trigger: `!ctx || !out || !written` @api:75 @cert:20
    LWIP_E023D = 0x023D, // tls_send_client_certificate(): fails and returns false. Trigger: `!ctx->transcript_hash || !ctx->client_certificate_requested || ctx->state != TLS_STATE_SERVER_FINISHED_RECEIVED` @cert:65 @logic:45
    LWIP_E023E = 0x023E, // tls_send_client_certificate(): fails and returns false. Trigger: `!ctx->client_chain[ci]` @cert:65
    LWIP_E023F = 0x023F, // tls_send_client_certificate(): fails and returns false. Trigger: `der_len > 0xfffffau || list_len > 0xffffffu - der_len - 5u` @cert:65
    LWIP_E0240 = 0x0240, // tls_send_client_certificate(): fails and returns false. Trigger: `cert_body > 0xffffffu || out_len < cert_msg` @cert:65
    LWIP_E0241 = 0x0241, // tls_send_client_certificate(): fails and returns false. Trigger: `!ctx->transcript_hash || (ctx->hash_len != TLS_SHA256_DIGEST_LEN && ctx->hash_len != TLS_SHA384_DIGEST_LEN)` @cert:65
    LWIP_E0242 = 0x0242, // tls_send_client_certificate(): fails and returns false. Trigger: `!sv` @memory:85 @cert:20
    LWIP_E0243 = 0x0243, // tls_send_client_certificate(): fails and returns false. Trigger: `sign_rc != TLS_KEY_OP_OK || raw_sig_len != sizeof(sv->raw_sig)` @cert:65
    LWIP_E0244 = 0x0244, // tls_send_client_certificate(): fails and returns false. Trigger: `out_len < cv_msg` @api:75 @cert:20
    LWIP_E0245 = 0x0245, // tls_server_send_flight(): fails and returns false. Trigger: `!ctx || !out || !written` @api:75 @tls:20
    LWIP_E0246 = 0x0246, // tls_server_send_flight(): fails and returns false. Trigger: `!ctx->transcript_hash || ctx->state != TLS_STATE_HANDSHAKE_KEYS_DERIVED` @tls:60 @logic:45
    LWIP_E0247 = 0x0247, // tls_server_send_flight(): fails and returns false. Trigger: `out_cap < ee_len` @api:75 @tls:20
    LWIP_E0248 = 0x0248, // tls_server_send_flight(): fails and returns false. Trigger: `!ctx->server_chain[ci]` @tls:60
    LWIP_E0249 = 0x0249, // tls_server_send_flight(): certificate_list is a 24-bit length; refuse rather than silently truncate the field. Trigger: `der_len > 0xfffffau || list_len > 0xffffffu - der_len - 5u` @tls:60
    LWIP_E024A = 0x024A, // tls_server_send_flight(): fails and returns false. Trigger: `cert_body > 0xffffffu || out_cap < cert_msg` @tls:60
    LWIP_E024B = 0x024B, // tls_server_send_flight(): fails and returns false. Trigger: `!ctx->transcript_hash || (ctx->hash_len != TLS_SHA256_DIGEST_LEN && ctx->hash_len != TLS_SHA384_DIGEST_LEN)` @tls:60
    LWIP_E024C = 0x024C, // tls_server_send_flight(): fails and returns false. Trigger: `!sv` @memory:85 @tls:20
    LWIP_E024D = 0x024D, // tls_server_send_flight(): fails and returns false. Trigger: `sign_rc != TLS_KEY_OP_OK || raw_sig_len != sizeof(sv->raw_sig)` @tls:60
    LWIP_E024E = 0x024E, // tls_server_send_flight(): fails and returns false. Trigger: `out_cap < cv_msg` @api:75 @tls:20
    LWIP_E024F = 0x024F, // tls_server_recv_finished(): fails and returns false. Trigger: `!ctx || ctx->state != TLS_STATE_SERVER_FINISHED_RECEIVED` @tls:60 @logic:45
    LWIP_E0250 = 0x0250, // tls_recv_new_session_ticket(): fails and returns false. Trigger: `!ctx || !data || data_len < 4` @api:75 @tls:20
    LWIP_E0251 = 0x0251, // tls_recv_new_session_ticket(): fails and returns false. Trigger: `offset == 0` @peer:60 @tls:60
    LWIP_E0252 = 0x0252, // tls_recv_new_session_ticket(): fails and returns false. Trigger: `offset + 8 > msg_end` @peer:60 @tls:60
    LWIP_E0253 = 0x0253, // tls_recv_new_session_ticket(): fails and returns false. Trigger: `offset + 1 > msg_end` @peer:60 @tls:60
    LWIP_E0254 = 0x0254, // tls_recv_new_session_ticket(): fails and returns false. Trigger: `offset + nonce_len > msg_end` @peer:60 @tls:60
    LWIP_E0255 = 0x0255, // tls_recv_new_session_ticket(): fails and returns false. Trigger: `offset + 2 > msg_end` @peer:60 @tls:60
    LWIP_E0256 = 0x0256, // tls_recv_new_session_ticket(): fails and returns false. Trigger: `offset + ticket_len > msg_end` @peer:60 @tls:60
    LWIP_E0257 = 0x0257, // tls_recv_new_session_ticket(): fails and returns false. Trigger: `offset + 2 > msg_end` @peer:60 @tls:60
    LWIP_E0258 = 0x0258, // tls_recv_new_session_ticket(): fails and returns false. Trigger: `offset + ext_len != msg_end` @peer:60 @tls:60
    LWIP_E0259 = 0x0259, // tls_recv_key_update(): fails and returns false. Trigger: `!ctx || !data || data_len < 5` @api:75 @tls:20
    LWIP_E025A = 0x025A, // tls_recv_key_update(): fails and returns false. Trigger: `offset == 0 || msg_len != 1` @peer:60 @tls:60
    LWIP_E025B = 0x025B, // tls_recv_key_update(): fails and returns false. Trigger: `request_update != 0 && request_update != 1` @peer:60 @tls:60
    LWIP_E025C = 0x025C, // tls_recv_key_update(): fails and returns false. Trigger: `(hash_alg != TLS_HASH_SHA256 && hash_alg != TLS_HASH_SHA384) || (hlen != TLS_SHA256_DIGEST_LEN && hlen != TLS_SHA384_DIGEST_LEN) || (klen != 16 && klen != 32)` @peer:60 @tls:60
    LWIP_E025D = 0x025D, // tls_recv_key_update(): fails and returns false. Trigger: `!k` @memory:85 @tls:20
    LWIP_E025E = 0x025E, // tls_recv_key_update(): fails and returns false. Trigger: `!tls_hkdf_expand_label(hash_alg, ctx->keys.server_application_traffic_secret, hlen, , 11, NULL, 0, k->next_secret, hlen)` @crypto:40 @tls:35
    LWIP_E025F = 0x025F, // tls_recv_key_update(): fails and returns false. Trigger: `!tls_hkdf_expand_label(hash_alg, k->next_secret, hlen, , 3, NULL, 0, k->next_key, klen)` @crypto:40 @tls:35
    LWIP_E0260 = 0x0260, // tls_recv_key_update(): fails and returns false. Trigger: `!tls_hkdf_expand_label(hash_alg, k->next_secret, hlen, , 2, NULL, 0, k->next_iv, 12)` @crypto:40 @tls:35
    LWIP_E0261 = 0x0261, // tls_recv_key_update(): statistic only; long sessions are fine. Trigger: `request_update == 1 && !tls_send_key_update_record(ctx)` @tls:60
    LWIP_E0262 = 0x0262, // tls_ratchet_client_application_keys(): fails and returns false. Trigger: `(hash_alg != TLS_HASH_SHA256 && hash_alg != TLS_HASH_SHA384) || (hlen != TLS_SHA256_DIGEST_LEN && hlen != TLS_SHA384_DIGEST_LEN) || (klen != 16 && klen != 32)` @tls:60
    LWIP_E0263 = 0x0263, // tls_send_alert(): fails and returns false. Trigger: `!ctx` @api:75 @tls:20
    LWIP_E0264 = 0x0264, // tls_send_alert(): fails. Trigger: `level == TLS_ALERT_LEVEL_FATAL` @tls:60
    LWIP_E0265 = 0x0265, // tls_send_alert(): fails. Trigger: `level == TLS_ALERT_LEVEL_FATAL` @tls:60
    LWIP_E0266 = 0x0266, // tls_send_close_notify(): fails and returns false. Trigger: `!ctx` @api:75 @tls:20
    LWIP_E0267 = 0x0267, // tls_settle_ecdhe(): fails. Trigger: `!ok` @tls:60
    LWIP_E0268 = 0x0268, // tls_offload_settle(): fails. Trigger: `!ok` @tls:60
    LWIP_E0269 = 0x0269, // tls_hash_context_init(): fails and returns false. Trigger: `ctx == NULL` @api:75 @crypto:20
    LWIP_E026A = 0x026A, // tls_hash_context_init(): case TLS_SHA256_HW: ctx->digestlen = TLS_SHA256_DIGEST_LEN; ctx->init = tls_sha256hw_init; ctx->update = tls_sha256hw_update; ctx->digest =… Trigger: `default` @crypto:60
    LWIP_E026B = 0x026B, // tls_hash_update(): fails and returns. Trigger: `ctx == NULL || ctx->update == NULL || (data == NULL && len != 0)` @api:75 @crypto:20
    LWIP_E026C = 0x026C, // tls_hash_digest(): fails and returns. Trigger: `ctx == NULL || ctx->digest == NULL || digest == NULL` @api:75 @crypto:20
    LWIP_E026D = 0x026D, // tls_hash_context_alloc(): fails and returns NULL. Trigger: `!ctx` @memory:85 @crypto:20
    LWIP_E026E = 0x026E, // tls_mgf1(): fails and returns false. Trigger: `outbuf == NULL || (data == NULL && datalen != 0)` @api:75 @crypto:20
    LWIP_E026F = 0x026F, // tls_mgf1(): fails and returns false. Trigger: `!t` @memory:85 @crypto:20
    LWIP_E0270 = 0x0270, // tls_hkdf_extract(): fails and returns false. Trigger: `hash_len == 0 || !prk` @crypto:60
    LWIP_E0271 = 0x0271, // tls_hkdf_extract(): fails and returns false. Trigger: `!salt && salt_len != 0` @api:75 @crypto:20
    LWIP_E0272 = 0x0272, // tls_hkdf_extract(): ikm_len kept as-is so the caller controls how many zero bytes, but it can never exceed the zero buffer (HashLen at most). Trigger: `ikm_len > sizeof(zeros)` @crypto:60
    LWIP_E0273 = 0x0273, // tls_hkdf_extract(): fails and returns false. Trigger: `!ctx` @memory:85 @crypto:20
    LWIP_E0274 = 0x0274, // tls_hkdf_extract(): PRK = HMAC(salt, ikm). Trigger: `!tls_hmac_context_init(ctx, hash_algorithm, salt, salt_len)` @crypto:40
    LWIP_E0275 = 0x0275, // tls_hkdf_expand(): fails and returns false. Trigger: `hash_len == 0 || !prk || !okm` @crypto:60
    LWIP_E0276 = 0x0276, // tls_hkdf_expand(): fails and returns false. Trigger: `prk_len < hash_len` @api:75 @crypto:20
    LWIP_E0277 = 0x0277, // tls_hkdf_expand(): fails and returns false. Trigger: `!info && info_len > 0` @api:75 @crypto:20
    LWIP_E0278 = 0x0278, // tls_hkdf_expand(): Check okm_len is not too large: max = 255 * HashLen. Trigger: `okm_len > 255 * hash_len` @crypto:60
    LWIP_E0279 = 0x0279, // tls_hkdf_expand(): fails and returns false. Trigger: `!t` @memory:85 @crypto:20
    LWIP_E027A = 0x027A, // tls_hkdf_expand(): Initialize HMAC with PRK. Trigger: `!tls_hmac_context_init(&t->ctx, hash_algorithm, prk, prk_len)` @crypto:40
    LWIP_E027B = 0x027B, // tls_hkdf_expand_label(): fails and returns false. Trigger: `!secret || !label || !out || (!context && context_len != 0)` @api:75 @crypto:20
    LWIP_E027C = 0x027C, // tls_hkdf_expand_label(): Check label length: "tls13 " + label must be 7..255 bytes. Trigger: `full_label_len < 7 || full_label_len > 255` @crypto:60
    LWIP_E027D = 0x027D, // tls_hkdf_expand_label(): Check context length: 0..255 bytes. Trigger: `context_len > 255` @api:75 @crypto:20
    LWIP_E027E = 0x027E, // tls_hkdf_expand_label(): fails and returns false. Trigger: `needed > TLS_HKDF_LABEL_SCRATCH_SIZE` @crypto:60
    LWIP_E027F = 0x027F, // tls_derive_secret(): fails and returns false. Trigger: `hash_len == 0 || transcript_hash_len != hash_len` @crypto:60
    LWIP_E0280 = 0x0280, // tls_hmac_context_init(): fails and returns false. Trigger: `ctx == NULL` @api:75 @crypto:20
    LWIP_E0281 = 0x0281, // tls_hmac_context_init(): fails and returns false. Trigger: `key == NULL && keylen != 0` @api:75 @crypto:20
    LWIP_E0282 = 0x0282, // tls_hmac_context_init(): fails. Trigger: `ctx->blocklen == 0 || ctx->blocklen > TLS_HASH_MAX_BLOCK_LEN || ctx->digestlen == 0 || ctx->digestlen > TLS_HASH_MAX_DIGEST_LEN || ctx->digestlen > ctx->blockl…` @crypto:60
    LWIP_E0283 = 0x0283, // tls_hmac_context_init(): fails. Trigger: `!sum` @memory:85 @crypto:20
    LWIP_E0284 = 0x0284, // tls_hmac_context_init(): fails. Trigger: `!tls_hash_context_init(&ctx->_inner, algorithm)` @crypto:40
    LWIP_E0285 = 0x0285, // tls_pbkdf2(): fails and returns false. Trigger: `(password==NULL) || (key==NULL) || (salt==NULL) || (passlen==0) || (saltlen==0) || (keylen==0) || (rounds==0) || (rounds > TLS_PBKDF2_MAX_ROUNDS)` @api:75 @crypto:20
    LWIP_E0286 = 0x0286, // tls_pbkdf2(): fails and returns false. Trigger: `!t` @memory:85 @crypto:20
    LWIP_E0287 = 0x0287, // tls_pbkdf2(): algorithm (SHA-256, SHA-384, or SHA-512). Trigger: `!tls_hmac_context_init(&t->initial, algorithm, (const uint8_t *)password, passlen)` @crypto:40
    LWIP_E0288 = 0x0288, // tls_pbkdf2(): fails and returns false. Trigger: `hash_len == 0 || hash_len > HASH_BLOCK_OUT_MAX` @crypto:55
    LWIP_E0289 = 0x0289, // aes_init_impl(): fails and returns false. Trigger: `ctx == NULL` @api:75 @crypto:20
    LWIP_E028A = 0x028A, // aes_init_impl(): fails and returns false. Trigger: `(key == NULL) || (iv == NULL)` @api:75 @crypto:20
    LWIP_E028B = 0x028B, // aes_init_impl(): SP 800-38D 5.2.1.1: a GCM IV is at least 1 bit; an empty one would make J0 depend on the key alone. Trigger: `((mode != TLS_AES_GCM) && (mode != TLS_AES_CBC)) || (mode != TLS_AES_GCM && iv_len > AES_BLOCK_SIZE) || (mode == TLS_AES_GCM && iv_len == 0)` @crypto:60
    LWIP_E028C = 0x028C, // aes_init_impl(): fails and returns false. Trigger: `default` @crypto:60
    LWIP_E028D = 0x028D, // aes_init_impl(): fails. Trigger: `default` @crypto:60
    LWIP_E028E = 0x028E, // aes_verify_impl(): fails. Trigger: `!tag_ok` @crypto:60
    LWIP_E028F = 0x028F, // tls_rng_log_health_failure(): Source recovery continues after this event. @crypto:40
    LWIP_E0290 = 0x0290, // tls_rng_request_q_push(): fails and returns false. Trigger: `node == NULL` @memory:85 @crypto:20
    LWIP_E0291 = 0x0291, // tls_rng_fail(): fails. @crypto:70
    LWIP_E0292 = 0x0292, // tls_drbg_entropy_gather_step(): fails and returns false. Trigger: `g_tls_entropy_reserve_len >= target_bytes` @crypto:70
    LWIP_E0293 = 0x0293, // tls_drbg_apply_entropy_reserve(): fails and returns false. Trigger: `g_tls_rng_state != TLS_RNG_DRBG_READY_192 || !g_tls_drbg.seeded || g_tls_entropy_reserve_len < TLS_HASH_DRBG_ENTROPY_BYTES` @crypto:70
    LWIP_E0294 = 0x0294, // tls_drbg_apply_entropy_reserve(): fails and returns ok. Trigger: `!ok` @crypto:70
    LWIP_E0295 = 0x0295, // tls_random_bytes_ex(): fails and aborts (goto fail). Trigger: `g_tls_rng_request_active || (g_tls_rng_request_q_head != NULL)` @crypto:70
    LWIP_E0296 = 0x0296, // tls_random_bytes_ex(): fails and aborts (goto fail). Trigger: `!tls_drbg_generate_bytes(&g_tls_drbg, out, take)` @crypto:40
    LWIP_E0297 = 0x0297, // tls_request_random_bytes(): fails and returns false. Trigger: `!tls_rng_request_q_push(out, len, cb, arg)` @crypto:40
    LWIP_E0298 = 0x0298, // tls_rsa_encode_oaep(): initial sanity checks. Trigger: `(modulus_len > RSA_MODULUS_MAX_SUPPORTED) || (modulus_len < RSA_MODULUS_MIN_SUPPORTED) || (inbuf == NULL) || (outbuf == NULL) || (in_len == 0)` @api:75 @crypto:20
    LWIP_E0299 = 0x0299, // tls_rsa_encrypt(): fails and returns false. Trigger: `(inbuf == NULL) || (key == NULL) || (key->modulus == NULL) || (key->exponent == NULL) || (outbuf == NULL) || (in_len == 0) || (key->mod_len > RSA_MODULUS_MAX_S…` @crypto:60
    LWIP_E029A = 0x029A, // tls_rsa_encrypt(): Decode exponent from big-endian bytes into a uint24_t (LE). Trigger: `key->exp_len == 0 || key->exp_len > 3` @crypto:60
    LWIP_E029B = 0x029B, // tls_rsa_encrypt(): fails and returns false. Trigger: `!tls_rsa_public_key_shape_ok(key)` @crypto:40
    LWIP_E029C = 0x029C, // tls_rsa_decrypt_signature(): fails and returns false. Trigger: `(signature == NULL) || (key == NULL) || (key->modulus == NULL) || (key->exponent == NULL) || (outbuf == NULL) || (signature_len == 0) || (signature_len != key-…` @crypto:60
    LWIP_E029D = 0x029D, // tls_rsa_decrypt_signature(): fails and returns false. Trigger: `!tls_rsa_public_key_shape_ok(key)` @crypto:40
    LWIP_E029E = 0x029E, // tls_rsa_decrypt_signature(): RFC 8017 §5.2.2 step 1: s must be in [0, n-1]. Trigger: `memcmp(signature, key->modulus, key->mod_len) >= 0` @crypto:60
    LWIP_E029F = 0x029F, // tls_rsa_pss_verify(): fails. Trigger: `!ok` @crypto:60
    LWIP_E02A0 = 0x02A0, // tls_truststore_init(): fails and returns TLS_STORE_HASH_FAIL. Trigger: `!t || !tls_hash_context_init(&t->hash_ctx, TLS_HASH_SHA256)` @cert:70
    LWIP_E02A1 = 0x02A1, // tls_truststore_init(): warns and returns TLS_STORE_NOT_FOUND. Trigger: `!ts_h` @cert:40
    LWIP_E02A2 = 0x02A2, // tls_truststore_init(): fails and returns TLS_STORE_SIZE_INVALID. Trigger: `truststore_size < TLS_TRUSTSTORE_HEADER_LEN` @cert:70
    LWIP_E02A3 = 0x02A3, // tls_truststore_init(): fails and returns TLS_STORE_VERSION_MISMATCH. Trigger: `header->version != TLS_TRUSTSTORE_VERSION` @cert:70
    LWIP_E02A4 = 0x02A4, // tls_truststore_init(): fails and returns TLS_STORE_SIG_INVALID. Trigger: `!tls_rsa_decrypt_signature(header->sig, TRUSTSTORE_SIG_LEN, d_sig, &trust_store_key)` @crypto:40 @cert:35
    LWIP_E02A5 = 0x02A5, // tls_truststore_init(): fails. Trigger: `verified && !tls_truststore_validate_layout(header, truststore_size, NULL, NULL, NULL, NULL)` @cert:70
    LWIP_E02A6 = 0x02A6, // tls_truststore_init(): fails. Trigger: `!truststore_entry_copy` @memory:85 @cert:20
    LWIP_E02A7 = 0x02A7, // tls_truststore_init(): warns. Trigger: `now != 0 && now > store_created && now - store_created > TLS_TRUSTSTORE_AGE_WARN_SECONDS` @cert:40
    LWIP_E02A8 = 0x02A8, // tls_truststore_init(): fails. Trigger: `tls_ctx.truststore.status != TLS_STORE_SIZE_INVALID && tls_ctx.truststore.status != TLS_STORE_HASH_FAIL` @cert:70
    LWIP_E02A9 = 0x02A9, // tls_truststore_open_db(): fails and returns false. Trigger: `!valid` @cert:70
    LWIP_E02AA = 0x02AA, // tls_truststore_open_db(): fails and returns false. Trigger: `indexes_len > payload_len` @cert:70
    LWIP_E02AB = 0x02AB, // tls_x509_parse_name_common_name(): fails and returns false. Trigger: `!name_tlv || !out` @api:75 @cert:20
    LWIP_E02AC = 0x02AC, // tls_x509_parse_name_common_name(): fails and returns false. Trigger: `name_tlv->tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE)` @cert:70 @peer:60
    LWIP_E02AD = 0x02AD, // tls_x509_parse_name_common_name(): fails and returns false. Trigger: `!tls_asn1_child_cursor(name_tlv, &rdn_cursor)` @peer:55 @cert:50
    LWIP_E02AE = 0x02AE, // tls_x509_parse_name_common_name(): Name ::= SEQUENCE OF RDN RDN ::= SET OF AttributeTypeAndValue Only CN (2.5.4.3) is returned. Trigger: `!tls_asn1_child_cursor(&rdn_set, &set_cursor)` @peer:55 @cert:50
    LWIP_E02AF = 0x02AF, // tls_x509_parse_name_common_name(): fails and returns false. Trigger: `!tls_asn1_child_cursor(&atv_seq, &atv_cursor) || !tls_asn1_next(&atv_cursor, &attr_oid) || !tls_asn1_next(&atv_cursor, &attr_value)` @peer:55 @cert:50
    LWIP_E02B0 = 0x02B0, // tls_x509_parse_algorithm_identifier(): fails and returns false. Trigger: `!alg_tlv || !alg_out` @api:75 @cert:20
    LWIP_E02B1 = 0x02B1, // tls_x509_parse_algorithm_identifier(): fails and returns false. Trigger: `alg_tlv->tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE)` @cert:70 @peer:60
    LWIP_E02B2 = 0x02B2, // tls_x509_parse_algorithm_identifier(): fails and returns false. Trigger: `!tls_asn1_child_cursor(alg_tlv, &c) || !tls_asn1_next(&c, &oid)` @peer:55 @cert:50
    LWIP_E02B3 = 0x02B3, // tls_x509_parse_algorithm_identifier(): fails and returns false. Trigger: `oid.tag != ASN1_OBJECTID` @cert:70 @peer:60
    LWIP_E02B4 = 0x02B4, // tls_x509_parse_algorithm_identifier(): fails and returns false. Trigger: `param.tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE)` @cert:70 @peer:60
    LWIP_E02B5 = 0x02B5, // tls_x509_parse_algorithm_identifier(): fails and returns false. Trigger: `param.tag != ASN1_OBJECTID && param.tag != ASN1_NULL` @cert:70 @peer:60
    LWIP_E02B6 = 0x02B6, // tls_x509_parse_algorithm_identifier(): fails and returns false. Trigger: `!param_optional` @api:75 @cert:20
    LWIP_E02B7 = 0x02B7, // tls_x509_san_matches(): fails and returns false. Trigger: `!ext_data || ext_len == 0` @api:75 @cert:20
    LWIP_E02B8 = 0x02B8, // tls_x509_san_matches(): fails and returns false. Trigger: `!tls_asn1_cursor_init(&ext_cursor, ext_data, ext_len)` @peer:55 @cert:50
    LWIP_E02B9 = 0x02B9, // tls_x509_san_matches(): fails and returns false. Trigger: `!tls_asn1_child_cursor(&ext_tlv, &ext_list_cursor)` @peer:55 @cert:50
    LWIP_E02BA = 0x02BA, // tls_x509_san_matches(): fails and returns false. Trigger: `else branch` @cert:85
    LWIP_E02BB = 0x02BB, // tls_x509_san_matches(): fails and returns false. Trigger: `!tls_asn1_cursor_init(&san_cursor, value_tlv.value, value_tlv.len)` @peer:55 @cert:50
    LWIP_E02BC = 0x02BC, // tls_x509_san_matches(): fails and returns false. Trigger: `!tls_asn1_next(&san_cursor, &san_seq) || san_seq.tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE) || san_cursor.cur != san_cursor.end` @cert:85
    LWIP_E02BD = 0x02BD, // tls_x509_san_matches(): fails and returns false. Trigger: `!tls_asn1_child_cursor(&san_seq, &san_seq_cursor)` @peer:55 @cert:50
    LWIP_E02BE = 0x02BE, // tls_x509_san_matches(): fails and returns false. Trigger: `!tls_asn1_next(&san_cursor, &san_item)` @peer:55 @cert:50
    LWIP_E02BF = 0x02BF, // tls_x509_san_matches(): fails and returns false. Trigger: `san_item.tag == 0x87 && san_item.len != 4 && san_item.len != 16` @cert:85
    LWIP_E02C0 = 0x02C0, // tls_x509_san_matches(): fails and returns false. @cert:85
    LWIP_E02C1 = 0x02C1, // tls_x509_hostname_matches(): fails and returns false. Trigger: `!hostname` @api:75 @cert:20
    LWIP_E02C2 = 0x02C2, // tls_x509_hostname_matches(): fails and returns false. Trigger: `hostname_len == 0` @cert:85
    LWIP_E02C3 = 0x02C3, // tls_x509_hostname_matches(): Malformed IP-literal syntax (e.g. Trigger: `ip_len < 0` @cert:85
    LWIP_E02C4 = 0x02C4, // tls_x509_hostname_matches(): fails and returns false. @cert:85
    LWIP_E02C5 = 0x02C5, // tls_x509_digit_pair(): fails and returns false. Trigger: `p[0] < || p[0] > || p[1] < || p[1] >` @cert:70 @peer:60
    LWIP_E02C6 = 0x02C6, // tls_x509_time_to_unix(): fails and returns false. Trigger: `!data || len == 0 || !out_secs` @api:75 @cert:20
    LWIP_E02C7 = 0x02C7, // tls_x509_time_to_unix(): fails and returns false. Trigger: `len != 13 || v[12] !=` @cert:80 @peer:60
    LWIP_E02C8 = 0x02C8, // tls_x509_time_to_unix(): fails and returns false. Trigger: `!tls_x509_digit_pair(v, &yy) || !tls_x509_digit_pair(v + 2, &month) || !tls_x509_digit_pair(v + 4, &day) || !tls_x509_digit_pair(v + 6, &hour) || !tls_x509_dig…` @cert:80
    LWIP_E02C9 = 0x02C9, // tls_x509_time_to_unix(): fails and returns false. Trigger: `len != 15 || v[14] !=` @cert:80 @peer:60
    LWIP_E02CA = 0x02CA, // tls_x509_time_to_unix(): fails and returns false. Trigger: `!tls_x509_digit_pair(v, &y_hi) || !tls_x509_digit_pair(v + 2, &y_lo) || !tls_x509_digit_pair(v + 4, &month) || !tls_x509_digit_pair(v + 6, &day) || !tls_x509_d…` @cert:80
    LWIP_E02CB = 0x02CB, // tls_x509_time_to_unix(): fails and returns false. Trigger: `else branch` @cert:80
    LWIP_E02CC = 0x02CC, // tls_x509_time_to_unix(): fails and returns false. Trigger: `month < 1 || month > 12 || day < 1 || !tls_x509_day_valid(year, month, day) || hour > 23 || minute > 59 || second > 60` @cert:80 @peer:60
    LWIP_E02CD = 0x02CD, // tls_x509_time_in_validity(): fails and returns false. Trigger: `!cert` @api:75 @cert:20
    LWIP_E02CE = 0x02CE, // tls_x509_time_in_validity(): fails and returns false. Trigger: `!tls_x509_time_to_unix(cert->not_before, cert->not_before_len, cert->not_before_tag, &not_before_secs) || !tls_x509_time_to_unix(cert->not_after, cert->not_aft…` @cert:80
    LWIP_E02CF = 0x02CF, // tls_x509_time_in_validity(): Malformed/inverted validity window. Trigger: `not_before_secs > not_after_secs` @cert:80
    LWIP_E02D0 = 0x02D0, // tls_x509_time_in_validity(): Trace each Unix timestamp as high/low 16-bit words: the compact traceback extra field cannot hold a complete timestamp. Trigger: `now_secs < not_before_secs || now_secs > not_after_secs` @api:75 @cert:20
    LWIP_E02D1 = 0x02D1, // tls_x509_time_in_validity(): fails. Trigger: `now_secs < not_before_secs || now_secs > not_after_secs` @api:75 @cert:20
    LWIP_E02D2 = 0x02D2, // tls_x509_time_in_validity(): fails. Trigger: `now_secs < not_before_secs || now_secs > not_after_secs` @api:75 @cert:20
    LWIP_E02D3 = 0x02D3, // tls_x509_time_in_validity(): fails. Trigger: `now_secs < not_before_secs || now_secs > not_after_secs` @api:75 @cert:20
    LWIP_E02D4 = 0x02D4, // tls_x509_time_in_validity(): fails. Trigger: `now_secs < not_before_secs || now_secs > not_after_secs` @api:75 @cert:20
    LWIP_E02D5 = 0x02D5, // tls_x509_time_in_validity(): fails and returns false. Trigger: `now_secs < not_before_secs || now_secs > not_after_secs` @api:75 @cert:20
    LWIP_E02D6 = 0x02D6, // tls_x509_has_required_ca_constraints(): fails and returns false. Trigger: `!tls_x509_parse_certificate(cert_der, cert_len, parsed)` @peer:55 @cert:50
    LWIP_E02D7 = 0x02D7, // tls_x509_has_required_ca_constraints(): fails and returns false. Trigger: `!extensions || extensions_len == 0` @cert:70
    LWIP_E02D8 = 0x02D8, // tls_x509_parse_certificate(): fails and returns false. Trigger: `!cert_der || cert_len == 0 || !out` @api:75 @cert:20
    LWIP_E02D9 = 0x02D9, // tls_x509_parse_certificate(): all pointers reference cert_der. Trigger: `!tls_asn1_cursor_init(&top_cursor, cert_der, cert_len) || !tls_asn1_next(&top_cursor, &cert_seq)` @peer:55 @cert:50
    LWIP_E02DA = 0x02DA, // tls_x509_parse_certificate(): fails and returns false. Trigger: `cert_seq.tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE) || top_cursor.cur != top_cursor.end` @cert:70 @peer:60
    LWIP_E02DB = 0x02DB, // tls_x509_parse_certificate(): fails and returns false. Trigger: `!tls_asn1_child_cursor(&cert_seq, &cert_items) || !tls_asn1_next(&cert_items, &tbs) || !tls_asn1_next(&cert_items, &ca_sig_alg) || !tls_asn1_next(&cert_items,…` @cert:70 @peer:60
    LWIP_E02DC = 0x02DC, // tls_x509_parse_certificate(): fails and returns false. Trigger: `tbs.tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE)` @cert:70 @peer:60
    LWIP_E02DD = 0x02DD, // tls_x509_parse_certificate(): fails and returns false. Trigger: `ca_sig_val.tag != ASN1_BITSTRING || ca_sig_val.len < 1 || ca_sig_val.value[0] != 0` @cert:70 @peer:60
    LWIP_E02DE = 0x02DE, // tls_x509_parse_certificate(): fails and returns false. Trigger: `!tls_asn1_child_cursor(&tbs, &tbs_cursor)` @peer:55 @cert:50
    LWIP_E02DF = 0x02DF, // tls_x509_parse_certificate(): fails and returns false. Trigger: `!tls_asn1_next(&tbs_cursor, &item)` @peer:55 @cert:50
    LWIP_E02E0 = 0x02E0, // tls_x509_parse_certificate(): version is [0] EXPLICIT and optional in v1 certs. Trigger: `!tls_asn1_child_cursor(&item, &version_cursor) || !tls_asn1_next(&version_cursor, &version) || version_cursor.cur != version_cursor.end || version.tag != ASN1_…` @cert:70 @peer:60
    LWIP_E02E1 = 0x02E1, // tls_x509_parse_certificate(): version is [0] EXPLICIT and optional in v1 certs. Trigger: `!tls_asn1_next(&tbs_cursor, &item)` @peer:55 @cert:50
    LWIP_E02E2 = 0x02E2, // tls_x509_parse_certificate(): fails and returns false. Trigger: `!tls_x509_positive_integer_der(&item, false) || item.len > 20` @cert:70 @peer:60
    LWIP_E02E3 = 0x02E3, // tls_x509_parse_certificate(): fails and returns false. Trigger: `!tls_asn1_next(&tbs_cursor, &sig_alg) || !tls_asn1_next(&tbs_cursor, &issuer) || !tls_asn1_next(&tbs_cursor, &validity) || !tls_asn1_next(&tbs_cursor, &subject…` @cert:70 @peer:60
    LWIP_E02E4 = 0x02E4, // tls_x509_parse_certificate(): fails and returns false. Trigger: `issuer.tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE) || issuer.len == 0` @cert:70 @peer:60
    LWIP_E02E5 = 0x02E5, // tls_x509_parse_certificate(): fails and returns false. Trigger: `!tls_x509_parse_name_common_name(&issuer, &scratch_cn)` @peer:55 @cert:50
    LWIP_E02E6 = 0x02E6, // tls_x509_parse_certificate(): fails and returns false. Trigger: `validity.tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE)` @cert:70 @peer:60
    LWIP_E02E7 = 0x02E7, // tls_x509_parse_certificate(): fails and returns false. Trigger: `!tls_asn1_child_cursor(&validity, &validity_cursor) || !tls_asn1_next(&validity_cursor, &not_before) || !tls_asn1_next(&validity_cursor, &not_after) || validit…` @cert:70 @peer:60
    LWIP_E02E8 = 0x02E8, // tls_x509_parse_certificate(): fails and returns false. Trigger: `nb_tag != ASN1_UTCTIME && nb_tag != ASN1_GENERALIZEDTIME` @cert:70 @peer:60
    LWIP_E02E9 = 0x02E9, // tls_x509_parse_certificate(): fails and returns false. Trigger: `na_tag != ASN1_UTCTIME && na_tag != ASN1_GENERALIZEDTIME` @cert:70 @peer:60
    LWIP_E02EA = 0x02EA, // tls_x509_parse_certificate(): fails and returns false. Trigger: `!tls_x509_parse_name_common_name(&subject, &scratch_cn)` @peer:55 @cert:50
    LWIP_E02EB = 0x02EB, // tls_x509_parse_certificate(): SPKI — parse into pubkey. Trigger: `spki.tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE)` @cert:70 @peer:60
    LWIP_E02EC = 0x02EC, // tls_x509_parse_certificate(): fails and returns false. Trigger: `!tls_asn1_child_cursor(&spki, &spki_cursor) || !tls_asn1_next(&spki_cursor, &spki_alg) || !tls_asn1_next(&spki_cursor, &spki_bits) || spki_cursor.cur != spki_c…` @cert:70 @peer:60
    LWIP_E02ED = 0x02ED, // tls_x509_parse_certificate(): fails and returns false. Trigger: `!tls_x509_parse_algorithm_identifier(&spki_alg, &scratch_alg, &scratch_param, true)` @peer:55 @cert:50
    LWIP_E02EE = 0x02EE, // tls_x509_parse_certificate(): fails and returns false. Trigger: `spki_bits.tag != ASN1_BITSTRING` @cert:70 @peer:60
    LWIP_E02EF = 0x02EF, // tls_x509_parse_certificate(): fails and returns false. Trigger: `!tls_x509_signature_algorithm(&spki_alg, &pss_scheme) || pss_scheme != TLS_ALG_RSA_PSS_RSAE_SHA256` @cert:70 @peer:60
    LWIP_E02F0 = 0x02F0, // tls_x509_parse_certificate(): BIT STRING payload: skip the leading unused-bits byte. Trigger: `spki_bits.len < 2 || spki_bits.value[0] != 0x00` @cert:70 @peer:60
    LWIP_E02F1 = 0x02F1, // tls_x509_parse_certificate(): fails and returns false. Trigger: `!tls_asn1_cursor_init(&rsa_c, spki_bits.value + 1, spki_bits.len - 1) || !tls_asn1_next(&rsa_c, &rsa_seq) || rsa_seq.tag != (ASN1_CONSTRUCTED | ASN1_SEQUENCE)…` @cert:70 @peer:60
    LWIP_E02F2 = 0x02F2, // tls_x509_parse_certificate(): fails and returns false. Trigger: `!tls_asn1_child_cursor(&rsa_seq, &rsa_body) || !tls_asn1_next(&rsa_body, &rsa_mod) || !tls_asn1_next(&rsa_body, &rsa_exp) || rsa_body.cur != rsa_body.end || !t…` @cert:70 @peer:60
    LWIP_E02F3 = 0x02F3, // tls_x509_parse_certificate(): EC public key: BIT STRING value after the unused-bits byte. Trigger: `spki_bits.len < 2 || spki_bits.value[0] != 0` @cert:70 @peer:60
    LWIP_E02F4 = 0x02F4, // tls_x509_parse_certificate(): fails and returns false. Trigger: `!tls_x509_parse_authority_key_id(out->extensions, out->extensions_len, &out->authority_key_id, &out->authority_key_id_len)` @peer:55 @cert:50
    LWIP_E02F5 = 0x02F5, // tls_x509_parse_certificate(): fails and returns false. Trigger: `!tls_x509_parse_algorithm_identifier(&ca_sig_alg, &scratch_alg, &scratch_param, true)` @peer:55 @cert:50
    LWIP_E02F6 = 0x02F6, // tls_x509_decode_pem_certificate(): fails and returns false. Trigger: `!pem_data || !der_out || !der_written || size == 0` @api:75 @cert:20
    LWIP_E02F7 = 0x02F7, // tls_x509_decode_pem_certificate(): fails and returns false. Trigger: `size < (sizeof(begin_banner) - 1) || memcmp(pem_data, begin_banner, sizeof(begin_banner) - 1) != 0` @cert:70 @peer:60
    LWIP_E02F8 = 0x02F8, // tls_x509_decode_pem_certificate(): fails and returns false. Trigger: `!p` @cert:70
    LWIP_E02F9 = 0x02F9, // tls_x509_decode_pem_certificate(): fails and returns false. Trigger: `b64_count >= der_out_len` @cert:70 @peer:60
    LWIP_E02FA = 0x02FA, // tls_x509_decode_pem_certificate(): Normalize PEM body into a contiguous base64 buffer in der_out, then decode in place (safe because decoded output is smaller). Trigger: `(*p != ) && (*p != ) && (*p != ) && (*p != )` @cert:70 @peer:60
    LWIP_E02FB = 0x02FB, // tls_x509_decode_pem_certificate(): fails and returns false. Trigger: `p >= end || b64_count == 0 || (b64_count & 3) != 0` @cert:70 @peer:60
    LWIP_E02FC = 0x02FC, // tls_x509_decode_pem_certificate(): fails and returns false. Trigger: `i == 0 || i > der_out_len` @cert:70 @peer:60
    LWIP_E02FD = 0x02FD, // tls_x509_import_certificate(): fails and returns NULL. Trigger: `!pem_data || size == 0` @api:75 @cert:20
    LWIP_E02FE = 0x02FE, // tls_x509_import_certificate(): fails and returns NULL. Trigger: `!obj` @memory:85 @cert:20
    LWIP_E02FF = 0x02FF, // tls_x509_import_certificate(): fails. Trigger: `!tls_x509_decode_pem_certificate(pem_data, size, obj->der, der_cap, &der_len)` @peer:55 @cert:50
    LWIP_E0300 = 0x0300, // tls_x509_import_certificate(): Parse into the object itself. Trigger: `!tls_x509_parse_certificate(obj->der, der_len, obj)` @peer:55 @cert:50
    LWIP_E0301 = 0x0301, // x509_sha256_identifier(): fails and returns false. Trigger: `identifier->tag != 0x30 || !tls_asn1_child_cursor(identifier, &c) || !tls_asn1_next(&c, &oid) || oid.tag != ASN1_OBJECTID || oid.len != sizeof(sha256) || memcm…` @cert:70
    LWIP_E0302 = 0x0302, // x509_sha256_identifier(): fails and returns false. Trigger: `c.cur != c.end && (!tls_asn1_next(&c, &param) || param.tag != ASN1_NULL || param.len)` @cert:70
    LWIP_E0303 = 0x0303, // tls_x509_signature_algorithm(): fails and returns false. Trigger: `!alg` @api:75 @cert:20
    LWIP_E0304 = 0x0304, // tls_x509_signature_algorithm(): fails and returns false. Trigger: `!identifier || identifier->tag != 0x30 || !tls_asn1_child_cursor(identifier, &c) || !tls_asn1_next(&c, &oid) || oid.tag != ASN1_OBJECTID` @cert:70
    LWIP_E0305 = 0x0305, // tls_x509_signature_algorithm(): rsaEncryption identifies a key, never a certificate signature. Trigger: `oid.len == sizeof(oid_rsa_encryption) && !memcmp(oid.value, oid_rsa_encryption, oid.len)` @cert:70
    LWIP_E0306 = 0x0306, // tls_x509_signature_algorithm(): RFC 4055 defaults are SHA-1/MGF1-SHA-1/saltLen=20. Trigger: `!tls_asn1_next(&c, &param) || param.tag != 0x30 || c.cur != c.end` @cert:70
    LWIP_E0307 = 0x0307, // tls_x509_signature_algorithm(): fails and returns false. Trigger: `!tls_asn1_child_cursor(&param, &params)` @peer:55 @cert:50
    LWIP_E0308 = 0x0308, // tls_x509_signature_algorithm(): fails and returns false. Trigger: `!tls_asn1_next(&params, &field) || field.tag < 0xa0 || field.tag > 0xa3 || (seen && field.tag <= previous) || !tls_asn1_child_cursor(&field, &explicit_value) |…` @cert:70
    LWIP_E0309 = 0x0309, // tls_x509_signature_algorithm(): fails and returns false. Trigger: `!x509_sha256_identifier(&value)` @cert:45
    LWIP_E030A = 0x030A, // tls_x509_signature_algorithm(): fails and returns false. Trigger: `value.tag != 0x30 || !tls_asn1_child_cursor(&value, &mask) || !tls_asn1_next(&mask, &mask_oid) || mask_oid.tag != ASN1_OBJECTID || mask_oid.len != sizeof(mgf1)…` @cert:70
    LWIP_E030B = 0x030B, // tls_x509_signature_algorithm(): fails and returns false. Trigger: `value.tag != ASN1_INTEGER || value.len != 1 || value.value[0] != (field.tag == 0xa2 ? 32 : 1)` @cert:70
    LWIP_E030C = 0x030C, // tls_x509_signature_algorithm(): fails and returns false. Trigger: `(seen & 7) != 7` @cert:70
    LWIP_E030D = 0x030D, // tls_x509_signature_algorithm(): fails and returns false. Trigger: `!tls_asn1_next(&c, &param) || (scheme == TLS_ALG_RSA_PKCS1_SHA256 && (param.tag != ASN1_NULL || param.len)) || scheme == TLS_ALG_ECDSA_SECP256R1_SHA256 || sche…` @cert:70
    LWIP_E030E = 0x030E, // tls_x509_signature_algorithm(): fails and returns false. Trigger: `c.cur != c.end` @cert:70
    /* error-ids:end */
} lwip_error_id_t;

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
    uint16_t eid;    /* lwip_error_id_t for WARN / ERROR / ERROR_MSG, else 0 */
    union
    {
        const char *msg;        /* INFO / ERROR_MSG: message           */
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
        struct
        {
            uint8_t subtype;      /* lwip_power_event_t                  */
            uint8_t charging;     /* boot_BatteryCharging() != 0         */
        } power;                 /* POWER                                */
    } data;
};

/** One captured traceback entry, newest-first from lwip_traceback_copy().
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
 *
 * @internal Not part of the public API (absent from exports.txt and
 * public_api_manifest.csv on purpose). The user's persisted config
 * (file_log_enabled / log_verbosity, set from the config app UI) is the
 * sole authority over what gets observed and logged; log_file.c is the only
 * caller, from lwip_log_file_start()/lwip_log_file_stop(). A dev embedding
 * this stack must not be able to install a callback that bypasses, starves,
 * or silently disables the user's file logger.
 */
void lwip_set_event_cb(lwip_event_fn event_fn);

/** Return the currently installed event callback (NULL if none).
 * @internal Not part of the public API; see lwip_set_event_cb(). */
lwip_event_fn lwip_get_event_cb(void);

/** Return recent WARN/ERROR/socket-error trace entries, newest first.
 *  Legacy API: the returned array lives on lwIP's heap and is allocated on the
 *  first call, so it costs nothing unless used. The pointer stays valid until
 *  the next lwip_get_traceback() call. Prefer lwip_traceback_copy(), which
 *  needs no allocation and writes into the caller's buffer. */
const struct lwip_traceback_entry *lwip_get_traceback(uint8_t *count);

/** Copy recent WARN/ERROR/socket-error trace entries into @p dst, newest
 *  first, and return how many were written (at most @p cap and at most
 *  LWIP_TRACEBACK_DEPTH).
 *
 *  Copies instead of returning an internal array so the stack keeps only one
 *  traceback ring: readers that want chronological order (the file logger)
 *  materialise it in a short-lived buffer of their own. */
size_t lwip_traceback_copy(struct lwip_traceback_entry *dst, size_t cap);

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
void lwip_event_emit_code(uint8_t module, uint8_t kind, uint32_t loc, uint16_t extra,
                          uint16_t eid);
void lwip_event_emit_info(uint8_t module, const char *msg);
void lwip_event_emit_error_info(uint8_t module, const char *msg, uint16_t eid);
void lwip_event_emit_state(uint8_t module, void *owner, uint16_t change_event);
void lwip_event_emit_io_file(uint8_t module, uint8_t dir, const char *name, uint32_t bytes);
void lwip_event_emit_io_eth(uint8_t module, uint8_t dir, uint32_t bytes);
void lwip_event_emit_power(uint8_t module, uint8_t subtype, uint8_t charging);
void lwip_traceback_push_socket(uint16_t component, uint16_t operation,
                                int raw_error, uint16_t mapped_error,
                                uint16_t status);

/* ----------------------------------------------------------------------
 * Call-site macros. Each .c file using these must first define:
 *   #define LWIP_DBG_FILE_ID  <one of lwip_debug_file_id_t>
 *   #define LWIP_DBG_MODULE   <one of lwip_debug_module_t>
 * -------------------------------------------------------------------- */
/* `eid` is an LWIP_EXXXX constant from lwip_error_id_t; see the rules there. */
#define ERROR(eid)                                       \
    lwip_event_emit_code(LWIP_DBG_MODULE, LWIP_EV_ERROR, \
                         LWIP_EVENT_CODE(LWIP_DBG_FILE_ID, __LINE__), 0, (uint16_t)(eid))

#define ERROR_CODE(eid, extra)                                                           \
    lwip_event_emit_code(LWIP_DBG_MODULE, LWIP_EV_ERROR,                                 \
                         LWIP_EVENT_CODE(LWIP_DBG_FILE_ID, __LINE__), (uint16_t)(extra), \
                         (uint16_t)(eid))

/* Evaluate once and preserve the caller's file/line, including forwarding
 * returns. Success and asynchronous progress are not failures. */
#define LWIP_TRACE_RETURN(eid, expression)                              \
    do                                                                  \
    {                                                                   \
        err_t trace_result_ = (expression);                             \
        if (trace_result_ != ERR_OK && trace_result_ != ERR_INPROGRESS) \
        {                                                               \
            ERROR_CODE(eid, trace_result_);                             \
        }                                                               \
        return trace_result_;                                           \
    } while (0)

#define WARN(eid)                                       \
    lwip_event_emit_code(LWIP_DBG_MODULE, LWIP_EV_WARN, \
                         LWIP_EVENT_CODE(LWIP_DBG_FILE_ID, __LINE__), 0, (uint16_t)(eid))

#define WARN_CODE(eid, extra)                                                            \
    lwip_event_emit_code(LWIP_DBG_MODULE, LWIP_EV_WARN,                                  \
                         LWIP_EVENT_CODE(LWIP_DBG_FILE_ID, __LINE__), (uint16_t)(extra), \
                         (uint16_t)(eid))

#define DEBUG()                                          \
    lwip_event_emit_code(LWIP_DBG_MODULE, LWIP_EV_DEBUG, \
                         LWIP_EVENT_CODE(LWIP_DBG_FILE_ID, __LINE__), 0, LWIP_E0000)

#define INFO(str) \
    lwip_event_emit_info(LWIP_DBG_MODULE, (str))

#define ERROR_INFO(eid, str) \
    lwip_event_emit_error_info(LWIP_DBG_MODULE, (str), (uint16_t)(eid))

#define STATE_CHG(owner, change_event) \
    lwip_event_emit_state(LWIP_DBG_MODULE, (void *)(owner), (uint16_t)(change_event))

#define IO_FILE(dir, name, bytes) \
    lwip_event_emit_io_file(LWIP_DBG_MODULE, (uint8_t)(dir), (name), (uint32_t)(bytes))

#define IO_ETH(dir, bytes) \
    lwip_event_emit_io_eth(LWIP_DBG_MODULE, (uint8_t)(dir), (uint32_t)(bytes))

#define POWER_EVENT(subtype, charging) \
    lwip_event_emit_power(LWIP_DBG_MODULE, (uint8_t)(subtype), (uint8_t)(charging))

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
