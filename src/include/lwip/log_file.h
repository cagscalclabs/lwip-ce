#ifndef LWIP_LOG_FILE_H
#define LWIP_LOG_FILE_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Active log appvar.  Hard-capped at LWIP_CFG_LOG_FILE_MAX_BYTES (16 KiB).
 * When it fills, it is rotated into an archive slot via ti_Rename and a fresh
 * active file begins. */
#define LWIP_LOG_APPVAR      "lwIPLog"

/* Longest single formatted log line log_file.c ever writes (including the
 * terminating newline), kept in sync with LOG_LINE_MAX there. The viewer
 * (config app) uses this to size its per-line read buffer so a long line is
 * wrapped across rows instead of silently truncated. */
#define LWIP_LOG_LINE_MAX    192u

/* Archive slot appvars: "lwIPLg00" .. "lwIPLg08" (max 9 slots, indices 0-8).
 * A 3-byte ring-metadata appvar tracks which slots are occupied. */
#define LWIP_LOG_ARCHIVE_PFX "lwIPLg"
#define LWIP_LOG_META_APPVAR "lwIPLgMD"

/**
 * Start the file logger.
 *
 * Installs an internal event callback that captures every lwIP event to
 * lwIPLog using a RAM-staging/flush scheme.  Any previously registered event
 * callback is chained: both still fire.
 *
 * Each active log is hard-capped at LWIP_CFG_LOG_FILE_MAX_BYTES (16 KiB).
 * When it fills, it is rotated into the next archive slot; the oldest slot
 * is evicted if max_archive_slots are already occupied.
 *
 * @param max_archive_slots  Number of archive slots to keep (1-9).
 * @return true on success.
 *
 * @internal Not part of the public API (absent from exports.txt and
 * public_api_manifest.csv on purpose). Called only from the two
 * config-driven entry points (lwip_stack_init() in lwIP.c, and main.c's
 * startup) using the user's persisted file_log_enabled setting -- a dev
 * embedding this stack must not be able to start logging the user disabled,
 * or stop logging the user enabled.
 */
bool lwip_log_file_start(uint8_t max_archive_slots);

/** Flush the in-RAM staging buffer to the appvar immediately.
 *  No-op if the logger is not running.
 * @internal Not part of the public API. Viewing, clearing, and iterating
 * captured logs is the config app's job (main.c), which reads the appvars
 * directly -- there is deliberately no app-facing API for any of it. A dev
 * embedding this stack should direct the user to the config app to manage
 * their own captured logs, not build another path to them. */
void lwip_log_file_flush(void);

/** Stop the file logger, flush remaining data, restore previous callback.
 * @internal Not part of the public API; see lwip_log_file_start(). */
void lwip_log_file_stop(void);

#ifdef __cplusplus
}
#endif

#endif /* LWIP_LOG_FILE_H */
