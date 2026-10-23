#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

#define LWIP_DBG_FILE_ID LWIP_FILE_LOG_FILE
#define LWIP_DBG_MODULE  LWIP_DBG_MOD_LWIP

#include <sys/rtc.h>

#include "lwip/log_file.h"
#include "lwip/app_config.h"
#include "lwip/logging.h"
#include "lwip/mem.h"
#include "../lwip-imports.h"

/* Log line format (plain ASCII, newline-terminated):
 *
 *   <ts>: TBK: <module> <file>:<line> [x<extra_hex>]\n
 *   <ts>: EVT: <kind> <module> [<detail>]\n
 *
 * <ts> = rtc_Time() seconds (rolls at 86400).
 * TBK = traceback-class event (WARN or ERROR).
 * EVT = everything else.
 */

/* LOG_LINE_MAX must cover the worst case amongst all formatted lines below,
 * including the longest file name (lwip_debug_file_name) and an INFO message
 * at its largest caller-supplied length. Kept generous so a future longer
 * INFO string or file name doesn't silently truncate instead of failing to
 * compile/fit. Shared with the viewer (config app) via LWIP_LOG_LINE_MAX so
 * both sides agree on the longest line that can ever appear in the file.
 * LOG_STAGE_SIZE must hold at least a couple of LOG_LINE_MAX lines so one
 * oversized line can't starve log_stage_text(). */
#define LOG_LINE_MAX    LWIP_LOG_LINE_MAX
#define LOG_STAGE_SIZE  (LOG_LINE_MAX * 3u)

/* ---------------------------------------------------------------------------
 * Ring metadata layout in lwIPLgMD (3 bytes):
 *   [0] head        — index of the oldest archive slot
 *   [1] count       — number of occupied archive slots
 *   [2] max_slots   — saved copy of the user setting
 * ---------------------------------------------------------------------------
 */
typedef struct { uint8_t head, count, max_slots; } log_ring_t;

static uint8_t     *g_stage        = NULL;
static size_t       g_stage_used   = 0;
static uint8_t      g_max_slots    = LWIP_CFG_LOG_ARCHIVE_SLOTS_DEFAULT;
static bool         g_running      = false;
static lwip_event_fn g_prev_cb     = NULL;

/* ---------------------------------------------------------------------------
 * Helpers: ring metadata
 * ------------------------------------------------------------------------- */

static void ring_read(log_ring_t *r)
{
    uint8_t h = file_fn.ti_open(LWIP_LOG_META_APPVAR, "r");
    if (!h) { r->head = 0; r->count = 0; r->max_slots = g_max_slots; return; }
    uint8_t buf[3] = {0};
    file_fn.ti_read(buf, 1, 3, h);
    file_fn.ti_close(h);
    r->head      = buf[0];
    r->count     = buf[1];
    r->max_slots = buf[2] ? buf[2] : g_max_slots;
}

static void ring_write(const log_ring_t *r)
{
    file_fn.ti_delete(LWIP_LOG_META_APPVAR);
    uint8_t h = file_fn.ti_open(LWIP_LOG_META_APPVAR, "w");
    if (!h) return;
    uint8_t buf[3] = { r->head, r->count, r->max_slots };
    file_fn.ti_resize(3, h);
    file_fn.ti_write(buf, 1, 3, h);
    file_fn.ti_setarchivestatus(1, h);
    file_fn.ti_close(h);
}

/* Build the appvar name for archive slot index i: "lwIPLgXX". */
static void slot_name(uint8_t idx, char out[9])
{
    /* LWIP_LOG_ARCHIVE_PFX is "lwIPLg" (6 chars) + 2-digit decimal + NUL. */
    out[0] = 'l'; out[1] = 'w'; out[2] = 'I'; out[3] = 'P';
    out[4] = 'L'; out[5] = 'g';
    out[6] = (char)('0' + idx / 10u);
    out[7] = (char)('0' + idx % 10u);
    out[8] = '\0';
}

/* ---------------------------------------------------------------------------
 * Rotation: rename lwIPLog → lwIPLgXX, update ring metadata.
 * Called only when the active file is full.
 * ------------------------------------------------------------------------- */

static void log_rotate(void)
{
    log_ring_t r;
    ring_read(&r);

    /* If max_slots shrank since these slots were written (e.g. the user
     * lowered the archive-slot setting), the saved count can exceed the new
     * max. Evict the extra oldest slots first so count/head/max_slots stay
     * consistent; otherwise (head + i) % max_slots aliases two logical
     * slots onto the same index and the viewer shows one archive twice. */
    while (r.count > g_max_slots)
    {
        char orphan[9];
        slot_name(r.head, orphan);
        file_fn.ti_delete(orphan);
        r.head = (uint8_t)((r.head + 1u) % (r.max_slots ? r.max_slots : g_max_slots));
        r.count--;
    }
    r.max_slots = g_max_slots;

    uint8_t write_idx;
    if (r.count < r.max_slots)
    {
        /* Free slot: (head + count) % max_slots */
        write_idx = (uint8_t)((r.head + r.count) % r.max_slots);
        r.count++;
    }
    else
    {
        /* All slots full: evict oldest (head), advance head. */
        write_idx = r.head;
        r.head = (uint8_t)((r.head + 1u) % r.max_slots);
        /* count stays at max_slots */
    }

    char aname[9];
    slot_name(write_idx, aname);

    /* Delete the target slot if it exists, then rename active log into it. */
    file_fn.ti_delete(aname);
    if (!file_fn.ti_rename(LWIP_LOG_APPVAR, aname))
    {
        /* Rename failed: the active log is still intact under its old name.
         * Do not advance the ring or let the next flush truncate it. */
        return;
    }

    /* Archive the slot (survives a RAM clear). */
    uint8_t ah = file_fn.ti_open(aname, "r+");
    if (ah)
    {
        file_fn.ti_setarchivestatus(1, ah);
        file_fn.ti_close(ah);
    }

    ring_write(&r);
    /* Active log is now gone; next flush will create a fresh one. */
}

/* ---------------------------------------------------------------------------
 * Staging / flush
 * ------------------------------------------------------------------------- */

static void log_flush_internal(void)
{
    if (g_stage_used == 0)
        return;

    uint8_t h = file_fn.ti_open(LWIP_LOG_APPVAR, "r+");
    if (!h)
        h = file_fn.ti_open(LWIP_LOG_APPVAR, "w");
    if (!h)
    {
        g_stage_used = 0;
        return;
    }

    uint16_t current_size = file_fn.ti_getsize(h);

    /* How many bytes can we still fit before hitting the hard cap? */
    uint16_t space = (current_size < LWIP_CFG_LOG_FILE_MAX_BYTES)
                   ? (uint16_t)(LWIP_CFG_LOG_FILE_MAX_BYTES - current_size)
                   : 0u;

    if (space > 0)
    {
        size_t write_len = g_stage_used < space ? g_stage_used : (size_t)space;
        file_fn.ti_seek(0, SEEK_END, h);
        file_fn.ti_write(g_stage, 1, write_len, h);
        /* Shift remaining staged bytes to the front, if any. */
        if (write_len < g_stage_used)
        {
            g_stage_used -= write_len;
            memmove(g_stage, g_stage + write_len, g_stage_used);
        }
        else
        {
            g_stage_used = 0;
        }
    }

    file_fn.ti_close(h);

    /* If the file is now full, rotate it into an archive slot. */
    h = file_fn.ti_open(LWIP_LOG_APPVAR, "r");
    if (h)
    {
        uint16_t sz = file_fn.ti_getsize(h);
        file_fn.ti_close(h);
        if (sz >= LWIP_CFG_LOG_FILE_MAX_BYTES)
            log_rotate();
    }

    /* If staged bytes remain (they fit in the next file), write them now. */
    if (g_stage_used > 0)
    {
        h = file_fn.ti_open(LWIP_LOG_APPVAR, "w");
        if (h)
        {
            file_fn.ti_write(g_stage, 1, g_stage_used, h);
            file_fn.ti_close(h);
            g_stage_used = 0;
        }
    }
}

static void log_stage_text(const char *line, size_t len)
{
    if (len == 0 || len > LOG_STAGE_SIZE)
        return;
    if (g_stage_used + len > LOG_STAGE_SIZE)
        log_flush_internal();
    if (g_stage_used + len <= LOG_STAGE_SIZE)
    {
        memcpy(g_stage + g_stage_used, line, len);
        g_stage_used += len;
    }
}

/* ---------------------------------------------------------------------------
 * String helpers
 * ------------------------------------------------------------------------- */

static const char *kind_str(uint8_t kind)
{
    switch ((lwip_event_kind_t)kind)
    {
    case LWIP_EV_INFO:      return "INFO";
    case LWIP_EV_DEBUG:     return "DBG";
    case LWIP_EV_WARN:      return "WARN";
    case LWIP_EV_ERROR:     return "ERR";
    case LWIP_EV_STATE_CHG: return "STATE";
    case LWIP_EV_IO_FILE:   return "IOFILE";
    case LWIP_EV_IO_ETH:    return "IOETH";
    case LWIP_EV_POWER:     return "PWR";
    default:                return "?";
    }
}

static uint32_t log_ts(void) { return rtc_Time(); }

/* Append the current traceback (newest first) to the log immediately after
 * an ERROR line, so a failure's call-site history is captured inline rather
 * than only being queryable live via lwip_get_traceback(). Only entries with
 * a real file/line are rendered here; socket-wrapper entries (file==0) are
 * skipped since they carry no {file,line} to show. */
static void log_dump_traceback(void)
{
    uint8_t count = 0;
    const struct lwip_traceback_entry *tb = lwip_get_traceback(&count);
    char line[LOG_LINE_MAX];

    for (uint8_t i = 0; i < count; i++)
    {
        const struct lwip_traceback_entry *e = &tb[i];
        if (e->file == LWIP_FILE_NONE && e->line == 0 && e->component == 0)
            continue; /* nothing meaningful to show */

        const char *mod = lwip_debug_module_name(e->module);
        const char *fname = lwip_debug_file_name(e->file);
        int n;
        if (e->extra)
            n = snprintf(line, sizeof(line), "  tb[%u]: %s %s %s:%lu x%x\n",
                         (unsigned)i, kind_str(e->kind), mod, fname,
                         (unsigned long)e->line, (unsigned)e->extra);
        else
            n = snprintf(line, sizeof(line), "  tb[%u]: %s %s %s:%lu\n",
                         (unsigned)i, kind_str(e->kind), mod, fname,
                         (unsigned long)e->line);
        if (n > 0)
            log_stage_text(line, (size_t)n);
    }
}

/* ---------------------------------------------------------------------------
 * Event callback
 * ------------------------------------------------------------------------- */

static void log_event_cb(const struct lwip_event *ev)
{
    if (g_prev_cb)
        g_prev_cb(ev);

    if (!g_running)
        return;

    char line[LOG_LINE_MAX];
    int n = 0;
    uint32_t ts = log_ts();
    const char *mod = lwip_debug_module_name(ev->module);

    switch (ev->kind)
    {
    case LWIP_EV_WARN:
    case LWIP_EV_ERROR:
    {
        uint8_t  fid   = LWIP_EVENT_CODE_FILE(ev->data.code.loc);
        uint32_t lnum  = LWIP_EVENT_CODE_LINE(ev->data.code.loc);
        uint16_t extra = ev->data.code.extra;
        const char *fname = lwip_debug_file_name(fid);
        if (extra)
            n = snprintf(line, sizeof(line), "%lu: TBK: %s %s:%lu x%x\n",
                         (unsigned long)ts, mod, fname,
                         (unsigned long)lnum, (unsigned)extra);
        else
            n = snprintf(line, sizeof(line), "%lu: TBK: %s %s:%lu\n",
                         (unsigned long)ts, mod, fname, (unsigned long)lnum);
        break;
    }
    case LWIP_EV_DEBUG:
    {
        uint8_t  fid  = LWIP_EVENT_CODE_FILE(ev->data.code.loc);
        uint32_t lnum = LWIP_EVENT_CODE_LINE(ev->data.code.loc);
        const char *fname = lwip_debug_file_name(fid);
        n = snprintf(line, sizeof(line), "%lu: EVT: DBG %s %s:%lu\n",
                     (unsigned long)ts, mod, fname, (unsigned long)lnum);
        break;
    }
    case LWIP_EV_INFO:
    {
        const char *msg = ev->data.msg ? ev->data.msg : "";
        n = snprintf(line, sizeof(line), "%lu: EVT: INFO %s %s\n",
                     (unsigned long)ts, mod, msg);
        break;
    }
    case LWIP_EV_STATE_CHG:
    {
        const char *sname = lwip_debug_state_change_name(ev->data.state.change_event);
        n = snprintf(line, sizeof(line), "%lu: EVT: STATE %s %s\n",
                     (unsigned long)ts, mod, sname);
        break;
    }
    case LWIP_EV_IO_FILE:
    {
        const char *dir  = (ev->data.file.dir == LWIP_IO_READ) ? "RD" : "WR";
        const char *name = ev->data.file.name ? ev->data.file.name : "?";
        n = snprintf(line, sizeof(line), "%lu: EVT: IOFILE %s %s %s %lu\n",
                     (unsigned long)ts, mod, dir, name,
                     (unsigned long)ev->data.file.bytes);
        break;
    }
    case LWIP_EV_IO_ETH:
    {
        const char *dir = (ev->data.eth.dir == LWIP_IO_RX) ? "RX" : "TX";
        n = snprintf(line, sizeof(line), "%lu: EVT: IOETH %s %s %lu\n",
                     (unsigned long)ts, mod, dir,
                     (unsigned long)ev->data.eth.bytes);
        break;
    }
    case LWIP_EV_POWER:
        n = snprintf(line, sizeof(line), "%lu: EVT: PWR %s sub=%u chrg=%u\n",
                     (unsigned long)ts, mod,
                     (unsigned)ev->data.power.subtype,
                     (unsigned)ev->data.power.charging);
        break;
    default:
        n = snprintf(line, sizeof(line), "%lu: EVT: %s %s\n",
                     (unsigned long)ts, kind_str(ev->kind), mod);
        break;
    }

    if (n > 0)
        log_stage_text(line, (size_t)n);

    /* Per project convention: when the last emit was an ERROR, immediately
     * follow it with the call-site traceback so the on-calculator log is
     * self-contained for diagnosing a failure after the fact. */
    if (ev->kind == LWIP_EV_ERROR)
        log_dump_traceback();
}

/* ---------------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------------- */

bool lwip_log_file_start(uint8_t max_archive_slots)
{
    if (g_running)
        return true;
    if (max_archive_slots < LWIP_CFG_LOG_ARCHIVE_SLOTS_MIN)
        max_archive_slots = LWIP_CFG_LOG_ARCHIVE_SLOTS_MIN;
    if (max_archive_slots > LWIP_CFG_LOG_ARCHIVE_SLOTS_MAX)
        max_archive_slots = LWIP_CFG_LOG_ARCHIVE_SLOTS_MAX;

    g_stage = (uint8_t *)mem_malloc(LOG_STAGE_SIZE);
    if (!g_stage)
        return false;

    g_max_slots   = max_archive_slots;
    g_stage_used  = 0;
    g_prev_cb     = lwip_get_event_cb();
    g_running     = true;
    lwip_set_event_cb(log_event_cb);
    return true;
}

void lwip_log_file_flush(void)
{
    if (!g_running)
        return;
    log_flush_internal();
}

void lwip_log_file_stop(void)
{
    if (!g_running)
        return;
    log_flush_internal();
    g_running = false;
    lwip_set_event_cb(g_prev_cb);
    g_prev_cb = NULL;
    mem_free(g_stage);
    g_stage      = NULL;
    g_stage_used = 0;
}

