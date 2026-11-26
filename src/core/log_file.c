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
#include "../lwIP.h"
#include "../lwip-imports.h"
#include "../drivers/rtc_tod.h"

/* Log line format (plain ASCII, newline-terminated):
 *
 *   <ts> TBK: [e<id_hex4> ]<module> <file>:<line> [x<extra_hex>]\n
 *   <ts> EVT: ERR: [e<id_hex4> ]<module> <message>\n
 *   <ts> EVT: <kind> <module> [<detail>]\n
 *   <ts> EVT: WARN: e<id> <module> tcp retry <why> #<n> <lport>><rport> seq=<hex> len=<n> fl=<SAFPR>\n
 *   <ts> EVT: ERR: e<id> <module> tcp give-up <why> after <n> <lport>><rport> seq=<hex> len=<n> fl=<SAFPR>\n
 *   <ts> INFO: Session Start: Version <ver>; Date: YYYY-MM-DD\n
 *   <ts> <source>: Setting clock from <YYYY-MM-DD HH:MM:SS> to <YYYY-MM-DD HH:MM:SS>\n
 *
 * <ts> = HH:MM:SS, local wall-clock time from the RTC (rtc_tod.h): the clock
 * the user sets, so a time the user remembers maps straight onto log lines.
 * Capture records use the same clock. Whole seconds; log order is file order.
 * The Session Start line opens every logging session (it is written directly,
 * bypassing the event log level, so it is always present) and gives the date,
 * so each session's times can be placed on a calendar: a later <ts> smaller
 * than the one before it means midnight passed. When lwIP-CE itself sets the
 * clock (SNTP sync, or raising an implausibly early clock), a "Setting clock"
 * line, stamped with the old clock, is written first, regardless of log level.
 * A change made in TI-OS while the stack is not running leaves no line.
 * Logs from before v3.2.3 stamp lines with rtc_Time() as "<counter>: ", a
 * free-running seconds counter unrelated to the time of day.
 * TBK = traceback-class event (WARN or ERROR).
 * EVT = everything else.
 * e<id_hex4> = stable error ID (lwip_error_id_t in logging.h), lowercase hex;
 *              omitted when the site has none (LWIP_E0000).
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
 * Ring metadata layout in lwIPLgMD (4 bytes; archived, survives a RAM clear):
 *   [0] head        — index of the oldest archive slot
 *   [1] count       — number of occupied archive slots
 *   [2] max_slots   — saved copy of the user setting
 *   [3] open        — 1 between lwip_log_file_start() and _stop(). Still set
 *                     at the next start means the previous session never
 *                     stopped: a crash/NMI reset, a RAM clear, or a program
 *                     that exited without stopping the log. The active log
 *                     lives in RAM, so that session's tail is lost; the flag
 *                     is the only trace it leaves. Older 3-byte files read
 *                     as open = 0.
 * ---------------------------------------------------------------------------
 */
typedef struct { uint8_t head, count, max_slots, open; } log_ring_t;

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
    if (!h) { r->head = 0; r->count = 0; r->max_slots = g_max_slots; r->open = 0; return; }
    uint8_t buf[4] = {0};
    file_fn.ti_read(buf, 1, 4, h);
    file_fn.ti_close(h);
    r->head      = buf[0];
    r->count     = buf[1];
    r->max_slots = buf[2] ? buf[2] : g_max_slots;
    r->open      = buf[3] == 1;
}

static void ring_write(const log_ring_t *r)
{
    file_fn.ti_delete(LWIP_LOG_META_APPVAR);
    uint8_t h = file_fn.ti_open(LWIP_LOG_META_APPVAR, "w");
    if (!h) return;
    uint8_t buf[4] = { r->head, r->count, r->max_slots, r->open };
    file_fn.ti_resize(4, h);
    file_fn.ti_write(buf, 1, 4, h);
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
    case LWIP_EV_ERROR_MSG: return "ERR";
    case LWIP_EV_STATE_CHG: return "STATE";
    case LWIP_EV_IO_FILE:   return "IOFILE";
    case LWIP_EV_IO_ETH:    return "IOETH";
    case LWIP_EV_POWER:     return "PWR";
    case LWIP_EV_TCP_RETRY: return "WARN";
    case LWIP_EV_TCP_GIVEUP: return "ERR";
    default:                return "?";
    }
}

static const char *tcp_reason_str(uint8_t reason)
{
    switch ((lwip_tcp_retry_reason_t)reason)
    {
    case LWIP_TCP_RETRY_RTO:        return "rto";
    case LWIP_TCP_RETRY_FAST:       return "fast";
    case LWIP_TCP_GIVEUP_SYN:       return "syn";
    case LWIP_TCP_GIVEUP_DATA:      return "data";
    case LWIP_TCP_GIVEUP_PERSIST:   return "persist";
    case LWIP_TCP_GIVEUP_KEEPALIVE: return "keepalive";
    default:                        return "?";
    }
}

/* TCP flags as letters, Wireshark order: S(YN) A(CK) F(IN) P(SH) R(ST). */
static void tcp_flags_str(uint8_t f, char out[6])
{
    char *o = out;
    if (f & 0x02) *o++ = 'S';
    if (f & 0x10) *o++ = 'A';
    if (f & 0x01) *o++ = 'F';
    if (f & 0x08) *o++ = 'P';
    if (f & 0x04) *o++ = 'R';
    if (o == out) *o++ = '-';
    *o = '\0';
}

/* One formatted line at a time: the event callback stages its line before
 * log_dump_traceback() reuses the buffer. Static because the callback runs for
 * allocator events too, so it must not allocate. */
static char g_log_line[LOG_LINE_MAX];

const struct lwip_traceback_entry *lwip_traceback_at(size_t i);

#ifndef LWIP_TRACEBACK_DUMP_DEPTH
#define LWIP_TRACEBACK_DUMP_DEPTH 16u
#endif

/* Append the current traceback (newest first) to the log immediately after
 * an ERROR line, so a failure's call-site history is captured inline rather
 * than only being queryable live via lwip_traceback_copy(). Only entries with
 * a real file/line are rendered here; socket-wrapper entries (file==0) are
 * skipped since they carry no {file,line} to show. */
static void log_dump_traceback(void)
{
    /* Walks the ring in place (newest first); nothing is copied. */
    char *line = g_log_line;

    for (size_t i = 0; i < LWIP_TRACEBACK_DUMP_DEPTH; i++)
    {
        const struct lwip_traceback_entry *e = lwip_traceback_at(i);
        if (!e)
            break;
        if (e->file == LWIP_FILE_NONE && e->line == 0 && e->component == 0)
            continue; /* nothing meaningful to show */

        const char *mod = lwip_debug_module_name(e->module);
        const char *fname = lwip_debug_file_name(e->file);
        int n;
        if (e->extra)
            n = snprintf(line, LOG_LINE_MAX, "  tb[%u]: %s %s %s:%lu x%x\n",
                         (unsigned)i, kind_str(e->kind), mod, fname,
                         (unsigned long)e->line, (unsigned)e->extra);
        else
            n = snprintf(line, LOG_LINE_MAX, "  tb[%u]: %s %s %s:%lu\n",
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

    char *line = g_log_line;
    int n = 0;
    char ts[9];
    rtc_tod_format(rtc_tod_seconds(), ts);
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
        /* Stable error ID first (eXXXX), when the site has one. */
        char eid[7] = "";
        if (ev->eid)
            snprintf(eid, sizeof eid, "e%04x ", (unsigned)ev->eid);
        if (extra)
            n = snprintf(line, LOG_LINE_MAX, "%s TBK: %s%s %s:%lu x%x\n",
                         ts, eid, mod, fname,
                         (unsigned long)lnum, (unsigned)extra);
        else
            n = snprintf(line, LOG_LINE_MAX, "%s TBK: %s%s %s:%lu\n",
                         ts, eid, mod, fname, (unsigned long)lnum);
        break;
    }
    case LWIP_EV_DEBUG:
    {
        uint8_t  fid  = LWIP_EVENT_CODE_FILE(ev->data.code.loc);
        uint32_t lnum = LWIP_EVENT_CODE_LINE(ev->data.code.loc);
        const char *fname = lwip_debug_file_name(fid);
        n = snprintf(line, LOG_LINE_MAX, "%s EVT: DBG %s %s:%lu\n",
                     ts, mod, fname, (unsigned long)lnum);
        break;
    }
    case LWIP_EV_INFO:
    {
        const char *msg = ev->data.msg ? ev->data.msg : "";
        n = snprintf(line, LOG_LINE_MAX, "%s EVT: INFO %s %s\n",
                     ts, mod, msg);
        break;
    }
    case LWIP_EV_ERROR_MSG:
    {
        const char *msg = ev->data.msg ? ev->data.msg : "";
        if (ev->eid)
            n = snprintf(line, LOG_LINE_MAX, "%s EVT: ERR: e%04x %s %s\n",
                         ts, (unsigned)ev->eid, mod, msg);
        else
            n = snprintf(line, LOG_LINE_MAX, "%s EVT: ERR: %s %s\n",
                         ts, mod, msg);
        break;
    }
    case LWIP_EV_STATE_CHG:
    {
        const char *sname = lwip_debug_state_change_name(ev->data.state.change_event);
        n = snprintf(line, LOG_LINE_MAX, "%s EVT: STATE %s %s\n",
                     ts, mod, sname);
        break;
    }
    case LWIP_EV_IO_FILE:
    {
        const char *dir  = (ev->data.file.dir == LWIP_IO_READ) ? "RD" : "WR";
        const char *name = ev->data.file.name ? ev->data.file.name : "?";
        n = snprintf(line, LOG_LINE_MAX, "%s EVT: IOFILE %s %s %s %lu\n",
                     ts, mod, dir, name,
                     (unsigned long)ev->data.file.bytes);
        break;
    }
    case LWIP_EV_IO_ETH:
    {
        const char *dir = (ev->data.eth.dir == LWIP_IO_RX) ? "RX" : "TX";
        n = snprintf(line, LOG_LINE_MAX, "%s EVT: IOETH %s %s %lu\n",
                     ts, mod, dir,
                     (unsigned long)ev->data.eth.bytes);
        break;
    }
    case LWIP_EV_TCP_RETRY:
    case LWIP_EV_TCP_GIVEUP:
    {
        const struct lwip_event_tcp *t = &ev->data.tcp;
        char fl[6];
        tcp_flags_str(t->flags, fl);
        bool giveup = ev->kind == LWIP_EV_TCP_GIVEUP;
        n = snprintf(line, LOG_LINE_MAX,
                     "%s EVT: %s: e%04x %s tcp %s %s %s%u %u>%u seq=%08lx len=%u fl=%s\n",
                     ts, giveup ? "ERR" : "WARN", (unsigned)ev->eid, mod,
                     giveup ? "give-up" : "retry", tcp_reason_str(t->reason),
                     giveup ? "after " : "#", (unsigned)t->count,
                     (unsigned)t->local_port, (unsigned)t->remote_port,
                     (unsigned long)t->seq, (unsigned)t->len, fl);
        break;
    }
    case LWIP_EV_POWER:
        n = snprintf(line, LOG_LINE_MAX, "%s EVT: PWR %s sub=%u chrg=%u\n",
                     ts, mod,
                     (unsigned)ev->data.power.subtype,
                     (unsigned)ev->data.power.charging);
        break;
    default:
        n = snprintf(line, LOG_LINE_MAX, "%s EVT: %s %s\n",
                     ts, kind_str(ev->kind), mod);
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

/* First line of every session; see the format note at the top. Staged
 * directly rather than emitted as an event, so no log level filters it. */
static void log_session_start_line(void)
{
    uint8_t day, month, day2, month2;
    uint16_t year, year2;
    uint32_t tod;
    char ts[9];

    /* Date, time, date again: retry if midnight passed between the reads. */
    do {
        boot_GetDate(&day, &month, &year);
        tod = rtc_tod_seconds();
        boot_GetDate(&day2, &month2, &year2);
    } while (day != day2 || month != month2 || year != year2);
    rtc_tod_format(tod, ts);

    int n = snprintf(g_log_line, LOG_LINE_MAX,
                     "%s INFO: Session Start: Version %s; Date: %04u-%02u-%02u\n",
                     ts, LWIP_CE_VERSION_STRING, (unsigned)year,
                     (unsigned)month, (unsigned)day);
    if (n > 0)
        log_stage_text(g_log_line, (size_t)n < LOG_LINE_MAX ? (size_t)n
                                                            : LOG_LINE_MAX - 1u);
}

/* Clock-change line; see lwip_log_file_clock_set() in log_file.h. Staged
 * directly, like the Session Start line, so no log level filters it. */
void lwip_log_file_clock_set(const char *source, const char *from, const char *to)
{
    if (!g_running)
        return;
    char ts[9];
    rtc_tod_format(rtc_tod_seconds(), ts);
    int n = snprintf(g_log_line, LOG_LINE_MAX, "%s %s: Setting clock from %s to %s\n",
                     ts, source, from, to);
    if (n > 0)
        log_stage_text(g_log_line, (size_t)n < LOG_LINE_MAX ? (size_t)n
                                                            : LOG_LINE_MAX - 1u);
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

    log_session_start_line();

    /* Unclean-shutdown detection: see the ring metadata layout above. */
    log_ring_t r;
    ring_read(&r);
    if (r.open)
        WARN(LWIP_E030F);
    r.open = 1;
    ring_write(&r);
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
    log_ring_t r;
    ring_read(&r);
    r.open = 0;
    ring_write(&r);
    g_running = false;
    lwip_set_event_cb(g_prev_cb);
    g_prev_cb = NULL;
    mem_free(g_stage);
    g_stage      = NULL;
    g_stage_used = 0;
}

