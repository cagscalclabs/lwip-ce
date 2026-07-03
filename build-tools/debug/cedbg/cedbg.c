/*
 * cedbg - a headless scriptable frontend for the CEmu core (libcemucore).
 *
 * Drives the eZ80 emulator from a line-oriented command stream (stdin or a
 * script file) and exposes register/memory inspection, breakpoints, watch-
 * points, single-stepping and screenshots -- the pieces needed to debug
 * eZ80 assembly (e.g. bigint.s) without the Qt GUI.
 *
 * The CEmu core calls gui_debug_open() synchronously the instant a break/
 * watch/step fires; the CPU is frozen for the duration of that call, so the
 * callback simply records the reason and longjmps back to the command loop.
 * The global `cpu` then holds the exact machine state at the trap.
 */

#include "emu.h"
#include "cpu.h"
#include "mem.h"
#include "lcd.h"
#include "link.h"
#include "asic.h"
#include "keypad.h"
#include "schedule.h"
#include "extras.h"
#include "control.h"
#include "usb/usb.h"
#include "debug/debug.h"
#include "netbridge.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>      /* clock_gettime for real-time pacing */
#include <inttypes.h>

/* ------------------------------------------------------------------ */
/* Required core frontend callbacks                                    */
/* ------------------------------------------------------------------ */

void gui_console_clear(void) {}

void gui_console_printf(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
}

void gui_console_err_printf(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

/* ------------------------------------------------------------------ */
/* Debug trap plumbing                                                 */
/* ------------------------------------------------------------------ */

static volatile int trap_reason;   /* DBG_* reason of the most recent trap */
static volatile uint32_t trap_data;
static volatile bool trapped;      /* latched: a trap fired this run        */

static const char *reason_str(int r) {
    switch (r) {
        case DBG_USER:             return "user";
        case DBG_READY:            return "ready";
        case DBG_FROZEN:           return "frozen (di/halt)";
        case DBG_BREAKPOINT:       return "breakpoint";
        case DBG_WATCHPOINT_READ:  return "watch-read";
        case DBG_WATCHPOINT_WRITE: return "watch-write";
        case DBG_PORT_READ:        return "port-read";
        case DBG_PORT_WRITE:       return "port-write";
        case DBG_STEP:             return "step";
        case DBG_WATCHDOG_TIMEOUT: return "watchdog";
        case DBG_MISC_RESET:       return "reset";
        default:                   return "other";
    }
}

/* Called synchronously by the core when a breakpoint/watch/step fires. We must
 * RETURN normally (not longjmp) so the core's debug_open() can restore the CPU
 * scheduler state it saved around this call. We just latch the trap; the run
 * loop notices `trapped` and stops feeding the emulator more ticks. */
void gui_debug_open(int reason, uint32_t data) {
    if (reason == DBG_READY) return;   /* fires on reset; nothing armed yet */
    trap_reason = reason;
    trap_data = data;
    trapped = true;
    /* Make emu_run() break out of its loop after this instruction completes,
     * so we stop precisely at the trap instead of finishing the slice. */
    sched.run_event_triggered = true;
}

void gui_debug_close(void) {}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

/* emu_run takes a tick count; with a run rate of 1000 ticks/sec, one slice of
 * 100 ticks is ~100ms of emulated time. Small enough to poll for traps. */
#define RUN_RATE  1000U
#define RUN_SLICE 100ULL

/* Run the emulator until a debug trap fires or `max_ticks` of emulated time
 * elapse with no trap. Mirrors the GUI's approach: feed the core small slices
 * and check the trap latch between them, so gui_debug_open() returns normally
 * and the core restores its scheduler/CPU state around each trap. Returns true
 * if a trap occurred. */
static bool run_until_trap(uint64_t max_ticks) {
    trap_reason = -1;
    trapped = false;
    uint64_t elapsed = 0;
    while (elapsed < max_ticks) {
        emu_run(RUN_SLICE);
        elapsed += RUN_SLICE;
        if (trapped) return true;
        if (cpu.abort == CPU_ABORT_EXIT) return false;
    }
    return false;
}

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* Real-time-paced run for ~max_ticks of emulated time (rate=1000 -> 1 tick =
 * 1 ms). Throttles emulation to wall-clock so async libusb transfers in the
 * physical-USB backend complete in step (passthrough needs real-time pacing).
 * Returns true if a debug trap fired. Stops early on Ctrl-C-like CPU exit. */
static bool run_realtime(uint64_t max_ticks) {
    trap_reason = -1;
    trapped = false;
    const uint64_t SLICE = 5;        /* 5 ms emulated per step */
    const uint64_t ns_per_tick = 1000000ULL;  /* rate 1000 -> 1 tick = 1 ms */
    uint64_t elapsed = 0;
    uint64_t t0 = now_ns();
    while (elapsed < max_ticks) {
        emu_run(SLICE);
        elapsed += SLICE;
        if (trapped) return true;
        if (cpu.abort == CPU_ABORT_EXIT) return false;
        /* Sleep so emulated time tracks wall-clock: target = t0 + elapsed*ns. */
        uint64_t target = t0 + elapsed * ns_per_tick;
        uint64_t now = now_ns();
        if (target > now) {
            struct timespec rq = {
                .tv_sec  = (time_t)((target - now) / 1000000000ULL),
                .tv_nsec = (long)((target - now) % 1000000000ULL)
            };
            nanosleep(&rq, NULL);
        }
    }
    return false;
}

/* Inject an OS key token, giving the OS time to consume it. sendKey() returns
 * false while a previous key is still pending, so we run the emulator and
 * retry. Each key is followed by a settle period so the OS processes it. */
static void inject_key(uint16_t key) {
    for (int tries = 0; tries < 50; tries++) {
        if (sendKey(key)) break;
        run_until_trap(50);   /* let the OS drain the pending key */
    }
    run_until_trap(200);      /* settle: let the OS act on this key */
}

/* Replicates the autotester "launch" action purely via core key injection:
 * CLEAR, [Asm(], prgm, type NAME, ENTER. Assumes the home screen is focused.
 * Clears any stale OS key/scancode state first (e.g. after a prior csc) and
 * gives the OS ample time to consume each token so a second launch in a
 * session is reliable. */
static void do_screenshot(const char *path);
static void launch_program(const char *name, bool is_asm) {
    /* Drain stale key state: clear the kbd "key ready" + scancode-ready flags
     * so the first injected key is not dropped. (CE_kbdFlags 0xD00080 bit3,
     * graphFlags2 0xD0009F bit5 — see core/extras.c.) */
    mem_poke_byte(0xD0009F, mem_peek_byte(0xD0009F) & ~(1 << 5));
    mem_poke_byte(0xD00080, mem_peek_byte(0xD00080) & ~(1 << 3));
    run_until_trap(500);

    /* Two CLEARs: a prior launch leaves its "Asm(prgmNAME" command line in the
     * home-screen edit buffer. One CLEAR wipes the line content; a second
     * CLEAR (harmless on an already-empty line) guarantees we start typing on a
     * fresh entry line, so the new name isn't appended to the stale one and
     * mis-parsed into a RAM-clearing bad command. Required for reliable
     * second-and-later launches in a single session. */
    inject_key(CE_KEY_CLEAR);
    run_until_trap(500);
    inject_key(CE_KEY_CLEAR);
    run_until_trap(500);
    if (is_asm) inject_key(CE_KEY_ASM);
    inject_key(CE_KEY_PRGM);
    for (const char *p = name; *p; p++) {
        sendLetterKeyPress(*p);
        run_until_trap(400);
    }
    inject_key(CE_KEY_ENTER);
    run_until_trap(500);
}

static void print_regs(void) {
    eZ80registers_t *r = &cpu.registers;
    printf("PC=%06X  SP=%06X  (ADL=%d)\n", r->PC, r->SPL, cpu.ADL);
    printf("AF=%04X  BC=%06X  DE=%06X  HL=%06X\n", r->AF, r->BC, r->DE, r->HL);
    printf("IX=%06X  IY=%06X\n", r->IX, r->IY);
    printf("flags: %c%c%c%c%c%c  (S Z H PV N C)\n",
           r->flags.S  ? 'S' : '-',
           r->flags.Z  ? 'Z' : '-',
           r->flags.H  ? 'H' : '-',
           r->flags.PV ? 'P' : '-',
           r->flags.N  ? 'N' : '-',
           r->flags.C  ? 'C' : '-');
}

static void do_peek(uint32_t addr, uint32_t len) {
    for (uint32_t i = 0; i < len; i += 16) {
        printf("%06X: ", addr + i);
        char ascii[17]; ascii[16] = 0;
        for (uint32_t j = 0; j < 16; j++) {
            if (i + j < len) {
                uint8_t b = mem_peek_byte(addr + i + j);
                printf("%02X ", b);
                ascii[j] = (b >= 0x20 && b < 0x7f) ? (char)b : '.';
            } else {
                printf("   ");
                ascii[j] = ' ';
            }
        }
        printf(" %s\n", ascii);
    }
}

/* Save a screenshot as a binary PPM (P6, 320x240). */
static void do_screenshot(const char *path) {
    static uint32_t frame[LCD_WIDTH * LCD_HEIGHT];
    emu_lcd_drawframe(frame);
    FILE *f = fopen(path, "wb");
    if (!f) { printf("error: cannot open %s\n", path); return; }
    fprintf(f, "P6\n%d %d\n255\n", LCD_WIDTH, LCD_HEIGHT);
    for (int i = 0; i < LCD_WIDTH * LCD_HEIGHT; i++) {
        uint32_t px = frame[i];          /* ARGB / xRGB */
        unsigned char rgb[3] = {
            (unsigned char)(px >> 16),
            (unsigned char)(px >> 8),
            (unsigned char)(px)
        };
        fwrite(rgb, 1, 3, f);
    }
    fclose(f);
    printf("screenshot -> %s\n", path);
}

static void report_trap(void) {
    if (trap_reason >= 0) {
        printf("[trap] %s @ PC=%06X data=%06X\n",
               reason_str(trap_reason), cpu.registers.PC, trap_data);
        print_regs();
    } else {
        printf("[ran] no trap; PC=%06X\n", cpu.registers.PC);
    }
}

/* ------------------------------------------------------------------ */
/* Command loop                                                        */
/* ------------------------------------------------------------------ */

static void usage_help(void) {
    printf(
      "commands:\n"
      "  loadrom <path>            load a ROM/image and boot\n"
      "  send <file> [ram|arch]    transfer a variable/program\n"
      "  break <hexaddr>           set execution breakpoint\n"
      "  unbreak <hexaddr>         remove breakpoint\n"
      "  watch r|w|rw <hexaddr> <len>   set watchpoint\n"
      "  unwatch <hexaddr>         remove watchpoint\n"
      "  run [slices]              run until a trap (default 50 slices)\n"
      "  step                      single step one instruction\n"
      "  stepover                  step over call\n"
      "  regs                      dump CPU registers\n"
      "  peek <hexaddr> <len>      hexdump memory (no side effects)\n"
      "  poke <hexaddr> <hexbyte>  write one byte\n"
      "  shot <path.ppm>           save LCD screenshot\n"
      "  launch <NAME> [asm]       run a program by name (CLEAR,prgm,type,ENTER)\n"
      "  keytok <hextoken>         inject one OS key token (enter=5 clear=9 prgm=DA)\n"
      "  csc <hexscancode>         inject a raw scan code for ASM progs (enter=09)\n"
      "  key <row> <col>           press+release a physical key\n"
      "  help / quit\n");
}

static uint32_t hx(const char *s) { return (uint32_t)strtoul(s, NULL, 16); }

/* Grab the remainder of the line as a single argument (filenames may contain
 * spaces). Trims leading blanks and a trailing newline. Returns NULL if empty.
 * Operates on the strtok save-pointer region, so call right after the verb. */
static char *rest_of_line(char **saveptr) {
    char *p = strtok_r(NULL, "\r\n", saveptr);
    if (!p) return NULL;
    while (*p == ' ' || *p == '\t') p++;
    return *p ? p : NULL;
}

int main(int argc, char **argv) {
    FILE *script = stdin;
    if (argc > 1) {
        script = fopen(argv[1], "r");
        if (!script) { fprintf(stderr, "cannot open script %s\n", argv[1]); return 1; }
    }

    setvbuf(stdout, NULL, _IONBF, 0);   /* unbuffered: survive hard exits */
    printf("cedbg: headless CEmu debugger. type 'help'.\n");

    bool dbg_inited = false;
    char line[512];
    while (fgets(line, sizeof line, script)) {
        /* strip comments and trailing newline */
        char *hash = strchr(line, '#'); if (hash) *hash = 0;
        char *saveptr;
        char *tok = strtok_r(line, " \t\r\n", &saveptr);
        if (!tok) continue;

        if (!strcmp(tok, "help")) { usage_help(); }
        else if (!strcmp(tok, "quit") || !strcmp(tok, "exit")) { break; }
        else if (!strcmp(tok, "loadrom")) {
            char *p = rest_of_line(&saveptr);
            if (!p) { printf("usage: loadrom <path>\n"); continue; }
            /* debug_init() MUST run before emu_load(): the CPU executes
             * instructions during boot and debug_inst_start() dereferences
             * the debug.addr buffer that debug_init() allocates. */
            if (!dbg_inited) { debug_init(); dbg_inited = true; }
            emu_state_t st = emu_load(EMU_DATA_ROM, p);
            if (st != EMU_STATE_VALID) {
                /* try as a saved image */
                st = emu_load(EMU_DATA_IMAGE, p);
            }
            printf("loadrom %s -> %s\n", p,
                   st == EMU_STATE_VALID ? "ok" :
                   st == EMU_STATE_NOT_A_CE ? "not-a-ce" : "invalid");
            if (st == EMU_STATE_VALID) {
                emu_set_run_rate(RUN_RATE);   /* REQUIRED before emu_run */
                debug_flag(DBG_SOFT_COMMANDS, true);
                /* let the calculator boot to the OS */
                run_until_trap(200);
                printf("booted; PC=%06X\n", cpu.registers.PC);
            }
        }
        else if (!strcmp(tok, "send")) {
            char *p = strtok_r(NULL, " \t\r\n", &saveptr);
            char *loc = strtok_r(NULL, " \t\r\n", &saveptr);
            int location = (loc && !strcmp(loc, "arch")) ? LINK_ARCH : LINK_RAM;
            if (!p) { printf("usage: send <file> [ram|arch]\n"); continue; }
            int rc = emu_send_variable(p, location);
            /* The transfer runs asynchronously over emulated USB; the OS must
             * get CPU time to receive and commit the variable before the next
             * send (or an install that looks it up). Run until USB settles. */
            run_until_trap(20000);
            printf("send %s -> %s\n", p, rc == LINK_GOOD ? "ok" :
                   rc == LINK_WARN ? "warn" : "err");
        }
        else if (!strcmp(tok, "break")) {
            char *a = strtok_r(NULL, " \t\r\n", &saveptr);
            if (!a) { printf("usage: break <hexaddr>\n"); continue; }
            debug_watch(hx(a), DBG_MASK_EXEC, true);
            printf("break @ %06X\n", hx(a));
        }
        else if (!strcmp(tok, "unbreak")) {
            char *a = strtok_r(NULL, " \t\r\n", &saveptr);
            if (!a) { printf("usage: unbreak <hexaddr>\n"); continue; }
            debug_watch(hx(a), DBG_MASK_EXEC, false);
            printf("unbreak @ %06X\n", hx(a));
        }
        else if (!strcmp(tok, "watch")) {
            char *kind = strtok_r(NULL, " \t\r\n", &saveptr);
            char *a = strtok_r(NULL, " \t\r\n", &saveptr);
            char *l = strtok_r(NULL, " \t\r\n", &saveptr);
            if (!kind || !a || !l) { printf("usage: watch r|w|rw <addr> <len>\n"); continue; }
            int mask = 0;
            if (strchr(kind, 'r')) mask |= DBG_MASK_READ;
            if (strchr(kind, 'w')) mask |= DBG_MASK_WRITE;
            uint32_t base = hx(a), len = hx(l);
            for (uint32_t i = 0; i < len; i++) debug_watch(base + i, mask, true);
            printf("watch %s @ %06X len %u\n", kind, base, len);
        }
        else if (!strcmp(tok, "unwatch")) {
            char *a = strtok_r(NULL, " \t\r\n", &saveptr);
            if (!a) { printf("usage: unwatch <hexaddr>\n"); continue; }
            debug_watch(hx(a), DBG_MASK_RW, false);
            printf("unwatch @ %06X\n", hx(a));
        }
        else if (!strcmp(tok, "run")) {
            char *n = strtok_r(NULL, " \t\r\n", &saveptr);
            uint64_t ticks = n ? strtoull(n, NULL, 10) : 5000;
            run_until_trap(ticks);
            report_trap();
        }
        else if (!strcmp(tok, "runrt")) {
            /* real-time-paced run for <seconds> (needed for physical USB
             * passthrough so libusb transfers complete in step). */
            char *n = strtok_r(NULL, " \t\r\n", &saveptr);
            unsigned secs = n ? (unsigned)strtoul(n, NULL, 10) : 10;
            run_realtime((uint64_t)secs * 1000);   /* rate 1000 -> 1000 ticks/s */
            report_trap();
        }
        else if (!strcmp(tok, "step")) {
            debug_step(DBG_STEP_IN, cpu.registers.PC);
            run_until_trap(1000);
            report_trap();
        }
        else if (!strcmp(tok, "stepover")) {
            debug_step(DBG_STEP_OVER, cpu.registers.PC);
            run_until_trap(100000);
            report_trap();
        }
        else if (!strcmp(tok, "find")) {
            /* find <start> <end> <hexbytes...> -- scan memory for a byte pattern
             * via mem_peek_byte (no side effects). Prints matching addresses. */
            char *s = strtok_r(NULL, " \t\r\n", &saveptr);
            char *e = strtok_r(NULL, " \t\r\n", &saveptr);
            if (!s || !e) { printf("usage: find <start> <end> <b0> <b1>..\n"); continue; }
            uint8_t pat[32]; int plen = 0;
            char *bp;
            while (plen < 32 && (bp = strtok_r(NULL, " \t\r\n", &saveptr)))
                pat[plen++] = (uint8_t)hx(bp);
            if (!plen) { printf("need >=1 pattern byte\n"); continue; }
            uint32_t a0 = hx(s), a1 = hx(e), hits = 0;
            for (uint32_t a = a0; a + plen <= a1; a++) {
                int j = 0;
                while (j < plen && mem_peek_byte(a + j) == pat[j]) j++;
                if (j == plen) { printf("  match @ %06X\n", a); if (++hits >= 16) break; }
            }
            printf("find: %u hit(s)\n", hits);
        }
        else if (!strcmp(tok, "breakreset")) {
            /* trap into the debugger on a reset/NMI (e.g. stack-overflow crash)
             * instead of silently resetting, so we can capture the crash PC. */
            debug_flag(DBG_OPEN_ON_RESET, true);
            printf("break-on-reset armed\n");
        }
        else if (!strcmp(tok, "stacklimit")) {
            printf("control.stackLimit = %06X\n", control.stackLimit);
        }
        else if (!strcmp(tok, "time")) {
            /* emulated time: cpu.seconds + the 32K-clock tick count (what the
             * calc's clock()/sys_now reads). For diagnosing timer advancement. */
            printf("cpu.seconds=%u  cycles=%u  32K_ticks=%llu\n",
                   cpu.seconds, cpu.cycles,
                   (unsigned long long)sched_total_time(CLOCK_32K));
        }
        else if (!strcmp(tok, "usbplug")) {
            /* plug a USB device backend by name, with an optional argument:
             *   usbplug ecm
             *   usbplug physical 0BDA:8153   (real host device via libusb)
             *   usbplug msd <image>          */
            char *dev = strtok_r(NULL, " \t\r\n", &saveptr);
            char *arg = strtok_r(NULL, " \t\r\n", &saveptr);
            if (!dev) { printf("usage: usbplug <ecm|physical|msd> [arg]\n"); continue; }
            const char *argv[2]; int argc = 1;
            argv[0] = dev;
            if (arg) { argv[1] = arg; argc = 2; }
            int rc = usb_plug_device(argc, argv, NULL, NULL);
            printf("usbplug %s%s%s -> rc=%d\n", dev, arg ? " " : "",
                   arg ? arg : "", rc);
        }
        else if (!strcmp(tok, "bridge")) {
            /* enable the host network bridge (ARP/DHCP responder + NAT). */
            netbridge_init();
            printf("bridge enabled\n");
        }
        else if (!strcmp(tok, "ecminject")) {
            /* ecminject <hexbytes...> -- queue a raw ethernet frame for the
             * calc to receive on the ECM bulk IN endpoint. */
            static uint8_t fr[1600];
            int n = 0; char *bp;
            while (n < (int)sizeof fr && (bp = strtok_r(NULL, " \t\r\n", &saveptr)))
                fr[n++] = (uint8_t)hx(bp);
            if (n == 0) { printf("usage: ecminject <b0> <b1> ..\n"); continue; }
            bool ok = ecm_inject_frame(fr, (uint16_t)n);
            printf("ecminject %d bytes -> %s\n", n, ok ? "queued" : "FAILED");
        }
        else if (!strcmp(tok, "regs")) { print_regs(); }
        else if (!strcmp(tok, "peek")) {
            char *a = strtok_r(NULL, " \t\r\n", &saveptr);
            char *l = strtok_r(NULL, " \t\r\n", &saveptr);
            if (!a) { printf("usage: peek <hexaddr> <len>\n"); continue; }
            do_peek(hx(a), l ? hx(l) : 16);
        }
        else if (!strcmp(tok, "poke")) {
            char *a = strtok_r(NULL, " \t\r\n", &saveptr);
            char *v = strtok_r(NULL, " \t\r\n", &saveptr);
            if (!a || !v) { printf("usage: poke <hexaddr> <hexbyte>\n"); continue; }
            mem_poke_byte(hx(a), (uint8_t)hx(v));
            printf("poke %06X = %02X\n", hx(a), (uint8_t)hx(v));
        }
        else if (!strcmp(tok, "shot")) {
            char *p = strtok_r(NULL, " \t\r\n", &saveptr);
            do_screenshot(p ? p : "screenshot.ppm");
        }
        else if (!strcmp(tok, "key")) {
            char *r = strtok_r(NULL, " \t\r\n", &saveptr);
            char *c = strtok_r(NULL, " \t\r\n", &saveptr);
            if (!r || !c) { printf("usage: key <row> <col>\n"); continue; }
            unsigned row = (unsigned)atoi(r), col = (unsigned)atoi(c);
            emu_keypad_event(row, col, true);
            run_until_trap(2);
            emu_keypad_event(row, col, false);
            run_until_trap(2);
            printf("key %u,%u\n", row, col);
        }
        else if (!strcmp(tok, "keytok")) {
            /* inject an OS key token (hex), e.g. enter=5 clear=9 prgm=DA */
            char *k = strtok_r(NULL, " \t\r\n", &saveptr);
            if (!k) { printf("usage: keytok <hextoken>\n"); continue; }
            inject_key((uint16_t)hx(k));
            printf("keytok %s\n", k);
        }
        else if (!strcmp(tok, "csc")) {
            /* inject a raw scan code (hex) into the os_GetCSC buffer; this is
             * what ASM programs (installer, DYLRSA) poll. enter=09 clear=0F
             * 2nd=36 left=02 right=03 up=04 down=01 (sk_* codes). */
            char *k = strtok_r(NULL, " \t\r\n", &saveptr);
            if (!k) { printf("usage: csc <hexscancode>\n"); continue; }
            for (int tries = 0; tries < 50; tries++) {
                if (sendCSC((uint8_t)hx(k))) break;
                run_until_trap(50);
            }
            run_until_trap(2000);   /* let the program consume the key */
            printf("csc %s -> PC=%06X\n", k, cpu.registers.PC);
        }
        else if (!strcmp(tok, "launch")) {
            /* launch <NAME> [asm]  -- types NAME after prgm and presses enter */
            char *name = strtok_r(NULL, " \t\r\n", &saveptr);
            char *mode = strtok_r(NULL, " \t\r\n", &saveptr);
            if (!name) { printf("usage: launch <NAME> [asm]\n"); continue; }
            bool is_asm = (mode && !strcmp(mode, "asm"));
            launch_program(name, is_asm);
            printf("launch %s%s -> PC=%06X\n", name, is_asm ? " (asm)" : "",
                   cpu.registers.PC);
        }
        else {
            printf("unknown command '%s' (try 'help')\n", tok);
        }
        fflush(stdout);
    }

    debug_free();
    emu_exit();
    if (script != stdin) fclose(script);
    return 0;
}
