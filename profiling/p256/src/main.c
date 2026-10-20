/*
 * P-256 assembly profiling target (standalone; see ../Makefile).
 *
 * Times tls_p256_publickey (a full 256-step ladder on G plus the affine
 * export) and the field/point primitives it is built from, using hardware
 * timer 1 clocked from the CPU clock, so every figure is in CPU cycles.
 * Milliseconds assume the stock 48 MHz clock.
 *
 * The keygen result is checked against the RFC 5903 section 8.1 initiator
 * key pair.  Results go to the home screen (and to the emulator console in
 * `make debug` builds).  Press any key to exit.
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <debug.h>
#include <sys/timers.h>
#include <ti/screen.h>
#include <ti/getcsc.h>

bool tls_p256_publickey(uint8_t public_key[65], const uint8_t private_key[32]);
/* Test shims, assembled with --defsym P256_TEST=1 (C ABI; 0 = mod p). */
void p256_test_mont_mul(uint8_t *out, const uint8_t *a, const uint8_t *b, uint8_t use_n);
void p256_test_mod_add(uint8_t *out, const uint8_t *a, const uint8_t *b, uint8_t use_n);
void p256_test_mod_sub(uint8_t *out, const uint8_t *a, const uint8_t *b, uint8_t use_n);
void p256_test_point_double(uint8_t out[96], const uint8_t in[96]);
void p256_test_point_add(uint8_t out[96], const uint8_t p[96], const uint8_t q[96]);

/* RFC 5903 section 8.1, initiator. */
static const uint8_t priv[32] = {
    0xc8,0x8f,0x01,0xf5,0x10,0xd9,0xac,0x3f,0x70,0xa2,0x92,0xda,0xa2,0x31,0x6d,0xe5,
    0x44,0xe9,0xaa,0xb8,0xaf,0xe8,0x40,0x49,0xc6,0x2a,0x9c,0x57,0x86,0x2d,0x14,0x33
};
static const uint8_t pub_expected[65] = {
    0x04,0xda,0xd0,0xb6,0x53,0x94,0x22,0x1c,0xf9,0xb0,0x51,0xe1,0xfe,0xca,0x57,0x87,
    0xd0,0x98,0xdf,0xe6,0x37,0xfc,0x90,0xb9,0xef,0x94,0x5d,0x0c,0x37,0x72,0x58,0x11,
    0x80,0x52,0x71,0xa0,0x46,0x1c,0xdb,0x82,0x52,0xd6,0x1f,0x1c,0x45,0x6f,0xa3,0xe5,
    0x9a,0xb1,0xf4,0x5b,0x33,0xac,0xcf,0x5f,0x58,0x38,0x9e,0x05,0x77,0xb8,0x99,0x0b,0xb3
};

/* Arbitrary operands below p (the public key's x/y/z happen to qualify). */
static uint8_t opa[96], opb[96], out[96], pub[65];

static void timer_start(void)
{
    timer_Disable(1);
    timer_Set(1, 0);
    timer_Enable(1, TIMER_CPU, TIMER_NOINT, TIMER_UP);
}

static uint32_t timer_cycles(void)
{
    return timer_GetSafe(1, TIMER_UP);
}

static void report(const char *name, uint32_t cycles)
{
    printf("%-8s%9lu cc\n", name, (unsigned long)cycles);
    dbg_printf("%s: %lu cycles\n", name, (unsigned long)cycles);
}

int main(void)
{
    uint32_t c, ms;
    bool ok;

    os_ClrHome();
    puts("P-256 profiling");

    /* Operands: x/y of the expected public key, reversed to LE (< p). */
    for (uint8_t i = 0; i < 32; i++) {
        opa[i]      = pub_expected[32 - i];
        opa[32 + i] = pub_expected[64 - i];
        opa[64 + i] = pub_expected[32 - i] ^ pub_expected[64 - i];
    }
    opa[95] &= 0x7f;                      /* keep z < p */
    memcpy(opb, opa + 32, 64);
    memcpy(opb + 64, opa, 32);

    timer_start(); p256_test_mont_mul(out, opa, opb, 0); report("mont_mul", timer_cycles());
    timer_start(); p256_test_mod_add(out, opa, opb, 0);  report("mod_add", timer_cycles());
    timer_start(); p256_test_mod_sub(out, opa, opb, 0);  report("mod_sub", timer_cycles());
    timer_start(); p256_test_point_double(out, opa);     report("pt_dbl", timer_cycles());
    timer_start(); p256_test_point_add(out, opa, opb);   report("pt_add", timer_cycles());

    timer_start();
    ok = tls_p256_publickey(pub, priv);
    c = timer_cycles();
    ok = ok && memcmp(pub, pub_expected, sizeof pub) == 0;
    ms = c / 48000;
    report("keygen", c);
    printf("P-256 keygen: %lums %s\n", (unsigned long)ms, ok ? "PASS" : "FAIL");
    dbg_printf("P-256 keygen: %lums %s\n", (unsigned long)ms, ok ? "PASS" : "FAIL");

    puts("Press any key");
    while (!os_GetCSC())
        ;
    return ok ? 0 : 1;
}
