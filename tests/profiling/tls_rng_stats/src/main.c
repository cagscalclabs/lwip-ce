/**
 * @file main.c
 * @brief Collect repeated diagnostic windows from the selected raw RNG tap.
 *
 * The output AppVar is deliberately textual so it can be inspected directly
 * or processed by tools/analyze_rng_stats.py.  Entropy estimates belong in
 * the host-side analyzer: floating-point logarithms add no value to the
 * calculator-side sampler and would make the measurement program larger.
 */

#include <fileioc.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <ti/getkey.h>
#include <ti/screen.h>

#include <lwip/cryptography/random.h>
#include <lwip.h>

#define RNG_STATS_APPVAR "RNGSTATS"
#define RNG_STATS_RUNS 8u
#define RNG_STATS_SAMPLES_PER_RUN 32768u
#define RNG_READY_TIMEOUT_MS 15000u

static uint8_t output_handle;

static bool output_open(void)
{
    (void)ti_Delete(RNG_STATS_APPVAR);
    output_handle = ti_Open(RNG_STATS_APPVAR, "w");
    return output_handle != 0u;
}

static bool output_line(const char *format, ...)
{
    char line[512];
    va_list args;
    int length;

    va_start(args, format);
    length = vsnprintf(line, sizeof(line), format, args);
    va_end(args);

    if ((length <= 0) || ((size_t)length >= sizeof(line)))
    {
        return false;
    }

    return ti_Write(line, (size_t)length, 1u, output_handle) == 1u;
}

static void output_close(bool archive)
{
    if (output_handle == 0u)
    {
        return;
    }

    if (archive)
    {
        (void)ti_SetArchiveStatus(true, output_handle);
    }
    (void)ti_Close(output_handle);
    output_handle = 0u;
    if (!archive)
    {
        (void)ti_Delete(RNG_STATS_APPVAR);
    }
}

static void print_q16_percent(const char *label, uint32_t value)
{
    uint32_t percent_x100 = (value * 10000u + 32768u) >> 16;
    printf("%s%lu.%02lu%%\n",
           label,
           (unsigned long)(percent_x100 / 100u),
           (unsigned long)(percent_x100 % 100u));
}

int main(void)
{
    struct tls_rng_stats stats;
    uint8_t random_probe[8];
    uint8_t run;
    bool ok = true;

    os_ClrHome();
    printf("TLS RNG tap profile\n");

    if (!lwip_start())
    {
        printf("lwip_start failed: %u\n", (unsigned int)lwip_start_last_error());
        printf("Press any key\n");
        os_GetKey();
        return 1;
    }

    if (!lwip_tls_rng_wait_for_ready(TLS_RNG_STRENGTH_192,
                                     RNG_READY_TIMEOUT_MS))
    {
        printf("RNG setup timed out\n");
        lwip_stop();
        printf("Press any key\n");
        os_GetKey();
        return 1;
    }

    /* Exercise the same checked assembly sampling path used by callers of
     * the public RNG API before collecting raw diagnostic observations. */
    if (tls_random_bytes(random_probe, sizeof(random_probe)) == NULL)
    {
        printf("random source failed\n");
        lwip_stop();
        printf("Press any key\n");
        os_GetKey();
        return 1;
    }

    if (!output_open())
    {
        printf("cannot open %s\n", RNG_STATS_APPVAR);
        lwip_stop();
        printf("Press any key\n");
        os_GetKey();
        return 1;
    }

    ok = output_line(
        "rng_stats,version=4,runs=%u,samples_per_run=%lu,lags=4,"
        "rct_cutoff=%u,apt_window=%u,apt_cutoff=%u\n",
        (unsigned int)RNG_STATS_RUNS,
        (unsigned long)RNG_STATS_SAMPLES_PER_RUN,
        (unsigned int)TLS_RNG_STATS_RCT_CUTOFF,
        (unsigned int)TLS_RNG_STATS_APT_WINDOW,
        (unsigned int)TLS_RNG_STATS_APT_CUTOFF);

    for (run = 0u; ok && (run < RNG_STATS_RUNS); run++)
    {
        os_ClrHome();
        printf("TLS RNG tap profile\n");
        printf("window %u/%u\n",
               (unsigned int)(run + 1u),
               (unsigned int)RNG_STATS_RUNS);

        if (!tls_rng_compute_stats(RNG_STATS_SAMPLES_PER_RUN, &stats))
        {
            ok = false;
            break;
        }

        ok = output_line(
            "run=%u,source=%06lX,mask=%02X,samples=%lu,ones=%lu,zeros=%lu,"
            "transitions=%lu,n00=%lu,n01=%lu,n10=%lu,n11=%lu,"
            "lag1_mismatches=%lu,lag2_mismatches=%lu,"
            "lag3_mismatches=%lu,lag4_mismatches=%lu,"
            "longest=%lu,longest0=%lu,longest1=%lu,"
            "p1_q16=%lu,bias_q16=%lu,transition_q16=%lu\n",
            (unsigned int)run,
            (unsigned long)stats.source_address,
            (unsigned int)stats.source_mask,
            (unsigned long)stats.sample_count,
            (unsigned long)stats.ones,
            (unsigned long)stats.zeros,
            (unsigned long)stats.transitions,
            (unsigned long)stats.pairs_00,
            (unsigned long)stats.pairs_01,
            (unsigned long)stats.pairs_10,
            (unsigned long)stats.pairs_11,
            (unsigned long)stats.lag_mismatches[0],
            (unsigned long)stats.lag_mismatches[1],
            (unsigned long)stats.lag_mismatches[2],
            (unsigned long)stats.lag_mismatches[3],
            (unsigned long)stats.longest_run,
            (unsigned long)stats.longest_zero_run,
            (unsigned long)stats.longest_one_run,
            (unsigned long)stats.p1_q16,
            (unsigned long)stats.bias_q16,
            (unsigned long)stats.transition_rate_q16);

        if (ok)
        {
            ok = output_line(
                "health_run=%u,evaluated=%02X,passed=%02X,rct_failures=%lu,"
                "apt_windows=%lu,apt_failures=%lu,apt_min_ones=%lu,"
                "apt_max_ones=%lu,startup_marginal_failures=%lu,"
                "distribution_windows=%lu,distribution_failures=%lu,"
                "distribution_min_ones=%lu,distribution_max_ones=%lu,"
                "distribution_min_disagreements=%lu,"
                "distribution_max_disagreements=%lu\n",
                (unsigned int)run,
                (unsigned int)stats.health_tests_evaluated,
                (unsigned int)stats.health_tests_passed,
                (unsigned long)stats.rct_failure_runs,
                (unsigned long)stats.apt_windows,
                (unsigned long)stats.apt_failures,
                (unsigned long)stats.apt_min_ones,
                (unsigned long)stats.apt_max_ones,
                (unsigned long)stats.startup_marginal_failures,
                (unsigned long)stats.distribution_windows,
                (unsigned long)stats.distribution_failures,
                (unsigned long)stats.distribution_min_ones,
                (unsigned long)stats.distribution_max_ones,
                (unsigned long)stats.distribution_min_disagreements,
                (unsigned long)stats.distribution_max_disagreements);
        }
        if (ok)
        {
            ok = output_line(
                "lag_health_run=%u,lag1_failures=%lu,lag1_min=%lu,lag1_max=%lu,"
                "lag2_failures=%lu,lag2_min=%lu,lag2_max=%lu,"
                "lag3_failures=%lu,lag3_min=%lu,lag3_max=%lu,"
                "lag4_failures=%lu,lag4_min=%lu,lag4_max=%lu\n",
                (unsigned int)run,
                (unsigned long)stats.lag_window_failures[0],
                (unsigned long)stats.lag_window_min_mismatches[0],
                (unsigned long)stats.lag_window_max_mismatches[0],
                (unsigned long)stats.lag_window_failures[1],
                (unsigned long)stats.lag_window_min_mismatches[1],
                (unsigned long)stats.lag_window_max_mismatches[1],
                (unsigned long)stats.lag_window_failures[2],
                (unsigned long)stats.lag_window_min_mismatches[2],
                (unsigned long)stats.lag_window_max_mismatches[2],
                (unsigned long)stats.lag_window_failures[3],
                (unsigned long)stats.lag_window_min_mismatches[3],
                (unsigned long)stats.lag_window_max_mismatches[3]);
        }

        printf("src %06lX mask %02X\n",
               (unsigned long)stats.source_address,
               (unsigned int)stats.source_mask);
        print_q16_percent("p(1) ", stats.p1_q16);
        print_q16_percent("bias ", stats.bias_q16);
    }

    output_close(ok);
    lwip_stop();

    os_ClrHome();
    if (ok)
    {
        printf("Profile complete\n");
        printf("Saved %s\n", RNG_STATS_APPVAR);
        printf("%lu raw bits\n",
               (unsigned long)RNG_STATS_RUNS * RNG_STATS_SAMPLES_PER_RUN);
    }
    else
    {
        printf("Profile failed\n");
        printf("partial output discarded\n");
    }
    printf("Press any key\n");
    os_GetKey();
    return ok ? 0 : 1;
}
