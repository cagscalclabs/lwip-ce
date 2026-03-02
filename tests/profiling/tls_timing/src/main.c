#include <fileioc.h>
#include <ti/getkey.h>
#include <ti/screen.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "aes.h"
#include "bytes.h"
#include "hash.h"
#include "hkdf.h"
#include "hmac.h"
#include "passwords.h"
#include "x25519.h"

#define TIMING_SAMPLES 20u
#define TIMING_REPS_FAST 128u
#define TIMING_REPS_MEDIUM 64u
#define TIMING_REPS_SLOW 16u

#define STABILITY_MAX_PCT_X100 100u
#define MAD_SIGMA_SCALE_X10000 14826u
#define MAD_ACCEPT_C 6u
#define MAD_ACCEPT_C_RIGOROUS 4u
#define DIFF_CONSISTENCY_NUM 3u
#define DIFF_CONSISTENCY_DEN 4u
#define TIMING_LOG_APPVAR "TLSTMLOG"
#define TIMING_CALIB_CLASS TIMING_CLASS_BEST

enum timing_input_class
{
    TIMING_CLASS_BEST = 0,
    TIMING_CLASS_WORST = 1,
    TIMING_CLASS_RANDOM = 2,
    TIMING_CLASS_EDGE = 3,
    TIMING_CLASS_COUNT = 4
};

static volatile uint8_t timing_sink;
static uint32_t timing_prng_state = 0x12345678u;
static uint8_t timing_log_handle;
static bool timing_log_enabled;

struct primitive_result
{
    uint32_t stability_mean;
    uint32_t stability_stddev;
    uint32_t stability_pct_x100;
    uint32_t stability_median;
    uint32_t stability_mad;
    uint32_t stability_sigma_x10000;
    uint32_t accepted_deviation;
    uint32_t accepted_deviation_rigorous;
    bool stability_pass;

    uint32_t class_means[TIMING_CLASS_COUNT];
    uint32_t class_medians[TIMING_CLASS_COUNT];
    uint32_t class_over_thresh_pct_x100[TIMING_CLASS_COUNT];
    uint32_t class_over_thresh_pct_x100_rigorous[TIMING_CLASS_COUNT];
    uint32_t max_pair_diff;
    bool differential_pass;

    bool fail;
};

static void show_progress(const char *name, uint16_t step, uint16_t total)
{
    uint8_t filled;
    uint8_t bar_width = 24u;
    uint8_t i;
    uint32_t pct_x100 = (total != 0) ? (uint32_t)(((uint32_t)step * 10000u) / total) : 0;

    if (total == 0)
    {
        total = 1;
    }

    filled = (uint8_t)((uint32_t)bar_width * step / total);

    os_ClrHome();
    printf("Running %s...\n", name);
    putchar('(');
    for (i = 0; i < bar_width; i++)
    {
        putchar((i < filled) ? '#' : '.');
    }
    putchar(')');
    printf("\n%lu.%02lu%%\n", (unsigned long)(pct_x100 / 100u), (unsigned long)(pct_x100 % 100u));
    printf("sample %u/%u", step, total);
}

static uint32_t prng_next(void)
{
    uint32_t x = timing_prng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    timing_prng_state = x;
    return x;
}

static uint32_t abs_u32_diff(uint32_t a, uint32_t b)
{
    return (a >= b) ? (a - b) : (b - a);
}

static uint32_t mean_u32(const uint32_t *samples, uint16_t count)
{
    uint64_t sum = 0;
    uint16_t i;

    for (i = 0; i < count; i++)
    {
        sum += samples[i];
    }

    return (count != 0) ? (uint32_t)(sum / count) : 0;
}

static void sort_u32(uint32_t *values, uint16_t count)
{
    uint16_t i;

    for (i = 1; i < count; i++)
    {
        uint32_t key = values[i];
        uint16_t j = i;
        while (j > 0 && values[j - 1] > key)
        {
            values[j] = values[j - 1];
            j--;
        }
        values[j] = key;
    }
}

static uint32_t median_u32(const uint32_t *samples, uint16_t count)
{
    uint32_t work[TIMING_SAMPLES];
    uint16_t i;

    if (count == 0)
    {
        return 0;
    }

    for (i = 0; i < count; i++)
    {
        work[i] = samples[i];
    }
    sort_u32(work, count);

    if ((count & 1u) != 0u)
    {
        return work[count / 2u];
    }

    return (uint32_t)(((uint64_t)work[(count / 2u) - 1u] + (uint64_t)work[count / 2u]) / 2u);
}

static uint32_t isqrt_u64(uint64_t x)
{
    uint64_t op = x;
    uint64_t res = 0;
    uint64_t one = (uint64_t)1 << 62;

    while (one > op)
    {
        one >>= 2;
    }

    while (one != 0)
    {
        if (op >= res + one)
        {
            op -= res + one;
            res = (res >> 1) + one;
        }
        else
        {
            res >>= 1;
        }
        one >>= 2;
    }

    return (uint32_t)res;
}

static void compute_stats(const uint32_t *samples, uint16_t count,
                          uint32_t *mean, uint32_t *stddev, uint32_t *pct_x100)
{
    uint32_t local_mean;
    uint64_t var_sum = 0;
    uint16_t i;

    local_mean = mean_u32(samples, count);

    for (i = 0; i < count; i++)
    {
        int64_t diff = (int64_t)samples[i] - (int64_t)local_mean;
        var_sum += (uint64_t)(diff * diff);
    }

    *mean = local_mean;
    *stddev = (count != 0) ? isqrt_u64(var_sum / count) : 0;
    *pct_x100 = (local_mean != 0) ? (uint32_t)(((uint64_t)(*stddev) * 10000u) / local_mean) : 0;
}

static void compute_robust_stats(const uint32_t *samples, uint16_t count,
                                 uint32_t *median, uint32_t *mad, uint32_t *sigma_x10000)
{
    uint32_t abs_dev[TIMING_SAMPLES];
    uint16_t i;

    *median = median_u32(samples, count);
    for (i = 0; i < count; i++)
    {
        abs_dev[i] = abs_u32_diff(samples[i], *median);
    }
    *mad = median_u32(abs_dev, count);
    *sigma_x10000 = (uint32_t)(((uint64_t)(*mad) * MAD_SIGMA_SCALE_X10000) / 1u);
}

static uint32_t robust_accept_deviation(uint32_t sigma_x10000, uint32_t c_factor)
{
    uint32_t threshold = (uint32_t)(((uint64_t)sigma_x10000 * c_factor + 5000u) / 10000u);
    if (threshold < c_factor)
    {
        threshold = c_factor;
    }
    return threshold;
}

static const char *class_name(uint16_t class_id)
{
    switch (class_id)
    {
    case TIMING_CLASS_BEST:
        return "best";
    case TIMING_CLASS_WORST:
        return "worst";
    case TIMING_CLASS_RANDOM:
        return "random";
    case TIMING_CLASS_EDGE:
        return "edge";
    default:
        return "unknown";
    }
}

static bool timing_log_begin(void)
{
    (void)ti_Delete(TIMING_LOG_APPVAR);
    timing_log_handle = ti_Open(TIMING_LOG_APPVAR, "w");
    if (!timing_log_handle)
    {
        timing_log_enabled = false;
        return false;
    }

    timing_log_enabled = true;
    (void)ti_SetArchiveStatus(false, timing_log_handle);
    return true;
}

static void timing_log_end(void)
{
    if (!timing_log_handle)
    {
        return;
    }

    if (timing_log_enabled)
    {
        (void)ti_SetArchiveStatus(true, timing_log_handle);
    }
    ti_Close(timing_log_handle);
    timing_log_handle = 0;
    timing_log_enabled = false;
}

static void timing_logf(const char *fmt, ...)
{
    char line[192];
    int written;
    va_list args;

    if (!timing_log_enabled || !timing_log_handle)
    {
        return;
    }

    va_start(args, fmt);
    written = vsnprintf(line, sizeof(line), fmt, args);
    va_end(args);

    if (written <= 0)
    {
        return;
    }
    if ((size_t)written >= sizeof(line))
    {
        written = (int)(sizeof(line) - 1u);
    }

    if (ti_Write(line, (size_t)written, 1, timing_log_handle) != 1)
    {
        timing_log_enabled = false;
    }
}

static void fill_pattern(uint8_t *buf, size_t len, uint8_t input_class)
{
    size_t i;
    uint32_t r;

    switch (input_class)
    {
    case TIMING_CLASS_BEST:
        memset(buf, 0x00, len);
        break;
    case TIMING_CLASS_WORST:
        memset(buf, 0xFF, len);
        break;
    case TIMING_CLASS_RANDOM:
        for (i = 0; i < len; i++)
        {
            r = prng_next();
            buf[i] = (uint8_t)r;
        }
        break;
    case TIMING_CLASS_EDGE:
        for (i = 0; i < len; i++)
        {
            if (i < (len / 2u))
            {
                buf[i] = 0x00;
            }
            else
            {
                buf[i] = 0xFF;
            }
        }
        if (len > 0)
        {
            buf[len / 2u] ^= 0x7F;
        }
        break;
    default:
        memset(buf, 0xAA, len);
        break;
    }
}

static uint32_t time_bytes_compare_case(uint8_t input_class)
{
    uint8_t a[64];
    uint8_t b[64];
    bool eq;
    uint8_t mismatch_idx;
    clock_t start;

    fill_pattern(a, sizeof(a), TIMING_CLASS_EDGE);
    memcpy(b, a, sizeof(a));

    switch (input_class)
    {
    case TIMING_CLASS_BEST:
        break;
    case TIMING_CLASS_WORST:
        b[0] ^= 0x01;
        break;
    case TIMING_CLASS_RANDOM:
        mismatch_idx = (uint8_t)(prng_next() % sizeof(a));
        b[mismatch_idx] ^= 0x01;
        break;
    case TIMING_CLASS_EDGE:
        b[sizeof(a) - 1] ^= 0x01;
        break;
    default:
        break;
    }

    start = clock();
    eq = tls_bytes_compare(a, b, sizeof(a));
    timing_sink ^= (uint8_t)eq;
    return (uint32_t)(clock() - start);
}

static uint32_t time_sha256_case(uint8_t input_class)
{
    uint8_t msg[128];
    uint8_t digest[TLS_SHA256_DIGEST_LEN];
    struct tls_hash_context ctx;
    bool ok;
    clock_t start;

    fill_pattern(msg, sizeof(msg), input_class);

    start = clock();
    ok = tls_hash_context_init(&ctx, TLS_HASH_SHA256);
    if (!ok)
    {
        timing_sink ^= 0xA1;
        return (uint32_t)(clock() - start);
    }
    tls_hash_update(&ctx, msg, sizeof(msg));
    tls_hash_digest(&ctx, digest);
    timing_sink ^= digest[0];

    return (uint32_t)(clock() - start);
}

static uint32_t time_hmac_case(uint8_t input_class)
{
    static const uint8_t key[32] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F};
    uint8_t msg[128];
    struct tls_hmac_context ctx;
    uint8_t digest[TLS_SHA256_DIGEST_LEN];
    bool ok;
    clock_t start;

    fill_pattern(msg, sizeof(msg), input_class);

    start = clock();
    ok = tls_hmac_context_init(&ctx, TLS_HASH_SHA256, key, sizeof(key));
    if (!ok)
    {
        timing_sink ^= 0xA2;
        return (uint32_t)(clock() - start);
    }
    tls_hmac_update(&ctx, msg, sizeof(msg));
    tls_hmac_digest(&ctx, digest);
    timing_sink ^= digest[0];

    return (uint32_t)(clock() - start);
}

static uint32_t time_hkdf_case(uint8_t input_class)
{
    uint8_t salt[32];
    uint8_t ikm[32];
    uint8_t info[32];
    uint8_t prk[32];
    uint8_t okm[64];
    bool ok;
    clock_t start;

    fill_pattern(salt, sizeof(salt), input_class);
    fill_pattern(ikm, sizeof(ikm), input_class);
    fill_pattern(info, sizeof(info), input_class);

    start = clock();
    ok = tls_hkdf_extract(TLS_HASH_SHA256, salt, sizeof(salt), ikm, sizeof(ikm), prk);
    ok = ok && tls_hkdf_expand(TLS_HASH_SHA256, prk, sizeof(prk), info, sizeof(info), okm, sizeof(okm));
    if (!ok)
    {
        timing_sink ^= 0xA3;
        return (uint32_t)(clock() - start);
    }

    timing_sink ^= okm[0];
    return (uint32_t)(clock() - start);
}

static uint32_t time_pbkdf2_case(uint8_t input_class)
{
    static const uint8_t salt[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    char password[16];
    uint8_t key[32];
    bool ok;
    clock_t start;

    switch (input_class)
    {
    case TIMING_CLASS_BEST:
        memset(password, 'a', sizeof(password));
        break;
    case TIMING_CLASS_WORST:
        memset(password, 'Z', sizeof(password));
        break;
    case TIMING_CLASS_RANDOM:
    {
        uint8_t i;
        for (i = 0; i < sizeof(password); i++)
        {
            password[i] = (char)('a' + (prng_next() % 26u));
        }
    }
    break;
    case TIMING_CLASS_EDGE:
        memset(password, 0, sizeof(password));
        password[0] = 'A';
        password[sizeof(password) - 1] = 'z';
        break;
    default:
        memset(password, 'x', sizeof(password));
        break;
    }

    start = clock();
    ok = tls_pbkdf2(password,
                    sizeof(password),
                    salt,
                    sizeof(salt),
                    key,
                    sizeof(key),
                    128,
                    TLS_HASH_SHA256);
    if (!ok)
    {
        timing_sink ^= 0xA4;
        return (uint32_t)(clock() - start);
    }

    timing_sink ^= key[0];
    return (uint32_t)(clock() - start);
}

static uint32_t time_aes_gcm_encrypt_case(uint8_t input_class)
{
    static const uint8_t key[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    static const uint8_t iv[12] = {
        0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B};
    static const uint8_t aad[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE};
    uint8_t pt[64];
    uint8_t ct[64];
    uint8_t tag[TLS_AES_AUTH_TAG_SIZE];
    struct tls_aes_context ctx;
    bool ok;
    clock_t start;

    fill_pattern(pt, sizeof(pt), input_class);

    start = clock();
    ok = tls_aes_init(&ctx, TLS_AES_GCM, key, sizeof(key), iv, sizeof(iv));
    ok = ok && tls_aes_update_aad(&ctx, aad, sizeof(aad));
    ok = ok && tls_aes_encrypt(&ctx, pt, sizeof(pt), ct);
    ok = ok && tls_aes_digest(&ctx, tag);
    if (!ok)
    {
        timing_sink ^= 0xA5;
        return (uint32_t)(clock() - start);
    }

    timing_sink ^= ct[0] ^ tag[0];
    return (uint32_t)(clock() - start);
}

static uint32_t time_aes_gcm_decrypt_verify_case(uint8_t input_class)
{
    static const uint8_t key[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    static const uint8_t iv[12] = {
        0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B};
    static const uint8_t aad[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE};
    uint8_t pt[64];
    uint8_t recovered[64];
    uint8_t ct[64];
    uint8_t tag[TLS_AES_AUTH_TAG_SIZE];
    struct tls_aes_context enc;
    struct tls_aes_context dec;
    bool ok;
    clock_t start;

    fill_pattern(pt, sizeof(pt), input_class);

    ok = tls_aes_init(&enc, TLS_AES_GCM, key, sizeof(key), iv, sizeof(iv));
    ok = ok && tls_aes_update_aad(&enc, aad, sizeof(aad));
    ok = ok && tls_aes_encrypt(&enc, pt, sizeof(pt), ct);
    ok = ok && tls_aes_digest(&enc, tag);
    if (!ok)
    {
        timing_sink ^= 0xA6;
        return 0;
    }

    start = clock();
    ok = tls_aes_init(&dec, TLS_AES_GCM, key, sizeof(key), iv, sizeof(iv));
    ok = ok && tls_aes_verify(&dec, aad, sizeof(aad), ct, sizeof(ct), tag);
    if (ok)
    {
        ok = tls_aes_init(&dec, TLS_AES_GCM, key, sizeof(key), iv, sizeof(iv));
        ok = ok && tls_aes_update_aad(&dec, aad, sizeof(aad));
        ok = ok && tls_aes_decrypt(&dec, ct, sizeof(ct), recovered);
    }
    if (!ok)
    {
        timing_sink ^= 0xA7;
        return (uint32_t)(clock() - start);
    }

    timing_sink ^= recovered[0];
    return (uint32_t)(clock() - start);
}

static uint32_t time_aes_cbc_encrypt_case(uint8_t input_class)
{
    static const uint8_t key[16] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xF0, 0x10};
    static const uint8_t iv[16] = {
        0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
        0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01};
    uint8_t pt[64];
    uint8_t ct[64];
    struct tls_aes_context ctx;
    bool ok;
    clock_t start;

    fill_pattern(pt, sizeof(pt), input_class);

    start = clock();
    ok = tls_aes_init(&ctx, TLS_AES_CBC, key, sizeof(key), iv, sizeof(iv));
    ok = ok && tls_aes_encrypt(&ctx, pt, sizeof(pt), ct);
    if (!ok)
    {
        timing_sink ^= 0xA8;
        return (uint32_t)(clock() - start);
    }

    timing_sink ^= ct[0];
    return (uint32_t)(clock() - start);
}

static uint32_t time_aes_cbc_decrypt_case(uint8_t input_class)
{
    static const uint8_t key[16] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xF0, 0x10};
    static const uint8_t iv[16] = {
        0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
        0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01};
    uint8_t pt[64];
    uint8_t ct[64];
    uint8_t recovered[64];
    struct tls_aes_context enc;
    struct tls_aes_context dec;
    bool ok;
    clock_t start;

    fill_pattern(pt, sizeof(pt), input_class);

    ok = tls_aes_init(&enc, TLS_AES_CBC, key, sizeof(key), iv, sizeof(iv));
    ok = ok && tls_aes_encrypt(&enc, pt, sizeof(pt), ct);
    if (!ok)
    {
        timing_sink ^= 0xA9;
        return 0;
    }

    start = clock();
    ok = tls_aes_init(&dec, TLS_AES_CBC, key, sizeof(key), iv, sizeof(iv));
    ok = ok && tls_aes_decrypt(&dec, ct, sizeof(ct), recovered);
    if (!ok)
    {
        timing_sink ^= 0xAA;
        return (uint32_t)(clock() - start);
    }

    timing_sink ^= recovered[0];
    return (uint32_t)(clock() - start);
}

static uint32_t time_aes_ccm_encrypt_case(uint8_t input_class)
{
    static const uint8_t key[16] = {
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F};
    static const uint8_t nonce[12] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B};
    static const uint8_t aad[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    uint8_t pt[64];
    uint8_t ct[64];
    uint8_t tag[TLS_AES_AUTH_TAG_SIZE];
    bool ok;
    clock_t start;

    fill_pattern(pt, sizeof(pt), input_class);

    start = clock();
    ok = tls_aes_ccm_encrypt(key, sizeof(key),
                             nonce, sizeof(nonce),
                             aad, sizeof(aad),
                             pt, sizeof(pt),
                             ct, tag, TLS_AES_AUTH_TAG_SIZE);
    if (!ok)
    {
        timing_sink ^= 0xAC;
        return (uint32_t)(clock() - start);
    }

    timing_sink ^= ct[0] ^ tag[0];
    return (uint32_t)(clock() - start);
}

static uint32_t time_aes_ccm_decrypt_case(uint8_t input_class)
{
    static const uint8_t key[16] = {
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F};
    static const uint8_t nonce[12] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B};
    static const uint8_t aad[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    uint8_t pt[64];
    uint8_t recovered[64];
    uint8_t ct[64];
    uint8_t tag[TLS_AES_AUTH_TAG_SIZE];
    bool ok;
    clock_t start;

    fill_pattern(pt, sizeof(pt), input_class);

    ok = tls_aes_ccm_encrypt(key, sizeof(key),
                             nonce, sizeof(nonce),
                             aad, sizeof(aad),
                             pt, sizeof(pt),
                             ct, tag, TLS_AES_AUTH_TAG_SIZE);
    if (!ok)
    {
        timing_sink ^= 0xAD;
        return 0;
    }

    start = clock();
    ok = tls_aes_ccm_decrypt(key, sizeof(key),
                             nonce, sizeof(nonce),
                             aad, sizeof(aad),
                             ct, sizeof(ct),
                             tag, TLS_AES_AUTH_TAG_SIZE,
                             recovered);
    if (!ok)
    {
        timing_sink ^= 0xAE;
        return (uint32_t)(clock() - start);
    }

    timing_sink ^= recovered[0];
    return (uint32_t)(clock() - start);
}

static uint32_t time_x25519_case(uint8_t input_class)
{
    static const uint8_t private_best[32] = {
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
        0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
        0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
        0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a};
    static const uint8_t private_worst[32] = {
        0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
        0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
        0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
        0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb};
    static const uint8_t peer_public[32] = {
        0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
        0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
        0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
        0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f};
    uint8_t private_random[32];
    uint8_t private_edge[32];
    uint8_t secret[32];
    const uint8_t *priv;
    bool ok;
    clock_t start;

    fill_pattern(private_random, sizeof(private_random), TIMING_CLASS_RANDOM);
    fill_pattern(private_edge, sizeof(private_edge), TIMING_CLASS_EDGE);

    switch (input_class)
    {
    case TIMING_CLASS_BEST:
        priv = private_best;
        break;
    case TIMING_CLASS_WORST:
        priv = private_worst;
        break;
    case TIMING_CLASS_RANDOM:
        priv = private_random;
        break;
    case TIMING_CLASS_EDGE:
        priv = private_edge;
        break;
    default:
        priv = private_best;
        break;
    }

    start = clock();
    ok = tls_x25519_secret(secret, priv, peer_public, NULL, NULL);
    if (!ok)
    {
        timing_sink ^= 0xAB;
        return (uint32_t)(clock() - start);
    }

    timing_sink ^= secret[0];
    return (uint32_t)(clock() - start);
}

static void run_primitive(const char *name, uint32_t (*fn)(uint8_t), uint16_t reps,
                          struct primitive_result *out)
{
    uint32_t samples[TIMING_CLASS_COUNT][TIMING_SAMPLES];
    uint16_t class_id;
    uint16_t i;
    uint16_t r;
    uint32_t acc;
    uint16_t total_steps = (uint16_t)(TIMING_CLASS_COUNT * TIMING_SAMPLES);
    uint16_t step = 0;

    for (class_id = 0; class_id < TIMING_CLASS_COUNT; class_id++)
    {
        (void)fn((uint8_t)class_id);
        (void)fn((uint8_t)class_id);
    }
    show_progress(name, 0, total_steps);
    timing_logf("primitive=%s,reps=%u,samples=%u\n", name, (unsigned int)reps, (unsigned int)TIMING_SAMPLES);

    for (i = 0; i < TIMING_SAMPLES; i++)
    {
        for (class_id = 0; class_id < TIMING_CLASS_COUNT; class_id++)
        {
            acc = 0;
            for (r = 0; r < reps; r++)
            {
                acc += fn((uint8_t)class_id);
            }
            samples[class_id][i] = acc;
            timing_logf("sample,%s,%s,%u,%lu\n",
                        name,
                        class_name(class_id),
                        (unsigned int)i,
                        (unsigned long)acc);
            step++;
            show_progress(name, step, total_steps);
        }
    }

    for (class_id = 0; class_id < TIMING_CLASS_COUNT; class_id++)
    {
        out->class_means[class_id] = mean_u32(samples[class_id], TIMING_SAMPLES);
        out->class_medians[class_id] = median_u32(samples[class_id], TIMING_SAMPLES);
        out->class_over_thresh_pct_x100[class_id] = 0;
        out->class_over_thresh_pct_x100_rigorous[class_id] = 0;
    }

    compute_stats(samples[TIMING_CALIB_CLASS], TIMING_SAMPLES,
                  &out->stability_mean, &out->stability_stddev, &out->stability_pct_x100);
    compute_robust_stats(samples[TIMING_CALIB_CLASS], TIMING_SAMPLES,
                         &out->stability_median, &out->stability_mad, &out->stability_sigma_x10000);
    out->accepted_deviation = robust_accept_deviation(out->stability_sigma_x10000, MAD_ACCEPT_C);
    out->accepted_deviation_rigorous = robust_accept_deviation(out->stability_sigma_x10000, MAD_ACCEPT_C_RIGOROUS);
    out->stability_pass = true;

    for (class_id = 0; class_id < TIMING_CLASS_COUNT; class_id++)
    {
        uint16_t over = 0;
        uint16_t over_rigorous = 0;
        for (i = 0; i < TIMING_SAMPLES; i++)
        {
            uint32_t dev = abs_u32_diff(samples[class_id][i], out->stability_median);
            if (dev > out->accepted_deviation)
            {
                over++;
            }
            if (dev > out->accepted_deviation_rigorous)
            {
                over_rigorous++;
            }
        }
        out->class_over_thresh_pct_x100[class_id] =
            (uint32_t)(((uint32_t)over * 10000u) / TIMING_SAMPLES);
        out->class_over_thresh_pct_x100_rigorous[class_id] =
            (uint32_t)(((uint32_t)over_rigorous * 10000u) / TIMING_SAMPLES);
    }

    out->max_pair_diff = 0;
    out->differential_pass = true;

    for (class_id = 0; class_id < TIMING_CLASS_COUNT; class_id++)
    {
        uint16_t other;
        for (other = class_id + 1; other < TIMING_CLASS_COUNT; other++)
        {
            uint32_t m1 = out->class_medians[class_id];
            uint32_t m2 = out->class_medians[other];
            uint32_t diff = abs_u32_diff(m1, m2);

            if (diff > out->max_pair_diff)
            {
                out->max_pair_diff = diff;
            }

            if ((class_id == TIMING_CALIB_CLASS || other == TIMING_CALIB_CLASS) &&
                diff > out->accepted_deviation)
            {
                uint16_t test = (class_id == TIMING_CALIB_CLASS) ? other : class_id;
                bool high = (out->class_medians[test] >= out->stability_median);
                uint16_t consistent = 0;

                for (i = 0; i < TIMING_SAMPLES; i++)
                {
                    int32_t sample_delta = (int32_t)samples[test][i] - (int32_t)out->stability_median;
                    if ((high && sample_delta > (int32_t)out->accepted_deviation) ||
                        (!high && sample_delta < -(int32_t)out->accepted_deviation))
                    {
                        consistent++;
                    }
                }

                if ((uint32_t)consistent * DIFF_CONSISTENCY_DEN >= (uint32_t)TIMING_SAMPLES * DIFF_CONSISTENCY_NUM)
                {
                    out->differential_pass = false;
                }
            }
        }
    }

    out->fail = !out->differential_pass;
    timing_logf("robust,%s,median=%lu,mad=%lu,sigma=%lu.%04lu,c=%u,accept=%lu,dpass=%u\n",
                name,
                (unsigned long)out->stability_median,
                (unsigned long)out->stability_mad,
                (unsigned long)(out->stability_sigma_x10000 / 10000u),
                (unsigned long)(out->stability_sigma_x10000 % 10000u),
                (unsigned int)MAD_ACCEPT_C,
                (unsigned long)out->accepted_deviation,
                out->differential_pass ? 1u : 0u);
    timing_logf("robust4,%s,median=%lu,mad=%lu,sigma=%lu.%04lu,c=%u,accept=%lu,dpass=%u\n",
                name,
                (unsigned long)out->stability_median,
                (unsigned long)out->stability_mad,
                (unsigned long)(out->stability_sigma_x10000 / 10000u),
                (unsigned long)(out->stability_sigma_x10000 % 10000u),
                (unsigned int)MAD_ACCEPT_C_RIGOROUS,
                (unsigned long)out->accepted_deviation_rigorous,
                out->differential_pass ? 1u : 0u);
    for (class_id = 0; class_id < TIMING_CLASS_COUNT; class_id++)
    {
        const int32_t trend = (int32_t)out->class_medians[class_id] - (int32_t)out->stability_median;
        const char trend_symbol = (trend > 0) ? '+' : ((trend < 0) ? '-' : '=');
        timing_logf("class,%s,%s,mean=%lu,median=%lu,trend=%c,over=%lu.%02lu%%\n",
                    name,
                    class_name(class_id),
                    (unsigned long)out->class_means[class_id],
                    (unsigned long)out->class_medians[class_id],
                    trend_symbol,
                    (unsigned long)(out->class_over_thresh_pct_x100[class_id] / 100u),
                    (unsigned long)(out->class_over_thresh_pct_x100[class_id] % 100u));
        timing_logf("class4,%s,%s,mean=%lu,median=%lu,trend=%c,over=%lu.%02lu%%\n",
                    name,
                    class_name(class_id),
                    (unsigned long)out->class_means[class_id],
                    (unsigned long)out->class_medians[class_id],
                    trend_symbol,
                    (unsigned long)(out->class_over_thresh_pct_x100_rigorous[class_id] / 100u),
                    (unsigned long)(out->class_over_thresh_pct_x100_rigorous[class_id] % 100u));
    }
}

static void show_result(const char *name, const struct primitive_result *result)
{
    os_ClrHome();
    os_FontSelect(os_LargeFont);
    printf("%s:%s",
           name,
           result->differential_pass ? "PASS" : "FAIL");
#ifdef TLS_TIMING_VERBOSE
    uint16_t class_id;
    os_FontSelect(os_SmallFont);
    printf("\nc=%u sig=%lu.%04lu max_delta=%lu",
           (unsigned int)MAD_ACCEPT_C,
           (unsigned long)(result->stability_sigma_x10000 / 10000u),
           (unsigned long)(result->stability_sigma_x10000 % 10000u),
           (unsigned long)result->accepted_deviation);
    for (class_id = 0; class_id < TIMING_CLASS_COUNT; class_id++)
    {
        const int32_t median_dev = (int32_t)result->class_medians[class_id] - (int32_t)result->stability_median;
        printf("\n%s median_dev=%+ld occur=%lu.%02lu%%",
               class_name(class_id),
               (long)median_dev,
               (unsigned long)(result->class_over_thresh_pct_x100[class_id] / 100u),
               (unsigned long)(result->class_over_thresh_pct_x100[class_id] % 100u));
    }
    os_GetKey();
    os_ClrHome();
    os_FontSelect(os_LargeFont);
    printf("%s:%s",
           name,
           result->differential_pass ? "PASS" : "FAIL");
    os_FontSelect(os_SmallFont);
    printf("\nc=%u sig=%lu.%04lu max_delta=%lu",
           (unsigned int)MAD_ACCEPT_C_RIGOROUS,
           (unsigned long)(result->stability_sigma_x10000 / 10000u),
           (unsigned long)(result->stability_sigma_x10000 % 10000u),
           (unsigned long)result->accepted_deviation_rigorous);
    for (class_id = 0; class_id < TIMING_CLASS_COUNT; class_id++)
    {
        const int32_t median_dev = (int32_t)result->class_medians[class_id] - (int32_t)result->stability_median;
        printf("\n%s median_dev=%+ld occur=%lu.%02lu%%",
               class_name(class_id),
               (long)median_dev,
               (unsigned long)(result->class_over_thresh_pct_x100_rigorous[class_id] / 100u),
               (unsigned long)(result->class_over_thresh_pct_x100_rigorous[class_id] % 100u));
    }
#endif
    os_FontSelect(os_LargeFont);
    os_GetKey();
}

int main(void)
{
    struct primitive_result r_bytes;
    struct primitive_result r_sha;
    struct primitive_result r_hmac;
    struct primitive_result r_hkdf;
    struct primitive_result r_pbkdf2;
    struct primitive_result r_aes_gcm_enc;
    struct primitive_result r_aes_gcm_decver;
    struct primitive_result r_aes_cbc_enc;
    struct primitive_result r_aes_cbc_dec;
    struct primitive_result r_aes_ccm_enc;
    struct primitive_result r_aes_ccm_dec;
    struct primitive_result r_x25519;

    (void)timing_log_begin();
    timing_logf("tls_timing,start,c=%u,c_rig=%u,sigma_scale=%u\n",
                (unsigned int)MAD_ACCEPT_C,
                (unsigned int)MAD_ACCEPT_C_RIGOROUS,
                (unsigned int)MAD_SIGMA_SCALE_X10000);

    run_primitive("BYTES", time_bytes_compare_case, TIMING_REPS_FAST, &r_bytes);
    show_result("BYTES", &r_bytes);

    run_primitive("SHA256", time_sha256_case, TIMING_REPS_FAST, &r_sha);
    show_result("SHA256", &r_sha);

    run_primitive("HMAC", time_hmac_case, TIMING_REPS_MEDIUM, &r_hmac);
    show_result("HMAC", &r_hmac);

    run_primitive("HKDF", time_hkdf_case, TIMING_REPS_MEDIUM, &r_hkdf);
    show_result("HKDF", &r_hkdf);

    run_primitive("PBKDF2", time_pbkdf2_case, TIMING_REPS_SLOW, &r_pbkdf2);
    show_result("PBKDF2", &r_pbkdf2);

    run_primitive("AESGCM-E", time_aes_gcm_encrypt_case, TIMING_REPS_MEDIUM, &r_aes_gcm_enc);
    show_result("AESGCM-E", &r_aes_gcm_enc);

    run_primitive("AESGCM-DV", time_aes_gcm_decrypt_verify_case, TIMING_REPS_MEDIUM, &r_aes_gcm_decver);
    show_result("AESGCM-DV", &r_aes_gcm_decver);

    run_primitive("AESCBC-E", time_aes_cbc_encrypt_case, TIMING_REPS_MEDIUM, &r_aes_cbc_enc);
    show_result("AESCBC-E", &r_aes_cbc_enc);

    run_primitive("AESCBC-D", time_aes_cbc_decrypt_case, TIMING_REPS_MEDIUM, &r_aes_cbc_dec);
    show_result("AESCBC-D", &r_aes_cbc_dec);

    run_primitive("AESCCM-E", time_aes_ccm_encrypt_case, TIMING_REPS_MEDIUM, &r_aes_ccm_enc);
    show_result("AESCCM-E", &r_aes_ccm_enc);

    run_primitive("AESCCM-D", time_aes_ccm_decrypt_case, TIMING_REPS_MEDIUM, &r_aes_ccm_dec);
    show_result("AESCCM-D", &r_aes_ccm_dec);

    run_primitive("X25519", time_x25519_case, TIMING_REPS_SLOW, &r_x25519);
    show_result("X25519", &r_x25519);
    timing_logf("tls_timing,end\n");
    timing_log_end();

    return 0;
}
