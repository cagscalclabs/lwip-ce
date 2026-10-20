#include <fileioc.h>
#include <ti/getkey.h>
#include <ti/screen.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/power.h>
#include <time.h>

#include <lwip/cryptography/aes.h>
#include <lwip/cryptography/bytes.h>
#include <lwip/cryptography/hash.h>
#include <lwip/cryptography/hkdf.h>
#include <lwip/cryptography/hmac.h>
#include <lwip/cryptography/passwords.h>
#include <lwip/cryptography/rsa.h>
#include <lwip/cryptography/x25519.h>
#include <lwip/cryptography/p256.h>
#include <lwip.h>

/* Dyload call overhead is far higher than the old statically-linked path
 * (every primitive call now goes through a dylib trampoline), so reps are
 * cut well below the static-link tuning to keep the full suite inside CI's
 * wall-clock budget. TIMING_SAMPLES is kept high enough for MAD/sigma to
 * stay meaningful. */
#define TIMING_SAMPLES 32u
#define TIMING_REPS_FAST 8u
#define TIMING_REPS_MEDIUM 4u
#define TIMING_REPS_SLOW 2u
/* Low-rep count for asymmetric (P-256, RSA) operations that take hundreds of
 * milliseconds per call; 2 reps provides a minimal warmup+measure pair. */
#define TIMING_REPS_LOWREP 2u

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
static bool timing_log_error_reported;

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
    bool differential_pass_rigorous;

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
        timing_log_error_reported = true;
        os_ClrHome();
        printf("Log open failed\n");
        printf("%s\n", TIMING_LOG_APPVAR);
        printf("Press any key");
        os_GetKey();
        return false;
    }

    timing_log_enabled = true;
    timing_log_error_reported = false;
    if (!ti_SetArchiveStatus(false, timing_log_handle))
    {
        timing_log_error_reported = true;
        os_ClrHome();
        printf("Log RAM move failed\n");
        printf("%s\n", TIMING_LOG_APPVAR);
        printf("Press any key");
        os_GetKey();
    }
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
        if (!ti_SetArchiveStatus(true, timing_log_handle) && !timing_log_error_reported)
        {
            timing_log_error_reported = true;
            os_ClrHome();
            printf("Log archive failed\n");
            printf("%s\n", TIMING_LOG_APPVAR);
            printf("Press any key");
            os_GetKey();
        }
    }
    if (!ti_Close(timing_log_handle) && !timing_log_error_reported)
    {
        timing_log_error_reported = true;
        os_ClrHome();
        printf("Log close failed\n");
        printf("%s\n", TIMING_LOG_APPVAR);
        printf("Press any key");
        os_GetKey();
    }
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
        timing_log_error_reported = true;
        os_ClrHome();
        printf("Log write failed\n");
        printf("%s bytes=%u\n", TIMING_LOG_APPVAR, (unsigned int)written);
        printf("Press any key");
        os_GetKey();
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
    {
        size_t boundary = len / 2u;
        for (i = 0; i < len; i++)
        {
            if (i < boundary)
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
    }
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
                    32,
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

/* ---------------------------------------------------------------------------
 * Slow (asymmetric) single-measurement helpers.
 *
 * run_slow_op() times a no-argument operation TIMING_REPS_LOWREP times and
 * reports the mean wall-clock duration in milliseconds.  It does NOT use the
 * multi-class statistical framework (which is unsuitable for operations that
 * take hundreds of milliseconds) and does not produce a pass/fail verdict.
 * Results go to the screen and to the timing log.
 * --------------------------------------------------------------------------*/

static void show_slow_result(const char *name, uint32_t mean_ms, bool ok)
{
    os_ClrHome();
    os_FontSelect(os_LargeFont);
    printf("%s\n", name);
    os_FontSelect(os_SmallFont);
    printf("%lu ms  %s\n", (unsigned long)mean_ms, ok ? "ok" : "FAIL");
#ifndef TLS_TIMING_AUTORUN
    printf("Press any key");
    os_GetKey();
#endif
}

static void run_slow_op(const char *name, uint32_t (*fn)(void), uint16_t reps)
{
    uint32_t total = 0;
    uint32_t mean_ms;
    uint16_t r;

    /* Discard first call (cold-cache warmup). */
    fn();

    for (r = 0; r < reps; r++)
    {
        total += fn();
    }

    /* CLOCKS_PER_SEC = 32768; multiply before dividing to keep precision. */
    mean_ms = (reps != 0) ? (uint32_t)(((uint64_t)(total / reps) * 1000u) / CLOCKS_PER_SEC) : 0u;
    timing_logf("slow,%s,reps=%u,mean_ms=%lu\n",
                name, (unsigned int)reps, (unsigned long)mean_ms);
    show_slow_result(name, mean_ms, true);
}

/* ---------------------------------------------------------------------------
 * P-256 timing entries (RFC 5903 / RFC 6979 test vectors for reproducibility).
 * --------------------------------------------------------------------------*/

/* RFC 5903 section 8.1, initiator key pair. */
static const uint8_t p256_priv_keygen[32] = {
    0xc8,0x8f,0x01,0xf5,0x10,0xd9,0xac,0x3f,0x70,0xa2,0x92,0xda,0xa2,0x31,0x6d,0xe5,
    0x44,0xe9,0xaa,0xb8,0xaf,0xe8,0x40,0x49,0xc6,0x2a,0x9c,0x57,0x86,0x2d,0x14,0x33
};
/* RFC 5903 section 8.1, responder public key for ECDH. */
static const uint8_t p256_peer_pub[65] = {
    0x04,0xd1,0x2d,0xfb,0x52,0x89,0xc8,0xd4,0xf8,0x12,0x08,0xb7,0x02,0x70,0x39,0x8c,
    0x34,0x22,0x96,0x97,0x0a,0x0b,0xcc,0xb7,0x4c,0x73,0x6f,0xc7,0x55,0x44,0x94,0xbf,
    0x63,0x56,0xfb,0xf3,0xca,0x36,0x6c,0xc2,0x3e,0x81,0x57,0x85,0x4c,0x13,0xc5,0x8d,
    0x6a,0xac,0x23,0xf0,0x46,0xad,0xa3,0x0f,0x83,0x53,0xe7,0x4f,0x33,0x03,0x98,0x72,0xab
};
/* RFC 6979 A.2.5 P-256 signing key and SHA-256("sample") hash + expected sig. */
static const uint8_t p256_sign_priv[32] = {
    0xc9,0xaf,0xa9,0xd8,0x45,0xba,0x75,0x16,0x6b,0x5c,0x21,0x57,0x67,0xb1,0xd6,0x93,
    0x4e,0x50,0xc3,0xdb,0x36,0xe8,0x9b,0x12,0x7b,0x8a,0x62,0x2b,0x12,0x0f,0x67,0x21
};
static const uint8_t p256_sample_hash[32] = {
    0xaf,0x2b,0xdb,0xe1,0xaa,0x9b,0x6e,0xc1,0xe2,0xad,0xe1,0xd6,0x94,0xf4,0x1f,0xc7,
    0x1a,0x83,0x1d,0x02,0x68,0xe9,0x89,0x15,0x62,0x11,0x3d,0x8a,0x62,0xad,0xd1,0xbf
};
static const uint8_t p256_sample_sig[64] = {
    0xef,0xd4,0x8b,0x2a,0xac,0xb6,0xa8,0xfd,0x11,0x40,0xdd,0x9c,0xd4,0x5e,0x81,0xd6,
    0x9d,0x2c,0x87,0x7b,0x56,0xaa,0xf9,0x91,0xc3,0x4d,0x0e,0xa8,0x4e,0xaf,0x37,0x16,
    0xf7,0xcb,0x1c,0x94,0x2d,0x65,0x7c,0x41,0xd4,0x36,0xc7,0xa1,0xb6,0xe2,0x9f,0x65,
    0xf3,0xe9,0x00,0xdb,0xb9,0xaf,0xf4,0x06,0x4d,0xc4,0xab,0x2f,0x84,0x3a,0xcd,0xa8
};

static uint8_t p256_pub_scratch[65];
static uint8_t p256_ss_scratch[32];
static uint8_t p256_sig_scratch[64];

static uint32_t time_p256_keygen(void)
{
    clock_t start = clock();
    bool ok = tls_p256_publickey(p256_pub_scratch, p256_priv_keygen);
    timing_sink ^= (uint8_t)ok ^ p256_pub_scratch[1];
    return (uint32_t)(clock() - start);
}

static uint32_t time_p256_secret(void)
{
    clock_t start = clock();
    bool ok = tls_p256_secret(p256_ss_scratch, p256_priv_keygen, p256_peer_pub);
    timing_sink ^= (uint8_t)ok ^ p256_ss_scratch[0];
    return (uint32_t)(clock() - start);
}

static uint32_t time_p256_sign(void)
{
    clock_t start = clock();
    bool ok = tls_p256_sign(p256_sig_scratch, p256_sample_hash, p256_sign_priv);
    timing_sink ^= (uint8_t)ok ^ p256_sig_scratch[0];
    return (uint32_t)(clock() - start);
}

static uint32_t time_p256_verify(void)
{
    /* Derive the public key once (outside the timed region) and cache it. */
    static uint8_t sign_pub[65];
    static bool sign_pub_ready = false;
    clock_t start;
    bool ok;

    if (!sign_pub_ready)
    {
        sign_pub_ready = tls_p256_publickey(sign_pub, p256_sign_priv);
    }
    start = clock();
    ok = sign_pub_ready && tls_p256_verify(p256_sample_sig, p256_sample_hash, sign_pub);
    timing_sink ^= (uint8_t)ok;
    return (uint32_t)(clock() - start);
}

/* ---------------------------------------------------------------------------
 * RSA-2048 PKCS#1-v1.5 SHA-256 timing entry.
 *
 * Test vector: NIST FIPS 186-4 RSA2048 SigVer (SHA-256), from the public
 * NIST CAVS SigVer15 test suite.  The modulus n, SHA-256 digest d, and
 * signature s are the first passing vector in the 2048-bit set.
 * --------------------------------------------------------------------------*/

/* NIST FIPS 186-4 CAVS 11.0 SigVer15, SHA-256, 2048-bit (first passing vector). */
static const uint8_t rsa2048_e[] = {0x01, 0x00, 0x01}; /* 65537 */
static const uint8_t rsa2048_n[256] = {
    0xce,0xee,0x9c,0x71,0x5f,0x38,0x13,0x76,0x7a,0x1b,0xf1,0xa9,0xe9,0x68,0x97,0x46,
    0x85,0x4c,0x3e,0xc2,0x79,0xb0,0xaf,0x6a,0x36,0x99,0x62,0xf9,0x25,0x31,0x4f,0x73,
    0x1a,0x9d,0x43,0x8c,0x74,0xf5,0xa4,0x1b,0xb8,0x0b,0xfb,0x14,0xc9,0x4e,0x6c,0x29,
    0xdf,0xa3,0x3d,0x8e,0x4b,0x37,0x03,0xb4,0xbd,0x00,0x30,0x6b,0xc4,0xf2,0x55,0x52,
    0xf4,0x59,0xaf,0xf7,0x4c,0x33,0xf0,0x7a,0xae,0xe3,0x7a,0xed,0x26,0x6c,0x27,0x9a,
    0xfc,0xaa,0x1c,0xf8,0x6d,0x00,0xef,0x2f,0x23,0x96,0x5a,0x8d,0xae,0xfd,0xf0,0xaf,
    0x35,0x7e,0x43,0x4c,0x68,0x64,0x0d,0xab,0xdf,0x58,0xb7,0x1c,0x33,0xd8,0x55,0x6e,
    0xb6,0x47,0x4c,0x49,0x4d,0x80,0xee,0x7a,0x63,0xb4,0x91,0x00,0x8f,0x4b,0x99,0x41,
    0x55,0xbf,0x80,0xaf,0x10,0x45,0x5a,0xf1,0x89,0x96,0x67,0xf6,0x2a,0x73,0x38,0xfb,
    0x37,0x24,0xef,0xca,0xce,0x5b,0x7b,0xd4,0x56,0xac,0xed,0xcb,0x19,0xcf,0x1c,0x4e,
    0x9b,0xf3,0x85,0xca,0xac,0x47,0x08,0x27,0x2c,0x86,0x9d,0x2c,0x9c,0x24,0x05,0x3b,
    0x5e,0x7b,0x6d,0x70,0x78,0x7e,0x6b,0x40,0x1a,0x6a,0x95,0x47,0xef,0x62,0xa0,0x65,
    0xe4,0x06,0x78,0x77,0x0b,0x0a,0x11,0x3e,0x73,0x78,0xe6,0x79,0x8a,0x40,0xd1,0x45,
    0x28,0xd4,0x4b,0x44,0x65,0xe1,0x33,0xe6,0xa4,0x80,0x2a,0x0d,0xe2,0xb2,0x11,0x7c,
    0x21,0x61,0x13,0x96,0x93,0x90,0x91,0x3c,0x43,0x04,0x7d,0xda,0x52,0xdc,0x4c,0x18,
    0x98,0x2b,0x21,0x31,0xc2,0x3f,0x6c,0xb2,0x88,0x95,0x2e,0x95,0xe3,0x48,0x89,0x93
};
static const uint8_t rsa2048_digest[32] = {
    0xf6,0x94,0xb9,0x3a,0x40,0x96,0xb7,0x9d,0x72,0x4c,0x37,0x9c,0x40,0xf0,0xb3,0xce,
    0x57,0x2c,0x1e,0x72,0x62,0x49,0xe7,0x93,0xf2,0x3a,0xca,0x44,0x92,0x4e,0x5a,0x41
};
static const uint8_t rsa2048_sig[256] = {
    0xa6,0x0f,0x74,0x6b,0x9c,0x06,0x02,0xcf,0xfa,0x31,0xf3,0xe5,0x9f,0x47,0x65,0x91,
    0x85,0x08,0xf2,0x07,0x2a,0x0e,0x9d,0x1c,0xcc,0x01,0xca,0xd5,0xf6,0xe2,0xf6,0xbf,
    0x76,0xf6,0x36,0xc2,0x5b,0x0b,0x5f,0x97,0xa0,0x51,0xc5,0x45,0x0c,0x23,0xa3,0x57,
    0x2e,0x9f,0xb3,0x1b,0xac,0x38,0x47,0xcb,0x54,0x91,0x2e,0x4c,0x16,0xb2,0xb3,0xdc,
    0xef,0x23,0x7e,0x01,0x03,0x43,0x3c,0x13,0xb6,0x51,0xe4,0x56,0xa6,0x7b,0x9c,0x4e,
    0x1e,0x39,0xa9,0x12,0x7f,0xc4,0x73,0xa7,0x82,0x47,0x04,0x43,0x7f,0x14,0x51,0x5c,
    0x86,0x86,0xb0,0xac,0x42,0x6e,0xf1,0xf0,0x4e,0x9b,0x00,0x23,0x26,0x58,0x70,0x29,
    0x8e,0x0e,0x5e,0xaa,0x87,0x1c,0xf7,0x97,0xb3,0xd4,0x9b,0x11,0x12,0x6d,0xfc,0x27,
    0x6f,0xb2,0x6d,0x61,0x34,0xb7,0x2b,0x22,0x0a,0x8a,0xce,0x6c,0xd8,0x21,0xf1,0xe4,
    0xf4,0x33,0xd1,0xd1,0x19,0xd5,0x00,0x4d,0xb2,0xe9,0x55,0x7e,0xe3,0x3a,0x85,0xe4,
    0xf3,0xe3,0xb7,0x2b,0x40,0x1a,0x89,0x43,0x03,0x6f,0x0b,0x82,0x6d,0xd8,0x78,0x94,
    0x53,0xdb,0x84,0x45,0xb7,0x91,0x0c,0x0f,0x93,0x96,0xf1,0x01,0x4a,0x39,0xf5,0x3e,
    0x60,0x9e,0xaa,0x82,0xc9,0x6e,0x5d,0xfb,0x87,0xf9,0xf2,0x56,0x79,0x34,0x5f,0x8e,
    0xeb,0xa4,0x37,0xf9,0xcd,0x23,0x85,0x98,0xac,0x5f,0x6d,0x38,0x81,0x05,0x0f,0x4a,
    0xa7,0xb1,0xe6,0x4f,0xd5,0x16,0x77,0x34,0x34,0xb5,0x8d,0x12,0x91,0x4a,0x41,0xd5,
    0x7b,0x95,0xf3,0x08,0x59,0x9a,0x33,0xf1,0xe4,0x58,0x66,0x03,0x1e,0xf2,0x04,0x5e
};

static uint8_t rsa2048_em_scratch[256];

static uint32_t time_rsa2048_pkcs1_verify(void)
{
    static const struct tls_rsa_key key = {
        sizeof(rsa2048_e), rsa2048_e, sizeof(rsa2048_n), rsa2048_n
    };
    clock_t start = clock();
    bool ok = tls_rsa_pkcs1_v15_sha256_verify(rsa2048_sig, sizeof(rsa2048_sig),
                                               rsa2048_digest, &key);
    timing_sink ^= (uint8_t)ok;
    return (uint32_t)(clock() - start);
}

static uint32_t time_rsa2048_decrypt_sig(void)
{
    static const struct tls_rsa_key key = {
        sizeof(rsa2048_e), rsa2048_e, sizeof(rsa2048_n), rsa2048_n
    };
    clock_t start = clock();
    bool ok = tls_rsa_decrypt_signature(rsa2048_sig, sizeof(rsa2048_sig),
                                        rsa2048_em_scratch, &key);
    timing_sink ^= (uint8_t)ok ^ rsa2048_em_scratch[0];
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
        uint16_t over_pos = 0;
        uint16_t over_neg = 0;
        uint16_t over_pos_rigorous = 0;
        uint16_t over_neg_rigorous = 0;
        for (i = 0; i < TIMING_SAMPLES; i++)
        {
            int32_t sample_delta = (int32_t)samples[class_id][i] - (int32_t)out->stability_median;
            if (sample_delta > (int32_t)out->accepted_deviation)
            {
                over_pos++;
            }
            else if (sample_delta < -(int32_t)out->accepted_deviation)
            {
                over_neg++;
            }
            if (sample_delta > (int32_t)out->accepted_deviation_rigorous)
            {
                over_pos_rigorous++;
            }
            else if (sample_delta < -(int32_t)out->accepted_deviation_rigorous)
            {
                over_neg_rigorous++;
            }
        }
        out->class_over_thresh_pct_x100[class_id] =
            (uint32_t)(((uint32_t)((over_pos > over_neg) ? over_pos : over_neg) * 10000u) / TIMING_SAMPLES);
        out->class_over_thresh_pct_x100_rigorous[class_id] =
            (uint32_t)(((uint32_t)((over_pos_rigorous > over_neg_rigorous) ? over_pos_rigorous : over_neg_rigorous) * 10000u) / TIMING_SAMPLES);
    }

    out->max_pair_diff = 0;
    out->differential_pass = true;
    out->differential_pass_rigorous = true;

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

            if ((class_id == TIMING_CALIB_CLASS || other == TIMING_CALIB_CLASS) &&
                diff > out->accepted_deviation_rigorous)
            {
                uint16_t test = (class_id == TIMING_CALIB_CLASS) ? other : class_id;
                bool high = (out->class_medians[test] >= out->stability_median);
                uint16_t consistent = 0;

                for (i = 0; i < TIMING_SAMPLES; i++)
                {
                    int32_t sample_delta = (int32_t)samples[test][i] - (int32_t)out->stability_median;
                    if ((high && sample_delta > (int32_t)out->accepted_deviation_rigorous) ||
                        (!high && sample_delta < -(int32_t)out->accepted_deviation_rigorous))
                    {
                        consistent++;
                    }
                }

                if ((uint32_t)consistent * DIFF_CONSISTENCY_DEN >= (uint32_t)TIMING_SAMPLES * DIFF_CONSISTENCY_NUM)
                {
                    out->differential_pass_rigorous = false;
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
                out->differential_pass_rigorous ? 1u : 0u);
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
#ifndef TLS_TIMING_AUTORUN
    os_FontSelect(os_LargeFont);
    printf("\nPress any key");
    os_GetKey();
#endif
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

    if (!lwip_start())
    {
        const char *start_error = lwip_get_start_errstring();

        os_ClrHome();
        printf("ERROR: lwip_start failed\n");
        printf("Loader %u: %s\n",
               (unsigned int)lwip_get_start_errno(),
               start_error ? start_error : "unknown");
        printf("Runtime: %u\n", (unsigned int)lwip_start_last_error());
        printf("Press any key");
        os_GetKey();
        return 1;
    }

    /* This unattended hardware profile can run for well beyond TI-OS's APD
     * window. Keep the calculator awake while measurements are in progress;
     * restore normal APD behavior before waiting at the final screen. */
    os_DisableAPD();

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

    /* --- RSA --- */
    timing_logf("tls_timing,section,RSA\n");
    os_ClrHome();
    os_FontSelect(os_LargeFont);
    printf("--- RSA ---\n");
#ifndef TLS_TIMING_AUTORUN
    printf("Press any key");
    os_GetKey();
#endif
    run_slow_op("RSA-DEC", time_rsa2048_decrypt_sig, TIMING_REPS_LOWREP);
    run_slow_op("RSA-VFY", time_rsa2048_pkcs1_verify, TIMING_REPS_LOWREP);

    /* --- P256 --- */
    timing_logf("tls_timing,section,P256\n");
    os_ClrHome();
    os_FontSelect(os_LargeFont);
    printf("--- P256 ---\n");
#ifndef TLS_TIMING_AUTORUN
    printf("Press any key");
    os_GetKey();
#endif
    run_slow_op("P256-KG", time_p256_keygen, TIMING_REPS_LOWREP);
    run_slow_op("P256-DH", time_p256_secret, TIMING_REPS_LOWREP);
    run_slow_op("P256-SG", time_p256_sign,   TIMING_REPS_LOWREP);
    run_slow_op("P256-VF", time_p256_verify, TIMING_REPS_LOWREP);

    timing_logf("tls_timing,end\n");
    timing_log_end();
    os_EnableAPD();

    os_ClrHome();
    os_FontSelect(os_LargeFont);
    printf("TLS Timing\n");
    printf("Done.");
    os_GetKey();

    return 0;
}
