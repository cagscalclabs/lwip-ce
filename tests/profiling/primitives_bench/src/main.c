/* Cycle-count benchmark for the TLS primitives and hot paths.
 *
 * Runs unattended under cemu-autotester: every measurement is appended to a
 * text AppVar (TLSBENCH) that the host converts with convbin. clock() counts
 * 32768 Hz OS timer ticks on CEdev (~1465 CPU cycles each at 48 MHz), so
 * every measurement below repeats the work enough times to stay well above
 * one tick. Ratios between builds are the quantity of interest.
 */
#include <fileioc.h>
#include <ti/getcsc.h>
#include <ti/screen.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <lwip/cryptography/aes.h>
#include <lwip/cryptography/bytes.h>
#include <lwip/cryptography/hash.h>
#include <lwip/cryptography/hkdf.h>
#include <lwip/cryptography/hmac.h>
#include <lwip/cryptography/p256.h>
#include <lwip/cryptography/p384.h>
#include <lwip/cryptography/passwords.h>
#include <lwip/cryptography/rsa.h>
#include <lwip/cryptography/x25519.h>
#include <lwip.h>

#define BENCH_APPVAR "TLSBENCH"
#define BENCH_BUF_LEN 4096u

static uint8_t bench_buf[BENCH_BUF_LEN];
static uint8_t bench_out[BENCH_BUF_LEN + 64u];
static uint8_t bench_key[32];
static uint8_t bench_iv[12];
static uint8_t bench_tag[16];
static const uint8_t bench_aad[5] = {0x17, 0x03, 0x03, 0x10, 0x00};
static volatile uint32_t bench_sink;
static uint8_t bench_handle;
static bool bench_log_ok;

static void bench_emit(const char *name, uint32_t ticks, uint32_t units)
{
    char line[64];
    if (!bench_log_ok)
    {
        return;
    }
    snprintf(line, sizeof(line), "%s,%lu,%lu\n", name,
             (unsigned long)ticks, (unsigned long)units);
    ti_Write(line, 1, (uint8_t)strlen(line), bench_handle);
}

static void bench_fill(void)
{
    uint32_t x = 0xC0FFEE11u;
    for (size_t i = 0; i < sizeof(bench_buf); i++)
    {
        x = x * 1664525u + 1013904223u;
        bench_buf[i] = (uint8_t)(x >> 24);
    }
    for (size_t i = 0; i < sizeof(bench_key); i++)
    {
        bench_key[i] = (uint8_t)(i * 7u + 1u);
    }
    for (size_t i = 0; i < sizeof(bench_iv); i++)
    {
        bench_iv[i] = (uint8_t)(i * 3u + 9u);
    }
}

/* --- hash ------------------------------------------------------------- */

static void bench_sha256_sweep(void)
{
    static const uint16_t sizes[] = {64, 256, 1024, 4096};
    char name[24];

    for (size_t s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++)
    {
        uint16_t len = sizes[s];
        uint16_t reps = (uint16_t)(16384u / len);
        uint8_t digest[TLS_SHA256_DIGEST_LEN];
        struct tls_hash_context ctx;
        clock_t t0;
        bool ok = true;

        for (uint16_t r = 0; r < 2; r++)
        {
            t0 = clock();
            for (uint16_t i = 0; i < reps; i++)
            {
                bool init_ok = tls_hash_context_init(&ctx, TLS_HASH_SHA256);
                ok = ok && init_ok;
                if (init_ok)
                {
                    tls_hash_update(&ctx, bench_buf, len);
                    tls_hash_digest(&ctx, digest);
                }
            }
            snprintf(name, sizeof(name), "sha256_%u_rep", (unsigned)len);
            bench_emit(name, (uint32_t)(clock() - t0), ok ? (uint32_t)len * reps : 0u);
        }
        bench_sink += digest[0];
    }
}

static void bench_sha384_sweep(void)
{
    static const uint16_t sizes[] = {64, 256, 1024};
    char name[24];

    for (size_t s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++)
    {
        uint16_t len = sizes[s];
        uint16_t reps = (uint16_t)(2048u / len);
        uint8_t digest[TLS_SHA384_DIGEST_LEN];
        struct tls_hash_context ctx;
        clock_t t0;
        bool ok = true;

        for (uint16_t r = 0; r < 2; r++)
        {
            t0 = clock();
            for (uint16_t i = 0; i < reps; i++)
            {
                bool init_ok = tls_hash_context_init(&ctx, TLS_HASH_SHA384);
                ok = ok && init_ok;
                if (init_ok)
                {
                    tls_hash_update(&ctx, bench_buf, len);
                    tls_hash_digest(&ctx, digest);
                }
            }
            snprintf(name, sizeof(name), "sha384_%u_rep", (unsigned)len);
            bench_emit(name, (uint32_t)(clock() - t0), ok ? (uint32_t)len * reps : 0u);
        }
        bench_sink += digest[0];
    }
}

static void bench_hmac_sweep(void)
{
    static const uint16_t sizes[] = {0, 64, 1024, 4096};
    char name[24];

    for (size_t s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++)
    {
        uint16_t len = sizes[s];
        uint16_t reps = (uint16_t)(16384u / (len ? len : 1u));
        uint8_t mac[TLS_SHA256_DIGEST_LEN];
        struct tls_hmac_context ctx;
        clock_t t0;
        bool ok = true;

        t0 = clock();
        for (uint16_t i = 0; i < reps; i++)
        {
            bool init_ok = tls_hmac_context_init(&ctx, TLS_HASH_SHA256, bench_key,
                                                 sizeof(bench_key));
            ok = ok && init_ok;
            if (init_ok)
            {
                if (len)
                {
                    tls_hmac_update(&ctx, bench_buf, len);
                }
                tls_hmac_digest(&ctx, mac);
            }
        }
        snprintf(name, sizeof(name), "hmac_%u_rep", (unsigned)len);
        bench_emit(name, (uint32_t)(clock() - t0),
                   ok ? (uint32_t)(len ? len : 0u) * reps : 0u);
        bench_sink += mac[0];
    }
}

/* --- AES -------------------------------------------------------------- */

static void bench_gcm_sweep(void)
{
    static const uint16_t sizes[] = {64, 1024, 4096};
    char name[24];

    for (size_t s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++)
    {
        uint16_t len = sizes[s];
        uint16_t reps = (uint16_t)(8192u / len);
        struct tls_aes_context ctx;
        clock_t t0;
        bool ok = true;

        /* encrypt: init + aad + encrypt + digest */
        t0 = clock();
        for (uint16_t i = 0; i < reps; i++)
        {
            bool init_ok = tls_aes_init(&ctx, TLS_AES_GCM, bench_key, 16,
                                        bench_iv, sizeof(bench_iv));
            ok = ok && init_ok;
            if (init_ok)
            {
                ok = ok && tls_aes_update_aad(&ctx, bench_aad, sizeof(bench_aad));
                ok = ok && tls_aes_encrypt(&ctx, bench_buf, len, bench_out);
                ok = ok && tls_aes_digest(&ctx, bench_tag);
            }
        }
        snprintf(name, sizeof(name), "gcm_enc_%u_rep", (unsigned)len);
        bench_emit(name, (uint32_t)(clock() - t0), ok ? (uint32_t)len * reps : 0u);

        /* verify: init + verify(aad, ct) over the same ciphertext */
        t0 = clock();
        for (uint16_t i = 0; i < reps; i++)
        {
            bool init_ok = tls_aes_init(&ctx, TLS_AES_GCM, bench_key, 16,
                                        bench_iv, sizeof(bench_iv));
            ok = ok && init_ok;
            if (init_ok)
            {
                ok = ok && tls_aes_verify(&ctx, bench_aad, sizeof(bench_aad),
                                          bench_out, len, bench_tag);
            }
        }
        snprintf(name, sizeof(name), "gcm_verify_%u_rep", (unsigned)len);
        bench_emit(name, (uint32_t)(clock() - t0), ok ? (uint32_t)len * reps : 0u);
        bench_sink += bench_tag[0];
    }
}

static void bench_gcm_decrypt(void)
{
    struct tls_aes_context ctx;
    clock_t t0;
    bool ok;
    bool ok2;

    ok = tls_aes_init(&ctx, TLS_AES_GCM, bench_key, 16, bench_iv, sizeof(bench_iv));
    ok = ok && tls_aes_verify(&ctx, bench_aad, sizeof(bench_aad), bench_out,
                              BENCH_BUF_LEN, bench_tag);
    t0 = clock();
    ok2 = tls_aes_decrypt(&ctx, bench_out, BENCH_BUF_LEN, bench_out);
    bench_emit("gcm_dec_4096", (uint32_t)(clock() - t0),
               (ok && ok2) ? BENCH_BUF_LEN : 0u);
    bench_sink += bench_out[0];
}

static void bench_cbc_sweep(void)
{
    static const uint16_t sizes[] = {64, 1024, 4096};
    char name[24];

    for (size_t s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++)
    {
        uint16_t len = sizes[s];
        uint16_t reps = (uint16_t)(8192u / len);
        struct tls_aes_context ctx;
        clock_t t0;
        bool ok = true;

        t0 = clock();
        for (uint16_t i = 0; i < reps; i++)
        {
            bool init_ok = tls_aes_init(&ctx, TLS_AES_CBC, bench_key, 16, bench_iv, 16);
            ok = ok && init_ok;
            if (init_ok)
            {
                ok = ok && tls_aes_encrypt(&ctx, bench_buf, len, bench_out);
            }
        }
        snprintf(name, sizeof(name), "cbc_enc_%u_rep", (unsigned)len);
        bench_emit(name, (uint32_t)(clock() - t0), ok ? (uint32_t)len * reps : 0u);
        bench_sink += bench_out[0];
    }
}

static void bench_bytes_compare(void)
{
    clock_t t0 = clock();
    bool eq = true;
    for (unsigned i = 0; i < 1024u; i++)
    {
        eq = tls_bytes_compare(bench_buf, bench_buf, 64u) && eq;
    }
    bench_emit("bytes_compare_64_x1024", (uint32_t)(clock() - t0), 1024u);
    bench_sink += (uint32_t)eq;
}

/* --- KDFs ------------------------------------------------------------- */

static void bench_pbkdf2(uint16_t rounds)
{
    uint8_t key[32];
    clock_t t0 = clock();
    bool ok = tls_pbkdf2("password", 8, bench_buf, 16, key, sizeof(key), rounds,
                         TLS_HASH_SHA256);
    char name[24];
    snprintf(name, sizeof(name), "pbkdf2_%u", (unsigned)rounds);
    bench_emit(name, (uint32_t)(clock() - t0), ok ? rounds : 0u);
    bench_sink += key[0];
}

static void bench_hkdf(void)
{
    uint8_t prk[32];
    uint8_t out[64];
    clock_t t0 = clock();
    bool ok = tls_hkdf_extract(TLS_HASH_SHA256, bench_key, sizeof(bench_key),
                               bench_buf, 32, prk);
    ok = ok && tls_hkdf_expand(TLS_HASH_SHA256, prk, sizeof(prk), bench_buf, 16,
                               out, sizeof(out));
    bench_emit("hkdf_extract_expand", (uint32_t)(clock() - t0), ok ? 1u : 0u);
    bench_sink += out[0];
}

/* --- RSA -------------------------------------------------------------- */

static uint8_t rsa_mod[512];
static uint8_t rsa_sig[512];
static uint8_t rsa_out[512];

static void bench_rsa(void)
{
    static const uint8_t exp[3] = {0x01, 0x00, 0x01};
    struct tls_rsa_key k2 = {3, exp, 256, rsa_mod};
    struct tls_rsa_key k4 = {3, exp, 512, rsa_mod};
    clock_t t0;
    bool ok, ok2;

    memset(rsa_mod, 0xFF, sizeof(rsa_mod));
    rsa_mod[255] = 0xFD;   /* odd, top bit set: 2048-bit modulus */
    rsa_mod[511] = 0xFD;   /* odd, top bit set: 4096-bit modulus */
    memset(rsa_sig, 0x55, sizeof(rsa_sig));

    t0 = clock();
    ok = tls_rsa_decrypt_signature(rsa_sig, 256, rsa_out, &k2);
    bench_emit("rsa2048_pub_exp", (uint32_t)(clock() - t0), ok ? 1u : 0u);

    t0 = clock();
    ok2 = tls_rsa_decrypt_signature(rsa_sig, 512, rsa_out, &k4);
    bench_emit("rsa4096_pub_exp", (uint32_t)(clock() - t0), ok2 ? 1u : 0u);
    bench_sink += (uint32_t)ok + rsa_out[0];
}

/* --- asymmetric ------------------------------------------------------- */

static void bench_x25519(void)
{
    uint8_t pub[32];
    uint8_t peer[32];
    uint8_t shared[32];
    clock_t t0;
    bool ok;

    memset(peer, 0, sizeof(peer));
    peer[0] = 9;
    t0 = clock();
    ok = tls_x25519_publickey(pub, bench_key, NULL, NULL);
    bench_emit("x25519_keygen", (uint32_t)(clock() - t0), ok ? 1u : 0u);
    t0 = clock();
    ok = ok && tls_x25519_secret(shared, bench_key, peer, NULL, NULL);
    bench_emit("x25519_secret", (uint32_t)(clock() - t0), ok ? 1u : 0u);
    bench_sink += pub[0] + shared[0];
}

static void bench_p256(void)
{
    uint8_t pub[65];
    uint8_t sig[64];
    uint8_t hash[32];
    clock_t t0;
    bool ok;
    bool ok2;

    memcpy(hash, bench_buf, sizeof(hash));
    t0 = clock();
    ok = tls_p256_publickey(pub, bench_key);
    bench_emit("p256_keygen", (uint32_t)(clock() - t0), ok ? 1u : 0u);
    t0 = clock();
    ok2 = tls_p256_sign(sig, hash, bench_key);
    bench_emit("p256_sign", (uint32_t)(clock() - t0), ok2 ? 1u : 0u);
    t0 = clock();
    ok2 = tls_p256_verify(sig, hash, pub);
    bench_emit("p256_verify", (uint32_t)(clock() - t0), ok2 ? 1u : 0u);
    bench_sink += (uint32_t)ok + pub[0] + sig[0];
}

static void bench_p384(void)
{
    uint8_t priv[48];
    uint8_t pub[97];
    uint8_t peer[97];
    uint8_t sig[96];
    uint8_t hash[48];
    clock_t t0;
    bool ok;
    bool ok2;

    memcpy(priv, bench_buf, sizeof(priv));
    priv[0] |= 0x01; /* ensure nonzero */
    memcpy(hash, bench_buf + 48, sizeof(hash));

    t0 = clock();
    ok = tls_p384_publickey(pub, priv);
    bench_emit("p384_keygen", (uint32_t)(clock() - t0), ok ? 1u : 0u);

    /* use pub as peer for ECDH (self-ECDH: result is not a real shared secret,
     * but exercises the full scalar-multiplication path) */
    memcpy(peer, pub, sizeof(peer));
    t0 = clock();
    ok2 = tls_p384_secret(pub, priv, peer);
    bench_emit("p384_ecdh", (uint32_t)(clock() - t0), ok2 ? 1u : 0u);

    /* re-derive pub for sign/verify */
    ok = tls_p384_publickey(pub, priv);
    t0 = clock();
    ok2 = tls_p384_sign(sig, hash, priv);
    bench_emit("p384_sign", (uint32_t)(clock() - t0), ok2 ? 1u : 0u);
    t0 = clock();
    ok2 = ok2 && tls_p384_verify(sig, hash, pub);
    bench_emit("p384_verify", (uint32_t)(clock() - t0), ok2 ? 1u : 0u);
    bench_sink += (uint32_t)ok + pub[0] + sig[0];
}

int main(void)
{
    os_ClrHome();
    if (!lwip_start())
    {
        os_PutStrFull("lwip_start failed");
        while (!os_GetCSC())
        {
        }
        return 1;
    }
    bench_fill();

    bench_handle = ti_Open(BENCH_APPVAR, "w");
    bench_log_ok = bench_handle != 0;
    if (bench_log_ok)
    {
        ti_Seek(0, SEEK_SET, bench_handle);
    }

    {
        volatile uint8_t probe_local = 0;
        bench_emit("probe_stack_addr", (uint32_t)(uintptr_t)&probe_local, 0);
        bench_emit("probe_bss_addr", (uint32_t)(uintptr_t)bench_buf, 0);
    }
    bench_emit("marker_start", 0, 0);
    bench_sha256_sweep();
    bench_sha384_sweep();
    bench_hmac_sweep();
    bench_cbc_sweep();
    bench_gcm_sweep();
    bench_gcm_decrypt();
    bench_bytes_compare();
    bench_hkdf();
    bench_rsa();
    bench_pbkdf2(1000u);
    bench_x25519();
    bench_p256();
    bench_p384();
    bench_emit("sink", bench_sink, 0);
    bench_emit("marker_done", 0, 0);

    if (bench_log_ok)
    {
        ti_Close(bench_handle);
        bench_log_ok = false;
    }

    os_ClrHome();
    printf("success");
    while (!os_GetCSC())
    {
    }
    return 0;
}
