#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
typedef uint32_t uint24_t;
#include "handshake.h"
#include "truststore.h"
#include "x509_internal.h"
#include "key_internal.h"
#include "hmac.h"

// Binder crypto is irrelevant to serialization/length checks in these tests.
#define ERROR_CODE(...) ((void)0)
static bool tls_hkdf_extract(uint8_t alg, const uint8_t *salt, size_t slen, const uint8_t *ikm, size_t ilen, uint8_t *out)
{ memset(out, 0, 32); return true; }
static bool tls_hkdf_expand_label(uint8_t alg, const uint8_t *secret, size_t slen, const char *label, size_t llen, const uint8_t *context, size_t clen, uint8_t *out, size_t n)
{ memset(out, 0, n); return true; }
bool tls_hmac_context_init(struct tls_hmac_context *ctx, uint8_t alg, const uint8_t *key, size_t n) { return true; }
void tls_hmac_update(struct tls_hmac_context *ctx, const uint8_t *p, size_t n) {}
void tls_hmac_digest(struct tls_hmac_context *ctx, uint8_t *out) { memset(out, 0, 32); }
static uint32_t sys_now(void) { return 1; }
static unsigned last_alert;
static bool tls_send_alert(struct tls_handshake_context *ctx,
                           uint8_t level, uint8_t description)
{
    (void)ctx;
    (void)level;
    last_alert = description;
    return true;
}

static unsigned pkcs_calls, pss_calls;
static unsigned cipher_calls;
static tls_alg_t last_cipher;
static uint8_t *aes_encrypt_oneshot(tls_alg_t alg, const uint8_t *key, size_t key_len,
    const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t len)
{
    cipher_calls++;
    last_cipher = alg;
    /* Return a minimal well-formed encrypt blob: iv_len=0, ct_len=0, tag_len=0 */
    uint8_t *blob = (uint8_t *)malloc(6);
    if (blob) memset(blob, 0, 6);
    return blob;
}
bool tls_rsa_encrypt(const uint8_t *in, size_t len, uint8_t *out,
                     const struct tls_rsa_key *key, uint8_t hash_alg)
{
    cipher_calls++;
    last_cipher = TLS_ALG_RSA_OAEP_SHA256;
    return true;
}
static size_t allocated;
uint8_t __rsa_transient[RSA_TRANSIENT_SIZE];
static struct tls_truststore_entry *root_entry;
static struct tls_truststore_entry *root_candidates[2];
static size_t root_candidate_count;
static unsigned ski_lookup_calls;
static void *mem_buffer_custom_malloc(size_t n) { return malloc(n); }
static void mem_buffer_custom_free(void *p) { free(p); }
static void *tls_fileio_alloc(size_t n) { return malloc(n); }
static void tls_fileio_free(void *p) { free(p); }
static bool tls_rng_healthcheck(void) { return true; }
static void *tls_random_bytes(void *buf, size_t n) { memset(buf, 0, n); return buf; }
#define TLS_RNG_STRENGTH_128 128u
static void *tls_random_bytes_ex(void *buf, size_t n, uint16_t strength)
{ assert(strength == TLS_RNG_STRENGTH_128); return tls_random_bytes(buf, n); }
static bool tls_request_random_bytes(uint8_t *buf, size_t n, void *cb, void *arg, bool blocking)
{ (void)cb; (void)arg; (void)blocking; memset(buf, 1, n); return true; }
static void mem_stats_tls_direct_add(size_t n, size_t unused) { allocated += n; }
static void mem_stats_tls_direct_release(size_t n, size_t unused) { assert(allocated >= n); allocated -= n; }
static void tls_secure_memzero(void *p, size_t n) { memset(p, 0, n); }
static uint64_t tls_random(void) { return 1; }
static unsigned x25519_public_calls;
static unsigned p256_public_calls;
static bool tls_x25519_publickey(uint8_t *pub, const uint8_t *priv, void *a, void *b)
{ (void)pub; (void)priv; (void)a; (void)b; x25519_public_calls++; return true; }
static bool tls_x25519_secret(uint8_t *out, const uint8_t *priv,
                             const uint8_t *peer, void *a, void *b)
{ (void)priv; (void)peer; (void)a; (void)b; memset(out, 0x33, 32); return true; }
static bool tls_p256_publickey(uint8_t *pub, const uint8_t *priv)
{ p256_public_calls++; (void)priv; memset(pub, 0x5a, 65); pub[0] = 0x04; return true; }
static bool tls_p256_secret(uint8_t *out, const uint8_t *priv, const uint8_t *peer)
{ (void)priv; (void)peer; memset(out, 0x44, 32); return true; }
static bool tls_p256_verify(const uint8_t *sig, const uint8_t *hash, const uint8_t *pub)
{ (void)sig; (void)hash; (void)pub; return true; }
static void tls_crypto_guard_enable(void) {}
static void tls_crypto_guard_disable(void) {}
/* No Wi-Fi bridge: every offload start returns 0, so the local code runs. */
typedef uint16_t lwip_crypto_job_t;
typedef enum { LWIP_CRYPTO_PENDING, LWIP_CRYPTO_OK, LWIP_CRYPTO_REJECTED,
               LWIP_CRYPTO_FAILED } lwip_crypto_status_t;
#define CTL_RSA_PKCS1_SHA256 1
#define CTL_RSA_PSS_SHA256 2
static lwip_crypto_job_t lwip_crypto_x25519(const uint8_t *s, const uint8_t *p, uint8_t *o) { return 0; }
static lwip_crypto_job_t lwip_crypto_p256(const uint8_t *s, const uint8_t *p, uint8_t *o) { return 0; }
static lwip_crypto_job_t lwip_crypto_p256_verify(const uint8_t *d, const uint8_t *p, const uint8_t *rs) { return 0; }
static lwip_crypto_status_t lwip_crypto_take(lwip_crypto_job_t job)
{ (void)job; return LWIP_CRYPTO_FAILED; }
static unsigned rsa_offload_calls;
static lwip_crypto_job_t lwip_crypto_rsa_verify(uint8_t a, const uint8_t *d, const uint8_t *m, size_t ml,
                                                const uint8_t *e, size_t el, const uint8_t *s)
{ rsa_offload_calls++; return 0; }
static void lwip_crypto_cancel(lwip_crypto_job_t job) {}
static void lwip_crypto_reseed(void) {}
static uint32_t lwip_sntp_read_rtc_raw(void) { return 1700000000; }
static uint32_t mock_unix_time = 1700000000;
static uint32_t lwip_sntp_get_unix_time(void) { return mock_unix_time; }
static void tls_hs_reasm_reset(struct tls_handshake_context *ctx) {}
static uint8_t hash_stub_alg __attribute__((unused));
static size_t hash_stub_bytes __attribute__((unused));
static unsigned hash_stub_inits __attribute__((unused));
bool tls_hash_context_init(struct tls_hash_context *ctx, uint8_t alg)
{ memset(ctx, 0, sizeof(*ctx)); hash_stub_alg = alg; hash_stub_bytes = 0; hash_stub_inits++; return true; }
void tls_hash_context_copy(struct tls_hash_context *dst, const struct tls_hash_context *src) { memcpy(dst, src, sizeof(*dst)); }
void tls_hash_update(struct tls_hash_context *ctx, const uint8_t *p, size_t n) { hash_stub_bytes += n; }
void tls_hash_digest(struct tls_hash_context *ctx, uint8_t *out) { memset(out, 0x42, 32); }
void tls_hash_clear(struct tls_hash_context *ctx) { memset(ctx, 0, sizeof(*ctx)); }
bool tls_rsa_pkcs1_v15_sha256_verify(const uint8_t *sig, size_t n, const uint8_t *hash, const struct tls_rsa_key *key)
{
    pkcs_calls++;
    return n == key->mod_len && key->modulus && key->modulus[0] == 0x81 &&
           sig[0] == 0x11 && hash[0] == 0x42;
}
bool tls_rsa_decrypt_signature(const uint8_t *sig, size_t n, uint8_t *em, const struct tls_rsa_key *key)
{
    if (n != key->mod_len || !key->modulus || key->modulus[0] != 0x81 ||
        !key->exponent || n > RSA_TRANSIENT_SIZE)
        return false;
    memcpy(em, sig, n);
    return true;
}
bool tls_rsa_pss_verify(const uint8_t *em, size_t n, const uint8_t *hash, size_t hlen, uint8_t alg)
{
    pss_calls++;
    return em[0] == 0x22 && hash[0] == 0x42;
}
bool tls_truststore_lookup_by_subject_index(const uint8_t *subject, size_t len,
                                            uint16_t index,
                                            struct tls_truststore_entry **out)
{
    if (!subject || len != TLS_TRUSTSTORE_SUBJECT_LEN) return false;
    if (root_candidate_count != 0)
    {
        if (index >= root_candidate_count) return false;
        *out = root_candidates[index];
        return *out != NULL &&
               memcmp((*out)->subject, subject, TLS_TRUSTSTORE_SUBJECT_LEN) == 0;
    }
    if (index != 0) return false;
    *out = root_entry;
    return root_entry != NULL &&
           memcmp(root_entry->subject, subject, TLS_TRUSTSTORE_SUBJECT_LEN) == 0;
}
bool tls_truststore_lookup_by_subject(const uint8_t *subject, size_t len, struct tls_truststore_entry **out)
{
    return tls_truststore_lookup_by_subject_index(subject, len, 0, out);
}
bool tls_truststore_lookup_key_id(const uint8_t *ski, size_t ski_len,
                                  struct tls_truststore_entry **out)
{
    ski_lookup_calls++;
    if (!ski || ski_len != 20 || ski[0] != 0xa0) return false;
    *out = root_entry;
    return root_entry != NULL;
}
bool tls_truststore_lookup(const uint8_t *ski, struct tls_truststore_entry **out)
{
    return tls_truststore_lookup_key_id(ski, TLS_TRUSTSTORE_SKI_LEN, out);
}

/* Replay entry point used by tls_cert_jobs_step once the job queue drains. */
static size_t replayed_bytes;
static bool replay_result = true;
static bool tls_consume_handshake_buffer(struct tls_handshake_context *ctx,
                                         const uint8_t *buf, size_t buf_len)
{
    (void)ctx; (void)buf;
    replayed_bytes += buf_len;
    return replay_result;
}
