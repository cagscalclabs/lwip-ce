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
static void *mem_buffer_custom_malloc(size_t n) { return malloc(n); }
static void mem_buffer_custom_free(void *p) { free(p); }
static void *tls_fileio_alloc(size_t n) { return malloc(n); }
static void tls_fileio_free(void *p) { free(p); }
static bool tls_rng_healthcheck(void) { return true; }
static void tls_random_bytes(uint8_t *buf, size_t n) { memset(buf, 0, n); }
static bool tls_request_random_bytes(uint8_t *buf, size_t n, void *cb, void *arg, bool blocking)
{ (void)cb; (void)arg; (void)blocking; memset(buf, 1, n); return true; }
static void mem_stats_tls_direct_add(size_t n, size_t unused) { allocated += n; }
static void mem_stats_tls_direct_release(size_t n, size_t unused) { assert(allocated >= n); allocated -= n; }
static void tls_secure_memzero(void *p, size_t n) { memset(p, 0, n); }
static uint64_t tls_random(void) { return 1; }
static bool tls_x25519_publickey(uint8_t *pub, const uint8_t *priv, void *a, void *b) { return true; }
static uint32_t lwip_sntp_read_rtc_raw(void) { return 1700000000; }
static uint32_t lwip_sntp_get_unix_time(void) { return 1700000000; }
static void tls_hs_reasm_reset(struct tls_handshake_context *ctx) {}
bool tls_hash_context_init(struct tls_hash_context *ctx, uint8_t alg) { memset(ctx, 0, sizeof(*ctx)); return true; }
void tls_hash_context_copy(struct tls_hash_context *dst, const struct tls_hash_context *src) { memcpy(dst, src, sizeof(*dst)); }
void tls_hash_update(struct tls_hash_context *ctx, const uint8_t *p, size_t n) {}
void tls_hash_digest(struct tls_hash_context *ctx, uint8_t *out) { memset(out, 0x42, 32); }
bool tls_rsa_pkcs1_v15_sha256_verify(const uint8_t *sig, size_t n, const uint8_t *hash, const struct tls_rsa_key *key)
{
    pkcs_calls++;
    return n == key->mod_len && sig[0] == 0x11 && hash[0] == 0x42;
}
bool tls_rsa_decrypt_signature(const uint8_t *sig, size_t n, uint8_t *em, const struct tls_rsa_key *key)
{
    if (n != key->mod_len || !key->modulus || !key->exponent || n > RSA_TRANSIENT_SIZE)
        return false;
    memcpy(em, sig, n);
    return true;
}
bool tls_rsa_pss_verify(const uint8_t *em, size_t n, const uint8_t *hash, size_t hlen, uint8_t alg)
{
    pss_calls++;
    return em[0] == 0x22 && hash[0] == 0x42;
}
bool tls_truststore_lookup_by_subject(const uint8_t *subject, size_t len, struct tls_truststore_entry **out)
{
    *out = root_entry;
    return root_entry != NULL;
}
