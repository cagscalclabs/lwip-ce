/**
 * @file main.c
 * @brief NIST CAVP-format primitive validation runner (calculator side).
 *
 * Reads CAVPIN.8xv (input vectors), dispatches each vector to the
 * appropriate primitive, and writes responses to CAVPOUT.8xv. Does NOT
 * grade itself; expected outputs live host-side in vectors/expected.json
 * and are compared by tests/common/scripts/parse_cavp_output_appvar.py.
 *
 * AppVar wire format (host-readable, see tests/common/scripts/cavp_fetch.py):
 *
 *   CAVPIN.8xv:
 *     magic[4]      = 'A','I','N','1'
 *     vector_count  uint16  little-endian
 *     repeat vector_count:
 *       algorithm_id  uint8   (1=AES-GCM, 2=SHA-256, 3=HMAC, 4=HKDF, 5=DRBG)
 *       test_id       uint16  little-endian
 *       payload_len   uint16  little-endian
 *       payload[payload_len]  algorithm-specific TLV (see runners below)
 *
 *   CAVPOUT.8xv:
 *     magic[4]      = 'A','O','U','T'
 *     response_count uint16 little-endian
 *     repeat response_count:
 *       test_id      uint16
 *       status       uint8   (0=ok, 1=unsupported, 2=internal_error)
 *       result_len   uint16
 *       result[result_len]
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <ti/screen.h>
#include <ti/vars.h>
#include <fileioc.h>
#include <ti/getkey.h>

#include "../../../../src/tls/includes/aes.h"
#include "../../../../src/tls/includes/hash.h"
#include "../../../../src/tls/includes/hmac.h"
#include "../../../../src/tls/includes/hkdf.h"
#include "../../../../src/tls/includes/rsa.h"
#include "../../../../src/tls/contrib/x25519/src/x25519.h"

#define CAVPIN_NAME "CAVPIN"
#define CAVPOUT_NAME "CAVPOUT"

#define ALG_AES_GCM                1
#define ALG_SHA256                 2
#define ALG_HMAC_SHA256            3
#define ALG_HKDF_SHA256            4
#define ALG_DRBG_SHA256            5
#define ALG_RSA_PSS_SHA256_VERIFY  6
#define ALG_X25519_PUBLICKEY       7
#define ALG_X25519_SECRET          8

#define STATUS_OK 0
#define STATUS_UNSUPPORTED 1
#define STATUS_INTERNAL 2

/* ---------- AppVar helpers (little-endian readers/writers) ---------- */

static uint16_t rd_u16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static void wr_u16(uint8_t *p, uint16_t v)
{
    p[0] = v & 0xFF;
    p[1] = (v >> 8) & 0xFF;
}

/* ---------- Per-algorithm payload runners ---------- */

/*
 * AES-GCM payload TLV (encrypt):
 *   key_len      uint8   (always 16)
 *   key          [key_len]
 *   iv_len       uint8   (always 12)
 *   iv           [iv_len]
 *   aad_len      uint16
 *   aad          [aad_len]
 *   pt_len       uint16
 *   pt           [pt_len]
 *
 * Response (little-endian):
 *   tag_len      uint8 (16)
 *   tag          [16]
 *   ct_len       uint16
 *   ct           [ct_len]
 */
static size_t run_aes_gcm(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_max)
{
    if (in_len < 1)
        return 0;
    size_t off = 0;
    uint8_t key_len = in[off++];
    if (off + key_len > in_len)
        return 0;
    const uint8_t *key = in + off;
    off += key_len;

    if (off + 1 > in_len)
        return 0;
    uint8_t iv_len = in[off++];
    if (off + iv_len > in_len)
        return 0;
    const uint8_t *iv = in + off;
    off += iv_len;

    if (off + 2 > in_len)
        return 0;
    uint16_t aad_len = rd_u16(in + off);
    off += 2;
    if (off + aad_len > in_len)
        return 0;
    const uint8_t *aad = in + off;
    off += aad_len;

    if (off + 2 > in_len)
        return 0;
    uint16_t pt_len = rd_u16(in + off);
    off += 2;
    if (off + pt_len > in_len)
        return 0;
    const uint8_t *pt = in + off;

    /* Need: ct (pt_len) + tag (16) + framing (1 + 16 tag header + 2 ct_len) */
    if (out_max < (size_t)1 + 16 + 2 + pt_len)
        return 0;

    struct tls_aes_context ctx;
    if (!tls_aes_init(&ctx, TLS_AES_GCM, key, key_len, iv, iv_len))
        return 0;
    if (aad_len && !tls_aes_update_aad(&ctx, aad, aad_len))
        return 0;

    uint8_t *ct_buf = out + 1 + 16 + 2; /* leave room for header */
    if (pt_len && !tls_aes_encrypt(&ctx, pt, pt_len, ct_buf))
        return 0;

    uint8_t tag[16];
    if (!tls_aes_digest(&ctx, tag))
        return 0;

    size_t o = 0;
    out[o++] = 16; /* tag_len */
    memcpy(out + o, tag, 16);
    o += 16;
    wr_u16(out + o, pt_len);
    o += 2;      /* ct_len */
    o += pt_len; /* ct already at ct_buf */
    return o;
}

/*
 * SHA-256 payload TLV:
 *   msg_len  uint16
 *   msg      [msg_len]
 *
 * Response:
 *   digest_len uint8 (32)
 *   digest     [32]
 */
static size_t run_sha256(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_max)
{
    if (in_len < 2)
        return 0;
    uint16_t msg_len = rd_u16(in);
    if ((size_t)2 + msg_len > in_len)
        return 0;
    if (out_max < 1 + 32)
        return 0;

    struct tls_hash_context hctx;
    if (!tls_hash_context_init(&hctx, TLS_HASH_SHA256))
        return 0;
    if (msg_len)
        tls_hash_update(&hctx, in + 2, msg_len);
    uint8_t digest[32];
    tls_hash_digest(&hctx, digest);

    out[0] = 32;
    memcpy(out + 1, digest, 32);
    return 33;
}

/*
 * HMAC-SHA-256 payload TLV:
 *   key_len  uint16
 *   key      [key_len]
 *   msg_len  uint16
 *   msg      [msg_len]
 *
 * Response: tag_len uint8 (32) + tag[32]
 */
static size_t run_hmac_sha256(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_max)
{
    if (in_len < 2)
        return 0;
    size_t off = 0;
    uint16_t key_len = rd_u16(in + off);
    off += 2;
    if (off + key_len > in_len)
        return 0;
    const uint8_t *key = in + off;
    off += key_len;

    if (off + 2 > in_len)
        return 0;
    uint16_t msg_len = rd_u16(in + off);
    off += 2;
    if (off + msg_len > in_len)
        return 0;
    const uint8_t *msg = in + off;

    if (out_max < 1 + 32)
        return 0;

    struct tls_hmac_context hctx;
    if (!tls_hmac_context_init(&hctx, TLS_HASH_SHA256, key, key_len))
        return 0;
    if (msg_len)
        tls_hmac_update(&hctx, msg, msg_len);
    uint8_t tag[32];
    tls_hmac_digest(&hctx, tag);

    out[0] = 32;
    memcpy(out + 1, tag, 32);
    return 33;
}

/*
 * HKDF-SHA-256 payload TLV:
 *   ikm_len   uint16
 *   ikm       [ikm_len]
 *   salt_len  uint16
 *   salt      [salt_len]
 *   info_len  uint16
 *   info      [info_len]
 *   L         uint16   (output length in bytes; must be <= 255*32 = 8160)
 *
 * Response: okm_len uint16 + okm[okm_len]
 */
static size_t run_hkdf_sha256(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_max)
{
    if (in_len < 2)
        return 0;
    size_t off = 0;
    uint16_t ikm_len = rd_u16(in + off);
    off += 2;
    if (off + ikm_len > in_len)
        return 0;
    const uint8_t *ikm = in + off;
    off += ikm_len;

    if (off + 2 > in_len)
        return 0;
    uint16_t salt_len = rd_u16(in + off);
    off += 2;
    if (off + salt_len > in_len)
        return 0;
    const uint8_t *salt = in + off;
    off += salt_len;

    if (off + 2 > in_len)
        return 0;
    uint16_t info_len = rd_u16(in + off);
    off += 2;
    if (off + info_len > in_len)
        return 0;
    const uint8_t *info = in + off;
    off += info_len;

    if (off + 2 > in_len)
        return 0;
    uint16_t L = rd_u16(in + off);

    if (L > 8160)
        return 0;
    if (out_max < (size_t)2 + L)
        return 0;

    /* HKDF = Extract + Expand. Most implementations of tls_hkdf_expand_label
     * already do Extract+Expand internally; here we use the lower-level
     * primitives that just do Expand. To be vendor-correct, we use the
     * two-step API: tls_hkdf_extract then tls_hkdf_expand. */
    uint8_t prk[32];
    if (!tls_hkdf_extract(TLS_HASH_SHA256, salt, salt_len, ikm, ikm_len, prk))
        return 0;
    if (!tls_hkdf_expand(TLS_HASH_SHA256, prk, 32, info, info_len, out + 2, L))
        return 0;

    wr_u16(out, L);
    return (size_t)2 + L;
}

/*
 * DRBG-SHA-256 payload TLV:
 *   entropy_len           uint16
 *   entropy               [entropy_len]
 *   nonce_len             uint16
 *   nonce                 [nonce_len]
 *   personalization_len   uint16
 *   personalization       [personalization_len]
 *   output_len            uint16
 *
 * Response: output_len uint16 + output[output_len]
 *
 * NOTE: This is a stub that returns STATUS_UNSUPPORTED for now because the
 * DRBG in this codebase is integrated with the TLS context, not exposed
 * as a standalone Hash_DRBG SP 800-90A API. To validate against NIST DRBG
 * vectors we'd need to add tls_drbg_instantiate / tls_drbg_generate /
 * tls_drbg_reseed entry points that accept caller-provided entropy.
 */
static size_t run_drbg_sha256(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_max)
{
    (void)in;
    (void)in_len;
    (void)out;
    (void)out_max;
    /* Signal unsupported via length 0 + caller sets status. */
    return 0;
}

/*
 * RSA-PSS-SHA-256 verify payload TLV:
 *   modulus_len  uint16    (n size, big-endian; typically 256 for RSA-2048)
 *   modulus      [modulus_len]
 *   exponent_len uint8
 *   exponent     [exponent_len]    (NOTE: project's RSA hardcodes e=65537;
 *                                   this field is accepted but ignored.)
 *   salt_len     uint8             (32 for PSS-SHA-256)
 *   msg_len      uint16
 *   msg          [msg_len]
 *   sig_len      uint16            (= modulus_len)
 *   sig          [sig_len]
 *
 * Response:
 *   verdict      uint8     (1 = signature valid, 0 = invalid)
 *
 * Verify is the composition of (a) RSA modexp to recover EM from the
 * signature using the supplied modulus, and (b) PSS padding check of EM
 * against SHA-256(msg). Both must succeed for verdict=1.
 */
static size_t run_rsa_pss_verify(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_max)
{
    if (in_len < 2 || out_max < 1) return 0;
    size_t off = 0;

    uint16_t modulus_len = rd_u16(in + off); off += 2;
    if (off + modulus_len > in_len) return 0;
    const uint8_t *modulus = in + off; off += modulus_len;

    if (off + 1 > in_len) return 0;
    uint8_t exp_len = in[off++];
    if (off + exp_len > in_len) return 0;
    /* Skip the exponent bytes — project's RSA hardcodes e=65537. */
    off += exp_len;

    if (off + 1 > in_len) return 0;
    uint8_t /* unused, format byte */ salt_len_byte = in[off++];
    (void)salt_len_byte;

    if (off + 2 > in_len) return 0;
    uint16_t msg_len = rd_u16(in + off); off += 2;
    if (off + msg_len > in_len) return 0;
    const uint8_t *msg = in + off; off += msg_len;

    if (off + 2 > in_len) return 0;
    uint16_t sig_len = rd_u16(in + off); off += 2;
    if (off + sig_len > in_len) return 0;
    const uint8_t *sig = in + off;

    /* sig and modulus must be the same length for RSA */
    if (sig_len != modulus_len) {
        out[0] = 0;  /* verdict: invalid (size mismatch is a hard reject) */
        return 1;
    }

    /* Step 1: RSA modexp to recover EM from sig.
     * em_buf is in a file-scope static rather than stack: powmod_exp_u24
     * carves ~2*modulus_len bytes of scratch off the stack internally,
     * and the eZ80 stack is tight. Moving the EM buffer off-stack also
     * rules out any caller-side stack-smash interaction with the bigint
     * workspace. */
    if (modulus_len > 256) {
        out[0] = 0;
        return 1;
    }
    static uint8_t em_buf[256];
    if (!tls_rsa_decrypt_signature(sig, sig_len, em_buf, modulus, modulus_len)) {
        out[0] = 0;
        return 1;
    }

    /* Step 2: SHA-256 the message. This intentionally happens after
     * modexp so the bigint stack workspace cannot clobber mhash. */
    struct tls_hash_context hctx;
    if (!tls_hash_context_init(&hctx, TLS_HASH_SHA256)) return 0;
    if (msg_len) tls_hash_update(&hctx, msg, msg_len);
    uint8_t mhash[32];
    tls_hash_digest(&hctx, mhash);

    /* Step 3: PSS padding check */
    bool ok = tls_rsa_pss_verify(em_buf, modulus_len, mhash, 32, TLS_HASH_SHA256);
    out[0] = ok ? 1 : 0;
    return 1;
}

/*
 * X25519-PUBLICKEY payload: priv[32].
 * Response: pub[32].
 */
static size_t run_x25519_publickey(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_max)
{
    if (in_len != 32 || out_max < 32) return 0;
    if (!tls_x25519_publickey(out, in, NULL, NULL)) return 0;
    return 32;
}

/*
 * X25519-SECRET payload: priv[32] || peer_pub[32].
 * Response: shared[32].
 */
static size_t run_x25519_secret(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_max)
{
    if (in_len != 64 || out_max < 32) return 0;
    const uint8_t *priv = in;
    const uint8_t *peer = in + 32;
    if (!tls_x25519_secret(out, priv, peer, NULL, NULL)) return 0;
    return 32;
}

/* ---------- Main runner ---------- */

int main(void)
{
    os_ClrHome();
    printf("CAVP runner\n");

    uint8_t in_handle = ti_Open(CAVPIN_NAME, "r");
    if (!in_handle)
    {
        printf("ERROR: no %s\n", CAVPIN_NAME);
        printf("Press any key");
        os_GetKey();
        return 1;
    }

    /* ti_GetDataPtr returns a pointer to the var content directly (no
     * leading length prefix to skip — that's a quirk of os_GetAppVarData,
     * which is a different API). ti_GetSize returns the content length. */
    size_t in_size = ti_GetSize(in_handle);
    const uint8_t *in = ti_GetDataPtr(in_handle);
    if (!in || in_size < 6)
    {
        ti_Close(in_handle);
        printf("ERROR: bad %s (size=%u)\n", CAVPIN_NAME, (unsigned)in_size);
        printf("Press any key");
        os_GetKey();
        return 1;
    }

    /* Validate magic */
    if (in[0] != 'A' || in[1] != 'I' || in[2] != 'N' || in[3] != '1')
    {
        ti_Close(in_handle);
        printf("ERROR: bad magic %02x%02x%02x%02x\n", in[0], in[1], in[2], in[3]);
        printf("Press any key");
        os_GetKey();
        return 1;
    }

    uint16_t vector_count = rd_u16(in + 4);
    size_t in_off = 6;

    /* Open output AppVar */
    (void)ti_Delete(CAVPOUT_NAME);
    uint8_t out_handle = ti_Open(CAVPOUT_NAME, "w");
    if (!out_handle)
    {
        ti_Close(in_handle);
        printf("ERROR: open %s\n", CAVPOUT_NAME);
        printf("Press any key");
        os_GetKey();
        return 1;
    }

    /* Write magic + placeholder response_count; we'll patch the count at end */
    uint8_t header[6] = {'A', 'O', 'U', 'T', 0, 0};
    ti_Write(header, sizeof(header), 1, out_handle);

    uint16_t responses_written = 0;
    /* Per-response scratch buffer: enough for the largest expected primitive
     * output. HKDF can emit up to 8160 bytes; cap response payload to keep
     * total AppVar size sane for this CI sample. */
    static uint8_t scratch[8192];

    printf("running %u vectors\n", vector_count);

    for (uint16_t i = 0; i < vector_count; i++)
    {
        if (in_off + 5 > in_size)
            break;
        uint8_t alg = in[in_off++];
        uint16_t test_id = rd_u16(in + in_off);
        in_off += 2;
        uint16_t payload_len = rd_u16(in + in_off);
        in_off += 2;
        if (in_off + payload_len > in_size)
            break;
        const uint8_t *payload = in + in_off;
        in_off += payload_len;

        size_t result_len = 0;
        uint8_t status = STATUS_OK;

        switch (alg)
        {
        case ALG_AES_GCM:
            result_len = run_aes_gcm(payload, payload_len, scratch, sizeof(scratch));
            if (result_len == 0)
                status = STATUS_INTERNAL;
            break;
        case ALG_SHA256:
            result_len = run_sha256(payload, payload_len, scratch, sizeof(scratch));
            if (result_len == 0)
                status = STATUS_INTERNAL;
            break;
        case ALG_HMAC_SHA256:
            result_len = run_hmac_sha256(payload, payload_len, scratch, sizeof(scratch));
            if (result_len == 0)
                status = STATUS_INTERNAL;
            break;
        case ALG_HKDF_SHA256:
            result_len = run_hkdf_sha256(payload, payload_len, scratch, sizeof(scratch));
            if (result_len == 0)
                status = STATUS_INTERNAL;
            break;
        case ALG_DRBG_SHA256:
            result_len = run_drbg_sha256(payload, payload_len, scratch, sizeof(scratch));
            status = STATUS_UNSUPPORTED;
            result_len = 0;
            break;
        case ALG_RSA_PSS_SHA256_VERIFY:
            result_len = run_rsa_pss_verify(payload, payload_len, scratch, sizeof(scratch));
            if (result_len == 0)
                status = STATUS_INTERNAL;
            break;
        case ALG_X25519_PUBLICKEY:
            result_len = run_x25519_publickey(payload, payload_len, scratch, sizeof(scratch));
            if (result_len == 0)
                status = STATUS_INTERNAL;
            break;
        case ALG_X25519_SECRET:
            result_len = run_x25519_secret(payload, payload_len, scratch, sizeof(scratch));
            if (result_len == 0)
                status = STATUS_INTERNAL;
            break;
        default:
            status = STATUS_UNSUPPORTED;
            result_len = 0;
            break;
        }

        uint8_t rec_header[5];
        wr_u16(rec_header, test_id);
        rec_header[2] = status;
        wr_u16(rec_header + 3, (uint16_t)result_len);
        ti_Write(rec_header, sizeof(rec_header), 1, out_handle);
        if (result_len)
            ti_Write(scratch, result_len, 1, out_handle);

        responses_written++;
    }

    /* Patch the response_count field in the AppVar header */
    ti_Seek(4, SEEK_SET, out_handle);
    uint8_t count_le[2];
    wr_u16(count_le, responses_written);
    ti_Write(count_le, 2, 1, out_handle);

    ti_SetArchiveStatus(true, out_handle);
    ti_Close(out_handle);

    ti_Close(in_handle);

    os_ClrHome();
    printf("CAVP runner\n");
    printf("Done.");
    os_GetKey();
    return 0;
}
