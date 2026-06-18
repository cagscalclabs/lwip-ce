#include <ti/vars.h>
#include <string.h>

#include "../includes/truststore.h"
#include "../includes/rsa.h"
#include "../includes/hash.h"
#include "../includes/bytes.h"

#define LWIP_DBG_FILE_ID LWIP_FILE_TRUSTSTORE
#define LWIP_DBG_MODULE  LWIP_DBG_MOD_TLS
#include "lwip/logging.h"

/* Temporary sub-step tracing for tls_truststore_init (key-gated). Set
 * TS_TRACE_ON 1 to re-enable. Superseded by the TLS debug callback
 * (tls_debug.h), which emits TRUSTSTORE_INIT / TRUSTSTORE_VERIFIED. */
#define TS_TRACE_ON 0
#if TS_TRACE_ON
#include <ti/screen.h>
#include <ti/getkey.h>
#define TS_TRACE(msg) do { os_ClrHome(); os_PutStrFull("tstore: " msg); \
                           os_PutStrFull(" [key]"); os_GetKey(); } while (0)
#else
#define TS_TRACE(msg) ((void)0)
#endif

/*
 * Truststore appvar format:
 * +---------------------+
 * | Header (264B)       |  <- tls_truststore_header (sig, version, timestamp, count)
 * +---------------------+
 * | Entries...           |  <- Array of variable-length tls_truststore_entry records
 * +---------------------+
 *
 * struct tls_truststore_header {
 *    uint8_t sig[256];            // RSA-2048 signature over header fields + entries
 *    uint16_t version;            // Truststore format version
 *    uint32_t created_timestamp;  // Unix timestamp
 *    uint16_t entry_count;        // Number of entries
 * };
 *
 * struct tls_truststore_entry (see truststore.h):
 *    uint32_t len;                       // total byte size of this entry
 *    uint8_t  subject[TLS_TRUSTSTORE_SUBJECT_LEN]; // Subject CN, null-padded
 *    uint8_t  ski[TLS_TRUSTSTORE_SKI_LEN];         // Subject Key Identifier
 *    uint32_t expiry_start;              // notBefore Unix timestamp
 *    uint32_t expiry_end;                // notAfter  Unix timestamp
 *    uint8_t  alg_id;                    // tls_cert_sig_alg_t
 *    uint8_t  key[];                     // raw public key bytes (RSA exp+mod, or EC point)
 *
 * Root anchoring: a chain's topmost cert is checked against this store by
 * subject-name lookup (tls_truststore_lookup_by_subject) of its issuer. If
 * absent, root anchoring is skipped for that chain (see truststore.h).
 *
 * [TODO] Age warning: if (now - created_timestamp) > TLS_TRUSTSTORE_AGE_WARN_DAYS,
 * library will print a warning suggesting truststore update.
 */

char *truststore_name = "lwIPCERT";
bool truststore_valid_for_session = false;

#define TLS_TRUSTSTORE_VERSION 1

uint8_t trust_store_pubkey[] = {
    0xA1, 0xD3, 0x45, 0x9D, 0xC3, 0xD2, 0x1D, 0x6A, 0x9B, 0xA1, 0xD2, 0xCD, 0xEB, 0x4A, 0x10, 0xD0,
    0x79, 0x34, 0xB1, 0x06, 0xDA, 0xB3, 0x6D, 0x36, 0x01, 0x75, 0x3E, 0xA3, 0x56, 0xBD, 0x74, 0xDB,
    0x5A, 0xBF, 0xC4, 0xF4, 0x25, 0x5A, 0xA6, 0x50, 0x8F, 0x5D, 0xDC, 0x1B, 0x99, 0x13, 0x0E, 0xD5,
    0x57, 0xE1, 0x47, 0x01, 0x9A, 0xCE, 0xC8, 0x78, 0x6E, 0x83, 0x0E, 0x38, 0xE5, 0xDB, 0xB9, 0x2B,
    0xB2, 0x09, 0x87, 0x29, 0x44, 0x2A, 0x19, 0xAB, 0xFD, 0xF9, 0xB0, 0x73, 0x61, 0xDA, 0x17, 0x3B,
    0xAC, 0x0C, 0x85, 0x41, 0x39, 0x74, 0x20, 0xF1, 0xD5, 0xC9, 0x59, 0x8E, 0xB0, 0x3C, 0xCC, 0x0A,
    0xF7, 0xB6, 0x18, 0x14, 0x24, 0x67, 0x14, 0x66, 0xF0, 0xB9, 0x26, 0x47, 0xDD, 0xAF, 0x40, 0x46,
    0x59, 0x29, 0x75, 0x5B, 0x6C, 0x85, 0x11, 0x3C, 0xD6, 0x32, 0xF1, 0x78, 0xA5, 0x02, 0xFC, 0x12,
    0xF6, 0x79, 0x4E, 0xDB, 0x1D, 0x53, 0xA8, 0xEC, 0xA7, 0x2C, 0x0E, 0x8F, 0x51, 0x14, 0x68, 0xDB,
    0x4C, 0x56, 0xB3, 0x40, 0xEA, 0x5E, 0x30, 0x2E, 0xE0, 0xBF, 0x1D, 0x33, 0xAB, 0x9F, 0x0E, 0x8D,
    0x85, 0x18, 0xED, 0xF7, 0xBA, 0xCC, 0xB2, 0xA7, 0xEE, 0xA6, 0xE0, 0xEC, 0xE5, 0xF5, 0x49, 0x44,
    0x74, 0x25, 0xD9, 0x8A, 0xCC, 0x71, 0xAA, 0x99, 0x05, 0x84, 0x64, 0x6A, 0x7E, 0x35, 0x8A, 0x01,
    0xFA, 0xA2, 0xD5, 0xE7, 0xA4, 0xF4, 0x3A, 0x6A, 0x94, 0x19, 0x75, 0x7F, 0xDD, 0xD3, 0x08, 0x58,
    0x20, 0x5C, 0xDA, 0xBB, 0x6E, 0xE3, 0xB5, 0x6E, 0x29, 0x7F, 0xA6, 0x01, 0x14, 0x33, 0x98, 0x81,
    0x72, 0xA5, 0x1A, 0x10, 0x78, 0x95, 0x97, 0x23, 0x19, 0x69, 0x0B, 0xC3, 0x59, 0x49, 0x3E, 0x6D,
    0x3D, 0x4D, 0xA5, 0x7B, 0x4B, 0xD5, 0x1A, 0xD0, 0x68, 0xD6, 0x59, 0x7B, 0xF6, 0x23, 0x69, 0x95};

#define TRUSTSTORE_SIG_LEN 256
tls_truststore_status_t tls_truststore_init(void)
{
    var_t *truststore_var;
    /* Decrypted-signature output uses the shared static RSA scratch region
     * (.bss) instead of a 256-byte stack local, to keep the deep
     * truststore->rsa->powmod call chain off the eZ80 stack. */
    uint8_t *d_sig = __rsa_transient;
    uint8_t tstore_hash[TLS_SHA256_DIGEST_LEN];
    struct tls_hash_context hash_ctx;

    /* Clear the session-valid flag up front so it is only ever true after
     * a fresh successful validation below. Without this, a stale `true`
     * from a previous lwip session could survive a stop/restart and let
     * certificate lookups trust an unvalidated store (fail-OPEN). */
    truststore_valid_for_session = false;

    TS_TRACE("E0 enter");
    // If hash init fails, error out early
    if (!tls_hash_context_init(&hash_ctx, TLS_HASH_SHA256))
    {
        ERROR_CODE(TLS_STORE_HASH_FAIL);
        return TLS_STORE_HASH_FAIL;
    }

    // Attempt to load the trust store.
    // Return with error if not found.
    truststore_var = os_GetAppVarData(truststore_name, NULL);
    if (!truststore_var)
    {
        WARN_CODE(TLS_STORE_NOT_FOUND);
        return TLS_STORE_NOT_FOUND;
    }
    TS_TRACE("E0b appvar found");

    // Get length of store, entry-db len, and sig ptr
    uint16_t truststore_size = *((uint16_t *)truststore_var);
    if (truststore_size < TLS_TRUSTSTORE_HEADER_LEN)
    {
        ERROR_CODE(TLS_STORE_SIZE_INVALID);
        return TLS_STORE_SIZE_INVALID;
    }
    uint8_t *store_header_bytes = (uint8_t *)truststore_var + 2;
    struct tls_truststore_header *header = (struct tls_truststore_header *)store_header_bytes;
    if (header->version != TLS_TRUSTSTORE_VERSION)
    {
        ERROR_CODE(TLS_STORE_VERSION_MISMATCH);
        return TLS_STORE_VERSION_MISMATCH;
    }
    uint8_t *store_db_start = store_header_bytes + TLS_TRUSTSTORE_HEADER_LEN;
    uint16_t store_db_len = truststore_size - TLS_TRUSTSTORE_HEADER_LEN;

    TS_TRACE("E1 hash hdr");
    // Hash header fields (version + timestamp + entry_count) and entries
    tls_hash_update(&hash_ctx, &header->version,
                    sizeof(header->version) + sizeof(header->created_timestamp) + sizeof(header->entry_count));
    TS_TRACE("E2 hash db");
    tls_hash_update(&hash_ctx, store_db_start, store_db_len);
    TS_TRACE("E3 digest");
    tls_hash_digest(&hash_ctx, tstore_hash);

    TS_TRACE("E4 rsa decrypt");
    // Decrypt the truststore signature
    if (!tls_rsa_decrypt_signature(header->sig, TRUSTSTORE_SIG_LEN, d_sig, trust_store_pubkey, sizeof(trust_store_pubkey)))
    {
        ERROR_CODE(TLS_STORE_SIG_INVALID);
        return TLS_STORE_SIG_INVALID;
    }
    TS_TRACE("E5 pss verify");
    // Verify the signature
    bool verified = tls_rsa_pss_verify(d_sig, sizeof(trust_store_pubkey), tstore_hash, hash_ctx.digestlen, TLS_HASH_SHA256);
    tls_secure_memzero(d_sig, TRUSTSTORE_SIG_LEN);
    TS_TRACE("E6 verify done");
    if (verified)
    {
        truststore_valid_for_session = true;
        INFO("truststore verified");
    }
    else
    {
        ERROR_CODE(TLS_STORE_SIG_INVALID);
    }
    return verified ? TLS_STORE_OK : TLS_STORE_SIG_INVALID;
}

static bool tls_truststore_open_db(uint8_t **db_out, uint16_t *db_len_out,
                                    struct tls_truststore_header **header_out)
{
    var_t *truststore_var = os_GetAppVarData(truststore_name, NULL);
    if (!truststore_var)
        return false;

    uint16_t truststore_size = *((uint16_t *)truststore_var);
    if (truststore_size < TLS_TRUSTSTORE_HEADER_LEN)
        return false;

    struct tls_truststore_header *header =
        (struct tls_truststore_header *)((uint8_t *)truststore_var + 2);
    if (header->version != TLS_TRUSTSTORE_VERSION)
        return false;

    *header_out  = header;
    *db_out      = (uint8_t *)header + TLS_TRUSTSTORE_HEADER_LEN;
    *db_len_out  = truststore_size - TLS_TRUSTSTORE_HEADER_LEN;
    return true;
}

bool tls_truststore_lookup(const uint8_t *ski, struct tls_truststore_entry **result)
{
    if (ski == NULL || !truststore_valid_for_session)
        return false;

    uint8_t *db;
    uint16_t db_len;
    struct tls_truststore_header *header;
    if (!tls_truststore_open_db(&db, &db_len, &header))
        return false;

    uint16_t count = 0, offset = 0;
    while (offset + sizeof(struct tls_truststore_entry) <= db_len)
    {
        struct tls_truststore_entry *entry =
            (struct tls_truststore_entry *)(db + offset);
        if (entry->len < sizeof(struct tls_truststore_entry) ||
            offset + entry->len > db_len)
            break;
        if (tls_bytes_compare(ski, entry->ski, TLS_TRUSTSTORE_SKI_LEN))
        {
            if (result) *result = entry;
            return true;
        }
        if (++count > header->entry_count) break;
        offset += (uint16_t)entry->len;
    }
    return false;
}

bool tls_truststore_lookup_by_subject(const uint8_t *subject, size_t subject_len,
                                      struct tls_truststore_entry **result)
{
    if (subject == NULL || subject_len == 0 || subject_len > TLS_TRUSTSTORE_SUBJECT_LEN ||
        !truststore_valid_for_session)
        return false;

    uint8_t *db;
    uint16_t db_len;
    struct tls_truststore_header *header;
    if (!tls_truststore_open_db(&db, &db_len, &header))
        return false;

    uint16_t count = 0, offset = 0;
    while (offset + sizeof(struct tls_truststore_entry) <= db_len)
    {
        struct tls_truststore_entry *entry =
            (struct tls_truststore_entry *)(db + offset);
        if (entry->len < sizeof(struct tls_truststore_entry) ||
            offset + entry->len > db_len)
            break;
        /* Match: subject bytes compare equal, rest of entry->subject is zero-padding */
        size_t entry_subj_len = 0;
        while (entry_subj_len < TLS_TRUSTSTORE_SUBJECT_LEN && entry->subject[entry_subj_len])
            entry_subj_len++;
        if (entry_subj_len == subject_len &&
            memcmp(subject, entry->subject, subject_len) == 0)
        {
            if (result) *result = entry;
            return true;
        }
        if (++count > header->entry_count) break;
        offset += (uint16_t)entry->len;
    }
    return false;
}
