#include <string.h>
#include "../../lwip-imports.h"

#include "../includes/truststore.h"
#include "../includes/rsa.h"
#include "../includes/hash.h"
#include "../includes/bytes.h"
#include "../includes/tls.h"
#include "lwip/sntp_time.h"

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
 * | SKI index[count]      |  <- sorted key[32] + metadata offset[2]
 * | Subject index[count]  |  <- sorted SHA-256(DER Name)[32] + metadata offset[2]
 * | Metadata...           |  <- Variable-length tls_truststore_entry records
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
 *    uint8_t  subject[TLS_TRUSTSTORE_SUBJECT_LEN]; // SHA-256(DER Subject Name)
 *    uint8_t  ski[TLS_TRUSTSTORE_SKI_LEN];         // Subject Key Identifier
 *    uint32_t expiry_start;              // notBefore Unix timestamp
 *    uint32_t expiry_end;                // notAfter  Unix timestamp
 *    uint8_t  alg_id;                    // tls_cert_sig_alg_t
 *    uint8_t  key[];                     // raw public key bytes (RSA exp+mod, or EC point)
 *
 * Root anchoring: a chain's topmost cert normally selects a root by matching
 * its AuthorityKeyIdentifier to the stored SubjectKeyIdentifier. If the AKI
 * keyIdentifier is absent, all current roots with the complete issuer Name
 * digest are tried and the topmost certificate's signature decides which key,
 * if any, is valid.
 * Failure to find and verify an anchor aborts the handshake.
 *
 * Stores older than the configured age threshold emit a warning after their
 * signature has been verified; individual root validity windows are enforced
 * during lookup.
 */

char *truststore_name = "lwIPCERT";
bool truststore_valid_for_session = false;
static uint8_t truststore_verified_hash[TLS_SHA256_DIGEST_LEN];

#define TLS_TRUSTSTORE_ENTRY_MAX \
    (sizeof(struct tls_truststore_entry) + 3u + RSA_MODULUS_MAX_SUPPORTED)
static union {
    uint32_t align;
    uint8_t bytes[TLS_TRUSTSTORE_ENTRY_MAX];
} truststore_entry_copy;

#define TLS_TRUSTSTORE_AGE_WARN_SECONDS (180u * 24u * 60u * 60u)

static uint16_t tls_truststore_read_u16(const uint8_t *p)
{
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static const uint8_t *tls_truststore_index_record(const uint8_t *index,
                                                   uint16_t position)
{
    return index + (size_t)position * TLS_TRUSTSTORE_INDEX_ENTRY_LEN;
}

static uint16_t tls_truststore_index_offset(const uint8_t *record)
{
    return tls_truststore_read_u16(record + TLS_TRUSTSTORE_INDEX_KEY_LEN);
}

/* Validate the entire signed v3 layout once, before making the store usable.
 * The SKI index is also the canonical metadata-order index: requiring its
 * offsets to describe every metadata entry exactly once makes arbitrary or
 * interior pointers impossible. The subject index may reorder those same
 * offsets, and is checked against the canonical index by binary search. */
static bool tls_truststore_validate_layout(
    const struct tls_truststore_header *header, uint16_t truststore_size,
    const uint8_t **ski_index_out, const uint8_t **subject_index_out,
    const uint8_t **metadata_out, uint16_t *metadata_len_out)
{
    size_t payload_len;
    size_t one_index_len;
    size_t indexes_len;
    const uint8_t *ski_index;
    const uint8_t *subject_index;
    const uint8_t *metadata;
    size_t metadata_len;
    size_t expected_offset = 0;
    uint16_t i;

    if (!header || header->entry_count == 0 ||
        truststore_size < TLS_TRUSTSTORE_HEADER_LEN)
        return false;

    payload_len = (size_t)truststore_size - TLS_TRUSTSTORE_HEADER_LEN;
    one_index_len = (size_t)header->entry_count *
                    TLS_TRUSTSTORE_INDEX_ENTRY_LEN;
    indexes_len = one_index_len * 2u;
    if (one_index_len / TLS_TRUSTSTORE_INDEX_ENTRY_LEN !=
            header->entry_count ||
        indexes_len < one_index_len || indexes_len > payload_len)
        return false;

    ski_index = (const uint8_t *)header + TLS_TRUSTSTORE_HEADER_LEN;
    subject_index = ski_index + one_index_len;
    metadata = subject_index + one_index_len;
    metadata_len = payload_len - indexes_len;
    if (metadata_len == 0 || metadata_len > UINT16_MAX)
        return false;

    for (i = 0; i < header->entry_count; i++)
    {
        const uint8_t *record = tls_truststore_index_record(ski_index, i);
        uint16_t offset = tls_truststore_index_offset(record);
        const struct tls_truststore_entry *entry;
        size_t entry_len;

        if (i != 0)
        {
            const uint8_t *previous =
                tls_truststore_index_record(ski_index, (uint16_t)(i - 1u));
            if (memcmp(previous, record, TLS_TRUSTSTORE_SKI_LEN) >= 0)
                return false;
        }
        if ((size_t)offset != expected_offset ||
            expected_offset + sizeof(struct tls_truststore_entry) > metadata_len)
            return false;

        entry = (const struct tls_truststore_entry *)(metadata + offset);
        entry_len = entry->len;
        if (entry_len < sizeof(struct tls_truststore_entry) ||
            entry_len > sizeof truststore_entry_copy.bytes ||
            entry_len > metadata_len - expected_offset ||
            memcmp(record, entry->ski, TLS_TRUSTSTORE_SKI_LEN) != 0)
            return false;
        expected_offset += entry_len;
    }
    if (expected_offset != metadata_len)
        return false;

    for (i = 0; i < header->entry_count; i++)
    {
        const uint8_t *record = tls_truststore_index_record(subject_index, i);
        uint16_t offset = tls_truststore_index_offset(record);
        const struct tls_truststore_entry *entry;
        const uint8_t *previous = NULL;
        int subject_order = 1;
        uint16_t low = 0, high = header->entry_count;

        if (i != 0)
        {
            previous = tls_truststore_index_record(subject_index,
                                                   (uint16_t)(i - 1u));
            subject_order = memcmp(previous, record,
                                   TLS_TRUSTSTORE_SUBJECT_LEN);
            if (subject_order > 0)
                return false;
        }

        /* The canonical SKI offsets are strictly increasing, so binary search
         * proves this subject-index offset names an entry boundary. */
        while (low < high)
        {
            uint16_t mid = (uint16_t)(low + (high - low) / 2u);
            uint16_t candidate = tls_truststore_index_offset(
                tls_truststore_index_record(ski_index, mid));
            if (candidate < offset)
                low = (uint16_t)(mid + 1u);
            else
                high = mid;
        }
        if (low >= header->entry_count ||
            tls_truststore_index_offset(
                tls_truststore_index_record(ski_index, low)) != offset)
            return false;
        entry = (const struct tls_truststore_entry *)(metadata + offset);
        if (memcmp(record, entry->subject, TLS_TRUSTSTORE_SUBJECT_LEN) != 0)
            return false;
        if (subject_order == 0)
        {
            const struct tls_truststore_entry *previous_entry =
                (const struct tls_truststore_entry *)(
                    metadata + tls_truststore_index_offset(previous));
            if (memcmp(previous_entry->ski, entry->ski,
                       TLS_TRUSTSTORE_SKI_LEN) >= 0)
                return false;
        }
    }

    if (ski_index_out) *ski_index_out = ski_index;
    if (subject_index_out) *subject_index_out = subject_index;
    if (metadata_out) *metadata_out = metadata;
    if (metadata_len_out) *metadata_len_out = (uint16_t)metadata_len;
    return true;
}

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
void tls_truststore_cleanup(void)
{
    truststore_valid_for_session = false;
    tls_secure_memzero(truststore_verified_hash,
                       sizeof truststore_verified_hash);
    tls_secure_memzero(&truststore_entry_copy,
                       sizeof truststore_entry_copy);
    tls_ctx.truststore.status = TLS_STORE_NOT_FOUND;
    tls_ctx.truststore.size = 0;
    tls_ctx.truststore.entry_count = 0;
    tls_ctx.truststore.version = 0;
    tls_ctx.truststore.created_timestamp = 0;
}

static void tls_truststore_invalidate(tls_truststore_status_t status)
{
    tls_truststore_cleanup();
    tls_ctx.truststore.status = status;
    tls_ctx.initialized = false;
    tls_ctx.network_up = false;
}

tls_truststore_status_t tls_truststore_init(void)
{
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
    tls_truststore_cleanup();

    TS_TRACE("E0 enter");
    // If hash init fails, error out early
    if (!tls_hash_context_init(&hash_ctx, TLS_HASH_SHA256))
    {
        tls_ctx.truststore.status = TLS_STORE_HASH_FAIL;
        ERROR_CODE(TLS_STORE_HASH_FAIL);
        return TLS_STORE_HASH_FAIL;
    }

    // Attempt to load the trust store.
    // Return with error if not found.
    uint8_t ts_h = file_fn.ti_open(truststore_name, "r");
    if (!ts_h)
    {
        tls_ctx.truststore.status = TLS_STORE_NOT_FOUND;
        WARN_CODE(TLS_STORE_NOT_FOUND);
        return TLS_STORE_NOT_FOUND;
    }
    TS_TRACE("E0b appvar found");

    // Get length of store, entry-db len, and sig ptr
    uint16_t truststore_size = file_fn.ti_getsize(ts_h);
    if (truststore_size < TLS_TRUSTSTORE_HEADER_LEN)
    {
        file_fn.ti_close(ts_h);
        tls_ctx.truststore.status = TLS_STORE_SIZE_INVALID;
        ERROR_CODE(TLS_STORE_SIZE_INVALID);
        return TLS_STORE_SIZE_INVALID;
    }
    uint8_t *store_header_bytes = (uint8_t *)file_fn.ti_getdataptr(ts_h);
    struct tls_truststore_header *header = (struct tls_truststore_header *)store_header_bytes;
    if (header->version != TLS_TRUSTSTORE_VERSION)
    {
        file_fn.ti_close(ts_h);
        tls_ctx.truststore.status = TLS_STORE_VERSION_MISMATCH;
        ERROR_CODE(TLS_STORE_VERSION_MISMATCH);
        return TLS_STORE_VERSION_MISMATCH;
    }
    uint8_t *store_db_start = store_header_bytes + TLS_TRUSTSTORE_HEADER_LEN;
    uint16_t store_db_len = truststore_size - TLS_TRUSTSTORE_HEADER_LEN;
    /* Keep the header metadata local until the signature verifies. Publishing
     * it up front meant a failed validation left tls_ctx.truststore.size,
     * .entry_count, .version and .created_timestamp describing an unverified
     * (attacker-supplied) header while .status was an error code. */
    const uint16_t store_entry_count = header->entry_count;
    const uint8_t store_version = header->version;
    const uint32_t store_created = header->created_timestamp;

    TS_TRACE("E1 hash hdr");
    // Hash header fields (version + timestamp + entry_count) and entries
    tls_hash_update(&hash_ctx, (const uint8_t *)&header->version,
                    sizeof(header->version) + sizeof(header->created_timestamp) + sizeof(header->entry_count));
    TS_TRACE("E2 hash db");
    tls_hash_update(&hash_ctx, store_db_start, store_db_len);
    TS_TRACE("E3 digest");
    tls_hash_digest(&hash_ctx, tstore_hash);

    TS_TRACE("E4 rsa decrypt");
    // Decrypt the truststore signature
    static const uint8_t trust_store_exp[] = {0x01, 0x00, 0x01}; /* 65537 BE */
    static const struct tls_rsa_key trust_store_key = {
        sizeof(trust_store_exp), trust_store_exp,
        sizeof(trust_store_pubkey), trust_store_pubkey,
    };
    if (!tls_rsa_decrypt_signature(header->sig, TRUSTSTORE_SIG_LEN, d_sig, &trust_store_key))
    {
        file_fn.ti_close(ts_h);
        tls_ctx.truststore.status = TLS_STORE_SIG_INVALID;
        ERROR_CODE(TLS_STORE_SIG_INVALID);
        return TLS_STORE_SIG_INVALID;
    }
    TS_TRACE("E5 pss verify");
    // Verify the signature
    bool verified = tls_rsa_pss_verify(d_sig, TRUSTSTORE_SIG_LEN, tstore_hash, hash_ctx.digestlen, TLS_HASH_SHA256);
    tls_secure_memzero(d_sig, TRUSTSTORE_SIG_LEN);
    if (verified &&
        !tls_truststore_validate_layout(header, truststore_size,
                                        NULL, NULL, NULL, NULL))
    {
        verified = false;
        tls_ctx.truststore.status = TLS_STORE_SIZE_INVALID;
        ERROR_CODE(TLS_STORE_SIZE_INVALID);
    }
    file_fn.ti_close(ts_h);
    tls_secure_memzero(&hash_ctx, sizeof hash_ctx);
    TS_TRACE("E6 verify done");
    if (verified)
    {
        memcpy(truststore_verified_hash, tstore_hash,
               sizeof truststore_verified_hash);
        truststore_valid_for_session = true;
        /* Only now is the header trustworthy enough to publish. */
        tls_ctx.truststore.size = truststore_size;
        tls_ctx.truststore.entry_count = store_entry_count;
        tls_ctx.truststore.version = store_version;
        tls_ctx.truststore.created_timestamp = store_created;
        tls_ctx.truststore.status = TLS_STORE_OK;
        uint32_t now = lwip_sntp_get_unix_time();
        if (now != 0 && now > store_created &&
            now - store_created > TLS_TRUSTSTORE_AGE_WARN_SECONDS)
            WARN_CODE((now - store_created) / (24u * 60u * 60u));
        INFO("truststore verified");
    }
    else
    {
        if (tls_ctx.truststore.status != TLS_STORE_SIZE_INVALID)
        {
            tls_ctx.truststore.status = TLS_STORE_SIG_INVALID;
            ERROR_CODE(TLS_STORE_SIG_INVALID);
        }
    }
    tls_secure_memzero(tstore_hash, sizeof tstore_hash);
    return verified ? TLS_STORE_OK : tls_ctx.truststore.status;
}

static bool tls_truststore_entry_current(const struct tls_truststore_entry *entry)
{
    uint32_t now = lwip_sntp_get_unix_time();
    return entry && now != 0 && entry->expiry_start <= entry->expiry_end &&
           now >= entry->expiry_start && now <= entry->expiry_end;
}

static bool tls_truststore_open_db(const uint8_t **ski_index_out,
                                    const uint8_t **subject_index_out,
                                    const uint8_t **metadata_out,
                                    uint16_t *metadata_len_out,
                                    struct tls_truststore_header **header_out,
                                    uint8_t *handle_out)
{
    uint8_t h = file_fn.ti_open(truststore_name, "r");
    if (!h)
    {
        tls_truststore_invalidate(TLS_STORE_NOT_FOUND);
        return false;
    }

    uint16_t truststore_size = file_fn.ti_getsize(h);
    if (truststore_size < TLS_TRUSTSTORE_HEADER_LEN)
    {
        tls_truststore_invalidate(TLS_STORE_SIZE_INVALID);
        file_fn.ti_close(h);
        return false;
    }

    struct tls_truststore_header *header =
        (struct tls_truststore_header *)file_fn.ti_getdataptr(h);
    if (!truststore_valid_for_session)
    {
        file_fn.ti_close(h);
        return false;
    }
    if (header->version != TLS_TRUSTSTORE_VERSION)
    {
        tls_truststore_invalidate(TLS_STORE_VERSION_MISMATCH);
        file_fn.ti_close(h);
        return false;
    }
    if (truststore_size != tls_ctx.truststore.size ||
        header->entry_count != tls_ctx.truststore.entry_count ||
        header->created_timestamp != tls_ctx.truststore.created_timestamp)
    {
        tls_truststore_invalidate(TLS_STORE_SIZE_INVALID);
        file_fn.ti_close(h);
        return false;
    }

    /* The appvar is reopened for every lookup and can change after tls_init().
     * Re-hash the exact signed payload before using it, then return only a
     * copied entry so no pointer survives ti_close(). */
    {
        struct tls_hash_context hash_ctx = {0};
        uint8_t current_hash[TLS_SHA256_DIGEST_LEN] = {0};
        uint8_t *db = (uint8_t *)header + TLS_TRUSTSTORE_HEADER_LEN;
        uint16_t db_len = truststore_size - TLS_TRUSTSTORE_HEADER_LEN;
        bool valid = tls_hash_context_init(&hash_ctx, TLS_HASH_SHA256);

        if (valid)
        {
            tls_hash_update(&hash_ctx, (const uint8_t *)&header->version,
                            sizeof(header->version) +
                            sizeof(header->created_timestamp) +
                            sizeof(header->entry_count));
            tls_hash_update(&hash_ctx, db, db_len);
            tls_hash_digest(&hash_ctx, current_hash);
            valid = tls_bytes_compare(current_hash, truststore_verified_hash,
                                      sizeof current_hash);
        }
        tls_secure_memzero(&hash_ctx, sizeof hash_ctx);
        tls_secure_memzero(current_hash, sizeof current_hash);
        if (!valid)
        {
            tls_truststore_invalidate(TLS_STORE_SIG_INVALID);
            file_fn.ti_close(h);
            ERROR_CODE(TLS_STORE_SIG_INVALID);
            return false;
        }
    }

    size_t one_index_len = (size_t)header->entry_count *
                           TLS_TRUSTSTORE_INDEX_ENTRY_LEN;
    size_t indexes_len = one_index_len * 2u;
    size_t payload_len = (size_t)truststore_size - TLS_TRUSTSTORE_HEADER_LEN;
    if (indexes_len > payload_len)
    {
        tls_truststore_invalidate(TLS_STORE_SIZE_INVALID);
        file_fn.ti_close(h);
        ERROR_CODE(TLS_STORE_SIZE_INVALID);
        return false;
    }

    const uint8_t *ski_index =
        (const uint8_t *)header + TLS_TRUSTSTORE_HEADER_LEN;
    *handle_out       = h;
    *header_out       = header;
    *ski_index_out    = ski_index;
    *subject_index_out = ski_index + one_index_len;
    *metadata_out     = ski_index + indexes_len;
    *metadata_len_out = (uint16_t)(payload_len - indexes_len);
    return true;
}

bool tls_truststore_lookup_key_id(const uint8_t *ski, size_t ski_len,
                                  struct tls_truststore_entry **result)
{
    if (ski == NULL || ski_len == 0 || ski_len > TLS_TRUSTSTORE_SKI_LEN ||
        !truststore_valid_for_session)
        return false;

    const uint8_t *ski_index;
    const uint8_t *subject_index;
    const uint8_t *metadata;
    uint16_t metadata_len;
    struct tls_truststore_header *header;
    uint8_t h;
    if (!tls_truststore_open_db(&ski_index, &subject_index, &metadata,
                                &metadata_len, &header, &h))
        return false;
    (void)subject_index;

    bool found = false;
    uint8_t lookup_key[TLS_TRUSTSTORE_SKI_LEN] = {0};
    uint16_t low = 0, high = header->entry_count;
    memcpy(lookup_key, ski, ski_len);
    while (low < high)
    {
        uint16_t mid = (uint16_t)(low + (high - low) / 2u);
        const uint8_t *record = tls_truststore_index_record(ski_index, mid);
        if (memcmp(record, lookup_key, TLS_TRUSTSTORE_SKI_LEN) < 0)
            low = (uint16_t)(mid + 1u);
        else
            high = mid;
    }
    if (low < header->entry_count)
    {
        const uint8_t *record = tls_truststore_index_record(ski_index, low);
        uint16_t offset = tls_truststore_index_offset(record);
        if (memcmp(record, lookup_key, TLS_TRUSTSTORE_SKI_LEN) == 0 &&
            (size_t)offset + sizeof(struct tls_truststore_entry) <= metadata_len)
        {
            const struct tls_truststore_entry *entry =
                (const struct tls_truststore_entry *)(metadata + offset);
            if (entry->len >= sizeof(struct tls_truststore_entry) &&
                entry->len <= sizeof truststore_entry_copy.bytes &&
                entry->len <= (size_t)metadata_len - offset &&
                tls_truststore_entry_current(entry))
            {
                if (result)
                {
                    memcpy(truststore_entry_copy.bytes, entry, entry->len);
                    *result = (struct tls_truststore_entry *)truststore_entry_copy.bytes;
                }
                found = true;
            }
        }
    }
    tls_secure_memzero(lookup_key, sizeof lookup_key);
    file_fn.ti_close(h);
    return found;
}

bool tls_truststore_lookup(const uint8_t *ski, struct tls_truststore_entry **result)
{
    return tls_truststore_lookup_key_id(ski, TLS_TRUSTSTORE_SKI_LEN, result);
}

bool tls_truststore_lookup_by_subject_index(const uint8_t *subject,
                                            size_t subject_len,
                                            uint16_t match_index,
                                            struct tls_truststore_entry **result)
{
    if (subject == NULL || subject_len != TLS_TRUSTSTORE_SUBJECT_LEN ||
        !truststore_valid_for_session)
        return false;

    const uint8_t *ski_index;
    const uint8_t *subject_index;
    const uint8_t *metadata;
    uint16_t metadata_len;
    struct tls_truststore_header *header;
    uint8_t h;
    if (!tls_truststore_open_db(&ski_index, &subject_index, &metadata,
                                &metadata_len, &header, &h))
        return false;
    (void)ski_index;

    bool found = false;
    uint8_t lookup_key[TLS_TRUSTSTORE_SUBJECT_LEN] = {0};
    uint16_t matches = 0;
    uint16_t low = 0, high = header->entry_count;
    memcpy(lookup_key, subject, subject_len);
    while (low < high)
    {
        uint16_t mid = (uint16_t)(low + (high - low) / 2u);
        const uint8_t *record =
            tls_truststore_index_record(subject_index, mid);
        if (memcmp(record, lookup_key, TLS_TRUSTSTORE_SUBJECT_LEN) < 0)
            low = (uint16_t)(mid + 1u);
        else
            high = mid;
    }
    while (low < header->entry_count)
    {
        const uint8_t *record = tls_truststore_index_record(subject_index, low);
        uint16_t offset;
        const struct tls_truststore_entry *entry;
        if (memcmp(record, lookup_key, TLS_TRUSTSTORE_SUBJECT_LEN) != 0)
            break;
        offset = tls_truststore_index_offset(record);
        if ((size_t)offset + sizeof(struct tls_truststore_entry) > metadata_len)
            break;
        entry = (const struct tls_truststore_entry *)(metadata + offset);
        if (entry->len < sizeof(struct tls_truststore_entry) ||
            entry->len > sizeof truststore_entry_copy.bytes ||
            entry->len > (size_t)metadata_len - offset)
            break;
        if (tls_truststore_entry_current(entry) && matches++ == match_index)
        {
            if (result)
            {
                memcpy(truststore_entry_copy.bytes, entry, entry->len);
                *result = (struct tls_truststore_entry *)truststore_entry_copy.bytes;
            }
            found = true;
            break;
        }
        low++;
    }
    tls_secure_memzero(lookup_key, sizeof lookup_key);
    file_fn.ti_close(h);
    return found;
}

bool tls_truststore_lookup_by_subject(const uint8_t *subject, size_t subject_len,
                                      struct tls_truststore_entry **result)
{
    return tls_truststore_lookup_by_subject_index(subject, subject_len, 0, result);
}
