
#ifndef tls_asn1_h
#define tls_asn1_h

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** @enum ASN.1 tag types */
enum tls_asn1_tags
{
    ASN1_RESVD = 0,   /**< RESERVED */
    ASN1_BOOLEAN,     /**< defines a BOOLEAN object */
    ASN1_INTEGER,     /**< defines an INTEGER object */
    ASN1_BITSTRING,   /**< defines a BIT STRING object */
    ASN1_OCTETSTRING, /**< defines an OCTET STRING object */
    ASN1_NULL,        /**< defines a NULL object (0 size, no data) */
    ASN1_OBJECTID,    /**< defines an OBJECT IDENTIFIER */
    ASN1_OBJECTDESC,  /**< defines an OBJECT DESCRIPTION */
    ASN1_INSTANCE,    /**< defines an INSTANCE */
    ASN1_REAL,        /**< defines a REAL object */
    ASN1_ENUMERATED,
    ASN1_EMBEDDEDPDV,
    ASN1_UTF8STRING,
    ASN1_RELATIVEOID,
    ASN1_SEQUENCE = 16, /**< defines a SEQUENCE */
    ASN1_SET,           /**< defines a SET */
    ASN1_NUMERICSTRING,
    ASN1_PRINTABLESTRING,
    ASN1_TELETEXSTRING,
    ASN1_VIDEOTEXSTRING,
    ASN1_IA5STRING,
    ASN1_UTCTIME,
    ASN1_GENERALIZEDTIME,
    ASN1_GRAPHICSTRING,
    ASN1_VISIBLESTRING,
    ASN1_GENERALSTRING,
    ASN1_UNIVERSALSTRING,
    ASN1_CHARSTRING,
    ASN1_BMPSTRING
};

/** @enum ASN.1 tag classes. */
enum tls_asn1_classes
{
    ASN1_UNIVERSAL = (0 << 6),   /**< tags defined in the ASN.1 standard. Most use cases on calc will be this. */
    ASN1_APPLICATION = (1 << 6), /**< tags unique to a particular application. */
    ASN1_CONTEXTSPEC = (2 << 6), /**< tags that need to be identified within a particular, well-definded context. */
    ASN1_PRIVATE = (3 << 6)      /**< reserved for use by a specific entity for their applications. */
};

/** @enum ASN.1 tag forms. */
enum tls_asn1_forms
{
    ASN1_PRIMITIVE = (0 << 5),  /**< this element should contain no nested elements. */
    ASN1_CONSTRUCTED = (1 << 5) /**< this element contains nested elements. */
};

/// @struct Generic field serialization used by higher-level parsers.
struct tls_asn1_serialization
{
    char *name;    /**< field label supplied by caller/parser */
    uint8_t tag;   /**< tag value returned. */
    size_t len;    /**< length of item. */
    uint8_t *data; /**< pointer to item value. */
};

/* --------------------------------------------------------------------------
 * DER Cursor API
 * -------------------------------------------------------------------------- */

/**
 * @brief One parsed DER TLV item.
 *
 * This describes a single ASN.1 element in Tag-Length-Value form.
 * Pointers reference the original input buffer; no copies are made.
 */
struct tls_asn1_tlv
{
    const uint8_t *tlv;   /**< Pointer to the tag byte (start of full TLV). */
    const uint8_t *value; /**< Pointer to content bytes only (value payload). */
    size_t len;           /**< Content length in bytes (value payload size). */
    size_t header_len;    /**< Header size in bytes (tag + DER length bytes). */
    uint8_t tag;          /**< Raw one-byte ASN.1 tag (class/form/number). */
};

/**
 * @brief Forward-only iterator state over a DER byte span.
 *
 * Typical usage:
 * 1. Call tls_asn1_cursor_init() once for a DER buffer.
 * 2. Repeatedly call tls_asn1_next() until it returns false.
 * 3. For constructed TLVs (SEQUENCE/SET/context constructed), call
 *    tls_asn1_child_cursor() to iterate nested elements.
 */
struct tls_asn1_cursor
{
    const uint8_t *cur; /**< Current read position. */
    const uint8_t *end; /**< One-past-end bound for this cursor span. */
};

/**
 * @brief Initialize a cursor over a DER buffer.
 * @param cursor Cursor to initialize.
 * @param data Pointer to first DER byte.
 * @param len Number of bytes available from @p data.
 * @return true on success, false on invalid arguments.
 */
bool tls_asn1_cursor_init(struct tls_asn1_cursor *cursor, const uint8_t *data, size_t len);

/**
 * @brief Parse the next TLV from a cursor and advance it.
 * @param cursor Active cursor.
 * @param out Output TLV descriptor.
 * @return true if one TLV was parsed successfully.
 * @return false if:
 * - cursor reached end of data (normal iteration completion), or
 * - input is malformed (invalid DER length/overflow/truncated TLV), or
 * - arguments are invalid.
 *
 * @note This API intentionally uses a single boolean return value. Callers
 * that need strict error distinction should track expected structure while
 * parsing (for example: required fields missing before false => parse failure).
 */
bool tls_asn1_next(struct tls_asn1_cursor *cursor, struct tls_asn1_tlv *out);

/**
 * @brief Create a cursor for a constructed parent TLV's value bytes.
 * @param parent Parent TLV from tls_asn1_next().
 * @param child Output child cursor spanning only parent's content.
 * @return true on success.
 * @return false if:
 * - @p parent is not constructed, or
 * - arguments are invalid.
 *
 * @note Call this only when tls_asn1_tag_constructed(parent->tag) is true.
 */
bool tls_asn1_child_cursor(const struct tls_asn1_tlv *parent, struct tls_asn1_cursor *child);

/** @brief Extract low 5-bit ASN.1 tag number from raw tag byte. */
uint8_t tls_asn1_tag_number(uint8_t tag);
/** @brief Extract class bits (ASN1_UNIVERSAL/APPLICATION/CONTEXTSPEC/PRIVATE). */
uint8_t tls_asn1_tag_class(uint8_t tag);
/** @brief Return true if constructed form bit is set on raw tag byte. */
bool tls_asn1_tag_constructed(uint8_t tag);

#endif
