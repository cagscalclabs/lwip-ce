
#ifndef tls_asn1_h
#define tls_asn1_h

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** @enum ASN.1 tag types */
enum tls_asn1_tags {
    ASN1_RESVD = 0,             /**< RESERVED */
    ASN1_BOOLEAN,               /**< defines a BOOLEAN object */
    ASN1_INTEGER,               /**< defines an INTEGER object */
    ASN1_BITSTRING,             /**< defines a BIT STRING object */
    ASN1_OCTETSTRING,           /**< defines an OCTET STRING object */
    ASN1_NULL,                  /**< defines a NULL object (0 size, no data) */
    ASN1_OBJECTID,              /**< defines an OBJECT IDENTIFIER */
    ASN1_OBJECTDESC,            /**< defines an OBJECT DESCRIPTION */
    ASN1_INSTANCE,              /**< defines an INSTANCE */
    ASN1_REAL,                  /**< defines a REAL object */
    ASN1_ENUMERATED,
    ASN1_EMBEDDEDPDV,
    ASN1_UTF8STRING,
    ASN1_RELATIVEOID,
    ASN1_SEQUENCE = 16,         /**< defines a SEQUENCE */
    ASN1_SET,                   /**< defines a SET */
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
enum tls_asn1_classes {
    ASN1_UNIVERSAL      = (0<<6),       /**< tags defined in the ASN.1 standard. Most use cases on calc will be this. */
    ASN1_APPLICATION    = (1<<6),       /**< tags unique to a particular application. */
    ASN1_CONTEXTSPEC    = (2<<6),       /**< tags that need to be identified within a particular, well-definded context. */
    ASN1_PRIVATE        = (3<<6)        /**< reserved for use by a specific entity for their applications. */
};

/** @enum ASN.1 tag forms. */
enum tls_asn1_forms {
    ASN1_PRIMITIVE      = (0<<5),       /**< this element should contain no nested elements. */
    ASN1_CONSTRUCTED    = (1<<5)        /**< this element contains nested elements. */
};

/// @struct Generic field serialization used by higher-level parsers.
struct tls_asn1_serialization {
    char *name;             /**< field label supplied by caller/parser */
    uint8_t tag;            /**< tag value returned. */
    size_t len;             /**< length of item. */
    uint8_t *data;          /**< pointer to item value. */
};

/** @define Returns the base type value (low 5 bits) of the tag. */
#define tls_asn1_gettag(tag)        ((tag) & 0b111111)
/** @define Returns the class (high 2 bits) of the tag. */
#define tls_asn1_getclass(tag)      (((tag)>>6) & 0b11)
/** @define Returns the form (bit 5) of the tag. */
#define tls_asn1_getform(tag)       (((tag)>>5) & 1)

/********************************************************************************
 * @brief ASN.1 encodes data.
 * @param tag       Bitwise XOR of \p tls_asn1_tags , \p tls_asn1_classes , \p tls_asn1_forms .
 * @param data     Pointer to data to encode.
 * @param len       Length of data to encode.
 * @param output    Pointer to buffer to write encoded data.
 * @returns Encoded size on success, @b 0 on error.
 * @note For most use cases, only \p tls_asn1_tags is needed for \p tag . SEQUENCE and SET will have
 * their constructed bits set automatically. Also, most uses of ASN.1 for TLS will be @b ASN1_UNIVERSAL .
 */
size_t tls_asn1_encode(uint8_t tag, const uint8_t *data, size_t len, uint8_t *output);

/* --------------------------------------------------------------------------
 * DER Cursor API (new)
 * -------------------------------------------------------------------------- */

struct tls_asn1_tlv
{
    const uint8_t *tlv;      /* points to tag byte */
    const uint8_t *value;    /* points to content bytes */
    size_t len;              /* content length */
    size_t header_len;       /* tag + length bytes */
    uint8_t tag;             /* full tag byte */
};

struct tls_asn1_cursor
{
    const uint8_t *cur;
    const uint8_t *end;
};

bool tls_asn1_cursor_init(struct tls_asn1_cursor *cursor, const uint8_t *data, size_t len);
bool tls_asn1_next(struct tls_asn1_cursor *cursor, struct tls_asn1_tlv *out);
bool tls_asn1_child_cursor(const struct tls_asn1_tlv *parent, struct tls_asn1_cursor *child);

uint8_t tls_asn1_tag_number(uint8_t tag);
uint8_t tls_asn1_tag_class(uint8_t tag);
bool tls_asn1_tag_constructed(uint8_t tag);

#endif
