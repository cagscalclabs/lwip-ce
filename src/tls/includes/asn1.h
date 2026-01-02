
#ifndef tls_asn1_h
#define tls_asn1_h


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

/// @struct Can be chained to create schemas for decoding ASN.1 structures. See @b keyfiles.c.
struct tls_asn1_schema {
    char *name;
    uint8_t tag;
    uint8_t depth;
    bool optional:1;        /**< flag indicating if item in schema is optional. */
    bool allow_null:1;      /**< flag indicating if item in schema can be NULL. */
    bool output:1;          /**< flag indicating if item in schema should be returned. */
    bool mode:1;            /**< flag indicating if this tag should be parsed as MATCH or SEEK. See \p tls_asn1_parse_mode */
    bool raw_output:1;      /**< flag indicating if raw DER bytes (including tag+length) should be returned instead of parsed content */
};

enum tls_asn1_parse_mode {
    ASN1_MATCH = false,     /**< next decoded item returned should match schema index.*/
    ASN1_SEEK = true        /**< skip over decoded items until next item matches schema index. */
};

/// @struct Can be chained in parallel to schema to create an output chain for decoding ANS.1 structures. See keyfiles.c
struct tls_asn1_serialization {
    char *name;             /**< name of the field returned. Same as \p tls_asn1_schema->name for item returned. */
    uint8_t tag;            /**< tag value returned. */
    size_t len;             /**< length of item. */
    uint8_t *data;          /**< pointer to item value. */
};


struct _asn1_node {
    const uint8_t *start;
    const uint8_t *next;
};
#define ASN1_MAX_DEPTH  16
/** @struct ASN.1 decoder state. */
struct tls_asn1_decoder_context {
    uint8_t depth;                              /**< Current location in the ASN.1 tree. */
    struct _asn1_node node[ASN1_MAX_DEPTH];     /**< Node metadata. */
};

/** @define Returns the base type value (low 5 bits) of the tag. */
#define tls_asn1_gettag(tag)        ((tag) & 0b111111)
/** @define Returns the class (high 2 bits) of the tag. */
#define tls_asn1_getclass(tag)      (((tag)>>6) & 0b11)
/** @define Returns the form (bit 5) of the tag. */
#define tls_asn1_getform(tag)       (((tag)>>5) & 1)

/********************************************************************************
 * @brief Initializes the ASN.1 decoder.
 * @param ctx       Pointer to ASN.1 context.
 * @param data      Pointer to data to decode.
 * @param len       Length of data to decode.
 * @returns @b true if initialization succeeded, @b false if error.
 */
bool tls_asn1_decoder_init(struct tls_asn1_decoder_context *ctx, const uint8_t *data, size_t len);

/********************************************************************************
 * @brief Returns the next decodable item in the ASN.1 data.
 * @param ctx       Pointer to ASN.1 context.
 * @param tag      Pointer to a @b uint8_t to write the decoded tag to.
 * @param data      Pointer to a @b *uint8_t to write the data pointer to.
 * @param len       Pointer to a @b size_t to write the decoded length to.
 * @param depth     Pointer to a @b uint8_t to write the parser depth to.
 * @returns @b true if an ASN.1 object is returned. @b false if error or end of data.
 * @note This call handles the tree structure of ASN.1 properly. If the previous call returned a @b constructed
 * object, then the subsequent calls parse the contents of that object until the end is reached.
 */
bool tls_asn1_decode_next(struct tls_asn1_decoder_context *ctx, const struct tls_asn1_schema *schema,
                          uint8_t *tag, uint8_t **data, size_t *len, uint8_t *depth);

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

#endif
