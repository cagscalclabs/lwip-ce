/**
 * @file xml.h
 * @brief Streaming XML/HTML pull parser for lwIP-CE
 * @author Anthony Cagliano
 * @author Claude Code
 *
 * Pull/event-style parser. The caller owns a small ring buffer, feeds raw
 * bytes via xml_take(), then pulls events with xml_next(). Event strings are
 * copied into fixed-size fields in xml_event_t, so events remain valid after
 * the parser advances.
 *
 * Streaming: xml_next() returns XML_ERR_NEED_MORE when the ring does not yet
 * contain a complete token. Feed more bytes with xml_take() and retry.
 *
 * Lax/HTML mode (XML_FLAG_LAX):
 *   - Tag names and attribute names are lowercased.
 *   - Void elements (<br>, <img>, etc.) auto-synthesize an ELEMENT_END.
 *   - Unquoted attribute values are accepted.
 *   - Boolean attributes (no =value) are accepted (value == "").
 *   - Bare & not forming a recognized entity is passed through as '&'.
 *   - <!DOCTYPE ...> declarations are skipped.
 *
 * Known constraints:
 *   - No namespace support.
 *   - No DTD or entity expansion beyond the built-in XML/HTML entities.
 *   - Processing instructions and comments are skipped silently.
 *   - Maximum element nesting depth: XML_MAX_DEPTH.
 *   - Maximum attributes per element: XML_MAX_ATTRS.
 *   - Names longer than XML_NAME_MAX are truncated.
 *   - Text longer than XML_TEXT_MAX is truncated (remainder discarded until
 *     the next tag boundary).
 *   - Attribute values longer than XML_ATTR_VAL_MAX are truncated.
 */

#ifndef LWIP_CE_XML_H
#define LWIP_CE_XML_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Tunable limits
 * ---------------------------------------------------------------------- */
#define XML_MAX_DEPTH       16
#define XML_MAX_ATTRS        8
#define XML_NAME_MAX        16   /* tag/attr name buffer including NUL */
#define XML_TEXT_MAX        64   /* text content buffer including NUL */
#define XML_ATTR_VAL_MAX    48   /* attribute value buffer including NUL */

/* -------------------------------------------------------------------------
 * Flags
 * ---------------------------------------------------------------------- */
#define XML_FLAG_LAX        0x01u  /* lax/HTML mode; see file header */

/* -------------------------------------------------------------------------
 * Public types
 * ---------------------------------------------------------------------- */
typedef enum {
    XML_OK = 0,
    XML_ERR_INVALID,     /* malformed input (strict mode) */
    XML_ERR_TRUNCATED,   /* stream ended with a partial token */
    XML_ERR_DEPTH,       /* nesting too deep */
    XML_ERR_DONE,        /* clean end of input */
    XML_ERR_NEED_MORE,   /* ring has no complete token yet — feed more bytes */
} xml_err_t;

typedef enum {
    XML_EVT_NONE = 0,
    XML_EVT_ELEMENT_START,  /* opening tag; attrs[] populated */
    XML_EVT_ELEMENT_END,    /* closing tag (explicit </tag>, />, or void) */
    XML_EVT_TEXT,           /* character data between tags */
} xml_event_type_t;

typedef struct {
    char     name[XML_NAME_MAX];
    char     value[XML_ATTR_VAL_MAX];
} xml_attr_t;

typedef struct {
    const char *str;
    size_t      len;
} xml_slice_t;

typedef struct {
    xml_event_type_t type;
    char             name[XML_NAME_MAX];   /* element name (START/END) */
    char             text[XML_TEXT_MAX];   /* character data (TEXT) */
    xml_attr_t       attrs[XML_MAX_ATTRS];
    uint8_t          attr_count;
    bool             self_closing;         /* true for /> and void elements */
} xml_event_t;

typedef struct {
    /* ring buffer — caller-owned memory */
    char          *ring;
    size_t         ring_len;
    size_t         wpos;       /* write head (next byte from xml_take) */
    size_t         rpos;       /* read head (parser cursor) */

    uint8_t        flags;      /* XML_FLAG_* */
    uint8_t        depth;

    /* incremental parse state (private values used by xml.c) */
    uint8_t        state;

    /* accumulation scratch — cleared at each new token */
    char           tag_name[XML_NAME_MAX];
    uint8_t        tag_name_len;
    bool           tag_closing;

    xml_attr_t     cur_attr;
    uint8_t        cur_attr_name_len;
    uint8_t        cur_attr_val_len;
    char           attr_quote;
    bool           attr_bool;  /* boolean attr — no value */

    xml_event_t    pending;    /* partially-built event */
    bool           has_pending;/* pending event ready to emit */

    /* void-element deferred end: emit ELEMENT_END on next xml_next call */
    bool           void_end_pending;
    char           void_end_name[XML_NAME_MAX];

    bool           finished;    /* set by xml_finish(); enables XML_ERR_DONE */

    /* text accumulation */
    char           text_buf[XML_TEXT_MAX];
    uint8_t        text_len;
    bool           text_overflow; /* text was truncated; discard until '<' */

    /* entity accumulation inside text */
    char           entity_buf[12];
    uint8_t        entity_len;
} xml_ctx_t;

typedef xml_ctx_t xml_parser_t;

/* -------------------------------------------------------------------------
 * API
 * ---------------------------------------------------------------------- */

/**
 * Initialize the parser.
 *
 * @param ctx      Parser context (caller-allocated, may be on stack or BSS).
 * @param ring     Caller-provided ring buffer (must remain valid).
 * @param ring_len Size of ring in bytes. Should be at least a few hundred
 *                 bytes; larger rings tolerate burstier input.
 * @param flags    0 or XML_FLAG_LAX.
 */
void xml_init(xml_ctx_t *ctx, char *ring, size_t ring_len, uint8_t flags);

/**
 * Signal end of input stream.
 *
 * After calling this, xml_next() will flush any remaining accumulated text
 * and return XML_ERR_DONE once the ring is empty. Without this call,
 * xml_next() returns XML_ERR_NEED_MORE whenever the ring drains in CONTENT
 * state (since it cannot tell whether more bytes are coming).
 *
 * Call xml_finish() after the last xml_take() when no more data will arrive.
 */
void xml_finish(xml_ctx_t *ctx);

/**
 * Feed raw bytes into the parser's ring buffer.
 *
 * Non-blocking: if the ring is full, only as many bytes as fit are consumed.
 * Returns the number of bytes actually written. The caller must retry any
 * unwritten tail after draining events with xml_next().
 */
size_t xml_take(xml_ctx_t *ctx, const char *buf, size_t len);

/**
 * Pull the next parsed event.
 *
 * Returns:
 *   XML_OK          — *evt is valid.
 *   XML_ERR_NEED_MORE — ring does not yet contain a complete token; feed more
 *                       bytes with xml_take() and call xml_next() again.
 *   XML_ERR_DONE    — input cleanly exhausted (ring empty, no partial token).
 *   XML_ERR_DEPTH   — element nesting exceeded XML_MAX_DEPTH.
 *   XML_ERR_INVALID — malformed input (strict mode only; lax mode recovers).
 */
xml_err_t xml_next(xml_ctx_t *ctx, xml_event_t *evt);

/**
 * Find an attribute by name in an event returned by xml_next().
 * Copies the value (NUL-terminated) into dst.
 * Returns true on match, false if not present or dst too small.
 */
bool xml_get_attr(const xml_event_t *evt, const char *name,
                  char *dst, size_t dst_len);

/**
 * Skip the current element body.
 *
 * Call immediately after an XML_EVT_ELEMENT_START event for a non-self-closing
 * element. The parser consumes events until the matching XML_EVT_ELEMENT_END.
 */
xml_err_t xml_skip(xml_ctx_t *ctx);

/**
 * Copy the immediate text content of the current element, then consume that
 * element's closing XML_EVT_ELEMENT_END.
 */
xml_err_t xml_get_inner_text(xml_ctx_t *ctx, char *dst, size_t dst_len);

/**
 * Build a comma-separated name=value list from an element event's attributes.
 * Returns the bytes written, excluding NUL, or (size_t)-1 if dst is too small.
 */
size_t xml_list_attrs(const xml_event_t *evt, char *dst, size_t dst_len);

/**
 * Copy a raw XML slice into a NUL-terminated buffer.
 */
bool xml_slice_copy(char *dst, size_t dst_len, const xml_slice_t *s);

/**
 * Decode a single XML entity reference at *src (must point to '&').
 * Writes the decoded character into *dst and sets *dst_written to 1.
 * Advances *src past the closing ';'.
 * Returns false if unrecognized or malformed; *src is unchanged.
 *
 * Supported: &amp; &lt; &gt; &apos; &quot; &nbsp;
 */
bool xml_decode_entity(const char **src, const char *src_end,
                       char *dst, size_t *dst_written);

#ifdef __cplusplus
}
#endif

#endif /* LWIP_CE_XML_H */
