/**
 * @file xml.h
 * @brief Minimal XML parser for lwIP-CE
 * @author Anthony Cagliano
 * @author Claude Code
 *
 * @note Pull/event-style SAX-like parser: no heap allocation, no DOM tree.
 * Caller drives event-by-event via xml_next(). Strings are returned as
 * slices into the input buffer (not NUL-terminated copies).
 *
 * Known constraints:
 * - Input must be a single contiguous buffer (no streaming).
 * - Maximum element nesting depth is XML_MAX_DEPTH.
 * - No namespace support.
 * - No DTD or entity expansion beyond the five predefined XML entities
 *   (&amp; &lt; &gt; &apos; &quot;).
 * - Processing instructions and comments are skipped silently.
 * - Attribute values are returned as raw slices (entities not expanded).
 */

#ifndef LWIP_CE_XML_H
#define LWIP_CE_XML_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define XML_MAX_DEPTH    16
#define XML_MAX_ATTRS     8

typedef enum {
    XML_OK = 0,
    XML_ERR_INVALID,
    XML_ERR_TRUNCATED,
    XML_ERR_DEPTH,
    XML_ERR_DONE,
} xml_err_t;

typedef enum {
    XML_EVT_NONE = 0,
    XML_EVT_ELEMENT_START,  /* opening tag, attributes populated */
    XML_EVT_ELEMENT_END,    /* closing tag (explicit </tag> or self-closing />) */
    XML_EVT_TEXT,           /* character data between tags */
} xml_event_type_t;

typedef struct {
    const char *str;  /* pointer into input buffer, NOT NUL-terminated */
    size_t      len;
} xml_slice_t;

typedef struct {
    xml_slice_t name;
    xml_slice_t value; /* raw, may contain entity references */
} xml_attr_t;

typedef struct {
    xml_event_type_t type;
    xml_slice_t      name;       /* element name (ELEMENT_START / ELEMENT_END) */
    xml_slice_t      text;       /* character data (TEXT) */
    xml_attr_t       attrs[XML_MAX_ATTRS];
    uint8_t          attr_count;
    bool             self_closing;
} xml_event_t;

typedef struct {
    const char *buf;
    size_t      len;
    size_t      pos;
    uint8_t     depth;
} xml_parser_t;

/**
 * Initialize a parser over a buffer.
 * The buffer must remain valid for the lifetime of the parser.
 */
void xml_init(xml_parser_t *p, const char *buf, size_t len);

/**
 * Advance to the next event.
 * Returns XML_OK and fills *evt on success.
 * Returns XML_ERR_DONE when the input is exhausted cleanly.
 */
xml_err_t xml_next(xml_parser_t *p, xml_event_t *evt);

/**
 * Skip the current element and all its children.
 * Call immediately after receiving XML_EVT_ELEMENT_START for an unwanted element.
 */
xml_err_t xml_skip(xml_parser_t *p);

/**
 * Copy a xml_slice_t into a NUL-terminated buffer.
 * Returns false if dst is too small (dst_len includes the NUL byte).
 *
 * Slices are raw pointers into the input buffer and are never NUL-terminated
 * by the parser. Use this function whenever you need a C string from a slice.
 * The parser cursor is not involved and does not move.
 *
 * Example:
 *   Input:  <title>lwIP News</title>
 *   After xml_next() yields XML_EVT_TEXT, evt.text is a slice of "lwIP News".
 *   xml_slice_copy(buf, sizeof(buf), &evt.text)
 *   => buf == "lwIP News", returns true. Cursor unchanged.
 */
bool xml_slice_copy(char *dst, size_t dst_len, const xml_slice_t *s);

/**
 * Decode a single XML entity reference at *src (must point to '&').
 * Writes the decoded character into *dst and sets *dst_written to 1.
 * Advances *src to point past the closing ';' of the entity.
 * Returns false if the entity is unrecognized or malformed; *src is unchanged.
 *
 * Supported entities: &amp; &lt; &gt; &apos; &quot;
 * This function operates on a raw pointer, not a parser state.
 * The xml_parser_t cursor is not involved and does not move.
 *
 * Example:
 *   Input text slice: "First &amp; stable"
 *   const char *src = "&amp;";
 *   const char *end = src + 5;
 *   char out; size_t written;
 *   xml_decode_entity(&src, end, &out, &written)
 *   => out == '&', written == 1, src now points past "&amp;". Returns true.
 */
bool xml_decode_entity(const char **src, const char *src_end, char *dst, size_t *dst_written);

/**
 * Find an attribute by name on the current element event and copy its value
 * into dst (NUL-terminated). Returns true on match, false if the attribute
 * is not present or dst is too small.
 *
 * Call this on the xml_event_t filled by xml_next() for an ELEMENT_START.
 * The parser cursor is not involved and does not move — evt holds all
 * attribute data already parsed from the opening tag.
 *
 * Example:
 *   Input:  <item id="42" category="release">...</item>
 *   Cursor: just past the '>' of the opening tag (xml_next returned ELEMENT_START).
 *   xml_get_attr(&evt, "id", buf, sizeof(buf))
 *   => buf == "42", returns true. Cursor unchanged.
 *   xml_get_attr(&evt, "missing", buf, sizeof(buf))
 *   => returns false. Cursor unchanged.
 */
bool xml_get_attr(const xml_event_t *evt, const char *name, char *dst, size_t dst_len);

/**
 * Read the immediate text content of the current element and copy it into
 * dst (NUL-terminated). Then consumes the closing ELEMENT_END event.
 *
 * The parser must be positioned just after an ELEMENT_START event (i.e.
 * the cursor is inside the element, before any children or text).
 *
 * Returns:
 *   XML_OK       — text copied, cursor is now past the closing tag.
 *   XML_ERR_DONE — element has no text (empty or child elements only).
 *   XML_ERR_INVALID — next event is not text, or dst is too small.
 *
 * Example:
 *   Input:  <title>v1.0 released</title><next/>
 *   Cursor: just past '>' of <title> (xml_next returned ELEMENT_START for "title").
 *   xml_get_inner_text(&p, buf, sizeof(buf))
 *   => buf == "v1.0 released", returns XML_OK.
 *   Cursor: now past </title>, positioned at <next/>.
 */
xml_err_t xml_get_inner_text(xml_parser_t *p, char *dst, size_t dst_len);

/**
 * Build a CSV string of all attributes on the current element event in the
 * form "name=value,name=value,...". Values containing commas or '=' are not
 * escaped. Returns the number of bytes written (excluding NUL), or
 * (size_t)-1 if dst is too small.
 *
 * Call this on the xml_event_t filled by xml_next() for an ELEMENT_START.
 * The parser cursor is not involved and does not move.
 *
 * Example:
 *   Input:  <item id="2" category="patch">...</item>
 *   Cursor: just past '>' of the opening tag (xml_next returned ELEMENT_START).
 *   xml_list_attrs(&evt, buf, sizeof(buf))
 *   => buf == "id=2,category=patch", returns 19. Cursor unchanged.
 *   If the element has no attributes, buf == "", returns 0.
 */
size_t xml_list_attrs(const xml_event_t *evt, char *dst, size_t dst_len);

#ifdef __cplusplus
}
#endif

#endif /* LWIP_CE_XML_H */
