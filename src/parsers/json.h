/**
 * @file json.h
 * @brief Minimal JSON parser for lwIP-CE
 * @author Anthony Cagliano
 * @author Claude Code
 *
 * @note Cursor-based parser modelled after tls_asn1_cursor: no heap allocation,
 * no DOM tree. json_next() advances the cursor and returns one token; for
 * objects and arrays the token carries the full content span and the parent
 * cursor has already advanced past the closer. Descend into a nested value by
 * calling json_enter(), which scopes a child cursor to that span.
 *
 * Because each cursor is always scoped to a single nesting level, there is no
 * depth stack and no skip primitive — to skip a nested value, simply don't
 * call json_enter() on it.
 *
 * Known constraints:
 * - Input must be a single contiguous buffer (no streaming).
 * - Unicode escape sequences (\uXXXX) are passed through uninterpreted.
 */

#ifndef LWIP_CE_JSON_H
#define LWIP_CE_JSON_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    JSON_OK = 0,
    JSON_ERR_INVALID,
    JSON_ERR_TRUNCATED,
    JSON_ERR_DONE,
} json_err_t;

typedef enum {
    JSON_TOK_NONE = 0,
    JSON_TOK_OBJECT,    /* { ... } — value span is the interior (between braces) */
    JSON_TOK_ARRAY,     /* [ ... ] — value span is the interior (between brackets) */
    JSON_TOK_KEY,       /* object key string */
    JSON_TOK_STRING,    /* string value */
    JSON_TOK_NUMBER,    /* number (raw slice) */
    JSON_TOK_BOOL,      /* true / false */
    JSON_TOK_NULL,      /* null */
} json_token_type_t;

typedef struct {
    const char *str;   /* pointer into input buffer, NOT NUL-terminated */
    size_t      len;
} json_slice_t;

typedef struct {
    json_token_type_t type;
    json_slice_t      value;      /* KEY/STRING/NUMBER/BOOL: the text slice
                                     OBJECT/ARRAY: the interior content span */
    bool              bool_value; /* valid when type == JSON_TOK_BOOL */
} json_token_t;

typedef struct {
    const char *buf;
    size_t      len;
    size_t      pos;
    bool        in_object;    /* true if this cursor spans an object interior */
    bool        expect_value; /* true after a key colon; only meaningful when in_object */
} json_parser_t;

/**
 * Initialize a cursor over a complete JSON buffer.
 * The buffer must remain valid for the lifetime of the cursor.
 */
void json_init(json_parser_t *p, const char *buf, size_t len);

/**
 * Scope a child cursor into the interior of an OBJECT or ARRAY token.
 * After json_next() returns a token with type JSON_TOK_OBJECT or JSON_TOK_ARRAY,
 * call this to get a cursor bounded to that value's contents.
 * The parent cursor is already positioned past the closing brace/bracket.
 *
 *   json_token_t tok;
 *   json_next(&parent, &tok);              // tok.type == JSON_TOK_OBJECT
 *   json_parser_t child;
 *   json_enter(&child, &tok);             // child spans the object interior
 *   json_get_string(&child, "key", ...);  // search within child only
 */
void json_enter(json_parser_t *child, const json_token_t *tok);

/**
 * Advance to the next token in the current cursor scope.
 *
 * Inside an object cursor: alternates JSON_TOK_KEY / value tokens.
 * Inside an array cursor: returns value tokens (STRING/NUMBER/BOOL/NULL/OBJECT/ARRAY).
 * At top level: returns the single root value.
 *
 * Returns JSON_OK and fills *tok on success.
 * Returns JSON_ERR_DONE when the cursor scope is exhausted.
 */
json_err_t json_next(json_parser_t *p, json_token_t *tok);

/**
 * Copy a json_slice_t into a NUL-terminated buffer.
 * Returns false if dst is too small (dst_len includes the NUL byte).
 */
bool json_slice_copy(char *dst, size_t dst_len, const json_slice_t *s);

#define json_token_copy(dst, dst_len, tok) \
    ((tok) != NULL && json_slice_copy((dst), (dst_len), &(tok)->value))

#define json_token_equals(tok, expected) \
    ((tok) != NULL && (expected) != NULL && (tok)->value.str != NULL && \
     (tok)->value.len == strlen(expected) && \
     memcmp((tok)->value.str, (expected), (tok)->value.len) == 0)

/**
 * Retrieve a key-value pair from the current object cursor.
 *
 * If key_name is non-NULL: scan forward for that key, fill *key and *value.
 *   Returns JSON_ERR_DONE if the key is not found before the object ends.
 *
 * If key_name is NULL: fill *key and *value with the next pair.
 *   Returns JSON_ERR_DONE when the object is exhausted.
 *   Use this form to iterate all pairs in an object.
 *
 * The cursor must be positioned inside an object (created via json_enter on
 * a JSON_TOK_OBJECT token, or initialized directly over object interior bytes).
 *
 * *key   type == JSON_TOK_KEY, value.str/len is the key name slice.
 * *value type is any value token; if OBJECT or ARRAY, call json_enter to descend.
 */
json_err_t json_get_key_value(json_parser_t *p, const char *key_name,
                               json_token_t *key, json_token_t *value);

/**
 * Convenience: scan for key in the current object cursor and copy its string
 * value into dst (NUL-terminated).
 * Returns JSON_ERR_INVALID if the value is not a string or dst is too small.
 */
json_err_t json_get_string(json_parser_t *p, const char *key, char *dst, size_t dst_len);

/**
 * Convenience: scan for key in the current object cursor and parse its numeric
 * value into *out as a signed long.
 * Returns JSON_ERR_INVALID if the value is not a number token.
 */
json_err_t json_get_number(json_parser_t *p, const char *key, long *out);

#ifdef __cplusplus
}
#endif

#endif /* LWIP_CE_JSON_H */
