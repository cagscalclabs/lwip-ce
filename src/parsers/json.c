/**
 * @file json.c
 * @brief Minimal JSON parser for lwIP-CE
 */

#include "json.h"
#include <string.h>
#include <stdlib.h>

static void skip_ws(json_parser_t *p)
{
    while (p->pos < p->len) {
        char c = p->buf[p->pos];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
            p->pos++;
        else
            break;
    }
}

/* Scan forward from pos to find the matching closer for an open brace/bracket.
 * opener/closer are '{'/'}' or '['/']'. Returns the index of the closer,
 * or (size_t)-1 on error. Handles nested structures and strings correctly. */
static size_t find_closer(json_parser_t *p, char opener, char closer)
{
    int depth = 1;
    size_t i = p->pos;
    while (i < p->len && depth > 0) {
        char c = p->buf[i];
        if (c == '"') {
            /* skip string: find unescaped closing quote */
            i++;
            while (i < p->len) {
                if (p->buf[i] == '\\') { i += 2; continue; }
                if (p->buf[i] == '"') { i++; break; }
                i++;
            }
            continue;
        }
        if (c == opener) depth++;
        else if (c == closer) { depth--; if (depth == 0) return i; }
        i++;
    }
    return (size_t)-1;
}

static json_err_t parse_string(json_parser_t *p, json_slice_t *out)
{
    /* caller has already consumed the opening '"' */
    size_t start = p->pos;
    while (p->pos < p->len) {
        char c = p->buf[p->pos];
        if ((unsigned char)c < 0x20u)
            return JSON_ERR_INVALID;
        if (c == '\\') {
            if (p->pos + 1u >= p->len)
                return JSON_ERR_TRUNCATED;
            p->pos += 2;
            continue;
        }
        if (c == '"') {
            out->str = p->buf + start;
            out->len = p->pos - start;
            p->pos++;
            return JSON_OK;
        }
        p->pos++;
    }
    return JSON_ERR_TRUNCATED;
}

static json_err_t parse_literal(json_parser_t *p, const char *lit, size_t lit_len)
{
    if (p->pos + lit_len > p->len) return JSON_ERR_TRUNCATED;
    if (memcmp(p->buf + p->pos, lit, lit_len) != 0) return JSON_ERR_INVALID;
    p->pos += lit_len;
    return JSON_OK;
}

static json_err_t parse_number(json_parser_t *p, json_slice_t *out)
{
    size_t start = p->pos;

    if (p->pos < p->len && p->buf[p->pos] == '-')
        p->pos++;

    if (p->pos >= p->len)
        return JSON_ERR_TRUNCATED;

    if (p->buf[p->pos] == '0') {
        p->pos++;
    } else if (p->buf[p->pos] >= '1' && p->buf[p->pos] <= '9') {
        do {
            p->pos++;
        } while (p->pos < p->len &&
                 p->buf[p->pos] >= '0' && p->buf[p->pos] <= '9');
    } else {
        return JSON_ERR_INVALID;
    }

    if (p->pos < p->len && p->buf[p->pos] == '.') {
        p->pos++;
        if (p->pos >= p->len ||
            p->buf[p->pos] < '0' || p->buf[p->pos] > '9')
            return JSON_ERR_INVALID;
        do {
            p->pos++;
        } while (p->pos < p->len &&
                 p->buf[p->pos] >= '0' && p->buf[p->pos] <= '9');
    }

    if (p->pos < p->len &&
        (p->buf[p->pos] == 'e' || p->buf[p->pos] == 'E')) {
        p->pos++;
        if (p->pos < p->len &&
            (p->buf[p->pos] == '+' || p->buf[p->pos] == '-'))
            p->pos++;
        if (p->pos >= p->len ||
            p->buf[p->pos] < '0' || p->buf[p->pos] > '9')
            return JSON_ERR_INVALID;
        do {
            p->pos++;
        } while (p->pos < p->len &&
                 p->buf[p->pos] >= '0' && p->buf[p->pos] <= '9');
    }

    out->str = p->buf + start;
    out->len = p->pos - start;
    return JSON_OK;
}

void json_init(json_parser_t *p, const char *buf, size_t len)
{
    p->buf          = buf;
    p->len          = len;
    p->pos          = 0;
    p->in_object    = false;
    p->expect_value = false;
}

void json_enter(json_parser_t *child, const json_token_t *tok)
{
    child->buf          = tok->value.str;
    child->len          = tok->value.len;
    child->pos          = 0;
    child->in_object    = (tok->type == JSON_TOK_OBJECT);
    child->expect_value = false;
}

json_err_t json_next(json_parser_t *p, json_token_t *tok)
{
    skip_ws(p);
    tok->value.str  = NULL;
    tok->value.len  = 0;
    tok->bool_value = false;
    tok->type       = JSON_TOK_NONE;

    if (p->pos >= p->len)
        return JSON_ERR_DONE;

    char c = p->buf[p->pos];

    /* separators: consume and retry */
    if (c == ',' || c == ':') {
        if (c == ':') p->expect_value = true;
        p->pos++;
        return json_next(p, tok);
    }

    if (c == '{' || c == '[') {
        char opener = c, closer = (c == '{') ? '}' : ']';
        p->pos++; /* skip opener */
        size_t close_idx = find_closer(p, opener, closer);
        if (close_idx == (size_t)-1) return JSON_ERR_TRUNCATED;
        tok->type      = (opener == '{') ? JSON_TOK_OBJECT : JSON_TOK_ARRAY;
        tok->value.str = p->buf + p->pos;
        tok->value.len = close_idx - p->pos;
        p->pos         = close_idx + 1; /* advance past closer */
        p->expect_value = false;
        return JSON_OK;
    }

    if (c == '}' || c == ']') {
        /* end of this cursor's scope — signal done */
        return JSON_ERR_DONE;
    }

    if (c == '"') {
        p->pos++;
        json_err_t err = parse_string(p, &tok->value);
        if (err != JSON_OK) return err;
        if (p->in_object && !p->expect_value) {
            tok->type = JSON_TOK_KEY;
            /* expect_value flips to true when the ':' separator is consumed */
        } else {
            tok->type       = JSON_TOK_STRING;
            p->expect_value = false;
        }
        return JSON_OK;
    }

    if (c == 't') {
        json_err_t err = parse_literal(p, "true", 4);
        if (err != JSON_OK) return err;
        tok->type        = JSON_TOK_BOOL;
        tok->bool_value  = true;
        tok->value.str   = "true";
        tok->value.len   = 4;
        p->expect_value  = false;
        return JSON_OK;
    }
    if (c == 'f') {
        json_err_t err = parse_literal(p, "false", 5);
        if (err != JSON_OK) return err;
        tok->type        = JSON_TOK_BOOL;
        tok->bool_value  = false;
        tok->value.str   = "false";
        tok->value.len   = 5;
        p->expect_value  = false;
        return JSON_OK;
    }
    if (c == 'n') {
        json_err_t err = parse_literal(p, "null", 4);
        if (err != JSON_OK) return err;
        tok->type       = JSON_TOK_NULL;
        p->expect_value = false;
        return JSON_OK;
    }
    if (c == '-' || (c >= '0' && c <= '9')) {
        json_err_t err = parse_number(p, &tok->value);
        if (err != JSON_OK) return err;
        tok->type       = JSON_TOK_NUMBER;
        p->expect_value = false;
        return JSON_OK;
    }

    return JSON_ERR_INVALID;
}

bool json_slice_copy(char *dst, size_t dst_len, const json_slice_t *s)
{
    if (s == NULL || s->str == NULL) return false;
    if (s->len + 1 > dst_len) return false;
    memcpy(dst, s->str, s->len);
    dst[s->len] = '\0';
    return true;
}

json_err_t json_get_key_value(json_parser_t *p, const char *key_name,
                               json_token_t *key, json_token_t *value)
{
    json_token_t t;
    for (;;) {
        json_err_t err = json_next(p, &t);
        if (err != JSON_OK) return err; /* JSON_ERR_DONE propagates */
        if (t.type != JSON_TOK_KEY) continue; /* skip non-key tokens */

        if (key_name != NULL) {
            size_t key_len = strlen(key_name);
            if (t.value.len != key_len || memcmp(t.value.str, key_name, key_len) != 0) {
                /* key didn't match — consume its value and continue */
                err = json_next(p, value);
                if (err != JSON_OK) return err;
                continue;
            }
        }

        *key = t;
        return json_next(p, value);
    }
}

json_err_t json_get_string(json_parser_t *p, const char *key, char *dst, size_t dst_len)
{
    json_token_t k, v;
    json_err_t err = json_get_key_value(p, key, &k, &v);
    if (err != JSON_OK) return err;
    if (v.type != JSON_TOK_STRING) return JSON_ERR_INVALID;
    if (!json_slice_copy(dst, dst_len, &v.value)) return JSON_ERR_INVALID;
    return JSON_OK;
}

json_err_t json_get_number(json_parser_t *p, const char *key, long *out)
{
    json_token_t k, v;
    char *end;
    json_err_t err = json_get_key_value(p, key, &k, &v);
    if (err != JSON_OK) return err;
    if (v.type != JSON_TOK_NUMBER) return JSON_ERR_INVALID;
    char buf[24];
    if (!json_slice_copy(buf, sizeof(buf), &v.value)) return JSON_ERR_INVALID;
    *out = strtol(buf, &end, 10);
    if (*end != '\0')
        return JSON_ERR_INVALID;
    return JSON_OK;
}
