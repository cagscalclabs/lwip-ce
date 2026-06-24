/**
 * @file xml.c
 * @brief Minimal XML parser for lwIP-CE
 */

#include "xml.h"
#include <string.h>

static void skip_ws(xml_parser_t *p)
{
    while (p->pos < p->len) {
        char c = p->buf[p->pos];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
            p->pos++;
        else
            break;
    }
}

static bool is_name_char(char c, bool first)
{
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == ':')
        return true;
    if (!first && ((c >= '0' && c <= '9') || c == '-' || c == '.'))
        return true;
    return false;
}

static xml_err_t parse_name(xml_parser_t *p, xml_slice_t *out)
{
    if (p->pos >= p->len || !is_name_char(p->buf[p->pos], true))
        return XML_ERR_INVALID;
    size_t start = p->pos;
    while (p->pos < p->len && is_name_char(p->buf[p->pos], false))
        p->pos++;
    out->str = p->buf + start;
    out->len = p->pos - start;
    return XML_OK;
}

static xml_err_t parse_attr_value(xml_parser_t *p, xml_slice_t *out)
{
    if (p->pos >= p->len)
        return XML_ERR_TRUNCATED;
    char quote = p->buf[p->pos];
    if (quote != '"' && quote != '\'')
        return XML_ERR_INVALID;
    p->pos++;
    size_t start = p->pos;
    while (p->pos < p->len && p->buf[p->pos] != quote)
        p->pos++;
    if (p->pos >= p->len)
        return XML_ERR_TRUNCATED;
    out->str = p->buf + start;
    out->len = p->pos - start;
    p->pos++; /* closing quote */
    return XML_OK;
}

static xml_err_t skip_comment(xml_parser_t *p)
{
    /* positioned after "<!--" */
    while (p->pos + 2 < p->len) {
        if (p->buf[p->pos] == '-' && p->buf[p->pos+1] == '-' && p->buf[p->pos+2] == '>') {
            p->pos += 3;
            return XML_OK;
        }
        p->pos++;
    }
    return XML_ERR_TRUNCATED;
}

static xml_err_t skip_pi(xml_parser_t *p)
{
    /* positioned after "<?" */
    while (p->pos + 1 < p->len) {
        if (p->buf[p->pos] == '?' && p->buf[p->pos+1] == '>') {
            p->pos += 2;
            return XML_OK;
        }
        p->pos++;
    }
    return XML_ERR_TRUNCATED;
}

void xml_init(xml_parser_t *p, const char *buf, size_t len)
{
    p->buf   = buf;
    p->len   = len;
    p->pos   = 0;
    p->depth = 0;
}

xml_err_t xml_next(xml_parser_t *p, xml_event_t *evt)
{
    memset(evt, 0, sizeof(*evt));

retry:
    skip_ws(p);
    if (p->pos >= p->len)
        return XML_ERR_DONE;

    if (p->buf[p->pos] != '<') {
        /* text content */
        size_t start = p->pos;
        while (p->pos < p->len && p->buf[p->pos] != '<')
            p->pos++;
        /* trim trailing whitespace */
        size_t end = p->pos;
        while (end > start && (p->buf[end-1] == ' ' || p->buf[end-1] == '\t'
                || p->buf[end-1] == '\r' || p->buf[end-1] == '\n'))
            end--;
        if (end == start)
            goto retry; /* whitespace-only text */
        evt->type     = XML_EVT_TEXT;
        evt->text.str = p->buf + start;
        evt->text.len = end - start;
        return XML_OK;
    }

    p->pos++; /* consume '<' */

    if (p->pos >= p->len)
        return XML_ERR_TRUNCATED;

    /* comment */
    if (p->pos + 2 < p->len && p->buf[p->pos] == '!'
            && p->buf[p->pos+1] == '-' && p->buf[p->pos+2] == '-') {
        p->pos += 3;
        xml_err_t err = skip_comment(p);
        if (err != XML_OK) return err;
        goto retry;
    }

    /* processing instruction or XML declaration */
    if (p->buf[p->pos] == '?') {
        p->pos++;
        xml_err_t err = skip_pi(p);
        if (err != XML_OK) return err;
        goto retry;
    }

    /* closing tag */
    if (p->buf[p->pos] == '/') {
        p->pos++;
        xml_err_t err = parse_name(p, &evt->name);
        if (err != XML_OK) return err;
        skip_ws(p);
        if (p->pos >= p->len || p->buf[p->pos] != '>')
            return XML_ERR_INVALID;
        p->pos++;
        if (p->depth > 0) p->depth--;
        evt->type = XML_EVT_ELEMENT_END;
        return XML_OK;
    }

    /* opening tag */
    xml_err_t err = parse_name(p, &evt->name);
    if (err != XML_OK) return err;

    evt->attr_count = 0;
    while (p->pos < p->len) {
        skip_ws(p);
        if (p->pos >= p->len) return XML_ERR_TRUNCATED;
        char c = p->buf[p->pos];
        if (c == '>' || c == '/') break;
        if (evt->attr_count >= XML_MAX_ATTRS)
            return XML_ERR_INVALID;
        xml_attr_t *attr = &evt->attrs[evt->attr_count];
        err = parse_name(p, &attr->name);
        if (err != XML_OK) return err;
        skip_ws(p);
        if (p->pos >= p->len || p->buf[p->pos] != '=')
            return XML_ERR_INVALID;
        p->pos++;
        skip_ws(p);
        err = parse_attr_value(p, &attr->value);
        if (err != XML_OK) return err;
        evt->attr_count++;
    }

    if (p->pos >= p->len) return XML_ERR_TRUNCATED;

    if (p->buf[p->pos] == '/') {
        p->pos++;
        if (p->pos >= p->len || p->buf[p->pos] != '>')
            return XML_ERR_INVALID;
        p->pos++;
        evt->self_closing = true;
        evt->type = XML_EVT_ELEMENT_START;
        return XML_OK;
    }

    p->pos++; /* consume '>' */
    if (p->depth >= XML_MAX_DEPTH) return XML_ERR_DEPTH;
    p->depth++;
    evt->type = XML_EVT_ELEMENT_START;
    return XML_OK;
}

xml_err_t xml_skip(xml_parser_t *p)
{
    int depth = 1;
    xml_event_t evt;
    while (depth > 0) {
        xml_err_t err = xml_next(p, &evt);
        if (err != XML_OK) return err;
        if (evt.type == XML_EVT_ELEMENT_START && !evt.self_closing)
            depth++;
        else if (evt.type == XML_EVT_ELEMENT_END)
            depth--;
    }
    return XML_OK;
}

bool xml_slice_copy(char *dst, size_t dst_len, const xml_slice_t *s)
{
    if (s->len + 1 > dst_len) return false;
    memcpy(dst, s->str, s->len);
    dst[s->len] = '\0';
    return true;
}

bool xml_decode_entity(const char **src, const char *src_end, char *dst, size_t *dst_written)
{
    if (*src >= src_end || **src != '&') return false;
    const char *p = *src + 1;

    static const struct { const char *name; char ch; } entities[] = {
        {"amp;",  '&'},
        {"lt;",   '<'},
        {"gt;",   '>'},
        {"apos;", '\''},
        {"quot;", '"'},
    };
    for (size_t i = 0; i < sizeof(entities)/sizeof(entities[0]); i++) {
        size_t nlen = strlen(entities[i].name);
        if ((size_t)(src_end - p) >= nlen && memcmp(p, entities[i].name, nlen) == 0) {
            *dst = entities[i].ch;
            *dst_written = 1;
            *src = p + nlen;
            return true;
        }
    }
    return false;
}

bool xml_get_attr(const xml_event_t *evt, const char *name, char *dst, size_t dst_len)
{
    size_t name_len = strlen(name);
    for (uint8_t i = 0; i < evt->attr_count; i++) {
        const xml_attr_t *a = &evt->attrs[i];
        if (a->name.len == name_len && memcmp(a->name.str, name, name_len) == 0)
            return xml_slice_copy(dst, dst_len, &a->value);
    }
    return false;
}

xml_err_t xml_get_inner_text(xml_parser_t *p, char *dst, size_t dst_len)
{
    xml_event_t evt;
    xml_err_t err = xml_next(p, &evt);
    if (err == XML_ERR_DONE) return XML_ERR_DONE;
    if (err != XML_OK) return err;
    if (evt.type == XML_EVT_ELEMENT_END) return XML_ERR_DONE;
    if (evt.type != XML_EVT_TEXT) return XML_ERR_INVALID;
    if (!xml_slice_copy(dst, dst_len, &evt.text)) return XML_ERR_INVALID;
    /* consume the closing ELEMENT_END */
    err = xml_next(p, &evt);
    if (err != XML_OK) return err;
    if (evt.type != XML_EVT_ELEMENT_END) return XML_ERR_INVALID;
    return XML_OK;
}

size_t xml_list_attrs(const xml_event_t *evt, char *dst, size_t dst_len)
{
    size_t out = 0;
    for (uint8_t i = 0; i < evt->attr_count; i++) {
        if (i > 0) {
            if (out + 2 > dst_len) return (size_t)-1;
            dst[out++] = ',';
        }
        const xml_attr_t *a = &evt->attrs[i];
        if (out + a->name.len + 1 + a->value.len + 1 > dst_len) return (size_t)-1;
        memcpy(dst + out, a->name.str, a->name.len);
        out += a->name.len;
        dst[out++] = '=';
        memcpy(dst + out, a->value.str, a->value.len);
        out += a->value.len;
    }
    dst[out] = '\0';
    return out;
}
