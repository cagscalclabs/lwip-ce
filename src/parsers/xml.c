/**
 * @file xml.c
 * @brief Ring-buffered XML/HTML parser for lwIP-CE
 */

#include "xml.h"
#include <string.h>
#include <stdint.h>

typedef enum {
    XML_S_CONTENT = 0,
    XML_S_TAG_OPEN,
    XML_S_TAG_NAME,
    XML_S_CLOSE_NAME,
    XML_S_ATTRS,
    XML_S_ATTR_NAME,
    XML_S_ATTR_EQ,
    XML_S_ATTR_VAL_START,
    XML_S_ATTR_VAL,
    XML_S_ATTR_UVAL,
    XML_S_SELF_CLOSE,
    XML_S_COMMENT,
    XML_S_COMMENT_D1,
    XML_S_COMMENT_D2,
    XML_S_PI,
    XML_S_PI_Q,
    XML_S_BANG,
    XML_S_BANG_SKIP,
    XML_S_ENTITY,
} xml_parse_state_t;

/* -------------------------------------------------------------------------
 * HTML void elements (lax mode) — auto-synthesize ELEMENT_END on START
 * ---------------------------------------------------------------------- */
static const char * const xml_void_elements[] = {
    "area", "base", "br", "col", "embed", "hr", "img", "input",
    "link", "meta", "param", "source", "track", "wbr",
};
#define XML_VOID_COUNT (sizeof(xml_void_elements) / sizeof(xml_void_elements[0]))

static bool xml_is_void(const char *name)
{
    size_t i;
    for (i = 0; i < XML_VOID_COUNT; i++) {
        if (strcmp(name, xml_void_elements[i]) == 0)
            return true;
    }
    return false;
}

/* -------------------------------------------------------------------------
 * Ring helpers
 * ---------------------------------------------------------------------- */
static size_t ring_used(const xml_ctx_t *ctx)
{
    if (ctx->ring == NULL || ctx->ring_len == 0)
        return 0;
    if (ctx->wpos >= ctx->rpos)
        return ctx->wpos - ctx->rpos;
    return ctx->ring_len - ctx->rpos + ctx->wpos;
}

static size_t ring_free(const xml_ctx_t *ctx)
{
    if (ctx->ring == NULL || ctx->ring_len < 2u)
        return 0;
    return ctx->ring_len - ring_used(ctx) - 1u; /* keep one slot empty */
}

/* Peek at byte at logical offset from rpos (0 = next byte to read). */
static bool ring_peek(const xml_ctx_t *ctx, size_t offset, char *out)
{
    if (offset >= ring_used(ctx))
        return false;
    *out = ctx->ring[(ctx->rpos + offset) % ctx->ring_len];
    return true;
}

/* Advance rpos by n bytes (consume). */
static void ring_consume(xml_ctx_t *ctx, size_t n)
{
    ctx->rpos = (ctx->rpos + n) % ctx->ring_len;
}

/* -------------------------------------------------------------------------
 * Character classification
 * ---------------------------------------------------------------------- */
static bool is_ws(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static bool slice_copy(char *dst, size_t dst_len, const char *src, size_t src_len)
{
    if (src_len + 1u > dst_len)
        return false;
    memcpy(dst, src, src_len);
    dst[src_len] = '\0';
    return true;
}

static bool is_name_start(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           c == '_' || c == ':';
}

static bool is_name_char(char c)
{
    return is_name_start(c) || (c >= '0' && c <= '9') ||
           c == '-' || c == '.';
}

static char xml_tolower(char c)
{
    if (c >= 'A' && c <= 'Z')
        return (char)(c + ('a' - 'A'));
    return c;
}

/* -------------------------------------------------------------------------
 * Entity table
 * ---------------------------------------------------------------------- */
static const struct { const char *name; char ch; } xml_entities[] = {
    {"amp;",  '&'},
    {"lt;",   '<'},
    {"gt;",   '>'},
    {"apos;", '\''},
    {"quot;", '"'},
    {"nbsp;", ' '},
};
#define XML_ENTITY_COUNT (sizeof(xml_entities) / sizeof(xml_entities[0]))

bool xml_decode_entity(const char **src, const char *src_end,
                       char *dst, size_t *dst_written)
{
    size_t i;
    const char *p;

    if (*src >= src_end || **src != '&')
        return false;
    p = *src + 1;
    for (i = 0; i < XML_ENTITY_COUNT; i++) {
        size_t nlen = strlen(xml_entities[i].name);
        if ((size_t)(src_end - p) >= nlen &&
            memcmp(p, xml_entities[i].name, nlen) == 0) {
            *dst = xml_entities[i].ch;
            *dst_written = 1;
            *src = p + nlen;
            return true;
        }
    }
    return false;
}

/* -------------------------------------------------------------------------
 * Name append helpers (to tag_name or cur_attr fields)
 * ---------------------------------------------------------------------- */
static void name_append(char *buf, uint8_t *len, uint8_t max, char c)
{
    if (*len + 1u < (uint8_t)max) {
        buf[(*len)++] = c;
        buf[*len] = '\0';
    }
}

/* -------------------------------------------------------------------------
 * Text flush into pending event
 * ---------------------------------------------------------------------- */
static void flush_text(xml_ctx_t *ctx, xml_event_t *evt_out)
{
    /* Trim trailing whitespace */
    while (ctx->text_len > 0) {
        char last = ctx->text_buf[ctx->text_len - 1u];
        if (!is_ws(last))
            break;
        ctx->text_len--;
    }
    ctx->text_buf[ctx->text_len] = '\0';

    memset(evt_out, 0, sizeof(*evt_out));
    evt_out->type = XML_EVT_TEXT;
    memcpy(evt_out->text, ctx->text_buf, ctx->text_len + 1u);

    ctx->text_len = 0;
    ctx->text_buf[0] = '\0';
    ctx->text_overflow = false;
}

static bool text_nonempty(const xml_ctx_t *ctx)
{
    uint8_t i;
    for (i = 0; i < ctx->text_len; i++) {
        if (!is_ws((unsigned char)ctx->text_buf[i]))
            return true;
    }
    return false;
}

/* -------------------------------------------------------------------------
 * Commit attribute from cur_attr scratch into pending.attrs[]
 * ---------------------------------------------------------------------- */
static void commit_attr(xml_ctx_t *ctx)
{
    if (ctx->cur_attr.name[0] == '\0')
        return;
    if (ctx->pending.attr_count >= XML_MAX_ATTRS)
        return;
    ctx->pending.attrs[ctx->pending.attr_count++] = ctx->cur_attr;
    memset(&ctx->cur_attr, 0, sizeof(ctx->cur_attr));
    ctx->cur_attr_name_len = 0;
    ctx->cur_attr_val_len = 0;
    ctx->attr_quote = '\0';
    ctx->attr_bool = false;
}

/* -------------------------------------------------------------------------
 * Initialisation
 * ---------------------------------------------------------------------- */
void xml_init(xml_ctx_t *ctx, char *ring, size_t ring_len, uint8_t flags)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->ring     = ring;
    ctx->ring_len = ring_len;
    ctx->flags    = flags;
    ctx->state    = XML_S_CONTENT;
}

/* -------------------------------------------------------------------------
 * xml_take
 * ---------------------------------------------------------------------- */
size_t xml_take(xml_ctx_t *ctx, const char *buf, size_t len)
{
    size_t free_bytes = ring_free(ctx);
    size_t n = len < free_bytes ? len : free_bytes;
    size_t first, second;

    if (ctx->ring == NULL || buf == NULL || ctx->ring_len < 2u || !n)
        return 0;

    /* wpos may wrap — split into two memcpy segments */
    first = ctx->ring_len - ctx->wpos;
    if (first > n)
        first = n;
    memcpy(ctx->ring + ctx->wpos, buf, first);
    second = n - first;
    if (second)
        memcpy(ctx->ring, buf + first, second);
    ctx->wpos = (ctx->wpos + n) % ctx->ring_len;
    return n;
}

/* -------------------------------------------------------------------------
 * xml_finish
 * ---------------------------------------------------------------------- */
void xml_finish(xml_ctx_t *ctx)
{
    ctx->finished = true;
}

/* -------------------------------------------------------------------------
 * xml_next  — incremental ring-backed pull parser
 * ---------------------------------------------------------------------- */
xml_err_t xml_next(xml_ctx_t *ctx, xml_event_t *evt)
{
    bool lax = (ctx->flags & XML_FLAG_LAX) != 0;
    char c;

    /* Emit a deferred void element end before doing anything else */
    if (ctx->void_end_pending) {
        ctx->void_end_pending = false;
        memset(evt, 0, sizeof(*evt));
        evt->type = XML_EVT_ELEMENT_END;
        evt->self_closing = true;
        memcpy(evt->name, ctx->void_end_name, XML_NAME_MAX);
        return XML_OK;
    }

    while (true) {
        if (!ring_peek(ctx, 0, &c)) {
            /* Ring empty */
            switch (ctx->state) {
            case XML_S_CONTENT:
                if (text_nonempty(ctx)) {
                    if (!ctx->finished)
                        return XML_ERR_NEED_MORE;
                    flush_text(ctx, evt);
                    return XML_OK;
                }
                return ctx->finished ? XML_ERR_DONE : XML_ERR_NEED_MORE;
            default:
                return ctx->finished ? XML_ERR_TRUNCATED : XML_ERR_NEED_MORE;
            }
        }

        ring_consume(ctx, 1);

        switch (ctx->state) {

        /* ---- text content -------------------------------------------- */
        case XML_S_CONTENT:
            if (c == '<') {
                if (text_nonempty(ctx)) {
                    /* Return the accumulated text first; re-process '<' */
                    ctx->rpos = (ctx->rpos + ctx->ring_len - 1u) % ctx->ring_len;
                    flush_text(ctx, evt);
                    return XML_OK;
                }
                ctx->text_len = 0;
                ctx->text_buf[0] = '\0';
                ctx->text_overflow = false;
                ctx->state = XML_S_TAG_OPEN;
                break;
            }
            if (c == '&') {
                /* Begin entity accumulation */
                ctx->entity_buf[0] = '\0';
                ctx->entity_len = 0;
                ctx->state = XML_S_ENTITY;
                break;
            }
            if (!ctx->text_overflow) {
                if (ctx->text_len + 1u < XML_TEXT_MAX) {
                    ctx->text_buf[ctx->text_len++] = c;
                    ctx->text_buf[ctx->text_len] = '\0';
                } else {
                    ctx->text_overflow = true;
                }
            }
            break;

        /* ---- entity inside text -------------------------------------- */
        case XML_S_ENTITY:
            if (c == ';') {
                /* Try to decode */
                size_t i;
                bool found = false;
                for (i = 0; i < XML_ENTITY_COUNT; i++) {
                    size_t nlen = strlen(xml_entities[i].name) - 1u; /* excl ';' */
                    if (ctx->entity_len == nlen &&
                        memcmp(ctx->entity_buf, xml_entities[i].name, nlen) == 0) {
                        if (!ctx->text_overflow &&
                            ctx->text_len + 1u < XML_TEXT_MAX) {
                            ctx->text_buf[ctx->text_len++] = xml_entities[i].ch;
                            ctx->text_buf[ctx->text_len] = '\0';
                        }
                        found = true;
                        break;
                    }
                }
                if (!found && lax) {
                    /* Unknown entity: emit '&', entity text, ';' literally */
                    size_t j;
                    if (!ctx->text_overflow && ctx->text_len + 1u < XML_TEXT_MAX)
                        ctx->text_buf[ctx->text_len++] = '&';
                    for (j = 0; j < ctx->entity_len && !ctx->text_overflow; j++) {
                        if (ctx->text_len + 1u < XML_TEXT_MAX)
                            ctx->text_buf[ctx->text_len++] = ctx->entity_buf[j];
                        else
                            ctx->text_overflow = true;
                    }
                    if (!ctx->text_overflow && ctx->text_len + 1u < XML_TEXT_MAX)
                        ctx->text_buf[ctx->text_len++] = ';';
                    if (ctx->text_len <= XML_TEXT_MAX)
                        ctx->text_buf[ctx->text_len] = '\0';
                } else if (!found) {
                    return XML_ERR_INVALID;
                }
                ctx->entity_len = 0;
                ctx->entity_buf[0] = '\0';
                ctx->state = XML_S_CONTENT;
                break;
            }
            if (ctx->entity_len + 1u < sizeof(ctx->entity_buf) - 1u) {
                ctx->entity_buf[ctx->entity_len++] = c;
                ctx->entity_buf[ctx->entity_len] = '\0';
            } else {
                /* Entity too long — emit raw & and bail */
                if (!ctx->text_overflow && ctx->text_len + 1u < XML_TEXT_MAX) {
                    ctx->text_buf[ctx->text_len++] = '&';
                    ctx->text_buf[ctx->text_len] = '\0';
                }
                ctx->entity_len = 0;
                ctx->entity_buf[0] = '\0';
                ctx->state = XML_S_CONTENT;
                /* re-process this char as content */
                ctx->rpos = (ctx->rpos + ctx->ring_len - 1u) % ctx->ring_len;
            }
            break;

        /* ---- just seen '<' ------------------------------------------- */
        case XML_S_TAG_OPEN:
            if (c == '/') {
                ctx->tag_name[0] = '\0';
                ctx->tag_name_len = 0;
                ctx->state = XML_S_CLOSE_NAME;
                break;
            }
            if (c == '!') {
                ctx->state = XML_S_BANG;
                break;
            }
            if (c == '?') {
                ctx->state = XML_S_PI;
                break;
            }
            if (is_name_start(c) || (lax && (c == '_'))) {
                memset(&ctx->pending, 0, sizeof(ctx->pending));
                ctx->tag_name[0] = '\0';
                ctx->tag_name_len = 0;
                memset(&ctx->cur_attr, 0, sizeof(ctx->cur_attr));
                ctx->cur_attr_name_len = 0;
                ctx->cur_attr_val_len = 0;
                ctx->attr_quote = '\0';
                ctx->attr_bool = false;
                char nc = lax ? xml_tolower(c) : c;
                name_append(ctx->tag_name, &ctx->tag_name_len, XML_NAME_MAX, nc);
                ctx->state = XML_S_TAG_NAME;
                break;
            }
            /* stray '<' in lax mode — treat as text */
            if (lax) {
                if (!ctx->text_overflow && ctx->text_len + 1u < XML_TEXT_MAX) {
                    ctx->text_buf[ctx->text_len++] = '<';
                    ctx->text_buf[ctx->text_len] = '\0';
                }
                ctx->state = XML_S_CONTENT;
                /* re-process c as content */
                ctx->rpos = (ctx->rpos + ctx->ring_len - 1u) % ctx->ring_len;
                break;
            }
            return XML_ERR_INVALID;

        /* ---- reading opening tag name --------------------------------- */
        case XML_S_TAG_NAME:
            if (is_name_char(c)) {
                char nc = lax ? xml_tolower(c) : c;
                name_append(ctx->tag_name, &ctx->tag_name_len, XML_NAME_MAX, nc);
                break;
            }
            /* name done */
            memcpy(ctx->pending.name, ctx->tag_name, XML_NAME_MAX);
            ctx->pending.type = XML_EVT_ELEMENT_START;
            if (is_ws(c)) {
                ctx->state = XML_S_ATTRS;
                break;
            }
            if (c == '>') {
                if (ctx->depth >= XML_MAX_DEPTH)
                    return XML_ERR_DEPTH;
                bool is_void = lax && xml_is_void(ctx->tag_name);
                if (!is_void)
                    ctx->depth++;
                *evt = ctx->pending;
                evt->self_closing = is_void;
                ctx->state = XML_S_CONTENT;
                if (is_void) {
                    ctx->void_end_pending = true;
                    memcpy(ctx->void_end_name, ctx->tag_name, XML_NAME_MAX);
                }
                return XML_OK;
            }
            if (c == '/') {
                ctx->state = XML_S_SELF_CLOSE;
                break;
            }
            if (!lax)
                return XML_ERR_INVALID;
            /* lax: treat as whitespace and keep reading attrs */
            ctx->state = XML_S_ATTRS;
            break;

        /* ---- reading attributes -------------------------------------- */
        case XML_S_ATTRS:
            if (is_ws(c))
                break;
            if (c == '>') {
                commit_attr(ctx);
                memcpy(ctx->pending.name, ctx->tag_name, XML_NAME_MAX);
                if (ctx->depth >= XML_MAX_DEPTH)
                    return XML_ERR_DEPTH;
                bool is_void = lax && xml_is_void(ctx->tag_name);
                if (!is_void)
                    ctx->depth++;
                *evt = ctx->pending;
                evt->self_closing = is_void;
                ctx->state = XML_S_CONTENT;
                if (is_void) {
                    ctx->void_end_pending = true;
                    memcpy(ctx->void_end_name, ctx->tag_name, XML_NAME_MAX);
                }
                return XML_OK;
            }
            if (c == '/') {
                commit_attr(ctx);
                ctx->state = XML_S_SELF_CLOSE;
                break;
            }
            if (is_name_start(c)) {
                commit_attr(ctx);
                memset(&ctx->cur_attr, 0, sizeof(ctx->cur_attr));
                ctx->cur_attr_name_len = 0;
                ctx->cur_attr_val_len = 0;
                ctx->attr_bool = false;
                char nc = lax ? xml_tolower(c) : c;
                name_append(ctx->cur_attr.name, &ctx->cur_attr_name_len,
                            XML_NAME_MAX, nc);
                ctx->state = XML_S_ATTR_NAME;
                break;
            }
            if (!lax)
                return XML_ERR_INVALID;
            break; /* lax: skip unknown chars in attr list */

        /* ---- reading attribute name ---------------------------------- */
        case XML_S_ATTR_NAME:
            if (is_name_char(c)) {
                char nc = lax ? xml_tolower(c) : c;
                name_append(ctx->cur_attr.name, &ctx->cur_attr_name_len,
                            XML_NAME_MAX, nc);
                break;
            }
            if (c == '=') {
                ctx->state = XML_S_ATTR_VAL_START;
                break;
            }
            /* boolean attribute or whitespace */
            if (is_ws(c) || c == '>' || c == '/') {
                if (lax) {
                    ctx->attr_bool = true;
                    ctx->cur_attr.value[0] = '\0';
                    commit_attr(ctx);
                    /* re-process c in ATTRS state */
                    ctx->rpos = (ctx->rpos + ctx->ring_len - 1u) % ctx->ring_len;
                    ctx->state = XML_S_ATTRS;
                    break;
                }
                if (c != '=')
                    return XML_ERR_INVALID;
            }
            ctx->state = XML_S_ATTR_EQ;
            break;

        /* ---- seen attr name, looking for '=' ------------------------- */
        case XML_S_ATTR_EQ:
            if (is_ws(c))
                break;
            if (c == '=') {
                ctx->state = XML_S_ATTR_VAL_START;
                break;
            }
            if (lax) {
                /* boolean attr — no = sign */
                ctx->attr_bool = true;
                ctx->cur_attr.value[0] = '\0';
                commit_attr(ctx);
                ctx->rpos = (ctx->rpos + ctx->ring_len - 1u) % ctx->ring_len;
                ctx->state = XML_S_ATTRS;
                break;
            }
            return XML_ERR_INVALID;

        /* ---- expecting opening quote or start of unquoted value ------ */
        case XML_S_ATTR_VAL_START:
            if (is_ws(c))
                break;
            if (c == '"' || c == '\'') {
                ctx->attr_quote = c;
                ctx->cur_attr_val_len = 0;
                ctx->cur_attr.value[0] = '\0';
                ctx->state = XML_S_ATTR_VAL;
                break;
            }
            if (lax) {
                /* unquoted value */
                ctx->attr_quote = '\0';
                ctx->cur_attr_val_len = 0;
                ctx->cur_attr.value[0] = '\0';
                /* re-process c as first char of unquoted value */
                ctx->rpos = (ctx->rpos + ctx->ring_len - 1u) % ctx->ring_len;
                ctx->state = XML_S_ATTR_UVAL;
                break;
            }
            return XML_ERR_INVALID;

        /* ---- reading quoted attribute value -------------------------- */
        case XML_S_ATTR_VAL:
            if (c == ctx->attr_quote) {
                commit_attr(ctx);
                ctx->state = XML_S_ATTRS;
                break;
            }
            if (ctx->cur_attr_val_len + 1u < XML_ATTR_VAL_MAX) {
                ctx->cur_attr.value[ctx->cur_attr_val_len++] = c;
                ctx->cur_attr.value[ctx->cur_attr_val_len] = '\0';
            }
            break;

        /* ---- reading unquoted attribute value (lax) ------------------- */
        case XML_S_ATTR_UVAL:
            if (is_ws(c) || c == '>' || c == '/') {
                commit_attr(ctx);
                ctx->rpos = (ctx->rpos + ctx->ring_len - 1u) % ctx->ring_len;
                ctx->state = XML_S_ATTRS;
                break;
            }
            if (ctx->cur_attr_val_len + 1u < XML_ATTR_VAL_MAX) {
                ctx->cur_attr.value[ctx->cur_attr_val_len++] = c;
                ctx->cur_attr.value[ctx->cur_attr_val_len] = '\0';
            }
            break;

        /* ---- self-closing '/>' --------------------------------------- */
        case XML_S_SELF_CLOSE:
            if (c == '>') {
                *evt = ctx->pending;
                evt->self_closing = true;
                memcpy(evt->name, ctx->tag_name, XML_NAME_MAX);
                ctx->state = XML_S_CONTENT;
                return XML_OK;
            }
            if (!lax)
                return XML_ERR_INVALID;
            /* lax: ignore stray chars before '>' */
            break;

        /* ---- closing tag name ---------------------------------------- */
        case XML_S_CLOSE_NAME:
            if (is_name_char(c)) {
                char nc = lax ? xml_tolower(c) : c;
                name_append(ctx->tag_name, &ctx->tag_name_len, XML_NAME_MAX, nc);
                break;
            }
            if (is_ws(c) || c == '>') {
                if (c != '>') {
                    /* skip to '>' */
                    char nc2;
                    while (ring_peek(ctx, 0, &nc2) && nc2 != '>')
                        ring_consume(ctx, 1);
                    if (!ring_peek(ctx, 0, &nc2))
                        return XML_ERR_NEED_MORE;
                    ring_consume(ctx, 1); /* consume '>' */
                }
                if (ctx->depth > 0)
                    ctx->depth--;
                memset(evt, 0, sizeof(*evt));
                evt->type = XML_EVT_ELEMENT_END;
                memcpy(evt->name, ctx->tag_name, XML_NAME_MAX);
                ctx->tag_name[0] = '\0';
                ctx->tag_name_len = 0;
                ctx->state = XML_S_CONTENT;
                return XML_OK;
            }
            if (!lax)
                return XML_ERR_INVALID;
            break;

        /* ---- inside <!-- ... --> ------------------------------------- */
        case XML_S_COMMENT:
            if (c == '-')
                ctx->state = XML_S_COMMENT_D1;
            break;

        case XML_S_COMMENT_D1:
            if (c == '-')
                ctx->state = XML_S_COMMENT_D2;
            else
                ctx->state = XML_S_COMMENT;
            break;

        case XML_S_COMMENT_D2:
            if (c == '>')
                ctx->state = XML_S_CONTENT;
            else if (c != '-')
                ctx->state = XML_S_COMMENT;
            break;

        /* ---- inside <? ... ?> --------------------------------------- */
        case XML_S_PI:
            if (c == '?')
                ctx->state = XML_S_PI_Q;
            break;

        case XML_S_PI_Q:
            if (c == '>')
                ctx->state = XML_S_CONTENT;
            else
                ctx->state = XML_S_PI;
            break;

        /* ---- seen '<!' -------------------------------------------- */
        case XML_S_BANG:
            if (c == '-') {
                /* might be <!-- */
                char nc;
                if (!ring_peek(ctx, 0, &nc))
                    return XML_ERR_NEED_MORE;
                if (nc == '-') {
                    ring_consume(ctx, 1);
                    ctx->state = XML_S_COMMENT;
                } else {
                    ctx->state = XML_S_BANG_SKIP;
                }
                break;
            }
            /* <!DOCTYPE or similar */
            ctx->state = XML_S_BANG_SKIP;
            break;

        /* ---- skipping <!...> (DOCTYPE, CDATA, etc.) ------------------- */
        case XML_S_BANG_SKIP:
            if (c == '>')
                ctx->state = XML_S_CONTENT;
            break;

        } /* switch */
    } /* while */
}

/* -------------------------------------------------------------------------
 * Helpers
 * ---------------------------------------------------------------------- */
bool xml_get_attr(const xml_event_t *evt, const char *name,
                  char *dst, size_t dst_len)
{
    size_t name_len = strlen(name);
    uint8_t i;

    for (i = 0; i < evt->attr_count; i++) {
        if (strlen(evt->attrs[i].name) == name_len &&
            memcmp(evt->attrs[i].name, name, name_len) == 0) {
            size_t vlen = strlen(evt->attrs[i].value);
            return slice_copy(dst, dst_len, evt->attrs[i].value, vlen);
        }
    }
    return false;
}

xml_err_t xml_skip(xml_ctx_t *ctx)
{
    xml_event_t evt;
    int depth = 1;

    while (depth > 0) {
        xml_err_t err = xml_next(ctx, &evt);
        if (err != XML_OK)
            return err;
        if (evt.type == XML_EVT_ELEMENT_START && !evt.self_closing) {
            depth++;
        } else if (evt.type == XML_EVT_ELEMENT_END) {
            depth--;
        }
    }
    return XML_OK;
}

xml_err_t xml_get_inner_text(xml_ctx_t *ctx, char *dst, size_t dst_len)
{
    xml_event_t evt;
    xml_err_t err = xml_next(ctx, &evt);

    if (err != XML_OK)
        return err;
    if (evt.type == XML_EVT_ELEMENT_END)
        return XML_ERR_DONE;
    if (evt.type != XML_EVT_TEXT)
        return XML_ERR_INVALID;
    if (!slice_copy(dst, dst_len, evt.text, strlen(evt.text)))
        return XML_ERR_INVALID;

    err = xml_next(ctx, &evt);
    if (err != XML_OK)
        return err;
    if (evt.type != XML_EVT_ELEMENT_END)
        return XML_ERR_INVALID;
    return XML_OK;
}

size_t xml_list_attrs(const xml_event_t *evt, char *dst, size_t dst_len)
{
    size_t out = 0;
    uint8_t i;

    if (dst_len == 0)
        return (size_t)-1;

    for (i = 0; i < evt->attr_count; i++) {
        size_t name_len = strlen(evt->attrs[i].name);
        size_t value_len = strlen(evt->attrs[i].value);

        if (i > 0) {
            if (out + 2u > dst_len)
                return (size_t)-1;
            dst[out++] = ',';
        }
        if (out + name_len + 1u + value_len + 1u > dst_len)
            return (size_t)-1;
        memcpy(dst + out, evt->attrs[i].name, name_len);
        out += name_len;
        dst[out++] = '=';
        memcpy(dst + out, evt->attrs[i].value, value_len);
        out += value_len;
    }
    dst[out] = '\0';
    return out;
}

bool xml_slice_copy(char *dst, size_t dst_len, const xml_slice_t *s)
{
    if (s == NULL || s->str == NULL)
        return false;
    return slice_copy(dst, dst_len, s->str, s->len);
}
