#include <ti/screen.h>
#include <ti/getkey.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "../../../../src/parsers/xml.h"
#include <lwip.h>

#define RING_SIZE 512u

static char g_ring[RING_SIZE];

/* Feed the whole buffer at once and signal end of stream. */
static void feed_all(xml_ctx_t *ctx, const char *buf, size_t len)
{
    xml_init(ctx, g_ring, sizeof(g_ring), 0);
    xml_take(ctx, buf, len);
    xml_finish(ctx);
}

static void show_result(bool ok)
{
    if (ok)
        printf("success");
    else
        printf("FAILED");
    os_GetKey();
    os_ClrHome();
}

/* -------------------------------------------------------------------------
 * Test payloads
 * ---------------------------------------------------------------------- */
static const char rss_payload[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<rss version=\"2.0\">"
      "<channel>"
        "<!-- main feed -->"
        "<title>lwIP-CE News</title>"
        "<item id=\"1\" category=\"release\">"
          "<title>v1.0 released</title>"
          "<description>First &amp; stable release</description>"
        "</item>"
        "<item id=\"2\" category=\"patch\">"
          "<title>v1.1 patch</title>"
          "<description>Bug fixes</description>"
        "</item>"
      "</channel>"
    "</rss>";

static const char html_payload[] =
    "<!DOCTYPE html>"
    "<html>"
    "<head><title>Test Page</title></head>"
    "<body>"
    "<h1>Hello World</h1>"
    "<p>First paragraph.</p>"
    "<br>"
    "<img src=\"logo.png\" alt=\"Logo\">"
    "<a href=\"http://example.com\">link text</a>"
    "<input type=\"text\" disabled>"
    "</body>"
    "</html>";

/* Unquoted attributes and mixed case tags */
static const char html_unquoted[] =
    "<HTML><BODY>"
    "<DIV class=container id=main>"
    "<P>text</P>"
    "</DIV>"
    "</BODY></HTML>";

/* &nbsp; entity and nested inline tags */
static const char html_entities[] =
    "<html><body>"
    "<p>Hello&nbsp;World</p>"
    "<p><strong>bold</strong> and <em>italic</em></p>"
    "</body></html>";

/* -------------------------------------------------------------------------
 * 1: Pull walk — PI and comment skipped, structure correct
 * ---------------------------------------------------------------------- */
static bool test_pull_walk(void)
{
    xml_ctx_t ctx;
    xml_event_t evt;

    feed_all(&ctx, rss_payload, sizeof(rss_payload) - 1u);

    /* PI skipped -> <rss> */
    if (xml_next(&ctx, &evt) != XML_OK) return false;
    if (evt.type != XML_EVT_ELEMENT_START) return false;
    if (strcmp(evt.name, "rss") != 0) return false;

    /* <channel> */
    if (xml_next(&ctx, &evt) != XML_OK) return false;
    if (evt.type != XML_EVT_ELEMENT_START) return false;
    if (strcmp(evt.name, "channel") != 0) return false;

    /* comment skipped -> <title> */
    if (xml_next(&ctx, &evt) != XML_OK) return false;
    if (evt.type != XML_EVT_ELEMENT_START) return false;
    if (strcmp(evt.name, "title") != 0) return false;

    return true;
}

/* -------------------------------------------------------------------------
 * 2: xml_get_attr on <item id="1" category="release">
 * ---------------------------------------------------------------------- */
static bool test_get_attr(void)
{
    xml_ctx_t ctx;
    xml_event_t evt;
    char buf[32];

    feed_all(&ctx, rss_payload, sizeof(rss_payload) - 1u);

    /* walk to first <item> */
    while (true) {
        if (xml_next(&ctx, &evt) != XML_OK) return false;
        if (evt.type == XML_EVT_ELEMENT_START && strcmp(evt.name, "item") == 0)
            break;
    }
    if (!xml_get_attr(&evt, "id", buf, sizeof(buf))) return false;
    if (strcmp(buf, "1") != 0) return false;
    if (!xml_get_attr(&evt, "category", buf, sizeof(buf))) return false;
    return strcmp(buf, "release") == 0;
}

/* -------------------------------------------------------------------------
 * 3: Text content — read text from <title>v1.0 released</title>
 * ---------------------------------------------------------------------- */
static bool test_text_content(void)
{
    xml_ctx_t ctx;
    xml_event_t evt;

    feed_all(&ctx, rss_payload, sizeof(rss_payload) - 1u);

    /* walk to first <item>, then its <title> child */
    bool in_item = false;
    while (true) {
        if (xml_next(&ctx, &evt) != XML_OK) return false;
        if (evt.type == XML_EVT_ELEMENT_START && strcmp(evt.name, "item") == 0) {
            in_item = true;
            continue;
        }
        if (in_item && evt.type == XML_EVT_ELEMENT_START &&
            strcmp(evt.name, "title") == 0)
            break;
    }
    if (xml_next(&ctx, &evt) != XML_OK) return false;
    if (evt.type != XML_EVT_TEXT) return false;
    return strcmp(evt.text, "v1.0 released") == 0;
}

/* -------------------------------------------------------------------------
 * 4: Entity decoding — &amp; inside text content
 * ---------------------------------------------------------------------- */
static bool test_entity_in_text(void)
{
    xml_ctx_t ctx;
    xml_event_t evt;

    feed_all(&ctx, rss_payload, sizeof(rss_payload) - 1u);

    /* walk to <description>First &amp; stable release</description> */
    while (true) {
        if (xml_next(&ctx, &evt) != XML_OK) return false;
        if (evt.type == XML_EVT_ELEMENT_START &&
            strcmp(evt.name, "description") == 0)
            break;
    }
    if (xml_next(&ctx, &evt) != XML_OK) return false;
    if (evt.type != XML_EVT_TEXT) return false;
    return strcmp(evt.text, "First & stable release") == 0;
}

/* -------------------------------------------------------------------------
 * 5: xml_decode_entity — built-in XML/HTML entities
 * ---------------------------------------------------------------------- */
static bool test_decode_entity(void)
{
    static const struct { const char *in; char expected; } cases[] = {
        {"&amp;",  '&'},
        {"&lt;",   '<'},
        {"&gt;",   '>'},
        {"&apos;", '\''},
        {"&quot;", '"'},
        {"&nbsp;", ' '},
    };
    size_t i;
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        const char *src = cases[i].in;
        char out;
        size_t written;
        if (!xml_decode_entity(&src, cases[i].in + strlen(cases[i].in),
                               &out, &written))
            return false;
        if (written != 1 || out != cases[i].expected)
            return false;
    }
    return true;
}

/* -------------------------------------------------------------------------
 * 6: Streaming — feed payload in small chunks, expect same events
 * ---------------------------------------------------------------------- */
static bool test_streaming(void)
{
    xml_ctx_t ctx;
    xml_event_t evt;
    const char *p = rss_payload;
    size_t remaining = sizeof(rss_payload) - 1u;
    const size_t CHUNK = 7u;
    int rss_seen = 0;
    int channel_seen = 0;
    int title_seen = 0;

    xml_init(&ctx, g_ring, sizeof(g_ring), 0);

    while (rss_seen < 1 || channel_seen < 1 || title_seen < 1) {
        xml_err_t err = xml_next(&ctx, &evt);
        if (err == XML_ERR_NEED_MORE || err == XML_ERR_DONE) {
            if (!remaining) {
                /* Exhausted input but still waiting — fail */
                if (err == XML_ERR_NEED_MORE) return false;
                break;
            }
            size_t n = remaining < CHUNK ? remaining : CHUNK;
            xml_take(&ctx, p, n);
            p += n;
            remaining -= n;
            continue;
        }
        if (err != XML_OK) return false;
        if (evt.type == XML_EVT_ELEMENT_START) {
            if (strcmp(evt.name, "rss") == 0)     rss_seen++;
            if (strcmp(evt.name, "channel") == 0) channel_seen++;
            if (strcmp(evt.name, "title") == 0)   title_seen++;
        }
    }
    return rss_seen == 1 && channel_seen == 1 && title_seen >= 1;
}

/* -------------------------------------------------------------------------
 * 7: Lax/HTML mode — void elements, boolean attrs, case folding
 * ---------------------------------------------------------------------- */
static bool test_lax_html(void)
{
    xml_ctx_t ctx;
    xml_event_t evt;
    char buf[64];
    int br_end_seen = 0;
    int img_start_seen = 0;
    int img_end_seen = 0;
    int disabled_seen = 0;
    int h1_text_seen = 0;

    xml_init(&ctx, g_ring, sizeof(g_ring), XML_FLAG_LAX);
    xml_take(&ctx, html_payload, sizeof(html_payload) - 1u);
    xml_finish(&ctx);

    while (true) {
        xml_err_t err = xml_next(&ctx, &evt);
        if (err == XML_ERR_DONE) break;
        if (err != XML_OK) return false;

        if (evt.type == XML_EVT_ELEMENT_END && strcmp(evt.name, "br") == 0)
            br_end_seen++;

        if (evt.type == XML_EVT_ELEMENT_START && strcmp(evt.name, "img") == 0) {
            img_start_seen++;
            /* check alt attribute */
            if (!xml_get_attr(&evt, "alt", buf, sizeof(buf))) return false;
            if (strcmp(buf, "Logo") != 0) return false;
        }
        if (evt.type == XML_EVT_ELEMENT_END && strcmp(evt.name, "img") == 0)
            img_end_seen++;

        if (evt.type == XML_EVT_ELEMENT_START && strcmp(evt.name, "input") == 0) {
            /* boolean attribute "disabled" should be present with empty value */
            if (xml_get_attr(&evt, "disabled", buf, sizeof(buf)))
                disabled_seen++;
        }

        if (evt.type == XML_EVT_TEXT && strcmp(evt.text, "Hello World") == 0)
            h1_text_seen++;
    }

    /* <br> must auto-generate an ELEMENT_END */
    if (!br_end_seen) return false;
    /* <img> must auto-generate START + END */
    if (!img_start_seen || !img_end_seen) return false;
    /* boolean "disabled" attr must be found */
    if (!disabled_seen) return false;
    /* h1 text must be extracted */
    if (!h1_text_seen) return false;

    return true;
}

/* -------------------------------------------------------------------------
 * 8: Second <item> attributes reachable
 * ---------------------------------------------------------------------- */
static bool test_second_item_attr(void)
{
    xml_ctx_t ctx;
    xml_event_t evt;
    char buf[32];
    int count = 0;

    feed_all(&ctx, rss_payload, sizeof(rss_payload) - 1u);

    while (count < 2) {
        if (xml_next(&ctx, &evt) != XML_OK) return false;
        if (evt.type == XML_EVT_ELEMENT_START && strcmp(evt.name, "item") == 0)
            count++;
    }
    if (!xml_get_attr(&evt, "id", buf, sizeof(buf))) return false;
    if (strcmp(buf, "2") != 0) return false;
    if (!xml_get_attr(&evt, "category", buf, sizeof(buf))) return false;
    return strcmp(buf, "patch") == 0;
}

/* -------------------------------------------------------------------------
 * 9: HTML — case folding: tag names lowercased in lax mode
 * ---------------------------------------------------------------------- */
static bool test_html_case_fold(void)
{
    xml_ctx_t ctx;
    xml_event_t evt;
    int div_seen = 0;
    int body_seen = 0;

    xml_init(&ctx, g_ring, sizeof(g_ring), XML_FLAG_LAX);
    xml_take(&ctx, html_unquoted, sizeof(html_unquoted) - 1u);
    xml_finish(&ctx);

    while (true) {
        xml_err_t err = xml_next(&ctx, &evt);
        if (err == XML_ERR_DONE) break;
        if (err != XML_OK) return false;
        if (evt.type == XML_EVT_ELEMENT_START) {
            /* All names must be lowercase */
            for (size_t i = 0; evt.name[i]; i++) {
                if (evt.name[i] >= 'A' && evt.name[i] <= 'Z')
                    return false;
            }
            if (strcmp(evt.name, "div") == 0) div_seen++;
            if (strcmp(evt.name, "body") == 0) body_seen++;
        }
    }
    return div_seen == 1 && body_seen == 1;
}

/* -------------------------------------------------------------------------
 * 10: HTML — unquoted attribute values
 * ---------------------------------------------------------------------- */
static bool test_html_unquoted_attrs(void)
{
    xml_ctx_t ctx;
    xml_event_t evt;
    char buf[32];

    xml_init(&ctx, g_ring, sizeof(g_ring), XML_FLAG_LAX);
    xml_take(&ctx, html_unquoted, sizeof(html_unquoted) - 1u);
    xml_finish(&ctx);

    while (true) {
        xml_err_t err = xml_next(&ctx, &evt);
        if (err == XML_ERR_DONE) return false; /* didn't find div */
        if (err != XML_OK) return false;
        if (evt.type == XML_EVT_ELEMENT_START && strcmp(evt.name, "div") == 0) {
            if (!xml_get_attr(&evt, "class", buf, sizeof(buf))) return false;
            if (strcmp(buf, "container") != 0) return false;
            if (!xml_get_attr(&evt, "id", buf, sizeof(buf))) return false;
            return strcmp(buf, "main") == 0;
        }
    }
}

/* -------------------------------------------------------------------------
 * 11: HTML — &nbsp; decoded as space in text
 * ---------------------------------------------------------------------- */
static bool test_html_nbsp(void)
{
    xml_ctx_t ctx;
    xml_event_t evt;

    xml_init(&ctx, g_ring, sizeof(g_ring), XML_FLAG_LAX);
    xml_take(&ctx, html_entities, sizeof(html_entities) - 1u);
    xml_finish(&ctx);

    while (true) {
        xml_err_t err = xml_next(&ctx, &evt);
        if (err == XML_ERR_DONE) break;
        if (err != XML_OK) return false;
        if (evt.type == XML_EVT_TEXT && strstr(evt.text, "Hello") != NULL) {
            /* &nbsp; should have become a space */
            return strcmp(evt.text, "Hello World") == 0;
        }
    }
    return false;
}

/* -------------------------------------------------------------------------
 * 12: HTML — nested inline tags produce correct START/END sequence
 * ---------------------------------------------------------------------- */
static bool test_html_nested_inline(void)
{
    xml_ctx_t ctx;
    xml_event_t evt;
    int strong_start = 0, strong_end = 0;
    int em_start = 0, em_end = 0;
    bool bold_text = false;
    bool italic_text = false;

    xml_init(&ctx, g_ring, sizeof(g_ring), XML_FLAG_LAX);
    xml_take(&ctx, html_entities, sizeof(html_entities) - 1u);
    xml_finish(&ctx);

    while (true) {
        xml_err_t err = xml_next(&ctx, &evt);
        if (err == XML_ERR_DONE) break;
        if (err != XML_OK) return false;
        if (evt.type == XML_EVT_ELEMENT_START) {
            if (strcmp(evt.name, "strong") == 0) strong_start++;
            if (strcmp(evt.name, "em") == 0)     em_start++;
        } else if (evt.type == XML_EVT_ELEMENT_END) {
            if (strcmp(evt.name, "strong") == 0) strong_end++;
            if (strcmp(evt.name, "em") == 0)     em_end++;
        } else if (evt.type == XML_EVT_TEXT) {
            if (strcmp(evt.text, "bold") == 0)   bold_text = true;
            if (strcmp(evt.text, "italic") == 0) italic_text = true;
        }
    }
    return strong_start == 1 && strong_end == 1 &&
           em_start == 1 && em_end == 1 &&
           bold_text && italic_text;
}

/* -------------------------------------------------------------------------
 * 13: HTML — href attribute on <a> link
 * ---------------------------------------------------------------------- */
static bool test_html_link_href(void)
{
    xml_ctx_t ctx;
    xml_event_t evt;
    char buf[64];

    xml_init(&ctx, g_ring, sizeof(g_ring), XML_FLAG_LAX);
    xml_take(&ctx, html_payload, sizeof(html_payload) - 1u);
    xml_finish(&ctx);

    while (true) {
        xml_err_t err = xml_next(&ctx, &evt);
        if (err == XML_ERR_DONE) return false;
        if (err != XML_OK) return false;
        if (evt.type == XML_EVT_ELEMENT_START && strcmp(evt.name, "a") == 0) {
            if (!xml_get_attr(&evt, "href", buf, sizeof(buf))) return false;
            return strcmp(buf, "http://example.com") == 0;
        }
    }
}

/* -------------------------------------------------------------------------
 * 14: HTML — chunked streaming with lax mode
 * ---------------------------------------------------------------------- */
static bool test_html_streaming(void)
{
    xml_ctx_t ctx;
    xml_event_t evt;
    const char *p = html_payload;
    size_t remaining = sizeof(html_payload) - 1u;
    const size_t CHUNK = 13u;
    /* Accumulate h1 text across possible fragment events */
    char h1_accum[64];
    size_t h1_accum_len = 0;
    bool in_h1 = false;
    bool h1_text_ok = false;
    int a_seen = 0;

    memset(h1_accum, 0, sizeof(h1_accum));
    xml_init(&ctx, g_ring, sizeof(g_ring), XML_FLAG_LAX);

    while (true) {
        xml_err_t err = xml_next(&ctx, &evt);
        if (err == XML_ERR_DONE) break;
        if (err == XML_ERR_NEED_MORE) {
            if (!remaining) return false; /* stuck with no input */
            size_t n = remaining < CHUNK ? remaining : CHUNK;
            xml_take(&ctx, p, n);
            p += n;
            remaining -= n;
            if (!remaining)
                xml_finish(&ctx);
            continue;
        }
        if (err != XML_OK) return false;
        if (evt.type == XML_EVT_ELEMENT_START) {
            if (strcmp(evt.name, "h1") == 0) {
                in_h1 = true; h1_accum_len = 0; h1_accum[0] = '\0';
            }
            if (strcmp(evt.name, "a") == 0) a_seen++;
        }
        if (evt.type == XML_EVT_ELEMENT_END && strcmp(evt.name, "h1") == 0) {
            in_h1 = false;
            if (strcmp(h1_accum, "Hello World") == 0) h1_text_ok = true;
        }
        if (in_h1 && evt.type == XML_EVT_TEXT) {
            size_t flen = strlen(evt.text);
            if (h1_accum_len + flen < sizeof(h1_accum) - 1u) {
                memcpy(h1_accum + h1_accum_len, evt.text, flen);
                h1_accum_len += flen;
                h1_accum[h1_accum_len] = '\0';
            }
        }
    }
    return h1_text_ok && a_seen == 1;
}

/* -------------------------------------------------------------------------
 * main
 * ---------------------------------------------------------------------- */
int main(void)
{
    if (!lwip_start()) return 1;
    os_ClrHome();

    show_result(test_pull_walk());
    show_result(test_get_attr());
    show_result(test_text_content());
    show_result(test_entity_in_text());
    show_result(test_decode_entity());
    show_result(test_streaming());
    show_result(test_lax_html());
    show_result(test_second_item_attr());
    show_result(test_html_case_fold());
    show_result(test_html_unquoted_attrs());
    show_result(test_html_nbsp());
    show_result(test_html_nested_inline());
    show_result(test_html_link_href());
    show_result(test_html_streaming());

    return 0;
}
