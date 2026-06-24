#include <ti/screen.h>
#include <ti/getkey.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <lwip/parsers/xml.h>
#include <lwip.h>

/* Real-world RSS-like XML payload */
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

static void show_result(bool ok)
{
    if (ok)
        printf("success");
    else
        printf("failed");
    os_GetKey();
    os_ClrHome();
}

/* 1: pull walk — PI skipped, comment skipped, structure correct */
static bool test_pull_walk(void)
{
    xml_parser_t p;
    xml_event_t evt;
    xml_init(&p, rss_payload, sizeof(rss_payload) - 1);

    /* PI skipped → <rss> */
    if (xml_next(&p, &evt) != XML_OK || evt.type != XML_EVT_ELEMENT_START) return false;
    if (evt.name.len != 3 || memcmp(evt.name.str, "rss", 3) != 0) return false;
    /* <channel> */
    if (xml_next(&p, &evt) != XML_OK || evt.type != XML_EVT_ELEMENT_START) return false;
    if (evt.name.len != 7 || memcmp(evt.name.str, "channel", 7) != 0) return false;
    /* comment skipped → <title> */
    if (xml_next(&p, &evt) != XML_OK || evt.type != XML_EVT_ELEMENT_START) return false;
    if (evt.name.len != 5 || memcmp(evt.name.str, "title", 5) != 0) return false;
    return true;
}

/* 2: xml_get_attr on <item id="1" category="release"> */
static bool test_get_attr(void)
{
    xml_parser_t p;
    xml_event_t evt;
    char buf[32];
    xml_init(&p, rss_payload, sizeof(rss_payload) - 1);

    /* walk to first <item> */
    int found = 0;
    while (!found) {
        if (xml_next(&p, &evt) != XML_OK) return false;
        if (evt.type == XML_EVT_ELEMENT_START
                && evt.name.len == 4 && memcmp(evt.name.str, "item", 4) == 0)
            found = 1;
    }
    if (!xml_get_attr(&evt, "id", buf, sizeof(buf))) return false;
    if (strcmp(buf, "1") != 0) return false;
    if (!xml_get_attr(&evt, "category", buf, sizeof(buf))) return false;
    return strcmp(buf, "release") == 0;
}

/* 3: xml_get_inner_text on <title>v1.0 released</title> */
static bool test_get_inner_text(void)
{
    xml_parser_t p;
    xml_event_t evt;
    char buf[64];
    xml_init(&p, rss_payload, sizeof(rss_payload) - 1);

    /* walk to first <item>, then to its <title> child */
    int in_item = 0;
    while (1) {
        if (xml_next(&p, &evt) != XML_OK) return false;
        if (evt.type == XML_EVT_ELEMENT_START
                && evt.name.len == 4 && memcmp(evt.name.str, "item", 4) == 0) {
            in_item = 1;
            continue;
        }
        if (in_item && evt.type == XML_EVT_ELEMENT_START
                && evt.name.len == 5 && memcmp(evt.name.str, "title", 5) == 0)
            break;
    }
    if (xml_get_inner_text(&p, buf, sizeof(buf)) != XML_OK) return false;
    return strcmp(buf, "v1.0 released") == 0;
}

/* 4: xml_list_attrs CSV on <item id="2" category="patch"> */
static bool test_list_attrs(void)
{
    xml_parser_t p;
    xml_event_t evt;
    char buf[64];
    xml_init(&p, rss_payload, sizeof(rss_payload) - 1);

    /* walk to second <item> */
    int count = 0;
    while (count < 2) {
        if (xml_next(&p, &evt) != XML_OK) return false;
        if (evt.type == XML_EVT_ELEMENT_START
                && evt.name.len == 4 && memcmp(evt.name.str, "item", 4) == 0)
            count++;
    }
    size_t n = xml_list_attrs(&evt, buf, sizeof(buf));
    if (n == (size_t)-1) return false;
    return strcmp(buf, "id=2,category=patch") == 0;
}

/* 5: xml_skip over first <item>, confirm second <item> reachable */
static bool test_skip_item(void)
{
    xml_parser_t p;
    xml_event_t evt;
    char buf[32];
    xml_init(&p, rss_payload, sizeof(rss_payload) - 1);

    /* walk to first <item> */
    while (1) {
        if (xml_next(&p, &evt) != XML_OK) return false;
        if (evt.type == XML_EVT_ELEMENT_START
                && evt.name.len == 4 && memcmp(evt.name.str, "item", 4) == 0)
            break;
    }
    if (xml_skip(&p) != XML_OK) return false;

    /* next element start should be second <item> */
    while (1) {
        if (xml_next(&p, &evt) != XML_OK) return false;
        if (evt.type == XML_EVT_ELEMENT_START) break;
    }
    if (evt.name.len != 4 || memcmp(evt.name.str, "item", 4) != 0) return false;
    if (!xml_get_attr(&evt, "id", buf, sizeof(buf))) return false;
    return strcmp(buf, "2") == 0;
}

/* 6: xml_decode_entity — all five predefined entities */
static bool test_entities(void)
{
    static const struct { const char *in; char expected; } cases[] = {
        {"&amp;",  '&'},
        {"&lt;",   '<'},
        {"&gt;",   '>'},
        {"&apos;", '\''},
        {"&quot;", '"'},
    };
    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        const char *src = cases[i].in;
        char out;
        size_t written;
        if (!xml_decode_entity(&src, cases[i].in + strlen(cases[i].in), &out, &written))
            return false;
        if (written != 1 || out != cases[i].expected)
            return false;
    }
    return true;
}

int main(void)
{
    if (!lwip_start()) return 1;
    os_ClrHome();

    show_result(test_pull_walk());
    show_result(test_get_attr());
    show_result(test_get_inner_text());
    show_result(test_list_attrs());
    show_result(test_skip_item());
    show_result(test_entities());

    return 0;
}
