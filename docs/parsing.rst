Parsing Responses
=================

``parsers.h`` is an umbrella over ``lwip/parsers/*.h``. The parsers work on
any contiguous buffer; you do not need the network stack running to use them.
They avoid heap allocation and use caller-supplied buffers throughout.

Include ``parsers.h`` (or the individual parser headers from
``lwip/parsers/``) — you still need to call ``lwip_start()`` even if you only
want the parsers, because the library must load its exports.

.. note::

   For programs that only use the crypto or parser APIs without networking, call
   ``lwip_start()`` but skip ``lwip_network_up()``.

JSON
----

The JSON parser is cursor-based over a complete in-memory response body.
``json_next()`` advances a cursor and returns one token at a time. Objects and
arrays come back as a single token whose ``value`` span covers the interior
content; the cursor has already moved past the closing delimiter. Descend into
an object or array with ``json_enter()``; to skip a container, just do not call
it — the parent cursor is already past it.

**Parse a flat object:**

.. code-block:: c

   #include <parsers.h>

   static const char body[] =
       "{\"token_type\":\"Bearer\",\"expires_in\":3600}";

   json_parser_t root, obj;
   json_token_t tok;
   char type_buf[32];
   long expires;

   json_init(&root, body, sizeof(body) - 1);
   if (json_next(&root, &tok) == JSON_OK && tok.type == JSON_TOK_OBJECT) {
       json_enter(&obj, &tok);
       json_get_string(&obj, "token_type", type_buf, sizeof(type_buf));
       json_get_number(&obj, "expires_in", &expires);
   }

**Walk an array and descend into each element:**

.. code-block:: c

   json_parser_t root, arr, item;
   json_token_t tok;

   json_init(&root, buf, len);
   json_next(&root, &tok);           /* JSON_TOK_ARRAY */
   json_enter(&arr, &tok);

   while (json_next(&arr, &tok) == JSON_OK) {
       if (tok.type != JSON_TOK_OBJECT) continue;
       json_enter(&item, &tok);      /* descend into this element */
       /* search item with json_get_string / json_get_key_value */
       /* previous elements are already past in &arr — no skip needed */
   }

XML
---

The XML parser is streaming and SAX-style. Feed bytes with ``xml_take()``,
call ``xml_finish()`` after the final byte, then pull events with
``xml_next()``. Comments and processing instructions are skipped
automatically. Event names, text, and attributes are copied into
``xml_event_t`` so you do not need to hold on to the original input buffer
after feeding.

``XML_FLAG_LAX`` enables HTML-tolerant mode: lowercase tag names, unquoted
attributes, boolean attributes, and auto-closed void elements.

.. code-block:: c

   #include <parsers.h>

   xml_ctx_t x;
   xml_event_t evt;
   char ring[512];
   char title[64], id_buf[8];

   xml_init(&x, ring, sizeof(ring), 0);
   xml_take(&x, buf, len);
   xml_finish(&x);

   while (xml_next(&x, &evt) == XML_OK) {
       if (evt.type != XML_EVT_ELEMENT_START) continue;
       if (strcmp(evt.name, "item") == 0) {
           xml_get_attr(&evt, "id", id_buf, sizeof(id_buf));
       } else if (strcmp(evt.name, "title") == 0) {
           xml_get_inner_text(&x, title, sizeof(title));
       }
   }

The ring buffer size determines how much unprocessed input the parser can
hold at once. Size it to fit the largest single element you expect to see.

URL Encoding
------------

``url_build_query()`` constructs an ``application/x-www-form-urlencoded``
body from parallel key and value arrays. Percent-encoding follows RFC 3986.

.. code-block:: c

   #include <parsers.h>

   char query[256];
   const char *keys[]   = {"grant_type", "client_id"};
   const char *values[] = {"client_credentials", "myapp"};
   url_build_query(query, sizeof(query), keys, values, 2);
   /* query == "grant_type=client_credentials&client_id=myapp" */

Individual percent-encode and percent-decode helpers are in
``lwip/parsers/url.h`` for use with raw URI components.
