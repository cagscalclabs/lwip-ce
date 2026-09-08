parsers.h and lwip/parsers/
===========================

``parsers.h`` is the root-level umbrella for the lower-level
``lwip/parsers/*.h`` headers. These headers provide small no-heap helpers for
common response formats. JSON uses a cursor over a complete buffer, XML uses a
caller-owned ring buffer and emits owned event strings, and URL helpers encode
or decode into caller-owned output buffers.

The JSON parser follows the same cursor model as the ASN.1 parser in
``lwip/cryptography/asn1.h``. For JSON objects and arrays the token carries the
full interior content span and the parent cursor has already advanced past the
closing brace or bracket. Descend into a nested value with ``json_enter()``; to
skip a nested value, do not enter it.

The XML parser is event-based and streaming. ``xml_take()`` feeds bytes,
``xml_finish()`` marks end-of-input, and ``xml_next()`` returns
``XML_EVT_ELEMENT_START``, ``XML_EVT_ELEMENT_END``, or ``XML_EVT_TEXT``.

.. list-table::
   :header-rows: 1
   :widths: 28 72

   * - Header
     - Purpose
   * - :doc:`json.h <parsers/json>`
     - Pull/cursor-based JSON parser with targeted key lookup and iterator helpers.
   * - :doc:`xml.h <parsers/xml>`
     - Streaming SAX-style XML/HTML parser with attribute lookup, skip,
       inner-text, and entity helpers.
   * - :doc:`url.h <parsers/url>`
     - RFC 3986 percent-encoding and query-string builder.

.. toctree::
   :hidden:

   parsers/json
   parsers/xml
   parsers/url
