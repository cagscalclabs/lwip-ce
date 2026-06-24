parsers.h and lwip/parsers/
===========================

``parsers.h`` is the root-level umbrella for the lower-level
``lwip/parsers/*.h`` headers. These headers provide zero-copy, cursor-based
parsers for common response formats. No heap allocation is required; all
parsers operate on a caller-supplied contiguous buffer and return slices
(pointer + length) directly into that buffer.

The JSON and XML parsers follow the same cursor model as the ASN.1 parser
in ``lwip/cryptography/asn1.h``: ``json_next()`` / ``xml_next()`` advance
the current cursor and return one token or event. For JSON objects and arrays
the token carries the full interior content span and the parent cursor has
already advanced past the closing brace or bracket. Descend into a nested
value by calling ``json_enter()``, which scopes a child cursor to that span.
To skip a nested value simply do not call ``json_enter()``; no explicit skip
primitive is needed.

.. list-table::
   :header-rows: 1
   :widths: 28 72

   * - Header
     - Purpose
   * - :doc:`json.h <parsers/json>`
     - Pull/cursor-based JSON parser with targeted key lookup and iterator helpers.
   * - :doc:`xml.h <parsers/xml>`
     - SAX-style XML parser with attribute lookup, inner-text extraction, and
       entity decoding.
   * - :doc:`url.h <parsers/url>`
     - RFC 3986 percent-encoding and query-string builder.

.. toctree::
   :hidden:

   parsers/json
   parsers/xml
   parsers/url
