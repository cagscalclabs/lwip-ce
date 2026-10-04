asn1.h — DER Cursor and TLV Parser
===================================

| **Header:** ``lwip/cryptography/asn1.h``
| **References:** `ITU-T X.690 <https://www.itu.int/rec/T-REC-X.690/en>`_ — DER/BER encoding rules

A forward-only cursor-based DER parser. All pointers in ``tls_asn1_tlv``
reference the original input buffer — no copies are made. Both the cursor
and TLV structs are caller-allocated.

Tag class constants: ``ASN1_UNIVERSAL``, ``ASN1_APPLICATION``,
``ASN1_CONTEXTSPEC``, ``ASN1_PRIVATE``. Common tag numbers:
``ASN1_INTEGER`` (2), ``ASN1_BITSTRING`` (3), ``ASN1_OCTETSTRING`` (4),
``ASN1_OBJECTID`` (6), ``ASN1_SEQUENCE`` (16), ``ASN1_UTCTIME`` (23),
``ASN1_GENERALIZEDTIME`` (24).

Cursor and TLV
--------------

.. c:function:: bool tls_asn1_cursor_init(struct tls_asn1_cursor *cursor, const uint8_t *data, size_t len)

   Initialize a cursor over a DER buffer.

   :param cursor: Caller-allocated cursor to initialize.
   :param data: Pointer to the first DER byte.
   :param len: Number of bytes available from ``data``.
   :returns: ``true`` on success, ``false`` on invalid arguments.

.. c:function:: bool tls_asn1_next(struct tls_asn1_cursor *cursor, struct tls_asn1_tlv *out)

   Parse the next TLV from the cursor and advance it. Returns ``false`` at
   end of data (normal completion) or on malformed input — callers that need
   to distinguish the two should track expected fields and treat a premature
   ``false`` as a parse failure.

   :param cursor: Active cursor.
   :param out: Receives the parsed TLV descriptor.
   :returns: ``true`` if a TLV was parsed; ``false`` at end of input or on
      malformed DER.

.. c:function:: bool tls_asn1_child_cursor(const struct tls_asn1_tlv *parent, struct tls_asn1_cursor *child)

   Create a cursor over the value bytes of a constructed TLV (SEQUENCE, SET,
   or context-constructed). Call only when ``tls_asn1_tag_constructed()`` is
   true for the parent tag.

   :param parent: A parsed TLV with the constructed form bit set.
   :param child: Receives a cursor spanning the parent's content bytes.
   :returns: ``true`` on success, ``false`` if the parent is not constructed
      or arguments are invalid.

Tag Helpers
-----------

.. c:function:: uint8_t tls_asn1_tag_number(uint8_t tag)

   Extract the low 5-bit tag number from a raw tag byte.

   :param tag: Raw ASN.1 tag byte.
   :returns: Tag number (0–30).

.. c:function:: uint8_t tls_asn1_tag_class(uint8_t tag)

   Extract the class bits from a raw tag byte.

   :param tag: Raw ASN.1 tag byte.
   :returns: One of ``ASN1_UNIVERSAL``, ``ASN1_APPLICATION``,
      ``ASN1_CONTEXTSPEC``, ``ASN1_PRIVATE``.

.. c:function:: bool tls_asn1_tag_constructed(uint8_t tag)

   Return whether the constructed form bit is set on a raw tag byte.

   :param tag: Raw ASN.1 tag byte.
   :returns: ``true`` if the tag indicates a constructed (nested) element.

Examples
--------

.. code-block:: c

   struct tls_asn1_cursor cursor;
   struct tls_asn1_tlv tlv;

   tls_asn1_cursor_init(&cursor, der_bytes, der_len);

   while (tls_asn1_next(&cursor, &tlv)) {
       /* tlv.tag, tlv.len, tlv.value */

       if (tls_asn1_tag_constructed(tlv.tag)) {
           struct tls_asn1_cursor child;
           tls_asn1_child_cursor(&tlv, &child);
           /* iterate child elements... */
       }
   }
