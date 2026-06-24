Getting Started
===============

lwIP-CE ships as a clean release surface for calculator applications. The
release headers are not a dump of upstream lwIP; they are filtered down to what
actually ships in this port, sorted into core and crypto.

Install lwIP-CE
---------------

lwIP-CE comes packaged with a number of files and directories:

.. code-block:: text

   release/
   ├── lwip.h                    # app-facing socket API umbrella header
   ├── cryptography.h            # crypto/TLS primitives umbrella header
   ├── lwip.asm                  # libload export/extern surface
   ├── lwip.lib                  # libload symbols for lwIP
   ├── lwip.8xv                  # lwIP LibLoad stub
   ├── lwip/
   │   ├── core/                 # lower-level lwIP core, netif, socket, PCB headers
   │   │   ├── altcp.h
   │   │   ├── altcp_tls.h
   │   │   ├── dns.h
   │   │   ├── ip4.h
   │   │   ├── netif.h
   │   │   ├── pbuf.h
   │   │   └── ...
   │   ├── cryptography/         # lower-level crypto/TLS helper headers
   │   │   ├── aes.h
   │   │   ├── hash.h
   │   │   ├── hkdf.h
   │   │   ├── rsa.h
   │   │   ├── truststore.h
   │   │   ├── x509.h
   │   │   └── ...
   │   └── parsers/              # zero-copy response parsers
   │       ├── json.h
   │       ├── xml.h
   │       └── url.h
   └── appinst/
       ├── lwIPINST.8xp          # installer program (run once on-calc)
       └── LWIP.0.8xv ... LWIP.N.8xv  # split dynamic-library AppVars

Copy ``lwip.h``, ``cryptography.h``, and the ``lwip/`` header tree into ``$CEDEV/include``, and ``lwip.lib`` into ``$CEDEV/lib/libload``. ``appinst/`` contains the actual lwIP-CE core, split into multiple appvars and the installer program. Send the entire contents of that directory and ``lwip.8xv`` to your TI-84+ CE and then run ``lwIPINST.8xp (prgmINSTALL)``. This will install lwIP as a TI Flash Application.

.. note::

    The app installer cannot overwrite an Application that already exists. When updating this library you will need to delete the Application and then possibly ``GarbageCollect`` on your device before trying to install a new version.

You will also need a USB CDC Ethernet adapter (CDC-ECM or CDC-NCM class). Some Ethernet-to-WiFi adapters work as well, provided they speak CDC Ethernet on the USB side and support Wi-Fi Protected Setup (WPS) (because implementing WPA is not really feasible with how crazy Wi-Fi drivers can be). This means your connection will be:

.. code-block:: text

    Calculator => USB Ethernet adapter => router
    Calculator => USB Ethernet adapter => Ethernet to Wi-Fi adapter


Start the Stack
---------------

.. danger::

    **STOP**. Before you do anything else!! If you are building a
    project for use with lwIP, **immediately** go into your makefile
    and add the following line:

    .. code-block:: text

        BSSHEAP_LOW >= 0xD072C6

    If you do not do this, lwIP and your program will unwittingly overlap
    their heap allocations and cause each other to fail in ways that
    we cannot predict.

Most applications should include ``lwip.h`` and use the app-facing
socket API:

.. code-block:: c

   #include <lwip.h>

   int main(void)
   {
       if (lwip_start() != 0) {
           return 1;
       }

       // if you want networking
       if (!lwip_network_up()) {
           return 1;
       }

       while (1) {
           lwip_poll_network_events();
           /* app work */
       }
   }

``lwip_start()`` (or ``lwip_start_with_crt(malloc, free, realloc)`` if you need to provide explicit CRT allocator hooks) **must be the first lwIP call** in your program. In most applications, use ``lwip_start()``; use ``lwip_start_with_crt(...)`` only when your runtime requires passing custom ``malloc``/``free``/``realloc`` function pointers. It returns
``true`` on success and ``false`` on failure, with ``lwip_get_start_errstring()`` returning a string-ified error message indicating what failed. Nothing else will work if this step is skipped or called out of order. In the event you forget ``lwip_start()``, rather than crashing, the exports will simply resolve to no-ops that clear all registers and ``lwip_get_start_errstring()`` will return: "function unsupported, version". The same thing happens if there is a version mismatch between the libload stub and the resident library. If the libload stub expects more functions than exist, the remaining functions remain resolved to the same no-op. If the libload stub expects less functions than the resident has, only the count the stub can absorb are patched. In this way, things remain stable even if the stub and resident app version desync.

``lwip_start()`` initializes the lwIP environment - bss/data segments, imports and exports, async API (``sys_timeouts``) and the memory system (``membuffer``). You are at liberty to use the stack's internals without bringing up networking, but if you want networking, you would next call ``lwip_network_up``. This brings up the USB Ethernet driver and calls ``lwip_init`` (the internal stack-up op).

``lwip_poll_network_events()`` must run from the main loop. There is no OS
thread sitting behind the stack doing this for you.

Reserve Memory Before Opening Sockets
--------------------------------------

The calculator's heap is shared between your app, lwIP's internal pools, and
anything else running. Before creating sockets, decide what your app needs to
hold for its own buffers and reserve it explicitly with ``mem_request()``,
``mem_resize()``, and ``mem_release()`` from ``lwip/core/mem.h``:

.. code-block:: c

   uint8_t *http_buf = mem_request(4096);
   if (!http_buf) {
       return 1; /* not enough heap left to proceed */
   }

   /* ... use http_buf for the lifetime of the app ... */

   mem_release(http_buf);

These calls route through the same accounting lwIP uses for its own pools, so
a reservation here is reflected in ``mem_get_stats()`` and counts against the
heap limit passed to ``mem_init``. Reserving up front, before sockets and
their pbufs start competing for the same heap, means you find out about a
too-small heap immediately instead of mid-handshake when a pbuf or TLS
scratch allocation silently fails. ``mem_resize()`` lets you grow or shrink a
reservation later without an extra free/request pair.

You are not forced to use ``mem_request/resize/release``, but it is recommended as it gives the stack better visibility into how much memory it actually has left (not what it thinks it has) which influences its memory-pressure behavior.

Use the Socket API
------------------

``lwip.h`` is an app-facing wrapper for programs that do not want to wire raw
TCP, UDP, ALTCP, and TLS callbacks by hand.

``lwip_socket_connect()`` starts the socket attempt. It does not mean the
socket is ready. Watch ``socket.status`` or subscribe to
``LWIP_SOCKET_EVENTF_STATE_CHANGE`` with ``lwip_socket_on_event()``.

``lwip_socket_create()`` accepts a transport selector, a netif selector, an
optional static IPv4 configuration, and a timeout:

.. code-block:: c

   lwip_socket_create(&socket, LWIP_SOCKET_TCP, LWIP_NETIF_EXT, NULL, 30000);

``NULL`` address info means DHCP mode. ``LWIP_NETIF_EXT`` rejects loopback and
waits for USB Ethernet, link-up, DHCP address, and gateway. A non-NULL
``lwip_socket_addrinfo_t`` applies static ``ip/netmask/gateway`` instead of
starting DHCP.

Transport selectors:

.. list-table::
   :header-rows: 1
   :widths: 32 68

   * - Protocol
     - Meaning
   * - ``LWIP_SOCKET_TCP``
     - Raw TCP via lwIP ``tcp_*``.
   * - ``LWIP_SOCKET_UDP``
     - UDP via lwIP ``udp_*``.
   * - ``LWIP_SOCKET_ALTCP``
     - ALTCP using the default TCP allocator.
   * - ``LWIP_SOCKET_ALTCP_TLS``
     - ALTCP wrapped in the CE TLS client path.

The service flags are netif-level startup requests for code that needs a
service without creating a socket:

.. list-table::
   :header-rows: 1
   :widths: 32 68

   * - Flag
     - Meaning
   * - ``LWIP_SOCKET_SVC_DHCP``
     - Start DHCP on the resident interface.
   * - ``LWIP_SOCKET_SVC_SNTP``
     - Start SNTP for time sync.
   * - ``LWIP_SOCKET_SVC_DNS``
     - Make DNS name resolution available for ``lwip_socket_connect()``.

These flags do not create private services per socket. ``lwip_socket_create()``
handles DHCP/DNS automatically in DHCP mode; apps can use
``lwip_request_services()`` for optional services such as SNTP.

Received app bytes are copied into the socket RX ring and acknowledged to lwIP
immediately. The app drains them with ``lwip_socket_read()``. There is no pbuf
ownership or ``recved`` call in the socket API.

Use ``lwip_socket_shutdown()`` for TCP-style half-close behavior. Use
``lwip_socket_close()`` for orderly full close. Use ``lwip_socket_abort()`` when
the socket has to be torn down immediately and lwIP should stop delivering
traffic for that PCB. Use ``lwip_socket_destroy()`` when the handle is no longer
needed.

This is a stubbed full socket shape. The callbacks are intentionally small;
real applications should move parsing, state transitions, and retry decisions
into their own code.

.. code-block:: c

   #include <lwip.h>
   #include <stdbool.h>
   #include <stdint.h>
   #include <string.h>

   static bool done;
   static bool want_close;
   static char response[128];
   static size_t response_len;

   static bool response_complete(void)
   {
       /* Replace with application-specific response framing. */
       return false;
   }

   static void on_event(void *arg, struct lwip_socket *socket,
                        lwip_socket_event_type_t type,
                        const void *data)
   {
       (void)arg;
       (void)data;

       if (type == LWIP_SOCKET_EVENT_STATE_CHANGE &&
           lwip_socket_status(socket) == LWIP_STATUS_CONNECTED) {
           static const uint8_t request[] =
               "GET / HTTP/1.0\r\n"
               "Host: example.com\r\n"
               "\r\n";
           if (lwip_socket_write(socket, request, sizeof(request) - 1) != LWIP_OK) {
               done = true;
           }
       } else if (type == LWIP_SOCKET_EVENT_IO) {
           size_t space = sizeof(response) - response_len - 1;
           response_len += lwip_socket_read(socket,
                                            (uint8_t *)response + response_len,
                                            space);
           response[response_len] = '\0';
           if (response_complete()) {
               want_close = true;
           }
       } else if (type == LWIP_SOCKET_EVENT_ERROR ||
                  (type == LWIP_SOCKET_EVENT_STATE_CHANGE &&
                   lwip_socket_status(socket) == LWIP_STATUS_CLOSED)) {
           done = true;
       }
   }

   int main(void)
   {
       struct lwip_socket socket;

       if (!lwip_start()) {
           return 1;
       }
       if (!lwip_network_up()) {
           return 1;
       }

       if (lwip_socket_create(&socket, LWIP_SOCKET_TCP, LWIP_NETIF_EXT,
                              NULL, 30000) != LWIP_OK) {
           return 1;
       }

       lwip_socket_on_event(&socket,
                            LWIP_SOCKET_EVENTF_STATE_CHANGE |
                            LWIP_SOCKET_EVENTF_IO,
                            on_event);

       if (lwip_socket_connect(&socket, "example.com", 80) != LWIP_OK) {
           lwip_socket_destroy(&socket);
           return 1;
       }

       while (!done) {
           lwip_poll_network_events();

           if (want_close && socket.status == LWIP_STATUS_CONNECTED) {
               lwip_socket_shutdown(&socket);
               want_close = false;
           }

           if (socket.status == LWIP_STATUS_CLOSED ||
               socket.status == LWIP_STATUS_ERROR) {
               done = true;
           }

           /* UI, keys, timers, and app work go here. */
       }

       int rc = socket.status == LWIP_STATUS_ERROR ? 1 : 0;
       if (socket.status != LWIP_STATUS_CLOSED) {
           lwip_socket_close(&socket);
       }
       lwip_socket_destroy(&socket);
       return rc;
   }

Choose an API Layer
-------------------

Use ``lwip.h`` when the program wants the app-facing stack and socket API. It
is a root-level umbrella header in the release and includes the curated
``lwip/core/*.h`` surface.

Use ``lwip/core/*.h`` when the program needs lower-level lwIP control at PCB or
netif level. This is the closer match for upstream lwIP examples.

Use ``cryptography.h`` when the program wants the TLS project's crypto
primitives directly, without opening a network socket. It is a root-level
umbrella header over ``lwip/cryptography/*.h``. Programs still need to call ``lwip_start()`` even if they just want to use cryptography.

Use ``parsers.h`` when the program needs to parse JSON, XML, or URL-encoded
response bodies. It is a root-level umbrella over ``lwip/parsers/*.h``. The
parsers operate on any contiguous buffer and do not require the network stack
to be running.

Parse Responses
---------------

``parsers.h`` is an umbrella over ``lwip/parsers/*.h`` — zero-copy,
cursor-based parsers for JSON, XML, and URL encoding. No heap allocation is
needed; all parsers work on a caller-supplied buffer and return slices
(pointer + length) directly into that buffer.

**JSON** follows the same cursor model as the ASN.1 parser. ``json_next()``
advances a cursor and returns one token. Objects and arrays are returned as a
single token whose ``value`` span covers the interior content; the parent
cursor has already advanced past the closing brace or bracket. Descend with
``json_enter()``; skip by simply not calling it.

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

To walk an array and descend only into elements you care about:

.. code-block:: c

   json_parser_t root, arr, item;
   json_token_t tok;

   json_init(&root, buf, len);
   json_next(&root, &tok);           /* JSON_TOK_ARRAY */
   json_enter(&arr, &tok);

   while (json_next(&arr, &tok) == JSON_OK) {
       if (tok.type != JSON_TOK_OBJECT) continue;
       json_enter(&item, &tok);      /* descend into this element */
       /* ... search item with json_get_string / json_get_key_value ... */
       /* previous elements are already past in &arr — no skip needed */
   }

**XML** is SAX-style. ``xml_next()`` returns one event at a time
(``XML_EVT_ELEMENT_START``, ``XML_EVT_ELEMENT_END``, ``XML_EVT_TEXT``).
Comments and processing instructions are skipped automatically. Call
``xml_skip()`` after an ``ELEMENT_START`` event to consume that element and
all its children without descending.

.. code-block:: c

   xml_parser_t p;
   xml_event_t evt;
   char title[64], id_buf[8];

   xml_init(&p, buf, len);
   while (xml_next(&p, &evt) == XML_OK) {
       if (evt.type != XML_EVT_ELEMENT_START) continue;
       if (evt.name.len == 4 && memcmp(evt.name.str, "item", 4) == 0) {
           xml_get_attr(&evt, "id", id_buf, sizeof(id_buf));
           /* descend to find <title> child */
       } else if (evt.type == XML_EVT_ELEMENT_START
                  && evt.name.len == 5 && memcmp(evt.name.str, "title", 5) == 0) {
           xml_get_inner_text(&p, title, sizeof(title));
       }
   }

**URL encoding** provides percent-encoding per RFC 3986 and a
``url_build_query()`` helper for constructing ``application/x-www-form-urlencoded``
bodies:

.. code-block:: c

   char query[256];
   const char *keys[]   = {"grant_type", "client_id"};
   const char *values[] = {"client_credentials", "myapp"};
   url_build_query(query, sizeof(query), keys, values, 2);
   /* query == "grant_type=client_credentials&client_id=myapp" */

Release Layout
--------------

The public release layout is:

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Path
     - Purpose
   * - ``lwip.h``
     - Root-level umbrella for the app-facing socket API and curated
       ``lwip/core/*.h`` headers.
   * - ``cryptography.h``
     - Root-level umbrella for ``lwip/cryptography/*.h``.
   * - ``parsers.h``
     - Root-level umbrella for ``lwip/parsers/*.h``.
   * - ``lwip/core/*.h``
     - Lower-level curated lwIP core, netif, socket, service, and PCB headers.
   * - ``lwip/cryptography/*.h``
     - Lower-level public cryptographic primitive and TLS helper headers.
   * - ``lwip/parsers/*.h``
     - JSON, XML, and URL-encoding parsers.
   * - ``lwip.asm``
     - Release export/extern assembly surface for the dynamic library.

The calculator is not a desktop lwIP target. There is no BSD sockets layer, no
filesystem-backed resolver state, no preemptive multitasking, and no async
runtime. Keep application loops explicit and keep ownership of buffers obvious.


Having Trouble
---------------

Having a weird issue you can't fix? Random timeouts, connection failures, socket errors? Because lwIP is callback buried inside of callbacks, with no way to surface what actually failed you usually only are aware of *socket_failed* or *write_error* or whatever the upper-level failure is, but not actually where it happened. You could spend days trying to guess and test what is actually broken. As of *1.0-rc4*, that is no longer an issue. lwIP provides a **traceback system** for debugging assistance.

.. code ::

    const struct lwip_traceback_entry *lwip_get_traceback(uint8_t *count);

This allows you to get a pointer to an ordered buffer containing the entire error/alert chain when you need it. You can then walk the response like so:

.. code ::

    uint8_t count;
    const struct lwip_traceback_entry *entries = lwip_get_traceback(&count);
    // ^ entries points to the most recent error

    for (uint8_t i = 0; i < count; i++) {
        const struct lwip_traceback_entry *e = &entries[i];
        printf("file_id: %u, line: %lu, errno=%u", e->file, e->line, e->raw_error);
    }
