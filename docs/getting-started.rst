Getting Started
===============

lwIP-CE ships as a curated release surface for calculator applications. The
release headers are not a dump of upstream lwIP. They are generated from what
this build can actually provide, then filtered through the public API manifest.

Start the Stack
---------------

Most applications should include ``lwip/conn.h`` and use the app-facing
connection API:

.. code-block:: c

   #include <lwip/conn.h>

   int main(void)
   {
       if (!lwip_start()) {
           return 1;
       }

       while (1) {
           lwip_poll_network_events();
           /* app work */
       }
   }

``lwip_start()`` initializes the resident network stack and USB Ethernet path.
``lwip_poll_network_events()`` must run from the main loop. There is no OS
thread sitting behind the stack doing this for you.

Use the Conn API
----------------

``conn.h`` is an app-facing wrapper for programs that do not want to wire raw
TCP, UDP, ALTCP, and TLS callbacks by hand.

``lwip_conn_connect()`` starts the connection attempt. It does not mean the
connection is ready. Watch ``conn.status`` or use ``lwip_conn_set_connected()``.

``lwip_conn_create()`` accepts these transport selectors:

.. list-table::
   :header-rows: 1
   :widths: 32 68

   * - Protocol
     - Meaning
   * - ``LWIP_PROTO_TCP``
     - Raw TCP via lwIP ``tcp_*``.
   * - ``LWIP_PROTO_UDP``
     - UDP via lwIP ``udp_*``.
   * - ``LWIP_PROTO_ALTCP``
     - ALTCP using the default TCP allocator.
   * - ``LWIP_PROTO_ALTCP_TLS``
     - ALTCP wrapped in the CE TLS client path.

The service flags are netif-level startup requests:

.. list-table::
   :header-rows: 1
   :widths: 32 68

   * - Flag
     - Meaning
   * - ``LWIP_CONN_SVC_DHCP``
     - Start DHCP on the resident interface.
   * - ``LWIP_CONN_SVC_SNTP``
     - Start SNTP for time sync.
   * - ``LWIP_CONN_SVC_DNS``
     - Make DNS name resolution available for ``lwip_conn_connect()``.

These flags do not create private services per connection. They make sure the
resident interface has the requested service running.

Once a service is already up on an interface, later connections do not need to
request it again. Passing ``0`` for ``flags`` is safe when you are reusing the
same interface and you do not need ``lwip_conn_create()`` to start anything new.
For example, one setup connection can request DHCP and DNS, and later
connections on that same interface can pass ``0`` without disabling those
services. The flags are startup requests, not per-connection ownership or
teardown controls.

Receive callbacks get a ``struct pbuf *``. The app owns that pbuf and must free
it when done. For TCP, the app must also call ``lwip_conn_recved()`` after it
has consumed or queued the bytes. Without that call, the TCP receive window
does not advance.

Use ``lwip_conn_shutdown()`` for TCP-style half-close behavior. Use
``lwip_conn_close()`` for orderly full close. Use ``lwip_conn_abort()`` when
the connection has to be torn down immediately and lwIP should stop delivering
traffic for that PCB. Use ``lwip_conn_destroy()`` when the handle is no longer
needed.

This is a stubbed full connection shape. The callbacks are intentionally small;
real applications should move parsing, state transitions, and retry decisions
into their own code.

.. code-block:: c

   #include <lwip/conn.h>
   #include <lwip/core/pbuf.h>
   #include <stdbool.h>
   #include <stdint.h>

   static bool done;
   static bool want_close;

   static bool response_complete(void)
   {
       /* Replace with application-specific response framing. */
       return false;
   }

   static void on_connected(void *arg, struct lwip_conn *conn)
   {
       (void)arg;

       static const uint8_t request[] =
           "GET / HTTP/1.0\r\n"
           "Host: example.com\r\n"
           "\r\n";

       if (lwip_conn_write(conn, request, sizeof(request) - 1) != LWIP_OK) {
           done = true;
       }
   }

   static void on_recv(void *arg, struct lwip_conn *conn, struct pbuf *p)
   {
       (void)arg;

       if (!p) {
           done = true;
           return;
       }

       uint16_t consumed = p->tot_len;

       for (struct pbuf *q = p; q != NULL; q = q->next) {
           const uint8_t *bytes = (const uint8_t *)q->payload;
           uint16_t len = q->len;

           /* Parse, copy, or display bytes here. */
           (void)bytes;
           (void)len;
       }

       lwip_conn_recved(conn, consumed);
       pbuf_free(p);

       if (response_complete()) {
           want_close = true;
       }
   }

   static void on_error(void *arg, struct lwip_conn *conn, lwip_error_t err)
   {
       (void)arg;
       (void)conn;
       (void)err;
       done = true;
   }

   static void on_closed(void *arg, struct lwip_conn *conn)
   {
       (void)arg;
       (void)conn;
       done = true;
   }

   int main(void)
   {
       struct lwip_conn conn;

       if (!lwip_start()) {
           return 1;
       }

       if (lwip_conn_create(&conn, NULL, LWIP_PROTO_TCP,
                            LWIP_CONN_SVC_DHCP | LWIP_CONN_SVC_DNS) != LWIP_OK) {
           return 1;
       }

       lwip_conn_set_connected(&conn, on_connected);
       lwip_conn_set_recv(&conn, on_recv);
       lwip_conn_set_err(&conn, on_error);
       lwip_conn_set_closed(&conn, on_closed);

       if (lwip_conn_connect(&conn, "example.com", 80) != LWIP_OK) {
           lwip_conn_destroy(&conn);
           return 1;
       }

       while (!done) {
           lwip_poll_network_events();

           if (want_close && conn.status == LWIP_STATUS_CONNECTED) {
               lwip_conn_shutdown(&conn);
               want_close = false;
           }

           if (conn.status == LWIP_STATUS_CLOSED ||
               conn.status == LWIP_STATUS_ERROR) {
               done = true;
           }

           /* UI, keys, timers, and app work go here. */
       }

       int rc = conn.status == LWIP_STATUS_ERROR ? 1 : 0;
       if (conn.status != LWIP_STATUS_CLOSED) {
           lwip_conn_close(&conn);
       }
       lwip_conn_destroy(&conn);
       return rc;
   }

Choose an API Layer
-------------------

Use ``conn.h`` when the program wants a small socket-ish wrapper around TCP,
UDP, ALTCP, or TLS.

Use ``core/`` when the program needs raw lwIP control at PCB level. This is the
closer match for upstream lwIP examples.

Use ``cryptography/`` when the program wants the TLS project's crypto
primitives directly, without opening a network connection.

Release Layout
--------------

The public release layout is:

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Path
     - Purpose
   * - ``lwip/conn.h``
     - App-facing connection wrapper.
   * - ``lwip/core.h``
     - Umbrella include for curated core headers.
   * - ``lwip/core/*.h``
     - Curated lwIP core headers for this implementation.
   * - ``lwip/cryptography.h``
     - Umbrella include for crypto headers.
   * - ``lwip/cryptography/*.h``
     - Public cryptographic primitives.
   * - ``lwip.asm``
     - Release export/extern assembly surface for the dynamic library.

The calculator is not a desktop lwIP target. There is no BSD sockets layer, no
filesystem-backed resolver state, no preemptive multitasking, and no async
runtime. Keep application loops explicit and keep ownership of buffers obvious.
