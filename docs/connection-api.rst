Connection API Guide
====================

``conn.h`` is an app-facing wrapper for programs that do not want to wire raw
TCP, UDP, ALTCP, and TLS callbacks by hand.

Basic Lifecycle
---------------

The normal flow is:

.. code-block:: c

   struct lwip_conn conn;

   lwip_start();
   lwip_conn_create(&conn, NULL, LWIP_PROTO_TCP, LWIP_CONN_SVC_DNS);
   lwip_conn_set_recv(&conn, on_recv);
   lwip_conn_set_err(&conn, on_err);
   lwip_conn_connect(&conn, "example.com", 80);

   while (conn.status != LWIP_STATUS_CLOSED &&
          conn.status != LWIP_STATUS_ERROR) {
       lwip_poll_network_events();
       /* app work */
   }

   lwip_conn_destroy(&conn);

``lwip_conn_connect()`` starts the connection attempt. It does not mean the
connection is ready. Watch ``conn.status`` or use ``lwip_conn_set_connected()``.

Protocols
---------

``lwip_conn_create()`` accepts:

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

Services
--------

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

Receive Ownership
-----------------

Receive callbacks get a ``struct pbuf *``. The app owns that pbuf and must free
it when done. For TCP, the app must also call ``lwip_conn_recved()`` after it
has consumed or queued the bytes. Without that call, the TCP receive window
does not advance.

Shutdown
--------

Use ``lwip_conn_shutdown()`` for TCP-style half-close behavior. Use
``lwip_conn_close()`` for hard teardown. Use ``lwip_conn_destroy()`` when the
handle is no longer needed.

The full reference for the wrapper lives at :doc:`api/conn`.
