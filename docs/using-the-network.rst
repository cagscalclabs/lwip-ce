Using the Network
=================

This page covers everything you need after ``lwip_start()`` to open
connections, serve requests, and diagnose network problems. If you only need
cryptography without networking, see :doc:`using-cryptography`.

Before starting, make sure the stack is initialized and the network interface
is up:

.. code-block:: c

   if (!lwip_start())   return 1;
   if (!lwip_network_up()) return 1;

See :doc:`getting-started` for the full setup sequence including the
required ``BSSHEAP_LOW`` makefile setting.

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
heap limit. Reserving up front, before sockets and their pbufs start competing
for the same heap, means you find out about a too-small heap immediately
instead of mid-handshake when an allocation silently fails. ``mem_resize()``
lets you grow or shrink a reservation later without an extra free/request pair.

You are not forced to use ``mem_request/resize/release``, but it is recommended
as it gives the stack better visibility into how much memory it actually has
left, which influences its memory-pressure behavior.

Use the Socket API
------------------

``lwip.h`` is an app-facing wrapper for programs that do not want to wire raw
TCP, UDP, ALTCP, and TLS callbacks by hand.

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
     - ALTCP wrapped in the CE TLS client path. Requires TLS enabled in the
       app configuration wizard. See :doc:`using-cryptography`.
   * - ``LWIP_SOCKET_ALTCP_WS``
     - WebSocket over plain TCP (RFC 6455).
   * - ``LWIP_SOCKET_ALTCP_WSS``
     - WebSocket over TLS. Also requires TLS enabled in wizard.

For ``LWIP_SOCKET_ALTCP_WS`` and ``LWIP_SOCKET_ALTCP_WSS`` sockets, call
``lwip_socket_set_ws_config(socket, path, subprotocol)`` after
``lwip_socket_create()`` and before ``lwip_socket_connect()``. ``path`` is the
WebSocket resource path (e.g. ``"/"``); ``subprotocol`` may be ``NULL``. The
strings are borrowed and must remain valid until ``lwip_socket_connect()``
returns.

``lwip_socket_connect()`` starts the connection attempt. It does not mean the
socket is ready. Watch ``socket.status`` or subscribe to
``LWIP_SOCKET_EVENTF_STATE_CHANGE`` with ``lwip_socket_on_event()``.

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

Minimal client example:

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

   static void on_event(struct lwip_socket *socket,
                        lwip_socket_event_type_t type,
                        const void *ev_data,
                        void *arg)
   {
       (void)ev_data;
       (void)arg;

       if (type == LWIP_SOCKET_EV_STATE_CHANGE &&
           lwip_socket_status(socket) == LWIP_STATUS_CONNECTED) {
           static const uint8_t request[] =
               "GET / HTTP/1.0\r\n"
               "Host: example.com\r\n"
               "\r\n";
           if (lwip_socket_write(socket, request, sizeof(request) - 1) != LWIP_OK) {
               done = true;
           }
       } else if (type == LWIP_SOCKET_EV_IO) {
           size_t space = sizeof(response) - response_len - 1;
           response_len += lwip_socket_read(socket,
                                            (uint8_t *)response + response_len,
                                            space);
           response[response_len] = '\0';
           if (response_complete()) {
               want_close = true;
           }
       } else if (type == LWIP_SOCKET_EV_ERROR ||
                  (type == LWIP_SOCKET_EV_STATE_CHANGE &&
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
                            on_event, NULL);

       if (lwip_socket_connect(&socket, "example.com", 80) != LWIP_OK) {
           lwip_socket_destroy(&socket);
           return 1;
       }

       while (!done) {
           lwip_service_events();

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

Server Sockets
--------------

``lwip_socket_listen()`` and ``lwip_socket_accept()`` extend the socket API to
cover TCP servers. A server socket never calls ``lwip_socket_connect()``; it
binds to a port and queues incoming connections for the application to dequeue
one at a time.

**Lifecycle:**

.. code-block:: text

   lwip_request_services(LWIP_SOCKET_SVC_DHCP | LWIP_SOCKET_SVC_DNS)
   lwip_socket_create()     — allocate the listen socket
   /* poll lwip_default_netif_info() until has_ipv4 */
   lwip_socket_listen()     — bind to port, enter listen state
   /* in the main loop: */
   lwip_socket_accept()     — dequeue one accepted peer (non-blocking)
   lwip_socket_read/write() — serve the peer
   lwip_socket_close()      — orderly close after response
   lwip_socket_destroy()    — release the peer handle
   /* repeat accept/serve; on exit: */
   lwip_socket_destroy()    — release the listen socket

``lwip_request_services()`` must be called before the main loop to start DHCP.
``lwip_socket_create()`` alone does not trigger DHCP — the async retry path
only runs for sockets that call ``lwip_socket_connect()``.

``lwip_socket_listen()`` is only valid on a ``LWIP_SOCKET_TCP`` socket in
``LWIP_STATUS_INIT`` state. After this call the socket becomes a passive
listener; do not call ``lwip_socket_connect()`` on it.

``lwip_socket_accept()`` is non-blocking. It returns ``LWIP_OK`` and fills the
caller-supplied ``peer`` handle when a connection is queued, or
``LWIP_ERR_STATE`` when the queue is empty. The returned peer is in
``LWIP_STATUS_CONNECTED`` state; the caller owns it and must call
``lwip_socket_destroy()`` when done.

.. code-block:: c

   #include <lwip.h>
   #include <stdbool.h>
   #include <stdint.h>
   #include <string.h>

   #define PORT       80
   #define BUF_MAX    512

   int main(void)
   {
       if (!lwip_start())
           return 1;
       if (!lwip_network_up())
           return 1;

       /* Start DHCP independently of the listen socket. */
       lwip_request_services(LWIP_SOCKET_SVC_DHCP | LWIP_SOCKET_SVC_DNS);

       struct lwip_socket server;
       if (lwip_socket_create(&server, LWIP_SOCKET_TCP,
                              LWIP_NETIF_EXT, NULL, 0) != LWIP_OK)
           return 1;

       /* Wait for a DHCP address before listening. */
       lwip_netif_info_t info = {0};
       do {
           lwip_service_events();
           lwip_default_netif_info(&info);
       } while (!info.has_ipv4);

       if (lwip_socket_listen(&server, PORT) != LWIP_OK) {
           lwip_socket_destroy(&server);
           return 1;
       }

       static char req[BUF_MAX];
       bool running = true;
       while (running) {
           lwip_service_events();

           struct lwip_socket peer;
           if (lwip_socket_accept(&server, &peer) == LWIP_OK) {
               /* Drain the request (simplified — real code should buffer
                * until \r\n\r\n is seen across multiple ticks). */
               size_t n = lwip_socket_available(&peer);
               if (n) {
                   n = lwip_socket_read(&peer, (uint8_t *)req,
                                        n < BUF_MAX - 1 ? n : BUF_MAX - 1);
                   req[n] = '\0';
               }

               static const uint8_t resp[] =
                   "HTTP/1.1 200 OK\r\n"
                   "Content-Type: text/plain\r\n"
                   "Content-Length: 5\r\n"
                   "Connection: close\r\n"
                   "\r\n"
                   "hello";
               lwip_socket_write(&peer, resp, sizeof(resp) - 1);
               lwip_socket_close(&peer);

               /* Drive the peer to CLOSED before destroying. */
               while (lwip_socket_is_active(&peer))
                   lwip_service_events();
               lwip_socket_destroy(&peer);
           }
       }

       lwip_socket_destroy(&server);
       return 0;
   }

.. note::

   For a production server, accumulate bytes from ``lwip_socket_read()`` across
   multiple ticks until the full HTTP header block (``\\r\\n\\r\\n``) is present
   before dispatching. See ``examples/httpd/`` for a complete multi-connection
   HTTP/1.1 server with keep-alive, idle timeouts, and concurrent peer handling.

Debugging: Traceback
--------------------

Connection failures inside lwIP can be hard to trace because the error
surfaces several callback layers above the actual failure site. As of
*1.0-rc4*, the stack records an ordered chain of errors you can retrieve
after a failure:

.. code-block:: c

    const struct lwip_traceback_entry *lwip_get_traceback(uint8_t *count);

Walk the result to find where the failure originated:

.. code-block:: c

    uint8_t count;
    const struct lwip_traceback_entry *entries = lwip_get_traceback(&count);
    /* entries[0] is the most recent error */

    for (uint8_t i = 0; i < count; i++) {
        const struct lwip_traceback_entry *e = &entries[i];
        printf("file_id: %u, line: %lu, errno=%u", e->file, e->line, e->raw_error);
    }

For real-time event logging across the stack, register a callback with
``lwip_set_event_cb()``. See :doc:`technical-details` for the event kinds
(``LWIP_EV_INFO``, ``LWIP_EV_WARN``, ``LWIP_EV_ERROR``, ``LWIP_EV_STATE_CHG``).
