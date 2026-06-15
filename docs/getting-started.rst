Getting Started
===============

lwIP-CE ships as a curated release surface for calculator applications. The
release headers are not a dump of upstream lwIP. They are generated from what
this build can actually provide, then filtered through the public API manifest.

Start the Stack
---------------

Most applications should include ``lwip.h`` and use the app-facing
socket API:

.. code-block:: c

   #include <lwip.h>

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

Use ``lwip.h`` when the program wants a small socket-ish wrapper around TCP,
UDP, ALTCP, or TLS.

Use ``core/`` when the program needs raw lwIP control at PCB level. This is the
closer match for upstream lwIP examples.

Use ``cryptography/`` when the program wants the TLS project's crypto
primitives directly, without opening a network socket.

Release Layout
--------------

The public release layout is:

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Path
     - Purpose
   * - ``lwip.h``
     - App-facing socket wrapper and curated core surface.
   * - ``cryptography.h``
     - Umbrella include for crypto headers.
   * - ``lwip/core/``
     - Umbrella include for curated core headers.
   * - ``lwip/core/*.h``
     - Curated lwIP core headers for this implementation.
   * - ``lwip/cryptography/*.h``
     - Public cryptographic primitives.
   * - ``lwip.asm``
     - Release export/extern assembly surface for the dynamic library.

The calculator is not a desktop lwIP target. There is no BSD sockets layer, no
filesystem-backed resolver state, no preemptive multitasking, and no async
runtime. Keep application loops explicit and keep ownership of buffers obvious.
