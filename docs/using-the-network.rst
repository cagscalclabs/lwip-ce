Using the Network
=================

This page covers everything you need after ``lwip_start()`` to open
connections, serve requests, and diagnose network problems.

Before starting, make sure the stack is initialized and the network interface
is up:

.. code-block:: c

   if (!lwip_start())   return 1;
   if (!lwip_network_up()) return 1;

See :doc:`getting-started` for the full setup sequence including the
required ``BSSHEAP_LOW`` makefile setting.

Socket-Style v. PCB-Level API
------------------------------

``lwip.h`` provides a socket-style API so that users familiar with sockets but not PCB-level programming can use a familiar API in their programs. If you want fine-grained control, use the PCB-level API for:

- `TCP connections and streams <https://www.nongnu.org/lwip/2_1_x/group__tcp__raw.html>`_
- `UDP datagrams <https://www.nongnu.org/lwip/2_1_x/group__udp__raw.html>`_
- `ALTCP abstraction layer <https://www.nongnu.org/lwip/2_1_x/group__altcp.html>`_ — wraps TCP, TLS, WebSocket
- `Raw IP protocol PCBs <https://www.nongnu.org/lwip/2_1_x/group__raw__api.html>`_
- `Packet buffer (pbuf) management <https://www.nongnu.org/lwip/2_1_x/group__pbuf.html>`_
- `Network interface (netif) control <https://www.nongnu.org/lwip/2_1_x/group__netif.html>`_

The full lwIP raw/callback API is documented by the `lwIP project <https://www.nongnu.org/lwip/2_1_x/group__callbackstyle__api.html>`_.
If you don't need fine-grained control, the socket-style API described below covers most use cases.

Creating a Socket
------------------

First, create a socket.

.. c:function:: lwip_error_t lwip_socket_create(struct lwip_socket *socket, lwip_socket_type_t type, lwip_socket_bind_descriptor_t bind, const lwip_socket_addrinfo_t *addrinfo, uint32_t timeout_ms)

   Allocate and initialize a socket handle. Non-blocking — returns immediately
   after binding the netif preference and kicking DHCP or applying static IP.
   Readiness is awaited asynchronously when ``lwip_socket_connect()`` is called.

   :param socket: Caller-allocated handle. Zeroed by this call. Must remain
      valid until ``lwip_socket_destroy()``.
   :param type: Transport selector (``lwip_socket_type_t``). See table below.
   :param bind: Netif preference (``lwip_socket_bind_descriptor_t``).
      ``LWIP_NETIF_EXT`` waits for USB Ethernet, link-up, DHCP address, and
      gateway. ``LWIP_NETIF_ANY`` accepts loopback or external.
      ``LWIP_NETIF_LOOP`` restricts to loopback only.
   :param addrinfo: ``NULL`` for DHCP. Non-``NULL`` pointer to a
      ``lwip_socket_addrinfo_t`` applies static ``ip``/``netmask``/``gateway``
      instead of starting DHCP.
   :param timeout_ms: Inactivity watchdog window for the connect/handshake
      phase in milliseconds. ``0`` uses the stack default. If no progress is
      made within this window the socket transitions to ``LWIP_STATUS_ERROR``.
   :returns: ``LWIP_OK`` on success, ``LWIP_ERR_MEM`` if allocation failed,
      ``LWIP_ERR_ARG`` if ``socket`` is ``NULL``.

Sockets own an internal, heap-allocated RX ring buffer that you can read from with ``lwip_socket_read()`` (more on that later). That buffer starts at 512 bytes and maxes out at 4 KiB. Should you need a larger (or smaller) max size, you can use the *extended attributes* socket creation function below.

.. c:function:: lwip_error_t lwip_socket_create_ex(struct lwip_socket *socket, lwip_socket_type_t type, lwip_socket_bind_descriptor_t bind, const lwip_socket_addrinfo_t *addrinfo, uint32_t timeout_ms, size_t rx_ring_max)

   Identical to ``lwip_socket_create()`` but lets you override the RX ring
   maximum. Use this when the default 4 KiB ceiling is too small (a high-bandwidth
   stream) or unnecessarily large (a tight-RAM scenario where you know the
   largest message that will arrive).

   The ring starts at ``LWIP_SOCKET_RX_RING_INIT_SIZE`` (512 B) and grows in
   ``LWIP_SOCKET_RX_RING_STEP_SIZE`` (512 B) increments up to ``rx_ring_max``.
   Passing ``0`` for ``rx_ring_max`` uses ``LWIP_SOCKET_RX_RING_MAX_SIZE``
   (4096 B), the same ceiling as ``lwip_socket_create()``.

   :param socket: Caller-allocated handle. Zeroed by this call.
   :param type: Transport selector (``lwip_socket_type_t``).
   :param bind: Netif preference (``lwip_socket_bind_descriptor_t``).
   :param addrinfo: ``NULL`` for DHCP; non-``NULL`` for static IP.
   :param timeout_ms: Connect/handshake inactivity watchdog in milliseconds.
      ``0`` uses the stack default.
   :param rx_ring_max: Hard ceiling for the RX ring in bytes. ``0`` uses
      ``LWIP_SOCKET_RX_RING_MAX_SIZE`` (4096 B).
   :returns: ``LWIP_OK`` on success, ``LWIP_ERR_MEM`` if allocation failed,
      ``LWIP_ERR_ARG`` if ``socket`` is ``NULL``.

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
       app configuration wizard.
   * - ``LWIP_SOCKET_ALTCP_WS``
     - WebSocket over plain TCP (RFC 6455).
   * - ``LWIP_SOCKET_ALTCP_WSS``
     - WebSocket over TLS. Also requires TLS enabled in wizard.
  
An example use case is given below:

.. code-block:: c

    struct lwip_socket s;
    lwip_socket_create(&s, LWIP_SOCKET_TCP, LWIP_NETIF_EXT, NULL, 30000);
    /*  Creates new socket on s using:
        - protocol TCP
        - external interfaces only
        - use DHCP for IP address
        - 30 second socket timeout */

Using Websockets
------------------

When using ``LWIP_SOCKET_ALTCP_WS`` or ``LWIP_SOCKET_ALTCP_WSS``, you will need to call one additional function to attach special configuration to the socket. The full function specification is below.

.. c:function:: lwip_error_t lwip_socket_set_ws_config(struct lwip_socket *socket, const char *path, const char *subprotocol)

   Set the WebSocket resource path and optional subprotocol for a
   ``LWIP_SOCKET_ALTCP_WS`` or ``LWIP_SOCKET_ALTCP_WSS`` socket. Must be called
   after ``lwip_socket_create()`` and before ``lwip_socket_connect()``. Has no
   effect on non-WebSocket socket types.

   :param socket: A WS or WSS socket handle.
   :param path: WebSocket resource path, e.g. ``"/"``. Borrowed — must remain
      valid until ``lwip_socket_connect()`` returns.
   :param subprotocol: Optional ``Sec-WebSocket-Protocol`` value, or ``NULL``.
      Borrowed under the same lifetime constraint as ``path``.
   :returns: ``LWIP_OK`` on success, ``LWIP_ERR_ARG`` if ``socket`` or ``path``
      is ``NULL``.

Socket Reconfiguration
-----------------------

Some socket attributes are modifiable in flight should the situation call for it.

.. c:function:: lwip_error_t lwip_socket_set_connect_timeout(struct lwip_socket *socket, uint32_t timeout_ms)

   Update the inactivity watchdog window after the socket has been created.
   The timer is reset to this new value immediately. Useful when you need a
   longer budget for a slow DNS lookup or TLS handshake than you knew at
   create time.

   :param socket: An initialised socket handle.
   :param timeout_ms: New watchdog window in milliseconds. ``0`` disarms the
      watchdog entirely (use with care — a stalled connect will never
      time out).
   :returns: ``LWIP_OK`` on success, ``LWIP_ERR_ARG`` if ``socket`` is ``NULL``.

.. c:function:: lwip_error_t lwip_socket_set_rx_limits(struct lwip_socket *socket, size_t initial_size, size_t max_size)

   Resize the RX ring buffer limits on an existing socket. Takes effect on
   the next internal growth step — it does not shrink a ring that has already
   expanded past the new maximum.

   Prefer ``lwip_socket_create_ex()`` when you know the right ceiling up front.
   Use this function when the ceiling needs to change after creation — for
   example, after reading a ``Content-Length`` header that tells you the
   response will be larger than expected.

   :param socket: An initialised socket handle.
   :param initial_size: New initial allocation in bytes. ``0`` keeps the
      current value.
   :param max_size: New hard ceiling in bytes. ``0`` keeps the current value.
   :returns: ``LWIP_OK`` on success, ``LWIP_ERR_ARG`` if ``socket`` is ``NULL``.

Requesting Services
--------------------

Before connecting, you may need to request network services such as DHCP, DNS,
or SNTP. ``lwip_socket_create()`` in DHCP mode starts DHCP and DNS
automatically, but you can also request them explicitly — and SNTP always
requires an explicit request.

.. c:function:: lwip_error_t lwip_request_services(uint8_t flags, uint32_t timeout_ms)

   Request one or more netif-level services on the default interface.
   Convenience wrapper around ``lwip_netif_request_services()`` with
   ``netif = NULL``. Blocks until services are up or the timeout expires.
   Services are shared — this does not create a private service per socket.

   :param flags: Bitwise OR of one or more service flags:

      - ``LWIP_SOCKET_SVC_DHCP`` — start DHCP on the default interface.
      - ``LWIP_SOCKET_SVC_DNS`` — make DNS resolution available for
        ``lwip_socket_connect()``.
      - ``LWIP_SOCKET_SVC_SNTP`` — start SNTP for time synchronisation.

   :param timeout_ms: How long to wait for the services to come up, in
      milliseconds. ``0`` queues the request and returns immediately
      (fire-and-forget; use ``lwip_are_services_ready()`` to poll).
   :returns: ``LWIP_OK`` once all requested services are up,
      ``LWIP_ERR_ARG`` if ``flags`` is empty, ``LWIP_ERR_STATE`` if the
      stack is not running, or a timeout error if services did not come up
      within ``timeout_ms``.

.. c:function:: lwip_error_t lwip_netif_request_services(struct netif *netif, uint8_t flags, uint32_t timeout_ms, lwip_netif_service_cb cb, void *cb_data)

   Request services on a specific interface, with an optional per-service
   callback. The callback fires once per service as it transitions to UP,
   FAILED, or TIMEOUT — never batched. If ``cb`` is ``NULL`` the call
   returns immediately after kicking the services (equivalent to
   ``timeout_ms = 0``).

   :param netif: Target interface, or ``NULL`` for the default interface.
   :param flags: Bitwise OR of ``LWIP_SOCKET_SVC_*`` flags (same as above).
   :param timeout_ms: Deadline in milliseconds; 0 means fire-and-forget.
   :param cb: Callback invoked per-service transition, or ``NULL``.
      Signature: ``void cb(struct netif *netif, const lwip_netif_service_event_t *ev, void *arg)``.
      ``ev->service_id`` is the single service that fired,
      ``ev->status`` is ``UP`` / ``FAILED`` / ``TIMEOUT``,
      ``ev->ready_bitmap`` is the bitmask of all services currently up.
   :param cb_data: Passed through as ``arg`` to the callback.
   :returns: ``LWIP_OK`` on success, ``LWIP_ERR_ARG`` if flags is empty,
      ``LWIP_ERR_STATE`` if the stack is not running,
      ``LWIP_ERR_MEM`` if the service-request table is full.

.. c:function:: bool lwip_are_services_ready(struct netif *netif, uint8_t flags)

   Synchronous poll — returns ``true`` if every service bit in ``flags`` is
   currently up on ``netif`` (``NULL`` = default interface). No side effects,
   no timer involvement. Use as the main-loop readiness gate after a
   fire-and-forget call to ``lwip_netif_request_services()``.

   :param netif: Interface to query, or ``NULL`` for the default interface.
   :param flags: Bitwise OR of ``LWIP_SOCKET_SVC_*`` flags to check.
   :returns: ``true`` iff all requested services are currently up.

.. code-block:: c

   /* Simple blocking form — request SNTP on the default interface.
    * DHCP and DNS start automatically when the socket is created in DHCP mode. */
   lwip_request_services(LWIP_SOCKET_SVC_SNTP, 10000);

   /* Per-service callback form — fires once per service as it comes up,
    * fails, or times out. Useful when you want to react to each transition
    * rather than block until all services are ready. */
   static void on_service(struct netif *netif,
                          const lwip_netif_service_event_t *ev,
                          void *arg)
   {
       if (ev->status == LWIP_NETIF_SERVICE_UP) {
           /* ev->service_id tells you which service just came up */
           if (ev->service_id == LWIP_SOCKET_SVC_SNTP)
               /* time is now synchronised */;
       }
   }

   lwip_netif_request_services(NULL,
                               LWIP_SOCKET_SVC_DHCP | LWIP_SOCKET_SVC_SNTP,
                               10000, on_service, NULL);

If you need DNS but DHCP did not configure a resolver, set one manually with
`dns_setserver() <https://www.nongnu.org/lwip/2_1_x/group__dns.html>`_ before
calling ``lwip_request_services()`` or ``lwip_socket_connect()``.

Socket as Client
-----------------

As a client you are connecting a socket to another remote endpoint.

.. c:function:: lwip_error_t lwip_socket_connect(struct lwip_socket *socket, const char *host, uint16_t port)

   Initiate a connection to a remote host. Non-blocking — returns as soon as
   the attempt is queued. The socket transitions through
   ``LWIP_STATUS_RESOLVING`` and ``LWIP_STATUS_CONNECTING`` before reaching
   ``LWIP_STATUS_CONNECTED`` (or ``LWIP_STATUS_ERROR`` on failure). Poll
   ``socket->status`` from the main loop or subscribe to
   ``LWIP_SOCKET_EVENTF_STATE_CHANGE`` via ``lwip_socket_on_event()`` to know
   when the socket is ready.

   :param socket: A socket handle previously initialised with
      ``lwip_socket_create()``.
   :param host: Hostname or dotted-decimal IPv4 address. DNS resolution is
      performed automatically if required.
   :param port: Remote port number (host byte order).
   :returns: ``LWIP_OK`` if the attempt was queued, ``LWIP_ERR_STATE`` if the
      socket is not in ``LWIP_STATUS_INIT`` state, ``LWIP_ERR_ARG`` if
      ``socket`` or ``host`` is ``NULL``.

Socket as Server
-----------------

As a server, you listen on one socket and accept incoming connections as
individual peer sockets, each of which you read from and write to independently.

.. c:function:: lwip_error_t lwip_socket_listen(struct lwip_socket *socket, uint16_t port)

   Bind a TCP socket to a local port and begin listening for connections. Only
   valid on a ``LWIP_SOCKET_TCP`` socket in ``LWIP_STATUS_INIT`` state. After
   this call the socket is a passive listener — do not call
   ``lwip_socket_connect()`` on it. Incoming peers are dequeued with
   ``lwip_socket_accept()``.

   :param socket: A TCP socket handle previously initialised with
      ``lwip_socket_create()``.
   :param port: Local port number to bind (host byte order).
   :returns: ``LWIP_OK`` on success, ``LWIP_ERR_STATE`` if the socket is not
      in ``LWIP_STATUS_INIT`` state, ``LWIP_ERR_PROTO`` if the socket is not
      TCP, ``LWIP_ERR_MEM`` on allocation failure.

.. c:function:: lwip_error_t lwip_socket_accept(struct lwip_socket *socket, struct lwip_socket *peer)

   Dequeue one accepted peer from a listening socket. Non-blocking — returns
   ``LWIP_ERR_STATE`` immediately if no peer is ready yet. On success,
   ``*peer`` is a fully-initialised socket in ``LWIP_STATUS_CONNECTED`` state.
   The caller owns the peer handle and must call ``lwip_socket_destroy()`` when
   done with it.

   :param socket: A listening socket (``lwip_socket_listen()`` must have been
      called on it).
   :param peer: Caller-allocated socket handle to receive the accepted
      connection.
   :returns: ``LWIP_OK`` on success, ``LWIP_ERR_STATE`` if the accept queue is
      empty, ``LWIP_ERR_ARG`` on bad arguments.

See the full multi-connection server skeleton in `TCP Server (multi-connection)`_ below.

Sending/Receiving Data Over a Socket
-------------------------------------

Received bytes are copied into the socket's RX ring and acknowledged to lwIP
immediately. There is no pbuf ownership or ``recved`` call in the socket API.

.. c:function:: size_t lwip_socket_available(const struct lwip_socket *socket)

   Return the number of bytes currently waiting in the socket's RX ring.
   Use this to check before calling ``lwip_socket_read()`` to avoid a
   zero-length read.

   :param socket: A connected socket handle.
   :returns: Number of bytes available to read; ``0`` if the ring is empty.

.. c:function:: size_t lwip_socket_read(struct lwip_socket *socket, uint8_t *buf, size_t len)

   Read up to ``len`` bytes from the socket's RX ring into ``buf``. Never
   blocks — returns immediately with however many bytes are available, clamped
   to ``len``. Returns ``0`` if the ring is empty.

   :param socket: A connected socket handle.
   :param buf: Caller-supplied buffer to receive the data.
   :param len: Maximum number of bytes to read.
   :returns: Number of bytes actually read (``0``–``len``).

.. c:function:: lwip_error_t lwip_socket_write(struct lwip_socket *socket, const uint8_t *buf, size_t len)

   Send ``len`` bytes from ``buf`` over the socket. The socket must be in
   ``LWIP_STATUS_CONNECTED`` state.

   :param socket: A connected socket handle.
   :param buf: Data to send.
   :param len: Number of bytes to send. Must be greater than ``0``.
   :returns: ``LWIP_OK`` on success, ``LWIP_ERR_CLOSED`` if the connection is
      closing or already closed, ``LWIP_ERR_STATE`` if the socket is not yet
      connected, ``LWIP_ERR_ARG`` if any argument is ``NULL`` or ``len`` is
      ``0``.

Closing/Destroying a Socket
-----------------------------

There are three ways to close a connection, plus a separate step to free the
handle. Choose based on whether you want a clean TCP handshake, a half-close,
or an immediate abort.

.. c:function:: lwip_error_t lwip_socket_close(struct lwip_socket *socket)

   Initiate an orderly TCP close. Sends a FIN to the remote, then waits (up to
   an internal timeout) for the remote to ACK and send its own FIN. The socket
   transitions to ``LWIP_STATUS_CLOSING`` and then to ``LWIP_STATUS_CLOSED``
   once the exchange completes. On timeout, the PCB is hard-aborted internally
   and ``LWIP_ERR_CLOSED`` is returned, but the handle is still safe to
   destroy.

   For UDP sockets, ``lwip_socket_close()`` simply removes the PCB and sets
   the status to ``LWIP_STATUS_CLOSED`` immediately.

   :param socket: A connected (or connecting) socket handle.
   :returns: ``LWIP_OK`` on clean close, ``LWIP_ERR_CLOSED`` if the ACK wait
      timed out, ``LWIP_ERR_MEM`` if the FIN could not be enqueued (retry),
      ``LWIP_ERR_ARG`` if ``socket`` is ``NULL``.

.. c:function:: lwip_error_t lwip_socket_shutdown(struct lwip_socket *socket)

   Send a FIN without waiting for the remote to close its side — TCP half-close.
   The local side stops sending but can still receive until the remote also
   closes. The socket transitions to ``LWIP_STATUS_CLOSING``. Use this when
   you have finished sending but want to drain any remaining inbound data before
   destroying the socket.

   :param socket: A connected TCP socket handle.
   :returns: ``LWIP_OK`` if the FIN was queued, ``LWIP_ERR_STATE`` if the
      socket has no live PCB, ``LWIP_ERR_ARG`` if ``socket`` is ``NULL``.
      Not applicable to UDP sockets.

.. c:function:: lwip_error_t lwip_socket_abort(struct lwip_socket *socket)

   Immediately tear down the connection by sending a TCP RST. No FIN handshake
   — the PCB is removed and all callbacks are detached synchronously. Use this
   when the connection must be torn down without waiting (e.g. error recovery,
   application exit).

   :param socket: Any socket handle.
   :returns: ``LWIP_OK`` on success, ``LWIP_ERR_ARG`` if ``socket`` is
      ``NULL``.

When the **remote** closes the connection you will see the status change
without calling any close function yourself:

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Status
     - Meaning
   * - ``LWIP_STATUS_CLOSED``
     - Remote sent FIN — clean close. Any unread bytes in the RX ring are
       still available before you destroy the socket.
   * - ``LWIP_STATUS_RESET``
     - Remote sent RST — connection immediately gone. No graceful exchange.
   * - ``LWIP_STATUS_ERROR``
     - Stack error: timeout, out-of-memory, or a local ``lwip_socket_abort()``.

In all three cases ``lwip_socket_is_active()`` returns ``false``. Poll
``socket->status`` or subscribe to ``LWIP_SOCKET_EVENTF_STATE_CHANGE`` to
detect these transitions.

.. c:function:: lwip_error_t lwip_socket_destroy(struct lwip_socket *socket)

   Free all resources held by the socket handle. This is **not** a graceful
   close — call ``lwip_socket_close()`` or ``lwip_socket_abort()`` first if
   the connection is still live, otherwise the PCB will be hard-aborted
   internally. For a listener socket, any connections waiting in the accept
   queue are also aborted and freed.

   Always call ``lwip_socket_destroy()`` exactly once per handle, even after
   ``lwip_socket_abort()``.

   :param socket: Any socket handle (connected, closed, or aborted).
   :returns: ``LWIP_OK`` on success, ``LWIP_ERR_ARG`` if ``socket`` is
      ``NULL``.

Client/Server Examples
------------------------

These are production-quality skeletons. Copy them as a starting point and fill
in your application logic where the comments indicate.

TCP Client
~~~~~~~~~~

Connects to a remote host, exchanges data across multiple ticks, then shuts
down cleanly. The protocol is left entirely to your application — substitute
your own send/receive logic where the comments indicate.

.. code-block:: c

   #include <lwip.h>
   #include <stdbool.h>
   #include <stdint.h>
   #include <string.h>

   #define RX_BUF_MAX 2048

   typedef struct {
       struct lwip_socket socket;
       uint8_t  rx_buf[RX_BUF_MAX];
       size_t   rx_len;
       bool     want_close;   /* set by app when it is done sending */
       bool     done;         /* set when main loop should exit */
       int      exit_code;
   } client_ctx_t;

   static void client_on_event(struct lwip_socket *sock,
                               lwip_socket_event_type_t type,
                               const void *ev_data,
                               void *arg)
   {
       client_ctx_t *ctx = (client_ctx_t *)arg;

       switch (type) {
       case LWIP_SOCKET_EV_STATE_CHANGE: {
           const lwip_socket_state_data_t *sd =
               (const lwip_socket_state_data_t *)ev_data;
           if (sd->current == LWIP_STATUS_CONNECTED) {
               /* TODO: send your opening message here, e.g.:
                *   lwip_socket_write(sock, my_handshake, sizeof(my_handshake));
                *   or just set a flag so the app knows its good to send stuff
                */
           } else if (sd->current == LWIP_STATUS_CLOSED ||
                      sd->current == LWIP_STATUS_RESET  ||
                      sd->current == LWIP_STATUS_ERROR) {
               ctx->exit_code = (sd->current == LWIP_STATUS_ERROR) ? 1 : 0;
               ctx->done = true;
           }
           break;
       }
       case LWIP_SOCKET_EV_IO: {
           const lwip_socket_io_data_t *io =
               (const lwip_socket_io_data_t *)ev_data;
           size_t space = sizeof(ctx->rx_buf) - ctx->rx_len;
           if (io->readable && space) {
               ctx->rx_len += lwip_socket_read(
                   sock,
                   ctx->rx_buf + ctx->rx_len,
                   space < io->readable ? space : io->readable);
           }
           /* TODO: parse ctx->rx_buf[0..ctx->rx_len] for complete messages.
            * Consume processed bytes by memmove-ing the remainder to the front
            * and adjusting ctx->rx_len.
            * Set ctx->want_close = true when the session is complete. */
           break;
       }
       case LWIP_SOCKET_EV_ERROR:
           ctx->exit_code = 1;
           ctx->done = true;
           break;
       }
   }

   int main(void)
   {
       if (!lwip_start())  return 1;
       if (!lwip_network_up()) return 1;

       client_ctx_t ctx = {0};

       if (lwip_socket_create(&ctx.socket, LWIP_SOCKET_TCP,
                              LWIP_NETIF_EXT, NULL, 30000) != LWIP_OK)
           return 1;

       lwip_socket_on_event(&ctx.socket,
                            LWIP_SOCKET_EVENTF_STATE_CHANGE |
                            LWIP_SOCKET_EVENTF_IO,
                            client_on_event, &ctx);

       if (lwip_socket_connect(&ctx.socket, "your.server.com", YOUR_PORT) != LWIP_OK) {
           lwip_socket_destroy(&ctx.socket);
           return 1;
       }

       while (!ctx.done) {
           lwip_service_events();

           /* Initiate half-close once the response is complete. */
           if (ctx.want_close &&
               ctx.socket.status == LWIP_STATUS_CONNECTED) {
               lwip_socket_shutdown(&ctx.socket);
               ctx.want_close = false;
           }

           /* Your UI, key-scan, timer, and app work goes here. */
       }

       /* If the remote did not already close us, do so now. */
       if (ctx.socket.status != LWIP_STATUS_CLOSED &&
           ctx.socket.status != LWIP_STATUS_RESET) {
           lwip_socket_close(&ctx.socket);
       }
       lwip_socket_destroy(&ctx.socket);
       return ctx.exit_code;
   }

TCP Server (multi-connection)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Listens on a port, accepts multiple concurrent connections from a fixed pool,
dispatches each one per main-loop tick, and tears them down cleanly when the
remote closes or an error occurs.

.. code-block:: c

   #include <lwip.h>
   #include <stdbool.h>
   #include <stdint.h>
   #include <string.h>

   #define PORT         8080
   #define MAX_CLIENTS  8
   #define BUF_MAX      512

   typedef enum {
       PEER_IDLE = 0,
       PEER_ACTIVE,
       PEER_CLOSING,   /* close issued, waiting for CLOSED */
   } peer_state_t;

   typedef struct {
       struct lwip_socket socket;
       peer_state_t       state;
       char               buf[BUF_MAX];
       size_t             buf_len;
   } peer_slot_t;

   static peer_slot_t peers[MAX_CLIENTS];

   /* Find a free slot; returns NULL if the pool is full. */
   static peer_slot_t *peer_alloc(void)
   {
       for (int i = 0; i < MAX_CLIENTS; i++)
           if (peers[i].state == PEER_IDLE)
               return &peers[i];
       return NULL;
   }

   static void peer_release(peer_slot_t *p)
   {
       lwip_socket_destroy(&p->socket);
       memset(p, 0, sizeof(*p));   /* returns slot to pool */
   }

   /* Called once per tick for each active peer.
    * Returns true when the slot should be released. */
   static bool peer_service(peer_slot_t *p)
   {
       lwip_status_t st = p->socket.status;

       /* Remote closed cleanly, reset, or a stack error — tear down. */
       if (st == LWIP_STATUS_CLOSED  ||
           st == LWIP_STATUS_RESET   ||
           st == LWIP_STATUS_ERROR)
           return true;

       /* Waiting for our own close to complete. */
       if (p->state == PEER_CLOSING)
           return !lwip_socket_is_active(&p->socket);

       /* ---- application logic ---- */

       /* Accumulate incoming bytes. */
       size_t avail = lwip_socket_available(&p->socket);
       if (avail) {
           size_t space = sizeof(p->buf) - p->buf_len;
           size_t n = avail < space ? avail : space;
           p->buf_len += lwip_socket_read(
               &p->socket, (uint8_t *)p->buf + p->buf_len, n);
       }

       /* TODO: parse p->buf[0..p->buf_len] for a complete message.
        * When ready to respond:
        *   lwip_socket_write(&p->socket, my_response, my_response_len);
        * When done with this peer:
        *   lwip_socket_close(&p->socket);
        *   p->state = PEER_CLOSING;
        *   p->buf_len = 0;
        */

       return false;
   }

   int main(void)
   {
       if (!lwip_start())      return 1;
       if (!lwip_network_up()) return 1;

       /* Request DHCP; server sockets don't auto-start it. */
       if (lwip_request_services(LWIP_SOCKET_SVC_DHCP, 30000) != LWIP_OK)
           return 1;

       struct lwip_socket server;
       if (lwip_socket_create(&server, LWIP_SOCKET_TCP,
                              LWIP_NETIF_EXT, NULL, 0) != LWIP_OK)
           return 1;

       if (lwip_socket_listen(&server, PORT) != LWIP_OK) {
           lwip_socket_destroy(&server);
           return 1;
       }

       bool running = true;
       while (running) {
           lwip_service_events();

           /* Accept new connections while pool has space. */
           peer_slot_t *slot = peer_alloc();
           if (slot) {
               if (lwip_socket_accept(&server, &slot->socket) == LWIP_OK) {
                   slot->state = PEER_ACTIVE;
               }
               /* else: queue empty this tick — slot stays IDLE */
           }

           /* Service every active peer. */
           for (int i = 0; i < MAX_CLIENTS; i++) {
               if (peers[i].state != PEER_IDLE) {
                   if (peer_service(&peers[i]))
                       peer_release(&peers[i]);
               }
           }

           /* Your UI, key-scan, timer, and app work goes here.
            * Set running = false to exit gracefully. */
       }

       /* Abort any still-open peers and destroy the listener. */
       for (int i = 0; i < MAX_CLIENTS; i++) {
           if (peers[i].state != PEER_IDLE) {
               lwip_socket_abort(&peers[i].socket);
               peer_release(&peers[i]);
           }
       }
       lwip_socket_destroy(&server);
       return 0;
   }

Memory Safety & Usage
-------------------------

One of the biggest issues you will run into with lwIP is memory-related. 

**Hardware Stack Usage**: lwIP consumes some space on the stack for scratch while copying resources, performing cryptography, and more. A quick review of the code suggests that average stack frame usage is ~200 bytes, with TLS Certificate Verify spiking to ~1 KiB and TLS Client Hello using ~800 bytes. Consider this when using stack-memory as the caller.

**Heap Usage**: The calculator's heap is shared between your app, lwIP's internal pools, and
anything else running. lwIP-CE tracks memory usage for all of its internals, and exposes an API by which the caller can reserve memory.

.. code-block:: c

    uint8_t *http_buf = mem_request(4096);
    if (!http_buf) {
       return 1; /* not enough heap left to proceed */
    }

    /* ... use http_buf for the lifetime of the app ... */

    /* ... possibly resize http_buf ... */
    uint8_t *new_http_buf = mem_resize(http_buf, 8192);
    if(new_http_buf)
        http_buf = new_http_buf;

   mem_release(http_buf);

While you are at perfect liberty to use ``malloc()`` or just statically-allocate memory, it is recommended to use this API for any heap allocations. Because lwIP-CE can wind up operating under severe memory constraints, having awareness of all buffers in use is important lest you wind up with out-of-memory errors while still believing you have memory available. Additionally, lwIP-CE can take certain actions to relieve memory pressure (ex: defer TCP window updates), but those will never happen if lwIP-CE is unaware that memory is actually low. 

To illustrate this, take the following example. Say you allocate an 8 KiB buffer via something like ``uint8_t buf[8192];`` as a static variable versus via ``mem_request()``. The table below will illustrate how lwIP-CE manages memory based on 54 KiB (what the stack tends to default to) and 46 KiB (the result of using ``mem_request()``)

.. list-table::
   :header-rows: 1
   :widths: 33 33 34

   * - Pressure Level
     - @ 54 KiB
     - @ 46 KiB
   * - MILD (70%)
     - 37.8 KiB
     - 32.2 KiB
   * - HIGH (85%)
     - 45.9 KiB
     - 39.1 KiB
   * - SEVERE (90%)
     - 48.6 KiB
     - 41.4 KiB
   * - CRITICAL (95%+)
     - 51.3 KiB
     - 43.7 KiB

The table lists the memory usage at which the stack would enter pressure state for each max heap cap. Notice that, in the case in which you reserved your 8 KiB buffer but lwIP-CE was unaware, the stack would OOM-fault before even hitting CRITICAL pressure state. This is just one example of the larger issue: the stack will make decisions based on the supposition it has more memory than it actually does if you do not tell it the memory is reserved. This is the main reason why I exposed this API surface and highly recommend people use it.

Users may return the current lwIP memory usage heuristics via the ``mem_get_stats()`` function.

Debugging
---------

For real-time event logging and post-mortem traceback, see :doc:`debugging`.
