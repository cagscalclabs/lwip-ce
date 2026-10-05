lwip.h
======

``lwip.h`` is the root-level application header. It exposes stack lifecycle,
socket creation, socket I/O, service requests, event callbacks, and memory
accounting.

.. doxygenfile:: lwip.h
   :project: lwip-ce

Connection readiness
--------------------

``lwip_socket_connect()`` waits asynchronously for a matching interface,
administrative up state, link, and usable address. DHCP is required for dynamic
external sockets, DNS for hostnames, and SNTP for TLS/WSS. Static sockets do not
start DHCP; numeric destinations do not require DNS. Loopback sockets require
no external services.

lwIP extended netif callbacks signal registration, link/address changes, and
removal. The socket layer processes these signals after USB events and lwIP
timeouts, outside the netif callback. A 100 ms dispatcher also checks service
completion and connection deadlines. Applications must keep calling
``lwip_service_events()`` while a connection is waiting; the timer does not run
independently of this NO_SYS event loop.
