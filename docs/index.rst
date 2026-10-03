lwIP-CE
=======

*TCP/IP, TLS 1.3, and USB Ethernet for a calculator that was not consulted.*

lwIP-CE is a port of the `lwIP <https://www.nongnu.org/lwip/2_1_x/>`_ network stack to the TI-84 Plus CE. It allows you to connect to the Internet from your graphing calculator.

.. note ::

  This is an API for allowing Internet connectivity in programs (similar to using sockets in
  C or Python). It is not a magic switch that lets the calculator just go online.

lwIP-CE is a full TCP/IP stack providing:

- A USB CDC class Ethernet driver supporting ECM and NCM.
- A membuffer driver designed to optimize resource ownership in a device that has very little RAM.
- A minimalistic TLS 1.3 client.
- An assortment of cryptographic primitives.
- JSON, XML, and URL encoders.

This documentation covers CE-specific behavior only. It does not mirror upstream lwIP's docs; for
standard lwIP types, callbacks, and protocol APIs, see the
`upstream lwIP API reference <https://www.nongnu.org/lwip/2_1_x/group__api.html>`_.

Where to start
--------------

- :doc:`getting-started`: Installation, configuration, basic stack flow.
- :doc:`using-the-network`: Using sockets, PCBs, and networking details.
- :doc:`parsing`: Using the JSON, XML, and URL encode parsers.
- :doc:`using-cryptography`: Using the cryptography subsystem.
- :doc:`debugging`: Using the stack debugging tools.
- :doc:`technical-details`: LibLoad handshake, TLS specifications, test harnesses.

.. include:: _site_toc.rst
