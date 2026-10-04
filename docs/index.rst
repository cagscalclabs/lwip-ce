lwIP-CE
=======

*TCP/IP, TLS 1.3, and USB Ethernet for a calculator that was not consulted.*

lwIP-CE is a port of the `lwIP <https://www.nongnu.org/lwip/2_1_x/>`_ network stack to the TI-84 Plus CE. It allows you to connect to the Internet from your graphing calculator.

.. note::

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

Requirements
-------------

- A TI-84+ CE graphing calculator.
- A USB Ethernet adapter compliant with **Communications Data Class (CDC)** subtype ECM or NCM. [#cdcnote]_
- An Ethernet cable connected to a switch, router, or an Ethernet-compatible WPS Wi-Fi adapter.
- A means to transfer the appropriate files to your calculator (TI Connect CE, TiLp2).
- **As developer**, the CE C toolchain, lwIP headers and .lib file.

.. rubric:: Notes

.. [#cdcnote] CDC ECM and NCM adapters make up a fair share of the market, but
   can be difficult to identify when purchasing. A reliable heuristic: 10/100
   adapters tend to be ECM; Gigabit adapters tend to be NCM. To confirm, plug
   the adapter into a computer and inspect the USB device descriptors. The
   CDC-class configuration will follow any vendor-specific configuration and
   will have a USB device class of ``0x00`` (``USB_INTERFACE_SPECIFIC_CLASS``);
   the CDC control interface will have class ``0x02`` (``USB_COMM_CLASS``) and
   subclass ``0x06`` (ECM) or ``0x0D`` (NCM).

Where to start
--------------

- :doc:`getting-started`: Installation, configuration, basic stack flow.
- :doc:`using-the-network`: Using sockets, PCBs, and networking details.
- :doc:`parsing`: Using the JSON, XML, and URL encode parsers.
- :doc:`using-cryptography`: Using the cryptography subsystem.
- :doc:`debugging`: Using the stack debugging tools.
- :doc:`technical-details`: LibLoad handshake, TLS specifications, test harnesses.

Contributing
-------------

lwIP-CE is under active development and as such welcomes platform-specific contributions.
It is rebased quarter-annually against upstream lwIP, but the cryptography needs to be written in ez80 assembly by those with knowledge of how to write efficient, timing-safe code.

**Required for full TLS 1.3 compliance:**

- P-256 key exchange (ECDHE secp256r1)
- P-256 signature verification (ECDSA secp256r1 SHA-256)
- RSA key expansion to 4096-bit

**Optional / nice to have:**

- SHA-384 — unlocks the AES-256-GCM-SHA384 cipher suite
- SHA-512 — stronger standalone hashing
- SHA-1 — needed to verify older CA certificates that still use sha1WithRSAEncryption

To contribute to the project, email the project maintainers at `info@cagscalclabs.net <mailto:info@cagscalclabs.net>`_ or join the
`CagsCalcLabs Discord server <https://discord.gg/bf8MUyZcMP>`_.

To support equipment purchases (adapters, cables, TI-84+ CE and later Evo units) and operational costs:

- `GitHub Sponsors <https://github.com/sponsors/cagscalclabs>`_
- `Ko-fi <https://ko-fi.com/cagscalclabs>`_
- `Buy Me a Coffee <https://www.buymeacoffee.com/cagscalclabs>`_


.. include:: _site_toc.rst
