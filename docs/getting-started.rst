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

You will also need a USB CDC Ethernet adapter (CDC-ECM or CDC-NCM class) for any program that uses networking. Some Ethernet-to-WiFi adapters work as well, provided they speak CDC Ethernet on the USB side and support Wi-Fi Protected Setup (WPS). Programs that only use the crypto or parser APIs do not need any adapter.

.. code-block:: text

    Calculator => USB Ethernet adapter => router
    Calculator => USB Ethernet adapter => Ethernet to Wi-Fi adapter

Set the BSSHEAP Constraint
--------------------------

.. danger::

    **Before doing anything else:** add the following line to your makefile
    for any project that links against lwIP-CE:

    .. code-block:: text

        BSSHEAP_LOW >= 0xD072C6

    lwIP-CE reserves an 8 KiB window at the bottom of the default
    ``BSSHEAP_LOW``. Without this line, your program's BSS and lwIP-CE's
    reserved memory will overlap and cause unpredictable failures.

    See :doc:`technical-details` for why this window exists.

Initialize the Stack
--------------------

``lwip_start()`` must be the first lwIP call in your program. It initializes
the stack's memory, timers, RNG, and TLS primitives. It does not bring up
the USB Ethernet interface; use ``lwip_network_up()`` for that.

.. code-block:: c

   #include <lwip.h>

   int main(void)
   {
       if (!lwip_start()) {
           /* lwip_get_start_errstring() returns a human-readable reason */
           return 1;
       }

       /* crypto and parser APIs are available here */

       /* if you also need networking: */
       if (!lwip_network_up()) {
           return 1;
       }

       while (1) {
           lwip_service_events();
           /* app work */
       }
   }

``lwip_start()`` returns ``true`` on success and ``false`` on failure.
``lwip_get_start_errstring()`` returns a human-readable string describing the
failure. ``lwip_get_start_errno()`` returns a numeric code.

If ``lwip_start()`` is skipped, all exports resolve to no-ops that clear all
registers. The same happens on a version mismatch between the LibLoad stub
and the resident app. See :doc:`technical-details` for details on the
LibLoad bootstrap.

For crypto-only programs (no networking), ``lwip_start()`` is sufficient —
``lwip_network_up()`` is not needed. Every unit test under
``tests/unit/`` relies on this pattern. See :doc:`using-cryptography` for
the crypto API.

``lwip_service_events()`` must be called regularly from your main loop while
networking is active. Incoming packets, TCP timers, and connection state
changes are all processed when this function runs. If it is not called often
enough, connections will stall or time out.

Release Layout
--------------

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
