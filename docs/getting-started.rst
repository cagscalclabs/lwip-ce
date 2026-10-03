Getting Started
===============

lwIP-CE Release Format
-----------------------

lwIP-CE comes packaged with a number of files and directories:

.. code-block:: text

   release/
   ├── lwip.h                    # app-facing socket API and batch-include for lwip/core/*
   ├── cryptography.h            # crypto/TLS primitives batch-include
   ├── lwip.asm                  # libload library stub source code
   ├── lwip.lib                  # libload symbols for lwIP
   ├── lwip.8xv                  # lwIP LibLoad stub
   ├── parsers.h                 # parsers batch-include
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

Developing with lwIP-CE
------------------------

This section will help you get set up to develop applications that use the lwIP-CE API.

Set the BSSHEAP Constraint
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. danger::

    **Before doing anything else:** add the following line to your makefile for any project that links against lwIP-CE:

    .. code-block:: text

        BSSHEAP_LOW >= 0xD072C6

    lwIP-CE reserves an 8 KiB window at the bottom of the default ``BSSHEAP_LOW``. Without this line, your program's BSS and lwIP-CE's reserved memory will overlap and cause unpredictable failures. See :doc:`technical-details` for why this window exists.

Install lwIP-CE Headers and .lib File
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In order to use lwIP-CE in your applications you will need to make sure the lwIP-CE headers and .lib file are installed into the correct locations.

- Copy ``lwip.h`` and ``cryptography.h`` into ``$CEDEV/include``.
- Copy the entire ``lwip`` folder into ``$CEDEV/include``.
- Copy ``lwip.lib`` into ``$CEDEV/lib/libload``.

Once that is done, you can reference the lwIP-CE headers in code as you would any other LibLoad or C standard header. Some examples:

.. code-block:: c

    #include <lwip.h>                   // for lwip main API
    #include <cryptography.h>           // for cryptography batch-include
    #include <parsers.h>                // for parsers batch-include
    #include <lwip/core/altcp.h>        // for ALTCP lwIP core
    #include <lwip/parsers/json.h>      // for JSON parser
    #include <lwip/cryptography/hash.h> // for hash API

Initialize the Dylib
~~~~~~~~~~~~~~~~~~~~~

``lwip_start()`` must be the first lwIP-CE call in your program. It first patches the lwIP-CE
LibLoad function table to call into the lwIP application and then initializes the stack's
memory subsystem, timers, and RNG. It does not bring up the USB Ethernet interface; use ``lwip_network_up()`` for that.

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

For cryptography or parser-only programs (no networking), ``lwip_start()`` is sufficient —
``lwip_network_up()`` is not needed. See :doc:`using-cryptography` for
the cryptography API and :doc:`parsing` for the parser API.

``lwip_service_events()`` must be called regularly from your main loop while
networking is active (again, not needed for cryptography or parser-only code). Incoming packets, TCP timers, and connection state changes are all processed when this function runs. If it is not called often enough or too often, connections will stall or time out, or timing race conditions may occur. Once per tick is reasonable for most use cases.

Installing & Using lwIP-CE Application (as End User)
-----------------------------------------------------

``appinst/`` contains the actual lwIP-CE installer, split into multiple appvars and the installer program. Send the entire contents of that directory and ``lwip.8xv`` to your TI-84+ CE and then run ``lwIPINST.8xp (prgmINSTALL)``. This will install lwIP as a TI Flash Application.

.. note::

    The app installer cannot overwrite an Application that already exists. When updating this library you will need to delete the Application and then possibly ``GarbageCollect`` on your device before trying to install a new version.

You will also need a USB CDC Ethernet adapter (CDC-ECM or CDC-NCM class) for any program that uses networking. Some Ethernet-to-WiFi adapters work as well, provided they speak CDC Ethernet on the USB side and support Wi-Fi Protected Setup (WPS).

.. code-block:: text

    ┌────────────┐   USB   ┌──────────────────┐  Ethernet  ┌────────┐
    │ Calculator │────────▶│ CDC Ethernet     │───────────▶│ Router │
    └────────────┘         │ adapter          │            └────────┘
                           └──────────────────┘

    ┌────────────┐   USB   ┌──────────────────┐   802.11   ┌────────┐
    │ Calculator │────────▶│ CDC Ethernet +   │ ·  ·  ·  · │  Wi-Fi │
    └────────────┘         │ Wi-Fi bridge     │            │ network│
                           └──────────────────┘            └────────┘

Programs that only use the cryptography or parser APIs do not need any adapter.

lwIP-CE Configuration Wizard
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When the end user runs the lwIP-CE app directly on the calculator, a configuration wizard opens. Settings are persisted to an AppVar and loaded by the stack at startup. This allows the user to have some control over network-specific security-critical settings. For example, a user may decide that they do not want their calculator connecting to anything requiring TLS, regardless of what the application they are running does. Disabling TLS in the wizard is a hard-stop on any TLS connection.

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Setting
     - Effect
   * - Hostname
     - Device hostname advertised over DHCP.
   * - Static IPv4
     - IP address, gateway, and netmask. Leave blank to use DHCP.
   * - Timezone / DST
     - UTC offset and daylight-saving toggle, used by SNTP to set the
       real-time clock. **For TLS, this setting plus the device clock are relevant to certificate expiry checks. If both are not properly set by the user, certificate validation will fail.**
   * - Enable TLS
     - When off, any attempt by an application to open a TLS socket fails
       immediately. Gives the end user final authority over whether the
       calculator makes encrypted connections.

These are end-user settings, not build-time flags — application code cannot
override them.