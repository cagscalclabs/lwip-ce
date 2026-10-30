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
   ├── wireless.h                # Wi-Fi control batch-include
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
   │   ├── parsers/              # zero-copy response parsers
   │   │   ├── json.h
   │   │   ├── xml.h
   │   │   └── url.h
   │   └── wireless/             # Wi-Fi bridge control
   │       └── wifi.h
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

        BSSHEAP_LOW = 0xD072C6

    lwIP-CE reserves an 8 KiB window at the bottom of the default ``BSSHEAP_LOW``. Without this line, your program's BSS and lwIP-CE's reserved memory will overlap and cause unpredictable failures. See :doc:`technical-details` for why this window exists.

Install lwIP-CE Headers and .lib File
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In order to use lwIP-CE in your applications you will need to make sure the lwIP-CE headers and .lib file are installed into the correct locations.

- Copy ``lwip.h``, ``parsers.h``, ``wireless.h`` and ``cryptography.h`` into ``$CEDEV/include``.
- Copy the entire ``lwip`` folder into ``$CEDEV/include``.
- Copy ``lwip.lib`` into ``$CEDEV/lib/libload``.

Once that is done, you can reference the lwIP-CE headers in code as you would any other LibLoad or C standard header. Some examples:

.. code-block:: c

    #include <lwip.h>                   // for lwip main API
    #include <cryptography.h>           // for cryptography batch-include
    #include <parsers.h>                // for parsers batch-include
    #include <lwip/core/altcp.h>        // for ALTCP lwIP core
    #include <lwip/parsers/json.h>      // for JSON parser
    #include <lwip/wireless/wifi.h>     // for Wi-Fi bridge control
    #include <lwip/cryptography/hash.h> // for hash API

Initialize the Dylib
~~~~~~~~~~~~~~~~~~~~~

``lwip_start()`` must be the first lwIP-CE call in your program. It first patches the lwIP-CE
LibLoad function table to call into the lwIP application and then initializes the stack's
memory subsystem and timers. The RNG starts on its first use. It does not bring up the USB Ethernet interface; use ``lwip_network_up()`` for that.

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

Call ``lwip_stop()`` before your program exits. It closes open connections and
takes the calculator out of USB network mode. A program that exits without it
leaves the calculator in that mode, and a connected PC cannot reach the
calculator over the TI link until the cable is unplugged and plugged back in.

``lwip_service_events()`` must be called regularly from your main loop while
networking is active (again, not needed for cryptography or parser-only code). Incoming packets, TCP timers, and connection state changes are all processed when this function runs. If it is not called often enough or too often, connections will stall or time out, or timing race conditions may occur. Once per tick is reasonable for most use cases.

Installing & Using lwIP-CE Application (as End User)
-----------------------------------------------------

``appinst/`` contains the actual lwIP-CE installer, split into multiple appvars and the installer program. Send the entire contents of that directory and ``lwip.8xv`` to your TI-84+ CE and then run ``lwIPINST.8xp (prgmINSTALL)``. This will install lwIP as a TI Flash Application.

.. note::

    The app installer cannot overwrite an Application that already exists. When updating this library you will need to delete the Application and then possibly ``GarbageCollect`` on your device before trying to install a new version.

Any program that uses networking needs either a USB CDC Ethernet adapter (CDC-ECM or CDC-NCM class) on an OTG cable, or the lwIP-CE Wi-Fi bridge on the calculator's stock cable (see :doc:`using-wifi`). Some Ethernet-to-WiFi adapters work as well, provided they speak CDC Ethernet on the USB side and support Wi-Fi Protected Setup (WPS).

.. code-block:: text

    ┌────────────┐   USB   ┌──────────────────┐  Ethernet  ┌────────┐
    │ Calculator │────────▶│ CDC Ethernet     │───────────▶│ Router │
    └────────────┘         │ adapter          │            └────────┘
                           └──────────────────┘

    ┌────────────┐   USB   ┌──────────────────┐   802.11   ┌────────┐
    │ Calculator │────────▶│ CDC Ethernet +   │ ·  ·  ·  · │  Wi-Fi │
    └────────────┘         │ Wi-Fi adapter    │            │ network│
                           └──────────────────┘            └────────┘

    ┌────────────┐   USB   ┌──────────────────┐   802.11   ┌────────┐
    │ Calculator │────────▶│ lwIP-CE Wi-Fi    │ ·  ·  ·  · │  Wi-Fi │
    └────────────┘  stock  │ bridge (ESP32)   │            │ network│
                    cable  └──────────────────┘            └────────┘

Programs that only use the cryptography or parser APIs do not need any adapter.

lwIP-CE Configuration Wizard
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When the end user runs the lwIP-CE app directly on the calculator, a configuration wizard opens. Use the arrow keys to move, **enter** to open an item, **left**/**right** to change a value, and **clear** to save and quit. Settings are persisted to an AppVar and loaded by the stack at startup. This allows the user to have some control over network-specific security-critical settings. For example, a user may decide that they do not want their calculator connecting to anything requiring TLS, regardless of what the application they are running does. Disabling TLS in the wizard is a hard-stop on any TLS connection.

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Setting
     - Effect
   * - Wi-Fi
     - Saved networks, scanning and connecting through the lwIP-CE Wi-Fi
       bridge. Shows the joined network, and updates on its own. See
       :doc:`using-wifi`.
   * - Hostname
     - Device hostname advertised over DHCP.
   * - Timezone / DST
     - UTC offset and daylight-saving toggle, used by SNTP to set the
       real-time clock. **For TLS, this setting plus the device clock are relevant to certificate expiry checks. If both are not properly set by the user, certificate validation will fail.**
   * - Enable TLS
     - When off, any attempt by an application to open a TLS socket fails
       immediately. Gives the end user final authority over whether the
       calculator makes encrypted connections.
   * - Capture limit / Packet capture
     - Largest packet capture AppVar, and a viewer for captured packets.

These are end-user settings, not build-time flags — application code cannot
override them.

AppVars Created by lwIP-CE
~~~~~~~~~~~~~~~~~~~~~~~~~~

lwIP-CE creates a small number of AppVars for persistent configuration and
optional runtime data. Names are shown with their exact spelling below.

.. list-table:: Runtime-created AppVars
   :header-rows: 1
   :widths: 18 27 55

   * - Name
     - Created when
     - Contents and lifecycle
   * - ``lwIPCFG``
     - The configuration wizard saves its settings.
     - Archived configuration containing the hostname, time settings, TLS and
       capture toggles, logging policy, and bridge options. If it is missing or
       invalid, lwIP-CE uses defaults; the wizard recreates it when settings are
       saved.
   * - ``lwIPPCAP``
     - Packet capture is enabled and the first captured records are flushed.
     - Packet records from all capturing interfaces. The file grows only to the
       configured 4, 8, 16, or 32 KiB limit, after which capture stops. It can
       be viewed and deleted from the configuration application.
   * - ``lwIPLog``
     - File logging is enabled and buffered events are flushed.
     - The active plain-text event and traceback log. It is capped at 16 KiB;
       when full, it is rotated into an archive slot and a new active log is
       created.
   * - ``lwIPLg00`` through ``lwIPLg08``
     - ``lwIPLog`` rotates.
     - Archived log files. The configured archive count is between one and
       nine; once full, the oldest slot is replaced. Rotated slots are archived
       so they survive a RAM clear.
   * - ``lwIPLgMD``
     - The first log rotation completes.
     - Three-byte archived ring metadata identifying the oldest log slot, the
       occupied slot count, and the configured maximum. Delete it together with
       the log files rather than editing it independently.
   * - ``lwIPPSKC``
     - ``lwip_stop()`` saves one or more unexpired TLS session tickets.
     - TLS 1.3 resumption cache for up to eight hosts. It is deleted when no
       live entries remain; deleting it merely forces later connections to use
       full handshakes.

.. danger::

   ``lwIPPSKC`` contains unencrypted TLS resumption key material. The
   calculator has no secure-storage facility, so do not share this AppVar.
   lwIP-CE validates its structure and ticket lifetime when loading it, but
   cannot protect it from a local attacker with access to calculator storage.

The following related AppVars are **not** created automatically by the runtime:

- ``lwIPCERT`` is the signed truststore distributed through the project's
  ``truststore-latest`` release. lwIP-CE reads it but does not generate it.
- Private-key and certificate-chain AppVars are supplied and named by the
  application. ``tools/lwip-cert-converter`` creates these files on the host.
- ``lwip.8xv`` and ``LWIP.N.8xv`` are installation/LibLoad artifacts shipped
  in the release, not runtime state.
- Saved Wi-Fi profiles are stored by the lwIP-CE Wi-Fi bridge and are not
  calculator AppVars.

Avoid deleting or editing runtime AppVars while lwIP-CE is active. Diagnostic
AppVars may still have buffered data waiting to be flushed, and the ticket
cache is rewritten during orderly shutdown.

Building from Source
--------------------

Run ``make dylib`` with the CE C toolchain and `ce-libify
<https://github.com/alessiodam/toolchain_libify>`_ installed. The stock
``convbin`` in a CEdev release cannot link the X25519 code and fails with
``Unsupported relocation type: 7 (expected R_Z80_24)``. Build ``convbin`` from
the ``R_Z80_BYTE012`` branch of `mateoconlechuga/convbin
<https://github.com/mateoconlechuga/convbin>`_ and copy it over
``$CEDEV/bin/convbin``, as the CI workflows do.
