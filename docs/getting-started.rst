Getting Started
===============

lwIP-CE ships as a curated release surface for calculator applications. The
release headers are not a dump of upstream lwIP. They are generated from what
this build can actually provide, then filtered through the public API manifest.

Start the Stack
---------------

Most applications should include ``lwip/conn.h`` and use the app-facing
connection API:

.. code-block:: c

   #include <lwip/conn.h>

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

Choose an API Layer
-------------------

Use ``conn.h`` when the program wants a small socket-ish wrapper around TCP,
UDP, ALTCP, or TLS.

Use ``core/`` when the program needs raw lwIP control at PCB level. This is the
closer match for upstream lwIP examples.

Use ``cryptography/`` when the program wants the TLS project's crypto
primitives directly, without opening a network connection.

Release Layout
--------------

The public release layout is:

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Path
     - Purpose
   * - ``lwip/conn.h``
     - App-facing connection wrapper.
   * - ``lwip/core.h``
     - Umbrella include for curated core headers.
   * - ``lwip/core/*.h``
     - Curated lwIP core headers for this implementation.
   * - ``lwip/cryptography.h``
     - Umbrella include for crypto headers.
   * - ``lwip/cryptography/*.h``
     - Public cryptographic primitives.
   * - ``lwip.s``
     - Release export/extern assembly surface for the dynamic library.

The calculator is not a desktop lwIP target. There is no BSD sockets layer, no
filesystem-backed resolver state, no preemptive multitasking, and no async
runtime. Keep application loops explicit and keep ownership of buffers obvious.
