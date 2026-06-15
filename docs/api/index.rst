Usable API
==========

lwIP-CE is forked from lwIP, but it is not a full desktop-style lwIP port. A lot
of upstream surface area is either removed or intentionally not exposed because
the calculator is not a true OS target: no async runtime, no multitasking, no
real filesystem, no BSD sockets layer, and not much above the PCB/raw API level.

The headers below are the curated API that exists for this implementation. The
release places two umbrella headers at the root: ``lwip.h`` for stack/socket
use and ``cryptography.h`` for direct crypto use. Lower-level headers live
under ``lwip/core/`` and ``lwip/cryptography/``.

.. list-table::
   :header-rows: 1
   :widths: 28 72

   * - Header group
     - Purpose
   * - :doc:`lwip.h <lwip>`
     - Root-level stack and socket API for applications that want a simpler
       path than working directly at PCB level.
   * - :doc:`core/ <core>`
     - Lower-level ``lwip/core/*.h`` includes, curated and modified to match
       what is actually available in this implementation.
   * - :doc:`cryptography.h and lwip/cryptography/ <cryptography>`
     - Root-level crypto umbrella and lower-level primitives that can be used
       outside the network stack.

For stack usage and a full socket example, start with :doc:`../getting-started`.

.. toctree::
   :hidden:

   lwip
   core
   cryptography
