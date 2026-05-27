Usable API
==========

lwIP-CE is forked from lwIP, but it is not a full desktop-style lwIP port. A lot
of upstream surface area is either removed or intentionally not exposed because
the calculator is not a true OS target: no async runtime, no multitasking, no
real filesystem, no BSD sockets layer, and not much above the PCB/raw API level.

The headers below are the curated API that exists for this implementation.

.. list-table::
   :header-rows: 1
   :widths: 28 72

   * - Header group
     - Purpose
   * - :doc:`conn.h <conn>`
     - A small socket-ish connection API exposed for applications that want a
       simpler path than working directly at PCB level.
   * - :doc:`core/ <core>`
     - lwIP core includes, curated and modified to match what is actually
       available in this implementation.
   * - :doc:`cryptography/ <cryptography>`
     - Algorithmically-secure primitives that can be used outside the network
       stack.

For stack usage and a full connection stub, start with :doc:`../getting-started`.

.. toctree::
   :hidden:

   conn
   core
   cryptography
