Technical Details
=================

This page collects the engineering notes that are deeper than the public API
reference: the design whitepaper, the CI validation harnesses, and the test
fixtures that keep the calculator build honest.


Configuration Wizard
--------------------

lwIP-CE has a configuration wizard that opens when you run the app. It keeps the
resident stack policy in one place:

- Hostname, static IPv4 settings, timezone, and DST

Allocator System
----------------

lwIP-CE uses a custom allocator system that can operate in two modes:

- Dynamic: *Default* lwIP-CE ingests malloc, free, and realloc. Only what is needed is absorbed. The stack manages its own pbuf pool, TLS scratch, RX rings, socket rings, and user-reserved regions; heap sizing is no longer a wizard-level policy knob.

- Static: *Requires manual* ``mem_init_static`` *followed by* ``lwip_init`` *instead of* ``lwip_start``. You give lwIP-CE a pointer and a size, and it treats that region as its heap.

The allocator also exposes live accounting. ``mem_get_stats`` fills a
``struct mem_accounting_stats`` with total heap, pbuf pool size/usage,
non-pool heap used/free, user-reserved bytes, TLS usage, RX ring usage, socket
ring usage, and pbuf/heap/effective pressure levels. Applications can poll this
each event-loop tick to render a live memory readout (the examples and test
harnesses stream it to the LCD). ``mem_set_global_pressure_cb`` registers an
observer that fires when the effective pressure level changes, for
transport-level backpressure (for example, delaying ``tcp_recved`` window
updates under load).


Ethernet Driver
---------------

The Ethernet driver is an abstraction layer on top of `USBDRVCE <https://ce-programming.github.io/toolchain/libraries/usbdrvce.html>`_, the TI-84+ CE USB driver provided as part of the CE toolchain.

The Ethernet driver supports USB-CDC-ECM and USB-CDC-NCM devices; in practice, ECM is common on 10/100 adapters, while NCM is common on gigabit-class adapters. It should also support hubs with a USB port that use one of those protocols, and an Ethernet adapter connected via a hub. Wi-Fi is possible only through an external Ethernet-to-Wi-Fi bridge (typically a USB Ethernet adapter connected to an Ethernet WiFi adapter). The adapter must handle association, WPA/WPA2, SSID selection, and key storage itself, typically through WPS or its own setup flow. lwIP-CE sees that device as Ethernet; it does not implement native Wi-Fi management.

The driver is event-loop driven. Applications must continue pumping the stack for RX, TX, timers, and device recovery to make progress.

TLS Stack
---------

The TLS stack is intentionally narrow: enough to make real secure client
sockets, not a general-purpose OS crypto subsystem.

.. list-table::
   :header-rows: 1
   :widths: 28 72

   * - Area
     - Position
   * - Threat model
     - Algorithmic security is in scope. Side channels are partially mitigated
       and partially out of scope. Hardware security is out of scope: no root
       of trust, secure enclave, crypto accelerator, protected filesystem, or
       trusted clock.
   * - RNG
     - SRAM-noise-derived. Entropy taps are statistically analyzed on hardware.
       Current dataset: correlation factor about ``1.1``; XOR conditioning
       depth ``17``; effective conditioning about ``16``; ``P(+)`` about
       ``0.5``; estimated min-entropy about ``1``.
   * - TLS trust store
     - Prior SPKI pinning model abandoned, new trust model WIP due to device
       storage constraints.
   * - Certificate chain
     - The stack walks the server's certificate chain and verifies the
       signatures it can currently support. RSA links are checked
       cryptographically. Unsupported signature algorithms, including P-256
       ECDSA, raise an ``ALERT``-severity debug warning and are allowed to
       pass for now so the stack remains usable before P-256 verification
       lands.

       There is no final root-of-trust anchor in this release. That mechanism
       is being redesigned, so the final intermediate or topmost certificate in
       the received chain dangles after adjacent-link checks. A later release
       will close this gap and remove the unsupported-algorithm fallback as the
       missing verification code lands.

   * - CertificateVerify
     - ``CertificateVerify`` is mandatory. For the current RSA path, the
       signature is verified against the leaf certificate's public key, proving
       possession of the leaf private key. This complements the best-effort
       chain walk above, but it is not a root-of-trust anchor by itself.

For more details, proofs, and datasets, see the whitepaper below.

Application Interfaces
----------------------

Network services and sockets
   Applications request netif-level services and drive sockets through a
   small C API rather than touching raw lwIP PCBs directly. ``lwip_request_services``
   (and the per-netif ``lwip_netif_request_services``) start DHCP, the DNS
   resolver, and SNTP on demand using ``LWIP_SOCKET_SVC_*`` flags; the per-netif
   form takes a status callback that fires once per requested service with a
   ``lwip_netif_service_status_t`` (up / timeout / failed), so an application
   can react to "DHCP is up" without polling. ``lwip_default_netif_info`` fills a
   ``lwip_netif_info_t`` snapshot (link/admin state, DHCP state, assigned IPv4
   address, gateway) for status displays.

Unified debug logging
   Diagnostics across the whole stack go through a single callback registered
   with ``lwip_set_debug(fn, mode, depth)``, replacing the former per-module
   debug hooks. Each event arrives as a ``struct lwip_debug_info`` carrying the
   emitting ``module``, the ``module_state`` (where in the code it fired),
   an ``errnum`` (0 = ok), the source ``line``, a verbosity ``depth``
   (``MILESTONE`` vs ``VERBOSE``), and a ``severity``:

   - ``INFO`` — normal progress / informational milestone.
   - ``ALERT`` — the stack noticed something wrong but chose to proceed (for
     example, an unsupported-but-tolerated certificate link).
   - ``ERROR`` — an operation is failing or aborting (always delivered,
     regardless of the configured depth).

   The callback's ``mode`` selects whether every emit is delivered
   (``LWIP_DBG_INFO``) or only error emits (``LWIP_DBG_ERROR``), and ``depth``
   gates verbosity. This gives an application one place to surface a clean
   high-level progress view or a deep trace, with the ALERT level making
   "proceeded despite a problem" distinguishable from a hard error.

CI And Test Harnesses
---------------------

The test harnesses are not decoration. They are there because the platform is
weird, the toolchain matters, and it is easy to pass a host-side test that says
nothing about the calculator binary.

.. list-table::
   :header-rows: 1
   :widths: 28 72

   * - Harness
     - What it proves
   * - CAVP primitive validation
     - Packs CAVP-derived vectors into ``CAVPIN.8xv``, runs the calculator-side
       primitive dispatcher in CEmu, saves ``CAVPOUT.8xv``, and grades the
       output on the host. This is regression evidence, not a formal NIST
       certificate.
   * - Timing profiler
     - Runs calculator-side timing captures so crypto and stack hot paths can be
       measured in the environment that actually ships.
   * - RNG entropy capture
     - Emits AppVars for raw and conditioned entropy paths, then analyzes the
       bit streams off-device. Entropy tests are not useful in the emulated CI
       pipeline because SRAM emulation is deterministic, so those captures are
       run on hardware and analyzed in the whitepaper instead.
   * - DAST hardware-in-the-loop
     - Runs the calculator-side ``tests/profiling/lwip_dast`` harness on real
       hardware because CEmu does not emulate Ethernet devices. The host-side
       ``build-tools/dast/lwip-dast.sh`` runner probes the calculator over the
       live network, advances the harness through UDP, TCP, raw/IP, and control
       states, writes ``tests/dast.json``, and CI gates the committed report.
   * - Doxygen/Sphinx docs build
     - Builds the generated API reference and the project docs with the same
       release headers users will see.

The CAVP harness uses AppVars because that is the natural calculator transport
boundary: host tools generate inputs, CEmu runs the app, and host tools parse
the saved output. That keeps the validation path close to how a real program
interacts with calculator storage instead of pretending this is a POSIX target.

Whitepaper
----------

The whitepaper is published as the latest generated PDF from the GitHub release
workflow. The docs build downloads that release asset and embeds it here so the
page renders the same PDF users would get from GitHub.

.. raw:: html

   <section class="whitepaper-panel">
     <div class="whitepaper-copy">
       <p class="whitepaper-kicker">Latest release PDF</p>
       <p>
         This covers the TLS work, RNG design, cryptographic constraints, and
         platform tradeoffs behind lwIP-CE.
       </p>
       <p>
         <a class="whitepaper-button" href="https://github.com/cagscalclabs/lwip-ce/releases/download/whitepaper-latest/whitepaper.pdf">
           Open the release PDF
         </a>
       </p>
     </div>
     <object class="whitepaper-viewer" data="_static/whitepaper.pdf" type="application/pdf">
       <p>
         Your browser did not render the embedded PDF.
         <a href="https://github.com/cagscalclabs/lwip-ce/releases/download/whitepaper-latest/whitepaper.pdf">
           Open the release PDF
         </a>.
       </p>
     </object>
   </section>
