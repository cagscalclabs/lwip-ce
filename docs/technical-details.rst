Technical Details
=================

This page collects the engineering notes that are deeper than the public API
reference: the design whitepaper, the CI validation harnesses, and the test
fixtures that keep the calculator build honest.


Configuration Wizard
--------------------

lwIP-CE has a configuration wizard that opens when you run the app. It keeps the
resident stack policy in one place:

- Allocator max heap
- Global service-up flags: DHCP, DNS, and NTP
- Hostname, static IPv4 settings, timezone, and DST
- Certificate/Full-chain verification mode
- USB/TLS logging and max log size
- Network service tests: HTTP server, NTP, DNS, ping, TCP echo, and TLS

Allocator System
----------------

lwIP-CE uses a custom allocator system that can operate in two modes:

- Dynamic: *Default* lwIP-CE ingests malloc, free, and realloc. Only what is needed is absorbed. This can be more memory-efficient but also suffers the malloc overhead. Max heap is tunable via lwIP-CE configuration wizard.

- Static: *Requires manual* ``mem_init_static`` *followed by* ``lwip_init`` *instead of* ``lwip_start``. You give lwIP-CE a pointer and a size, and it treats that region as its heap.

The allocator also exposes live accounting. ``mem_get_stats`` fills a
``struct mem_accounting_stats`` with the heap limit, heap used/free, the pbuf
pool size and usage, the user-reserved total, and per-pool plus effective
memory-pressure levels. Applications can poll this each event-loop tick to
render a live memory readout (the examples and test harnesses stream it to the
LCD). ``mem_set_global_pressure_cb`` registers an observer that fires when the
effective pressure level changes, for transport-level backpressure (for
example, delaying ``tcp_recved`` window updates under load).


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
   * - Trust store
     - A GitHub workflow parses system certificates, generates a curated
       truststore with abbreviated serialized metadata, signs it with the
       maintainer RSA-2048 private key, and ships the matching public key in lwIP-CE. Regenerated quarterly.

   * - CertificateVerify/Certificate
     - *CertificateVerify* is mandatory and is verified against the leaf
       certificate's ``SubjectPublicKeyInfo``. The server must select
       ``rsa_pss_rsae_sha256`` and the leaf must be RSA with a modulus
       between 1024 and 2048 bits, inclusive. Any other signature scheme
       (including ``ecdsa_secp256r1_sha256``, the wider RSA-PSS hashes,
       or non-RSA leaf keys) causes a fatal ``decrypt_error`` alert and
       the socket is aborted. ``ecdsa_secp256r1_sha256`` support is
       on the roadmap.

       Certificate chain trust is **adjacent-link signature verification**.
       SPKI pinning is no longer the chain-trust mechanism. As the
       ``Certificate`` message streams in, each link is checked against the
       next cert's public key (cert *N* is signed by cert *N+1*):

       - An ``RSA-2048`` link signed with ``sha256WithRSAEncryption`` is
         verified for real (PKCS#1 v1.5, SHA-256). A bad signature is fatal:
         the handshake aborts.
       - Any other signature type (``ecdsa_secp256r1_sha256``, wider RSA-PSS
         hashes, non-RSA issuer keys) is **not** verified; the link is
         accepted and the stack raises an ``ALERT``-severity debug event
         (``unsupported cert type, proceeding``) so the application can see
         the link went unchecked.
       - The topmost cert has no issuer in the chain and is left unverified
         (adjacent-links only; no truststore-root anchoring at this link).

       This is an **interim** model: it lets the calculator complete a
       handshake without running RSA/P-256 across an entire desktop-class
       chain, while still cryptographically checking the RSA links it can
       afford. As additional signature algorithms land (``ecdsa_secp256r1_sha256``
       is next), the ALERT-but-accept fallback will shrink. The leaf is still
       independently authenticated by the mandatory ``CertificateVerify``
       above.

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
