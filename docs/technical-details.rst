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
- Certificate verification mode
- USB/TLS logging and max log size
- Network service tests: HTTP server, NTP, DNS, ping, TCP echo, and TLS

*Certificate verification is currently fixed to CA pinning. lwIP-CE checks whether a non-leaf certificate in the presented chain matches an SPKI hash in the derived trust store. This does not verify the peer controls the private key for the leaf it is presenting. This is weaker than full WebPKI TLS and is an interim tradeoff because at this point we do not have a fast enough SignatureVerify algorithm. (I'd welcome a contributed RSA, ed25519, or P-256 algorithm in eZ80 that runs in a few seconds -- contact me if interested).*

Allocator System
----------------

lwIP-CE uses a custom allocator system that can operate in two modes:

- Dynamic: *Default* lwIP-CE ingests malloc, free, and realloc. Only what is needed is absorbed. This can be more memory-efficient but also suffers the malloc overhead. Max heap is tunable via lwIP-CE configuration wizard.

- Static: *Requires manual* ``mem_init_static`` *followed by* ``lwip_init`` *instead of* ``lwip_start``. You give lwIP-CE a pointer and a size, and it treats that region as its heap.


Ethernet Driver
---------------

The Ethernet path is USB-backed and tuned for the CE event loop. RX work is
drained explicitly, TX is staged through the driver, and recovery paths are
designed around endpoint/device state rather than threads. Applications still
need to pump network events; there is no background kernel doing it.

TLS Stack
---------

The TLS stack is intentionally narrow: enough to make real secure client
connections, not a general-purpose OS crypto subsystem.

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
       maintainer RSA-2048 private key, and ships the matching public key in
       lwIP-CE. Regenerated quarterly.

For more details, proofs, and datasets, see the whitepaper below.

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
