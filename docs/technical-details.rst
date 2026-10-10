Technical Details
=================

This page covers the LibLoad bootstrap internals, memory layout, and the
deeper engineering notes behind the stack.

LibLoad Environment
-------------------

Bootstrapping
~~~~~~~~~~~~~~~

lwIP-CE is too big to statically include into every program that wants to use it. The core
plus TLS is around 420 KiB, and the calculator only has just under 2 MB of Flash,
so statically linking it into each consumer would burn that space fast. Instead,
lwIP-CE ships as a resident **application** that other programs call into. One
copy lives on the calculator; everything else dispatches to it.

That "call into a resident app" trick is built on top of the CE toolchain's
``LIBLOAD`` mechanism -- but with some custom logic bolted on, because LIBLOAD
was not designed for this exact use case. 

``lwip.8xv`` is a LibLoad library that defines every function in lwIP that is part
of the public API as well as the bootstrapping function ``lwip_start()``.
Calling ``lwip_start()``:

- Locates the resident lwIP App in Flash.
- Jumps to a static offset from the start of the app, where the **exports table** is linked.
- Copies the exports to the LibLoad exports table.
- Calls ``lwip_init_runtime_internal()`` with the CRT pointers and a pointer/length to a table of functions to import.
- Zeroes ``.bss``, copies ``.data`` to its correct location.
- Copies the CRT pointers and imports to an **imports table** within the App's BSS.
- Returns to the caller.

So the consumer links against the tiny stub; the stub, once bootstrapped, routes
every call into the real app in Flash.

Heap Ownership
~~~~~~~~~~~~~~~~~

lwIP-CE is an oddity with regard to heap usage because the application itself needs
some heap space of its own. However, when you use lwIP-CE as a dylib (via LibLoad),
the heap allocations of the app are not active or initialized. This was solved by:

- Setting lwIP-CE's ``BSSHEAP_HIGH`` to ``0xD072C6`` causing the app to build with only 8 KiB of BSS/Heap space. This was precomputed to fit the needed space plus some headroom.
- Direct developers building with lwIP-CE to set ``BSSHEAP_LOW`` to ``0xD072C6`` in their program's makefile. This ensures that the caller does not clash with the library's heap usage.

The practical consequence for **consumer programs**: you must move your own
``BSSHEAP_LOW`` up by 8 KiB so your variables start *above* lwIP-CE's reserved
window. In other words, link with:

.. code-block:: text

   BSSHEAP_LOW = 0xD072C6

If you leave ``BSSHEAP_LOW`` at the default, your program's BSS and lwIP-CE's
will overlap, and you will have very bad things happen.


TLS Details
------------

The TLS stack is intentionally narrow: enough to make real secure client
sockets, not a general-purpose OS crypto subsystem. A thin TLS 1.3 client is
provided.

Algorithm Support
~~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 35 25 25 15

   * - Component / Purpose
     - Algorithm
     - OID / Code
     - Status
   * - Record encryption
     - AES-128-GCM-SHA256
     - ``0x1301``
     - Done
   * - Record encryption
     - AES-256-GCM-SHA384
     - ``0x1302``
     - Not planned (optional per RFC 8446; contributions welcome)
   * - Record encryption
     - ChaCha20-Poly1305-SHA256
     - ``0x1303``
     - Not planned (optional per RFC 8446; contributions welcome)
   * - Key exchange (ECDHE)
     - X25519
     - ``0x001d``
     - Done
   * - Key exchange (ECDHE)
     - secp256r1 (P-256)
     - ``0x0017``
     - TODO
   * - Server signature verification
     - rsa_pss_rsae_sha256
     - ``0x0804``
     - Done
   * - Server signature verification
     - ecdsa_secp256r1_sha256
     - ``0x0403``
     - TODO
   * - Server signature verification
     - rsa_pkcs1_sha256
     - ``0x0401``
     - Done (chain walk only)
   * - Certificate chain — link signature
     - sha256WithRSAEncryption (PKCS#1 v1.5)
     - ``1.2.840.113549.1.1.11``
     - Done
   * - Certificate chain — link signature
     - ecdsa-with-SHA256 (P-256)
     - ``1.2.840.10045.4.3.2``
     - TODO
   * - Trust store root verification
     - RSA-PSS-SHA256
     - ``1.2.840.113549.1.1.10``
     - Done
   * - Trust store root verification
     - ECDSA-SHA256 (P-256)
     - ``1.2.840.10045.4.3.2``
     - TODO

Security Posture
~~~~~~~~~~~~~~~~~

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
     - SRAM-noise-derived, NIST SP 800-90A/90B aligned. Measured min-entropy:
       H∞ ≈ 0.99998 bits per output bit (≈ 1.00000 across the full entropy
       pool), median effective correlation k_eff = 1.031 over a 1.2 MB
       nominal dataset per unit tested. See the whitepaper for the full
       entropy analysis.
   * - TLS trust store
     - A curated trust store derived from CA material staged on a common Linux
       box, shipped as a signed AppVar and verified with RSA-PSS-SHA256 against
       an embedded public key at ``tls_truststore_init``. Entries are looked up
       by subject name to anchor the topmost certificate in a received chain
       (see Certificate chain below).
   * - Certificate chain
     - The stack walks the server's certificate chain link by link. Each link
       is checked against the next certificate's public key with RSA PKCS#1
       v1.5 / sha256WithRSAEncryption; a bad signature on an RSA-SHA256 link is
       an ``ERROR`` and aborts the handshake. Unsupported signature algorithms
       on a link, including P-256 ECDSA, raise ``ALERT("unsupported signature algorithm")``
       and are allowed to pass so the stack remains usable before P-256 verification lands.

       Once the adjacent-link walk finishes, the topmost certificate's issuer
       is looked up in the trust store by subject name. If found and the
       stored key is RSA (PSS or PKCS#1-SHA256), the topmost certificate's
       signature is verified against it for real -- a bad signature here is
       also an ``ERROR`` and aborts. If the root entry isn't RSA, or isn't in
       the trust store at all, that raises ``ALERT("CA not in root")`` and the 
       chain is accepted. **This is a temporary behavior and will normalize 
       to fail-closed once P-256 (and possibly RSA-4096) is implemented.**

   * - CertificateVerify
     - ``CertificateVerify`` is mandatory. For the current RSA path, the
       signature is verified against the leaf certificate's public key, proving
       possession of the leaf private key. This complements the best-effort
       chain walk above, but it is not a root-of-trust anchor by itself.

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
