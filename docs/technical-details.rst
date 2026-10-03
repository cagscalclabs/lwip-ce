Technical Details
=================

This page covers the LibLoad bootstrap internals, memory layout, and the
deeper engineering notes behind the stack.

LibLoad Environment
-------------------

lwIP-CE is too big to copy into every program that wants to use it. The core
plus TLS is around 200 KB, and the calculator only has just under 2 MB of Flash,
so statically linking it into each consumer would burn that space fast. Instead,
lwIP-CE ships as a resident **application** that other programs call into. One
copy lives on the calculator; everything else dispatches to it.

That "call into a resident app" trick is built on top of the CE toolchain's
``LIBLOAD`` mechanism -- but with some custom logic bolted on, because LIBLOAD
was not designed for this exact use case. This section explains how the two fit
together.

What LIBLOAD normally does
~~~~~~~~~~~~~~~~~~~~~~~~~~

LIBLOAD is the toolchain's way of sharing code between programs without
recompiling it into each one. The usual flow looks like this:

- A library exposes a list of exported functions (its public API).
- At link time, those exports become a jump table -- one trampoline per
  function, each holding an *offset* rather than a real address.
- When a consumer program starts, a LIBLOAD bootstrap finds the library in
  memory and rewrites each trampoline: ``real address = library base + offset``.
- After that, calling an API function just hits its trampoline, which jumps to
  the resolved address.

This works great for small libraries that live in RAM as AppVars. The catch:
LIBLOAD assumes the *library* is the thing being loaded. lwIP-CE is an
**Application** sitting in Flash, not a RAM AppVar, so it needs a bit more.

How lwIP Works with LibLoad
~~~~~~~~~~~~~~~~~~~~~~~~~~~

A few working pieces make an Application usable as a LIBLOAD-style API source:

- The resident app (lwIP) links its own **export table** which is an exhaustive list of absolute
  addresses to all its publicly exported symbols into the Flash image at a fixed offset from ``app_base``.
- The resident app also reserves a slice of static memory at ``BSSHEAP_LOW`` just large enough to
  hold everything it requires (measured from the link output of the size of the BSS and data sections).
- The reserved BSS also holds an uninitialized **import table** which is an exhaustive list of the
  runtime addresses of any caller-owned functions: malloc implementation, and other LibLoad library imports.
- A small **companion library** linked as a LibLoad library provides a double-indirection of absolute
  jumps. The first layer is the ordinary LIBLOAD exports, relocated directly into the calling program — patching those in place would be awkward. The second layer adds a level of indirection at a fixed, known runtime address, which the companion can safely rewrite.
- The companion library provides ``lwip_init_runtime`` (and the underlying
  ``lwip_init_runtime_opaque``, which takes the import pointers explicitly --
  ``lwip_init_runtime`` is a thin wrapper that fills those in for the common
  case). Bootstrapping happens in three steps:

  1. Import ``malloc``, ``free``, ``realloc``, and any other LibLoad-imported
     function lwIP needs, and write them into an *import table*.
  2. Locate the lwIP Application, failing if it isn't installed. If found,
     jump to the fixed offset where the jump table lives and check for a
     *magic header*; a missing header is a failure.
  3. Once the magic check passes, copy the shared prefix of the resident
     app's *export table* and the companion library's expected export count
     into the second-layer LibLoad jump table in ``lwip.8xv``. Count
     differences are tolerated: trailing newer exports simply remain
     unavailable to that app/stub pairing.
  4. Once the *export table* is patched, ``lwip_init_runtime_internal`` is called
     which takes a pointer to the *import table* and the size of table. This function
     first initializes the ``.bss`` and ``.data`` sections of the Application's runtime
     and then copies the provided *import table* into its own BSS before returning control
     to the caller.

So the consumer links against the tiny stub; the stub, once bootstrapped, routes
every call into the real app in Flash.

The whole sequence, end to end:

.. code-block:: text

   +-------------------------------------------------------------+
   | LIBLOAD loads the companion library                         |
   | USB vtable filled via include_library 'usbdrvce';           |
   +-------------------------------------------------------------+
                              |
                              v
   +-------------------------------------------------------------+
   | consumer calls lwip_init_runtime(malloc, free, realloc)     |
   | -> host CRT pointers written into the imports table         |
   +-------------------------------------------------------------+
                              |
                              v
   +-------------------------------------------------------------+
   | bootstrap locates resident app and computes linked image    |
   | app not found -> fail closed                                |
   | base from app metadata; + fixed  offset -> export table     |
   +-------------------------------------------------------------+
                              |
                              v
   +-------------------------------------------------------------+
   | verify "LWIPTB" magic                                      |
   | missing/invalid descriptor -> fail closed                   |
   +-------------------------------------------------------------+
                              |
                              v
   +-------------------------------------------------------------+
   | patch shared export prefix -> relocated in-app address      |
   | trailing newer exports remain unavailable to this pairing   |
   +-------------------------------------------------------------+
                              |
                              v
   +-------------------------------------------------------------+
   | call lwip_init_runtime_internal  (now reachable!)           |
   | app zeroes .bss, copies .data from Flash,                   |
   | copies imports table into its reserved storage              |
   +-------------------------------------------------------------+
                              |
                              v
                     stack ready to use

The ordering is the subtle part: ``lwip_init_runtime_internal`` is itself an
exported call, so it can only run *after* the trampolines are patched. The
bootstrap reaches into the app to finish setting up the app.

Memory layout: the BSSHEAP contract
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Because the lwIP app's ``.bss`` and ``.data`` get initialized at runtime (Stage
2 above), they need a fixed home in RAM that does not collide with the consumer
program's own variables. lwIP-CE reserves an **8 KiB window** starting at the
toolchain's default ``BSSHEAP_LOW`` (``0xD052C6``), running up to
``0xD072C6``. That window holds the app's runtime ``.bss`` + ``.data`` (about
6.6 KiB in practice, with the rest as headroom for API growth).

The practical consequence for **consumer programs**: you must move your own
``BSSHEAP_LOW`` up by 8 KiB so your variables start *above* lwIP-CE's reserved
window. In other words, link with:

.. code-block:: text

   BSSHEAP_LOW >= 0xD072C6

If you leave ``BSSHEAP_LOW`` at the default, your program's BSS and lwIP-CE's
will overlap, and you will have very bad things happen.

Why it is done this way
~~~~~~~~~~~~~~~~~~~~~~~

It would be simpler to statically link lwIP into each program -- no bootstrap, no
trampolines, no memory contract. But "simpler" here means paying ~350 KB of
Flash per program that wants networking, on a device that does not have that to
spare. The resident-app model trades a one-time init dance for a single shared
copy, stable state across callers, and a public interface that does not balloon
every consumer's binary. The handshake above is the price of admission, and it
runs once at startup.

Configuration Wizard
--------------------

lwIP-CE has a configuration wizard that opens when you run the app. It keeps the
resident stack policy in one place:

- Hostname
- Static IPv4 settings
- Timezone, DST settings
- TLS enabled/disabled

The options present end-users with a modest level of control over how the stack behaves
on their device. Particularly with TLS. While this TLS implementation is decently-engineered
not everyone will feel comfortable connecting to secure services from an insecure device.
With TLS flagged off in the App settings, attempts by programs to use TLS will fail-closed
immediately unconditionally, giving end users the final authority.


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
