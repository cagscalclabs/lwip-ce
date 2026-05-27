Technical Details
=================

This page collects the engineering notes that are deeper than the public API
reference: the design whitepaper, the CI validation harnesses, and the test
fixtures that keep the calculator build honest.

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

For the details behind the cryptographic choices and the current validation
boundaries, read the whitepaper above.
