lwIP-CE Documentation
=====================

.. raw:: html

   <section class="lwip-hero">
     <div class="lwip-hero-copy">
       <p class="lwip-kicker">TCP/IP, TLS, and USB Ethernet for a calculator that was not consulted.</p>
       <h1>lwIP-CE</h1>
       <p class="lwip-lede">
         A real network stack forked from <a href="https://www.nongnu.org/lwip/2_1_x/">lwIP</a>, dragged onto the TI-84 Plus CE, wired through USB,
         trimmed for the platform, and packaged so C programs can actually use it.
       </p>
       <div class="lwip-actions">
         <a class="lwip-button lwip-button-primary" href="getting-started.html">Getting Started</a>
         <a class="lwip-button lwip-button-primary" href="api/index.html">Usable API</a>
         <a class="lwip-button" href="technical-details.html">Technical Details</a>
         <a class="lwip-button" href="credits.html">Credits &amp; References</a>
       </div>
     </div>
     <div class="lwip-hero-art" aria-hidden="true">
       <img src="_static/lwip-ce-console.svg" alt="" />
     </div>
   </section>

   <section class="lwip-strip">
     <p>
       This is not a mirror of lwIP&apos;s docs. The useful stuff here is the CE-specific
       behavior: what got exposed, what got cut, how the dynamic release is shaped,
       and where the sharp edges are.
     </p>
   </section>

   <section class="lwip-grid">
     <article>
       <h2>Small Machine, Real Stack</h2>
       <p>
         lwIP-CE keeps the raw lwIP model, but the build, memory profile, and USB
         Ethernet path are tuned for calculator reality instead of desktop fantasy.
       </p>
     </article>
     <article>
       <h2>Curated Release API</h2>
       <p>
         The release headers are generated from what the build can actually link,
         then filtered against a manually audited public manifest. If it is in the
         docs, it should be there on purpose.
       </p>
     </article>
     <article>
       <h2>TLS And Crypto</h2>
       <p>
         TLS, certificates, hashes, AES, RSA, HKDF, HMAC, ASN.1, and random
         generation live beside the network stack because sometimes the calculator
         needs to talk like a grown-up.
       </p>
     </article>
   </section>

   <section class="lwip-note">
     <h2>Where To Start</h2>
     <p>
       If you already know lwIP, start with the public API reference and look for
       what is CE-specific. If you do not know lwIP yet, read the upstream raw API
       docs first, then come back here for the Getting Started notes and the
       pieces that only exist because this is running on a TI-84 Plus CE.
     </p>
   </section>

.. include:: _site_toc.rst
