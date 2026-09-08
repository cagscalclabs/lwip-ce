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
       <h2>Curated Release API</h2>
       <p>The release headers are generated automatically from the intersection between symbols exposed at link time and a manifest file of functions.</p>
     </article>
      <article>
       <h2>Dual-Mode Allocator</h2>
       <p>
         lwIP&apos;s pbuf-allocation system can operate dynamically or statically. It can absorb and use the caller&apos;s malloc implementation, or it can receive a statically-allocated buffer and size.
       </p>
     </article>
     <article>
       <h2>TLS And Crypto</h2>
       <p>
         TLS, certificates, hashes, AES, RSA, HKDF, HMAC, ASN.1, and random number generation--a lightweight TLS 1.3 implementation. Primitives exposed for consumer use (eg: hashing a program).
       </p>
     </article>
   </section>

   <section class="lwip-note">
     <h2>Where To Start</h2>
     <p>
       If you already know lwIP, start with the <a href="api/index.html">Usable API</a> and look for
       what is CE-specific. If you do not know lwIP yet, read the <a href="https://www.nongnu.org/lwip/2_1_x/group__callbackstyle__api.html">upstream raw API docs</a> first, then come back here for the TI-84 Plus CE-specific breakdown.
     </p>
   </section>

.. include:: _site_toc.rst
