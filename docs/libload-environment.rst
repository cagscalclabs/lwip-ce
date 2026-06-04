LibLoad Environment
===================

lwIP-CE is too big to copy into every program that wants to use it. The core
plus TLS is around 200 KB, and the calculator only has just under 2 MB of Flash,
so statically linking it into each consumer would burn that space fast. Instead,
lwIP-CE ships as a resident **application** that other programs call into. One
copy lives on the calculator; everything else dispatches to it.

That "call into a resident app" trick is built on top of the CE toolchain's
``LIBLOAD`` mechanism -- but with some custom logic bolted on, because LIBLOAD
was not designed for this exact use case. This page explains how the two fit
together.

What LIBLOAD normally does
--------------------------

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

What lwIP-CE adds on top
------------------------

Two pieces make an Application usable as a LIBLOAD-style API source:

- The lwIP app links its own **export table** into the Flash image (the same
  idea as a library's export table). Its location is recorded so the bootstrap
  can find it later -- a byte offset from the app's base address, baked in at
  build time.
- A small **companion library** (the LIBLOAD stub the consumer actually links
  against) provides the consumer-side trampolines plus a bootstrap function. The
  bootstrap locates the installed lwIP app, reads its export table, and patches
  the local trampolines to point into the resident app.

So the consumer links against the tiny stub; the stub, once bootstrapped, routes
every ``lwip_*`` call into the real app in Flash.

The init handshake
------------------

Bringing the stack up happens in two stages -- the normal LIBLOAD part, then
lwIP-CE's own part.

**Stage 1 -- LIBLOAD does its usual thing.** When the consumer program loads,
LIBLOAD initializes the companion library exactly like any other library. The
library also pulls in ``usbdrvce`` via ``include_library``, so its imports table
gets the USB driver function pointers filled in at this point. The lwIP export
trampolines exist but are not yet patched -- calling one now would go nowhere.

**Stage 2 -- the consumer calls** ``lwip_init_runtime(malloc, free, realloc)``.
This is where the custom logic runs:

#. The three C-runtime pointers (``malloc``, ``free``, ``realloc``) are stored
   into the imports table. lwIP-CE has no libc of its own; it borrows the
   caller's.
#. The bootstrap locates the resident lwIP application by name and finds its
   base address.
#. It adds the baked-in offset to reach the app's export table, then checks a
   6-byte magic marker (``"LWIPTB"``) to make sure it found a real, compatible
   table and not a stale or mismatched build.
#. It walks the export table and patches every consumer-side trampoline:
   ``app base + offset``. After this loop, all ``lwip_*`` calls are live and
   dispatch into the app.
#. Finally -- now that the trampolines work -- it calls into the app one more
   time, to ``lwip_init_runtime_internal``. The app does the startup work that
   normally happens automatically but doesn't here (because the app was never
   "launched" in the usual sense): it zeroes its ``.bss``, copies its ``.data``
   from Flash into RAM, and copies the imports table (CRT + USB pointers) into
   its own reserved storage so its internal code can dispatch through them.

After ``lwip_init_runtime`` returns successfully, the stack is fully wired: the
consumer's malloc is in place, USB is reachable, and every API call lands in the
resident app.

Memory layout: the BSSHEAP contract
-----------------------------------

Because the lwIP app's ``.bss`` and ``.data`` get initialized at runtime (Stage
2 above), they need a fixed home in RAM that does not collide with the consumer
program's own variables. lwIP-CE reserves a **6 KiB window** starting at the
toolchain's default ``BSSHEAP_LOW`` (``0xD052C6``), running up to
``0xD06AC6``. That window holds the app's runtime ``.bss`` + ``.data`` (about
5.3 KiB in practice, with a little headroom).

The practical consequence for **consumer programs**: you must move your own
``BSSHEAP_LOW`` up by 6 KiB so your variables start *above* lwIP-CE's reserved
window. In other words, link with:

.. code-block:: text

   BSSHEAP_LOW >= 0xD06AC6

If you leave ``BSSHEAP_LOW`` at the default, your program's BSS and lwIP-CE's
will overlap, and things will corrupt in confusing ways. Bumping it 6 KiB higher
is the whole fix.

Why it is done this way
-----------------------

It would be simpler to statically link lwIP into each program -- no bootstrap, no
trampolines, no memory contract. But "simpler" here means paying ~200 KB of
Flash per program that wants networking, on a device that does not have that to
spare. The resident-app model trades a one-time init dance for a single shared
copy, stable state across callers, and a public interface that does not balloon
every consumer's binary. The handshake above is the price of admission, and it
runs once at startup.
