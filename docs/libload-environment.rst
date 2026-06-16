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

How lwIP Works with LibLoad
----------------------------

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
     *magic header*; a missing header or a size mismatch against what the
     companion expects is also a failure.
  3. Once both checks pass, copy the *export table* into the second-layer
     LibLoad jump table in ``lwip.8xv``.
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
   | verify "LWIPTB" magic and export count                      |
   | mismatch -> fail closed (stale / incompatible app)          |
   +-------------------------------------------------------------+
                              |
                              v
   +-------------------------------------------------------------+
   | patch each trampoline -> relocated in-app address           |
   | after this loop, every call dispatches into the app         |
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
-----------------------------------

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
-----------------------

It would be simpler to statically link lwIP into each program -- no bootstrap, no
trampolines, no memory contract. But "simpler" here means paying ~350 KB of
Flash per program that wants networking, on a device that does not have that to
spare. The resident-app model trades a one-time init dance for a single shared
copy, stable state across callers, and a public interface that does not balloon
every consumer's binary. The handshake above is the price of admission, and it
runs once at startup.
