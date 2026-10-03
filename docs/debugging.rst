Debugging
=========

lwIP-CE provides two complementary tools for diagnosing problems: a **live event
callback** that fires as the stack runs, and a **traceback buffer** that captures
the most recent WARN and ERROR events so you can read them after the fact. Neither
requires a debugger or a serial console — both work on real hardware.

Unified event callback
----------------------

All modules (USB driver, TLS, allocator, socket layer, WebSocket) route their
events through a single callback registered with ``lwip_set_event_cb()``:

.. code-block:: c

   void lwip_set_event_cb(lwip_event_fn event_fn);

Pass ``NULL`` to disable (callback is disabled by default). The callback signature is:

.. code-block:: c

   typedef void (*lwip_event_fn)(const struct lwip_event *ev);

``struct lwip_event`` has two fixed fields and a union:

.. code-block:: c

   struct lwip_event {
       uint8_t module;   /* lwip_debug_module_t — which component fired */
       uint8_t kind;     /* lwip_event_kind_t   — what kind of event    */
       union { ... } data;
   };

**Module values** (``ev->module``):

.. list-table::
   :header-rows: 1
   :widths: 35 65

   * - Constant
     - Component
   * - ``LWIP_DBG_MOD_LWIP``
     - Socket/connection layer, netif, dispatch
   * - ``LWIP_DBG_MOD_USB``
     - USB Ethernet driver
   * - ``LWIP_DBG_MOD_MEM``
     - Custom allocator
   * - ``LWIP_DBG_MOD_TLS``
     - TLS handshake, record layer, crypto
   * - ``LWIP_DBG_MOD_WS``
     - WebSocket framing layer

Call ``lwip_debug_module_name(ev->module)`` for a human-readable label (e.g.
``"tls"``).

**Event kinds** (``ev->kind``):

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Kind
     - Meaning and ``data`` field used
   * - ``LWIP_EV_INFO``
     - Normal progress milestone. ``data.msg`` is a literal string.
   * - ``LWIP_EV_DEBUG``
     - Trace point. Self-throttled: only fires when the ``{file, line}``
       changes from the previous DEBUG emit. ``data.code.loc`` encodes the
       location; ``data.code.extra`` is 0.
   * - ``LWIP_EV_WARN``
     - The stack noticed a problem but chose to proceed (for example, an
       unsupported certificate link type that was tolerated). ``data.code``
       carries the location and an optional extra value.
   * - ``LWIP_EV_ERROR``
     - Hard failure. ``data.code`` carries the location and optional extra.
   * - ``LWIP_EV_STATE_CHG``
     - A meaningful state transition. ``data.state.owner`` is the object
       (e.g. a socket pointer); ``data.state.change_event`` is a
       ``lwip_state_change_t`` value.
   * - ``LWIP_EV_IO_FILE``
     - AppVar or Flash read/write. ``data.file.dir`` (``LWIP_IO_READ`` /
       ``LWIP_IO_WRITE``), ``data.file.name``, ``data.file.bytes``.
   * - ``LWIP_EV_IO_ETH``
     - Network bytes received or sent. ``data.eth.dir`` (``LWIP_IO_RX`` /
       ``LWIP_IO_TX``), ``data.eth.bytes``.
   * - ``LWIP_EV_POWER``
     - USB or battery power state change. ``data.power.subtype``
       (``lwip_power_event_t``), ``data.power.charging``.

**State change values** for ``LWIP_EV_STATE_CHG``:

.. list-table::
   :header-rows: 1
   :widths: 45 55

   * - Constant
     - Meaning
   * - ``LWIP_STATE_LINK_UP`` / ``LWIP_STATE_LINK_DOWN``
     - Ethernet link state changed.
   * - ``LWIP_STATE_IP_ACQUIRED`` / ``LWIP_STATE_IP_LOST``
     - DHCP address assigned or lost.
   * - ``LWIP_STATE_CONN_CONNECTING``
     - Connection attempt in progress.
   * - ``LWIP_STATE_CONN_ESTABLISHED``
     - Connection is up and ready for I/O.
   * - ``LWIP_STATE_CONN_CLOSED``
     - Connection closed cleanly.
   * - ``LWIP_STATE_CONN_FAILED``
     - Connection failed (error or timeout).
   * - ``LWIP_STATE_TLS_HANDSHAKE_BEGIN``
     - TLS handshake started.
   * - ``LWIP_STATE_TLS_HANDSHAKE_DONE``
     - TLS handshake succeeded.
   * - ``LWIP_STATE_TLS_HANDSHAKE_FAILED``
     - TLS handshake failed.

Call ``lwip_debug_state_change_name(ev->data.state.change_event)`` for a
human-readable label (e.g. ``"conn_established"``).

**Decoding a code event location:**

ERROR, WARN, and DEBUG events encode ``{file_id, line}`` into ``data.code.loc``:

.. code-block:: c

   uint8_t  file_id = LWIP_EVENT_CODE_FILE(ev->data.code.loc);
   uint32_t line    = LWIP_EVENT_CODE_LINE(ev->data.code.loc);
   uint16_t extra   = ev->data.code.extra;   /* 0 for bare ERROR()/WARN() */

   /* Human-readable file name: */
   const char *filename = lwip_debug_file_name(file_id);  /* e.g. "handshake.c" */

**Minimal event callback example:**

.. code-block:: c

   #include <lwip.h>
   #include <ti/screen.h>
   #include <stdio.h>

   static void on_event(const struct lwip_event *ev)
   {
       char buf[80];
       switch (ev->kind) {
       case LWIP_EV_INFO:
           snprintf(buf, sizeof(buf), "[info] %s\n", ev->data.msg);
           break;
       case LWIP_EV_WARN:
           snprintf(buf, sizeof(buf), "[warn] %s:%lu extra=%u\n",
                    lwip_debug_file_name(LWIP_EVENT_CODE_FILE(ev->data.code.loc)),
                    LWIP_EVENT_CODE_LINE(ev->data.code.loc),
                    ev->data.code.extra);
           break;
       case LWIP_EV_ERROR:
           snprintf(buf, sizeof(buf), "[error] %s:%lu extra=%u\n",
                    lwip_debug_file_name(LWIP_EVENT_CODE_FILE(ev->data.code.loc)),
                    LWIP_EVENT_CODE_LINE(ev->data.code.loc),
                    ev->data.code.extra);
           break;
       case LWIP_EV_STATE_CHG:
           snprintf(buf, sizeof(buf), "[state] %s\n",
                    lwip_debug_state_change_name(ev->data.state.change_event));
           break;
       default:
           return;
       }
       os_PutStrFull(buf);
   }

   int main(void)
   {
       lwip_set_event_cb(on_event);
       if (!lwip_start()) return 1;
       /* ... */
   }

Traceback
---------

The event callback fires in real time. If a failure happens mid-handshake, you
may not have a screen up yet, or the failure may be buried inside a chain of
callbacks. The **traceback buffer** captures the most recent WARN and ERROR events
(and socket-layer errors) automatically, in newest-first order. Read it any time
after a failure:

.. code-block:: c

   const struct lwip_traceback_entry *lwip_get_traceback(uint8_t *count);

``count`` is filled with the number of entries. The returned pointer is owned by
lwIP and is valid until the next call to ``lwip_get_traceback()`` or until a new
entry is pushed into the buffer. Copy what you need before calling anything else.

``struct lwip_traceback_entry`` fields:

.. list-table::
   :header-rows: 1
   :widths: 25 20 55

   * - Field
     - Type
     - Meaning
   * - ``module``
     - ``uint8_t``
     - ``lwip_debug_module_t`` — which component raised the event.
   * - ``kind``
     - ``uint8_t``
     - ``lwip_event_kind_t`` — ``LWIP_EV_WARN`` or ``LWIP_EV_ERROR`` for code
       entries; other values for socket-wrapper entries.
   * - ``file``
     - ``uint8_t``
     - ``lwip_debug_file_id_t`` — source file. Pass to
       ``lwip_debug_file_name()`` to get the filename string. Zero for
       socket-wrapper entries (the causal ERROR is expected to precede them).
   * - ``line``
     - ``uint32_t``
     - Source line number. Zero for socket-wrapper entries.
   * - ``extra``
     - ``uint16_t``
     - Optional extra code from ``ERROR_CODE()`` / ``WARN_CODE()``; 0 for bare
       ``ERROR()`` / ``WARN()``.
   * - ``component``
     - ``uint16_t``
     - ``lwip_socket_error_component_t`` for socket-wrapper entries; 0 otherwise.
   * - ``operation``
     - ``uint16_t``
     - ``lwip_socket_error_operation_t`` for socket-wrapper entries; 0 otherwise.
   * - ``raw_error``
     - ``int``
     - Raw ``err_t`` or module-specific code for socket-wrapper entries; 0 otherwise.
   * - ``mapped_error``
     - ``uint16_t``
     - ``lwip_error_t`` for socket-wrapper entries; 0 otherwise.
   * - ``status``
     - ``uint16_t``
     - ``lwip_status_t`` for socket-wrapper entries; 0 otherwise.

**Traceback walkthrough example:**

.. code-block:: c

   uint8_t count;
   const struct lwip_traceback_entry *tb = lwip_get_traceback(&count);

   for (uint8_t i = 0; i < count; i++) {
       const struct lwip_traceback_entry *e = &tb[i];
       if (e->file) {
           /* Code-level WARN or ERROR */
           printf("[%s] %s:%lu",
                  lwip_debug_module_name(e->module),
                  lwip_debug_file_name(e->file),
                  e->line);
           if (e->extra)
               printf(" extra=0x%04x", e->extra);
           printf("\n");
       } else {
           /* Socket-wrapper error entry */
           printf("[socket] component=%u op=%u raw=%d mapped=%u status=%u\n",
                  e->component, e->operation,
                  e->raw_error, e->mapped_error, e->status);
       }
   }

.. note::

   ``DEBUG`` events do not occupy traceback slots — they are callback-only.
   Only WARN, ERROR, and socket-wrapper errors are captured.
