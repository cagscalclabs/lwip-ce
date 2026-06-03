/****************************************************************************
 * Unified imports table for the lwIP flash app.
 *
 * Holds the host CRT allocator pointers and the USB driver vtable that
 * lwIP's code dispatches through. The lwIP app holds the backing storage
 * (fn_imports_table); the libload bootstrap copies its own libload-side
 * table into it during init (see lwip_init_runtime_internal).
 */

#ifndef lwip_imports_h
#define lwip_imports_h

#include <stddef.h>

#include "drivers/usb_ethernet.h" /* struct usb_configurator */

/* Host CRT + USB vtable lwIP's code dispatches through. The lwIP app
 * holds the backing storage; the libload bootstrap copies its own
 * libload-side table into fn_imports_table during init. */
struct lwip_imports {
    void  *(*malloc)(size_t);
    void   (*free)(void *);
    void  *(*realloc)(void *, size_t);
    struct usb_configurator usb;
};
extern struct lwip_imports fn_imports_table;
#define usb_fn (fn_imports_table.usb)

#endif /* lwip_imports_h */
