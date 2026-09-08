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
    struct fileio_configurator
    {
        uint8_t (*ti_open)(const char *, const char *);
        int (*ti_close)(uint8_t);
        size_t (*ti_write)(const void *, size_t, size_t, uint8_t);
        size_t (*ti_read)(void *, size_t, size_t, uint8_t);
        uint16_t (*ti_getsize)(uint8_t);
        int (*ti_seek)(int, unsigned int, uint8_t);
        int (*ti_resize)(size_t, uint8_t);
        int (*ti_setarchivestatus)(uint8_t, uint8_t);
        int (*ti_delete)(const char *);
        void *(*ti_getdataptr)(uint8_t);
    } file;
};
extern struct lwip_imports fn_imports_table;
#define usb_fn  (fn_imports_table.usb)
#define file_fn (fn_imports_table.file)

/* Populate fn_imports_table.file with direct fileioc addresses. Must be called
 * at the top of main() when the lwIP flash app runs as the active OS program,
 * since the libload bootstrap (which normally fills the table) does not run. */
void lwip_fileio_self_init(void);

#endif /* lwip_imports_h */
