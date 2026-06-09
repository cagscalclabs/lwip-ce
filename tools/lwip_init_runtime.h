/**
 * @file lwip_init_runtime.h
 * @brief Libload bootstrap entry. Defined in the libload appvar
 *        (release/lwip.asm), NOT in the lwIP flash app.
 *
 * This is the one symbol a consumer reaches *before* the boomerang
 * trampoline patching has happened — it is the function that does the
 * patching. All other lwIP entry points (lwip_start, lwip_init, etc.)
 * may only be called once lwip_init_runtime() has returned true.
 */

#ifndef LWIP_INIT_RUNTIME_H
#define LWIP_INIT_RUNTIME_H

#include <stdbool.h>
#include <stdlib.h>  /* malloc / free / realloc for the wrapper macro */

#ifdef __cplusplus
extern "C" {
#endif

/** Locate the lwIP flash app, verify its export table magic, patch the
 *  libload trampolines, and run the app-side init. Returns true on
 *  success, false if the lwIP app is missing or its export-table layout
 *  doesn't match this libload build. */
bool lwip_init_runtime_opaque(void *malloc_fn, void *free_fn, void *realloc_fn);

#define lwip_init_runtime() \
    lwip_init_runtime_opaque(malloc, free, realloc)

#ifdef __cplusplus
}
#endif

#endif /* LWIP_INIT_RUNTIME_H */
