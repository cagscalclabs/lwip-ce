/* lwip_init_runtime_internal — runs once from inside the lwIP flash app
 * after the libload bootstrap has patched the export trampolines.
 * Performs the BSS/.data init crt0 normally does at app launch (which
 * doesn't run for us — the app isn't launched as the active OS program),
 * then copies the libload-side imports table into the app's reserved
 * fn_imports_table so app code can dispatch through usb_fn / the host
 * CRT pointers normally.
 */

#include <stddef.h>
#include <stdint.h>

#include "lwIP.h"
#include "drivers/usb_ethernet.h"

/* Linker-script-provided bounds (see linker_script_lwip.ld). */
extern uint8_t ___bss_low[];
extern uint8_t ___bss_len[];
extern uint8_t ___data_vma[];
extern uint8_t ___data_lma[];
extern uint8_t ___data_len[];

void lwip_init_runtime_internal(const void *imports_src, size_t imports_len)
{
    size_t i;
    size_t bss_len = (size_t)(uintptr_t)___bss_len;
    size_t data_len = (size_t)(uintptr_t)___data_len;
    size_t copy_len = sizeof(fn_imports_table);
    const uint8_t *src = (const uint8_t *)imports_src;
    uint8_t *dst = (uint8_t *)&fn_imports_table;

    for (i = 0; i < bss_len; i++)
    {
        ___bss_low[i] = 0;
    }
    for (i = 0; i < data_len; i++)
    {
        ___data_vma[i] = ___data_lma[i];
    }

    /* Bootstrap passes the libload-side table size as a sanity check;
     * if the lib was built against a different lwip_imports layout the
     * sizes won't match and we refuse to copy a misaligned blob. */
    if (imports_len != copy_len)
    {
        return;
    }
    for (i = 0; i < copy_len; i++)
    {
        dst[i] = src[i];
    }
}
