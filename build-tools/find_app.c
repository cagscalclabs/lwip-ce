/* Locate the installed "lwIP" flash application by walking the CE app table.
 *
 * Emitted to assembly and folded into the libload stub (lwip.asm) so the
 * runtime init can safely answer "is the lwIP app present?" — the OS
 * FindAppStart routine is not safe to call when the app is absent.
 *
 * Apps are stored descending from the top of the flash app region. Each is
 * preceded (at its high end) by a 24-bit size; a size of 0xFFFFFF marks the
 * end of the table. The CE app header is 0x100 bytes; the app name is a
 * length-prefixed string a few bytes in.
 *
 * Kept dependency-free on purpose (no strlen/strncmp/CRT helpers): the
 * emitted asm must drop straight into the stub without pulling extra symbols.
 * Build:  ez80-clang -S -Oz find_app.c   (see build-tools/functable.py).
 */

#include <stdbool.h>
#include <stdint.h>

/* Top of the flash application region (exclusive). */
#define CE_APP_REGION_TOP   ((const uint8_t *)0x3B0000)
/* CE app header size; the name token sits at header + 3. */
#define CE_APP_NAME_OFFSET  (0x100 + 3)

bool find_lwip_app(void)
{
    uintptr_t app = (uintptr_t)CE_APP_REGION_TOP;
    while (true)
    {
        app -= sizeof(uint24_t);
        const uint24_t size = *(const uint24_t *)app;
        if (size == UINT24_MAX)
            return false;          /* end of app table; not found */
        app -= size;

        const char *name = (const char *)(app + CE_APP_NAME_OFFSET);
        if (name[0] == 'l' && name[1] == 'w' &&
            name[2] == 'I' && name[3] == 'P' && name[4] == '\0')
            return true;
    }
}
