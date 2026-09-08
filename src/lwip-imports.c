/****************************************************************************
 * Backing storage for the unified imports table.
 *
 * The libload bootstrap (release/lwip.asm) populates this at load by
 * calling lwip_init_runtime_internal with its own libload-side copy.
 *
 * When the lwIP flash app runs as the active OS program (not via libload),
 * the bootstrap never runs and fn_imports_table remains zero. Call
 * lwip_fileio_self_init() before any file_fn dispatch in that path.
 */

#include <fileioc.h>
#include "lwip-imports.h"

struct lwip_imports fn_imports_table = {0};

/* ti_SetArchiveStatus is both a function and a convenience macro in fileioc.h.
 * Undefine the macro so we can take the underlying function's address. */
#ifdef ti_SetArchiveStatus
#undef ti_SetArchiveStatus
#endif

void lwip_fileio_self_init(void)
{
    fn_imports_table.file.ti_open             = ti_Open;
    fn_imports_table.file.ti_close            = ti_Close;
    fn_imports_table.file.ti_write            = ti_Write;
    fn_imports_table.file.ti_read             = ti_Read;
    fn_imports_table.file.ti_getsize          = ti_GetSize;
    fn_imports_table.file.ti_seek             = ti_Seek;
    fn_imports_table.file.ti_resize           = ti_Resize;
    fn_imports_table.file.ti_setarchivestatus = ti_SetArchiveStatus;
    fn_imports_table.file.ti_delete           = ti_Delete;
    fn_imports_table.file.ti_getdataptr       = ti_GetDataPtr;
}
