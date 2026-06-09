/****************************************************************************
 * Backing storage for the unified imports table.
 *
 * The libload bootstrap (release/lwip.asm) populates this at load by
 * calling lwip_init_runtime_internal with its own libload-side copy.
 */

#include "lwip-imports.h"

struct lwip_imports fn_imports_table = {0};
