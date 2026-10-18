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
#include <usbdrvce.h>
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

void lwip_usb_self_init(void)
{
    struct usb_configurator *usb = &fn_imports_table.usb;

    usb->reset_device = usb_ResetDevice;
    usb->disable_device = usb_DisableDevice;
    usb->ref_device = usb_RefDevice;
    usb->unref_device = usb_UnrefDevice;
    usb->set_device_data = usb_SetDeviceData;
    usb->get_device_data = usb_GetDeviceData;
    usb->get_role = usb_GetRole;
    usb->get_device_flags = usb_GetDeviceFlags;
    usb->schedule_transfer = usb_ScheduleTransfer;
    usb->control_transfer = usb_ControlTransfer;
    usb->get_config_descriptor_len = usb_GetConfigurationDescriptorTotalLength;
    usb->get_descriptor = usb_GetDescriptor;
    usb->get_string_descriptor = usb_GetStringDescriptor;
    usb->set_configuration = usb_SetConfiguration;
    usb->set_interface = usb_SetInterface;
    usb->get_device_endpoint = usb_GetDeviceEndpoint;
    usb->set_endpoint_data = usb_SetEndpointData;
    usb->get_endpoint_data = usb_GetEndpointData;
    usb->set_endpoint_flags = usb_SetEndpointFlags;
    usb->set_endpoint_halt = usb_SetEndpointHalt;
    usb->init = usb_Init;
    usb->handle_events = usb_HandleEvents;
    usb->cleanup = usb_Cleanup;
    usb->find_device = usb_FindDevice;
    usb->schedule_control_transfer = usb_ScheduleControlTransfer;
}
