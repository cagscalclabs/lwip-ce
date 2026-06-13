/****************************************************************************
 * Header File for Communications Data Class (CDC)
 * for USB-Ethernet devices
 * Includes definitions for CDC-ECM and CDC-NCM
 */

#ifndef cdc_h
#define cdc_h

#include <stdint.h>
#include <usbdrvce.h>
#include "mem.h"

#include "lwip/err.h"
#include "lwip/netif.h"

#define USB_CDC_MAX_RETRIES 3

/* Ethernet MTU - ECM & NCM */
#define ETHERNET_MTU 1518

/* Interrupt buffer size */
#define INTERRUPT_RX_MAX 64

/* NCM rx ntb size */
#define NCM_RX_NTB_MAX_SIZE 2048

/* USB CDC Ethernet Device Classes */
#define USB_ECM_SUBCLASS 0x06
#define USB_NCM_SUBCLASS 0x0D

/* Descriptor Class Codes */
#define USB_CS_INTERFACE_DESCRIPTOR 0x24
#define USB_UNION_FUNCTIONAL_DESCRIPTOR 0x06
#define USB_ETHERNET_FUNCTIONAL_DESCRIPTOR 0x0F
#define USB_NCM_FUNCTIONAL_DESCRIPTOR 0x1A

/* Class-Specific Interface Descriptor*/
typedef struct
{
    uint8_t bLength;
    uint8_t bDescriptorType;
    uint8_t bDescriptorSubType;
    uint8_t data[];
} usb_cs_interface_descriptor_t;

/* Union Functional Descriptor*/
typedef struct
{
    uint8_t bFunctionLength;
    uint8_t bDescriptorType;
    uint8_t bDescriptorSubType;
    uint8_t bControlInterface;
    uint8_t bInterface;
} usb_union_functional_descriptor_t;

/* Ethernet Functional Descriptor */
typedef struct
{
    uint8_t bFunctionLength;
    uint8_t bDescriptorType;
    uint8_t bDescriptorSubType;
    uint8_t iMacAddress;
    uint8_t bmEthernetStatistics[4];
    uint8_t wMaxSegmentSize[2];
    uint8_t wNumberMCFilters[2];
    uint8_t bNumberPowerFilters;
} usb_ethernet_functional_descriptor_t;

/* NCM Functional Descriptor*/
typedef struct
{
    uint8_t bFunctionLength;
    uint8_t bDescriptorType;
    uint8_t bDescriptorSubType;
    uint16_t bcdNcmVersion;
    uint8_t bmNetworkCapabilities;
} usb_ncm_functional_descriptor_t;

/* CDC Control Request Codes */
enum _cdc_request_codes
{
    REQUEST_SEND_ENCAPSULATED_COMMAND = 0,
    REQUEST_GET_ENCAPSULATED_RESPONSE,
    REQUEST_SET_ETHERNET_MULTICAST_FILTERS = 0x40,
    REQUEST_SET_ETHERNET_POWER_MANAGEMENT_PATTERN_FILTER,
    REQUEST_GET_ETHERNET_POWER_MANAGEMENT_PATTERN_FILTER,
    REQUEST_SET_ETHERNET_PACKET_FILTER,
    REQUEST_GET_ETHERNET_STATISTIC,
    REQUEST_GET_NTB_PARAMETERS = 0x80,
    REQUEST_GET_NET_ADDRESS,
    REQUEST_SET_NET_ADDRESS,
    REQUEST_GET_NTB_FORMAT,
    REQUEST_SET_NTB_FORMAT,
    REQUEST_GET_NTB_INPUT_SIZE,
    REQUEST_SET_NTB_INPUT_SIZE,
    REQUEST_GET_MAX_DATAGRAM_SIZE,
    REQUEST_SET_MAX_DATAGRAM_SIZE,
    REQUEST_GET_CRC_MODE,
    REQUEST_SET_CRC_MODE,
};

/* CDC Notification Codes */
enum _cdc_notification_codes
{
    NOTIFY_NETWORK_CONNECTION,
    NOTIFY_RESPONSE_AVAILABLE,
    NOTIFY_CONNECTION_SPEED_CHANGE = 0x2A
};

/* Defines dummy struct for ECM instance data (no data) */
struct _ecm
{
    uint8_t dummy;
};

/* Defines NTB Parameter Structure for CDC-NCM */
struct _ntb_params
{
    uint16_t wLength;
    uint16_t bmNtbFormatsSupported;
    uint32_t dwNtbInMaxSize;
    uint16_t wNdpInDivisor;
    uint16_t wNdpInPayloadRemainder;
    uint16_t wNdpInAlignment;
    uint16_t reserved;
    uint32_t dwNtbOutMaxSize;
    uint16_t wNdpOutDivisor;
    uint16_t wNdpOutPayloadRemainder;
    uint16_t wNdpOutAlignment;
    uint16_t wNtbOutMaxDatagrams;
};

/* Defines struct for NCM instance data */
struct _ncm
{
    uint8_t bm_capabilities;       // device capabilities
    uint16_t sequence;             // per NCM device - transfer sequence counter
    struct _ntb_params ntb_params; // NTB parameters for TX
};

// usb device metadata
typedef struct _eth_device_t
{
    usb_device_t device;
    uint8_t type;
    uint8_t hwaddr[6];
    bool rx_transfer_active;
    /* Per-device retry counters and "fatal" flag. Previously these were
     * function-static globals, which interleaved across multiple devices
     * and could trip device A's fatal threshold from device B's
     * transient errors. */
    uint8_t rx_retries;
    uint8_t tx_retries;
    uint8_t int_retries;
    /* Consecutive RX-drain invariant failures (pbuf chain too small for a
     * queued frame). Reset to 0 on any clean drain pass; when it reaches
     * ETH_RX_DRAIN_MAX_ERRORS the netif is aborted. See eth_rx_ring_drain. */
    uint8_t rx_drain_errors;
    bool disabled_with_error;
    bool shutting_down;
    bool dhcp_auto_started;
    struct mem_buffer *rx_ring;
    struct
    {
        usb_endpoint_t endpoint;
        usb_error_t (*callback)(usb_endpoint_t endpoint, usb_transfer_status_t status,
                                size_t transferred, usb_transfer_data_t *data);
        uint8_t buf[NCM_RX_NTB_MAX_SIZE];
    } rx;
    struct
    {
        usb_endpoint_t endpoint;
        err_t (*emit)(struct netif *netif, struct pbuf *p);
    } tx;
    struct
    {
        usb_endpoint_t endpoint;
        uint8_t buf[INTERRUPT_RX_MAX];
    } interrupt;
    union
    {
        struct _ncm ncm;
        struct _ecm ecm;
    } class;
    struct netif iface;
} eth_device_t;
extern eth_device_t eth;

/// @brief Callback function to be passed to @b usb_Init to enable Ethernet driver for lwIP
usb_error_t eth_usb_event_callback(usb_event_t event, void *event_data, usb_callback_data_t *callback_data);

/** @brief Halt every USB endpoint backing every active ethernet netif.
 *  Used during stack shutdown to quiesce the device-side transport
 *  before lwIP tears down its PCBs. After this call the USB driver
 *  will reject further schedule_transfer requests for these
 *  endpoints, ensuring no in-flight frames arrive mid-teardown. */
void eth_halt_all_endpoints(void);

/** @brief Enter intentional stack shutdown mode.
 *  Transfer callbacks stop re-arming endpoints and suppress endpoint
 *  errors caused by USB cleanup/disconnect sequencing.
 */
void eth_prepare_shutdown(void);

/** @brief Finalize intentional shutdown immediately before usb_Cleanup.
 *  Driver objects remain allocated until process/runtime reset so late USB
 *  callbacks still have valid inert callback data to inspect.
 */
void eth_finish_shutdown(void);

/** @brief Leave intentional shutdown mode before a new usb_Init attempt. */
void eth_reset_shutdown(void);


struct usb_configurator {
    // device interfacing
    usb_error_t (*reset_device)(usb_device_t device);
    usb_error_t (*disable_device)(usb_device_t device);
    usb_device_t (*ref_device)(usb_device_t device);
    usb_device_t (*unref_device)(usb_device_t device);
    void (*set_device_data)(usb_device_t device, usb_device_data_t *data);
    usb_device_data_t* (*get_device_data)(usb_device_t device);
    usb_role_t (*get_role)(void);
    usb_device_flags_t (*get_device_flags)(usb_device_t device);
    usb_error_t (*schedule_transfer)(usb_endpoint_t endpoint, void *buffer, size_t length,
                                     usb_transfer_callback_t handler,
                                     usb_transfer_data_t *data);
    usb_error_t (*control_transfer)(usb_endpoint_t device,
                                    const usb_control_setup_t *setup,
                                    void *buffer, unsigned retries,
                                    size_t *transferred);
    
    // descriptor interfacing
    size_t (*get_config_descriptor_len)(usb_device_t device, uint8_t index);
    usb_error_t (*get_descriptor)(usb_device_t device, usb_descriptor_type_t type, uint8_t index, void *descriptor, size_t length, size_t *transferred);
    usb_error_t (*get_string_descriptor)(usb_device_t device, uint8_t index, uint16_t langid, usb_string_descriptor_t *descriptor, size_t length, size_t *transferred);
    
    // configuration/interface interfacing
    usb_error_t (*set_configuration)(usb_device_t device,
                                     const usb_configuration_descriptor_t *descriptor,
                                     size_t length);
    usb_error_t (*set_interface)(usb_device_t device,
                                 const usb_interface_descriptor_t *descriptor,
                                 size_t length);
    
    // endpoint interfacing
    usb_endpoint_t (*get_device_endpoint)(usb_device_t device, uint8_t address);
    void (*set_endpoint_data)(usb_endpoint_t endpoint, usb_endpoint_data_t *data);
    usb_endpoint_data_t* (*get_endpoint_data)(usb_endpoint_t endpoint);
    void (*set_endpoint_flags)(usb_endpoint_t endpoint, usb_endpoint_flags_t flags);
    usb_error_t (*set_endpoint_halt)(usb_endpoint_t endpoint);

    // top-level USB driver entry points (formerly called directly by lwIP;
    // now routed through the vtable so the libload build can resolve them
    // via include_library '../usbdrvce/usbdrvce.asm' without a special case).
    usb_error_t (*init)(usb_event_callback_t handler, usb_callback_data_t *data,
                        const usb_standard_descriptors_t *device_descriptors,
                        usb_init_flags_t flags);
    usb_error_t (*handle_events)(void);
    void (*cleanup)(void);
};

/* The unified imports table (struct lwip_imports, fn_imports_table, and
 * the usb_fn dispatch macro) lives in lwip-imports.h. It is not included
 * here to avoid a circular dependency: lwip-imports.h embeds
 * struct usb_configurator and so includes this header. Files that need
 * usb_fn / fn_imports_table should include "lwip-imports.h" directly. */

/// @brief Polls for the registration status of interfaces.
/// @return A bitmap indicating what NETIFs are registered (netif->num)
/// @note Example: a return value of 0b00001101 indicates that en0, en2, and en3 currently exist.
/// @note The ifnum assignment system seeks to the next free ifnum.
/// @note Up to 8 simultaneous interfaces allowed. Any more causes device init to fail.
uint8_t eth_get_interfaces(void);

/// @brief Reports whether an ethernet netif has been brought down by an
///        unrecoverable link/device error (endpoint retry exhaustion or
///        RX-drain invariant failure).
/// @param netif The interface to query. May be NULL or a non-ethernet
///        netif, in which case the result is false.
/// @return true if the interface was aborted with an error and disabled;
///         false otherwise (including healthy, or simply down via the
///         normal admin path).
bool netif_is_link_error(const struct netif *netif);

#ifdef LWIP_ETHERNET_TEST_HOOKS
bool eth_test_ring_push_frame(eth_device_t *dev, const uint8_t *data, uint16_t len);
size_t eth_test_rx_ring_drain(struct mem_buffer *rb, void *user, size_t budget);
void eth_test_schedule_rx_for_netifs(void);
usb_error_t eth_test_ecm_receive(eth_device_t *dev, const uint8_t *frame, size_t len);
usb_error_t eth_test_ncm_receive(eth_device_t *dev, const uint8_t *ntb, size_t len);
#endif

#endif
