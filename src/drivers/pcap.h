#ifndef PCAP_H
#define PCAP_H

#include <stdbool.h>
#include <stdint.h>
#include "lwip/netif.h"

typedef enum {
    PCAP_DIR_RX = 0,
    PCAP_DIR_TX = 1,
} pcap_direction_t;
/* Staging buffer size. Sized so a full Ethernet frame record
 * (sizeof(struct pcap) + 1518) always fits in an empty buffer, which lets
 * pcap_write treat "doesn't fit" as purely "flush first, then retry". */
#define PCAP_BUFFER_LEN 2048

/* Sizing for the pool the per-interface capture buffers are carved from.
 * One buffer fits initially; the pool grows a buffer at a time up to the cap. */
#define PCAP_POOL_INIT_SIZE (PCAP_BUFFER_LEN)
#define PCAP_POOL_MAX_SIZE  (PCAP_BUFFER_LEN * 4)
#define PCAP_POOL_STEP_SIZE (PCAP_BUFFER_LEN)

typedef enum
{
    PCAP_OK,
    PCAP_ERR_ARG,
    PCAP_ERR_MEM

} pcap_err_t;

/* Per-interface capture state, embedded in the interface's device struct.
 * Records are staged into `buf` and flushed to the capture appvar in one
 * write once the next record wouldn't fit, which keeps the expensive
 * InsertMem/appvar-grow work off the per-frame path. */
struct pcap_if
{
    /* Staging buffer, or NULL when capture is off. Non-NULL is what gates
     * capture — there is no separate enable flag. */
    uint8_t *buf;
    /* Bytes currently staged in `buf` and not yet flushed. */
    size_t offset;
};

struct pcap
{
    struct netif *netif;
    char ifname[2];
    uint8_t ifnum;
    uint8_t direction;
    uint16_t len;
};

struct pcap_reader_ctx {
    char ifname_filter[2];
    /* 0xFF = no filter (match all). Safe sentinel: lwIP's netif allocator
     * reserves num=255 and never assigns it to a real interface. */
    uint8_t ifnum_filter;
    size_t offset;
    /* Open fileioc handle for the capture appvar; held for the reader's
     * lifetime so ti_getdataptr-derived pointers remain valid. Closed by
     * pcap_close_reader_ctx(). */
    uint8_t handle;
};

/**
 * @brief Applies the user's persisted pcap_enabled setting to every current
 * netif, enabling or disabling capture on each to match.
 *
 * This is the only entry point that turns capture on or off. There is
 * deliberately no per-netif enable/disable exposed to application code: the
 * user's config setting (lwip_app_config_t.pcap_enabled, set from the config
 * app UI) is the sole authority over whether traffic gets captured, so a
 * dev embedding this stack cannot silently turn capture on (or keep it on
 * after the user turned it off) from code.
 *
 * Safe to call at any time (link up/down, config change, interface added);
 * a netif already in the desired state is left alone.
 */
void pcap_apply_config(void);

/**
 * @brief Flushes any staged capture records for @b netif to the capture file.
 *
 * Records are normally staged in memory and written out in batches. Call this
 * to force a checkpoint — after it returns, everything captured so far on this
 * interface is visible to the reader API.
 *
 * @param netif The network interface to flush
 * @returns true on success or if there was nothing staged, false if the write
 * failed (which also disables capture on @b netif)
 */
bool pcap_flush(struct netif *netif);

/**
 * @brief Writes a packet capture to the capture file.
 * @param netif     The network interface the packet belongs to
 * @param dir       Inbound/outbound flag
 * @param data      Pointer to the packet payload
 * @param len       Size of the payload, in bytes
 * @returns true if written, false if error
 * @note **This function is internal, captures are netif-level.
 * Users should never need to use this function.**
 */
bool pcap_write(struct netif *netif, pcap_direction_t dir, const uint8_t *data, uint16_t len);

/**
 * @brief Releases an interface's capture buffer during device teardown.
 * @param netif The interface being torn down
 * @note **Internal.** Flushes staged records first, unless the device is
 * already dead (unplugged), in which case the tail is dropped rather than
 * running heap-moving OS routines on a teardown path.
 */
void pcap_release_on_teardown(struct netif *netif);

/**
 * @brief Initializes a cursor instance for reading the packet capture file.
 * @param ctx   Pointer to a pcap reader context
 * @returns true unless @b ctx is NULL
 * @note Flushes every capturing interface first, so the reader sees all
 * records captured up to this point.
 */
bool pcap_init_reader_ctx(struct pcap_reader_ctx *ctx);

/**
 * @brief Closes the reader context and releases the underlying file handle.
 * @param ctx   Pointer to a pcap reader context initialised by pcap_init_reader_ctx
 * @note Must be called when the caller is done reading; any pointers returned
 * by pcap_read_next become invalid after this call.
 */
void pcap_close_reader_ctx(struct pcap_reader_ctx *ctx);

/**
 * @brief Enables filter mode for the packet capture reader.
 * @param ctx   Pointer to a pcap reader context
 * @param netif Pointer to a network interface to filter for
 * @returns true unless @b ctx or @b netif are NULL
 * @note This function only has value if you are emiting a PCAP while
 * the program that uses the netif is running (as netif is a pointer).
 * If you are trying to view PCAPs generally, use @b pcap_set_filter_name_num.
 */
bool pcap_set_filter_netif(struct pcap_reader_ctx *ctx, struct netif *netif);

/**
 * @brief Enables filter mode for the packet capture reader by interface name and number.
 * @param ctx       Pointer to a pcap reader context
 * @param ifname    Two-character interface designation (e.g. "en")
 * @param ifnum     Interface number (0–254; 255 is reserved by lwIP)
 * @returns true unless @b ctx is NULL
 * @note Use this variant when reading a previously saved capture where the
 * original netif pointer is no longer available. For live captures, prefer
 * @b pcap_set_filter_netif.
 */
bool pcap_set_filter_name_num(struct pcap_reader_ctx *ctx, char ifname[2], uint8_t ifnum);

/**
 * @brief Advances the cursor to the next capture item.
 * @param ctx       Pointer to a pcap reader context
 * @param hdr       Pointer to address of the pcap header
 * @param data      Pointer to payload address
 * @returns true if success, false if @b ctx, @b header, or @b data are NULL 
 * or size is invalid, or no more records to return
 * @note Pointers returned are by reference and remain valid as long as the
 * PCAP file does not move. If you do file operations these pointers may 
 * become invalid.
 */
bool pcap_read_next(struct pcap_reader_ctx *ctx, struct pcap **hdr, const uint8_t **data);

#endif
