#ifndef PCAP_H
#define PCAP_H

#include <stdbool.h>
#include <stdint.h>
#include "lwip/netif.h"

typedef enum {
    PCAP_DIR_RX = 0,
    PCAP_DIR_TX = 1,
} pcap_direction_t;

struct pcap {
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
};

/// @brief Enables packet capture for the given netif
bool pcap_enable_on_netif(struct netif *netif);

/// @brief Disables packet capture for the given netif
bool pcap_disable_on_netif(struct netif *netif);

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
 * @brief Initializes a cursor instance for reading the packet capture file.
 * @param ctx   Pointer to a pcap reader context
 * @returns true unless @b ctx is NULL
 */
bool pcap_init_reader_ctx(struct pcap_reader_ctx *ctx);

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
