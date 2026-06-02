#include <ti/screen.h>
#include <ti/getkey.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "usb_ethernet.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"

extern int ethernet_test_pbuf_alloc_fail;

static uint8_t captured[4][64];
static uint16_t captured_len[4];
static uint8_t captured_count;
static uint8_t schedule_count;
static bool schedule_fail;

static usb_error_t fake_schedule_transfer(usb_endpoint_t endpoint, void *buffer,
                                          size_t length,
                                          usb_transfer_callback_t handler,
                                          usb_transfer_data_t *data)
{
    (void)endpoint;
    (void)buffer;
    (void)length;
    (void)handler;
    (void)data;
    schedule_count++;
    return schedule_fail ? USB_ERROR_FAILED : USB_SUCCESS;
}

static usb_error_t fake_disable_device(usb_device_t device)
{
    (void)device;
    return USB_SUCCESS;
}

static err_t capture_input(struct pbuf *p, struct netif *netif)
{
    (void)netif;
    if (!p || captured_count >= 4 || p->tot_len > sizeof(captured[0]))
    {
        if (p)
        {
            pbuf_free(p);
        }
        return ERR_MEM;
    }
    memcpy(captured[captured_count], p->payload, p->tot_len);
    captured_len[captured_count] = p->tot_len;
    captured_count++;
    pbuf_free(p);
    return ERR_OK;
}

static bool setup_dev(eth_device_t *dev)
{
    memset(dev, 0, sizeof(*dev));
    dev->type = USB_ECM_SUBCLASS;
    dev->rx.endpoint = (usb_endpoint_t)1;
    dev->rx.callback = (void *)1;
    dev->iface.name[0] = 'e';
    dev->iface.name[1] = 'n';
    dev->iface.state = dev;
    dev->iface.input = capture_input;
    dev->rx_ring = mem_buffer_create(MEM_BUFFER_RING, 512, 2048, 512, 0);
    if (!dev->rx_ring)
    {
        return false;
    }
    mem_buffer_set_drain(dev->rx_ring, eth_test_rx_ring_drain, &dev->iface);
    return true;
}

static void teardown_dev(eth_device_t *dev)
{
    if (dev->rx_ring)
    {
        mem_buffer_destroy(dev->rx_ring);
        dev->rx_ring = NULL;
    }
}

static bool test_ecm_ring_and_drain(void)
{
    eth_device_t dev;
    const uint8_t frame[] = {0x10, 0x20, 0x30, 0x40};
    captured_count = 0;

    if (!setup_dev(&dev))
    {
        return false;
    }
    bool ok = eth_test_ecm_receive(&dev, frame, sizeof(frame)) == USB_SUCCESS;
    ok = ok && mem_buffer_len(dev.rx_ring) == sizeof(frame) + 2u;
    ok = ok && eth_test_rx_ring_drain(dev.rx_ring, &dev.iface, 1) == 1;
    ok = ok && captured_count == 1;
    ok = ok && captured_len[0] == sizeof(frame);
    ok = ok && memcmp(captured[0], frame, sizeof(frame)) == 0;
    ok = ok && mem_buffer_len(dev.rx_ring) == 0;
    teardown_dev(&dev);
    return ok;
}

static bool test_budget_and_pbuf_failure(void)
{
    eth_device_t dev;
    const uint8_t one[] = {1};
    const uint8_t two[] = {2};
    captured_count = 0;
    ethernet_test_pbuf_alloc_fail = 0;

    if (!setup_dev(&dev))
    {
        return false;
    }
    bool ok = eth_test_ring_push_frame(&dev, one, sizeof(one));
    ok = ok && eth_test_ring_push_frame(&dev, two, sizeof(two));
    ok = ok && eth_test_rx_ring_drain(dev.rx_ring, &dev.iface, 1) == 1;
    ok = ok && captured_count == 1 && captured[0][0] == 1;
    ok = ok && mem_buffer_len(dev.rx_ring) == sizeof(two) + 2u;

    ethernet_test_pbuf_alloc_fail = 1;
    ok = ok && eth_test_rx_ring_drain(dev.rx_ring, &dev.iface, 1) == 0;
    ok = ok && mem_buffer_len(dev.rx_ring) == sizeof(two) + 2u;
    ethernet_test_pbuf_alloc_fail = 0;
    ok = ok && eth_test_rx_ring_drain(dev.rx_ring, &dev.iface, 1) == 1;
    ok = ok && captured_count == 2 && captured[1][0] == 2;
    teardown_dev(&dev);
    return ok;
}

static uint16_t put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)(v >> 8);
    return v;
}

static uint32_t put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
    return v;
}

static bool test_ncm_parse(void)
{
    eth_device_t dev;
    uint8_t ntb[96] = {0};
    const uint8_t d0[] = {0xaa, 0xbb, 0xcc};
    const uint8_t d1[] = {0x11, 0x22};
    captured_count = 0;

    if (!setup_dev(&dev))
    {
        return false;
    }
    dev.type = USB_NCM_SUBCLASS;

    put32(&ntb[0], 0x484d434e);
    put16(&ntb[4], 12);
    put16(&ntb[6], 7);
    put16(&ntb[8], sizeof(ntb));
    put16(&ntb[10], 16);

    put32(&ntb[16], 0x304d434e);
    put16(&ntb[20], 28);
    put16(&ntb[22], 0);
    put16(&ntb[24], 64);
    put16(&ntb[26], sizeof(d0));
    put16(&ntb[28], 72);
    put16(&ntb[30], sizeof(d1));
    put16(&ntb[32], 0);
    put16(&ntb[34], 0);
    memcpy(&ntb[64], d0, sizeof(d0));
    memcpy(&ntb[72], d1, sizeof(d1));

    bool ok = eth_test_ncm_receive(&dev, ntb, sizeof(ntb)) == USB_SUCCESS;
    ok = ok && eth_test_rx_ring_drain(dev.rx_ring, &dev.iface, 4) == 2;
    ok = ok && captured_count == 2;
    ok = ok && captured_len[0] == sizeof(d0);
    ok = ok && captured_len[1] == sizeof(d1);
    ok = ok && memcmp(captured[0], d0, sizeof(d0)) == 0;
    ok = ok && memcmp(captured[1], d1, sizeof(d1)) == 0;
    teardown_dev(&dev);
    return ok;
}

static bool test_schedule_failure_does_not_mark_active(void)
{
    eth_device_t dev;
    memset(&dev, 0, sizeof(dev));
    dev.type = USB_ECM_SUBCLASS;
    dev.rx.endpoint = (usb_endpoint_t)1;
    dev.rx.callback = (void *)1;
    dev.iface.name[0] = 'e';
    dev.iface.name[1] = 'n';
    dev.iface.state = &dev;
    dev.iface.next = NULL;
    netif_list = &dev.iface;
    schedule_count = 0;
    schedule_fail = true;
    eth_test_schedule_rx_for_netifs();
    bool ok = schedule_count == 1 && !dev.rx_transfer_active;
    schedule_fail = false;
    eth_test_schedule_rx_for_netifs();
    ok = ok && schedule_count == 2 && dev.rx_transfer_active;
    netif_list = NULL;
    return ok;
}

int main(void)
{
    os_ClrHome();
    fn_imports_table.usb.schedule_transfer = fake_schedule_transfer;
    fn_imports_table.usb.disable_device = fake_disable_device;

    bool ok = mem_init_dynamic(8192, malloc, free, realloc);
    ok = ok && test_ecm_ring_and_drain();
    ok = ok && test_budget_and_pbuf_failure();
    ok = ok && test_ncm_parse();
    ok = ok && test_schedule_failure_does_not_mark_active();

    printf(ok ? "success" : "failed");
    os_GetKey();
    return ok ? 0 : 1;
}
