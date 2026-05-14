![lwIP Main Build](https://github.com/cagstech/lwip-ce/actions/workflows/build.yml/badge.svg&cache=1) ![Module Tests](https://github.com/cagstech/lwip-ce/actions/workflows/tests.yml/badge.svg?branch=tls&cache=1) ![SAST](https://github.com/cagstech/lwip-ce/actions/workflows/sast.yml/badge.svg?cache=1)

 **Note**
CI is currently failing due to an ongoing refactor/migration into the new binutils toolchain structure. This is expected during the transition period.


# lwIP-CE #

## Stability Reports ##

Status of lwIP application build from branch `master`.



Status of TLS unit tests.



## What are lwIP and lwIP-CE ##

**lwIP** is a full networking stack for low-resource device like embedded systems. This makes it perfect for something as ridiclous as a graphing calculator.
It is maintained by non-GNU (https://github.com/lwip-tcpip/lwip).
**lwIP-CE** is the name for the lwIP fork targetting the Texas Instruments TI-84+ CE graphing calculator.
You can view the original readme [here](./README-ORIG.md).

This implementation differs from the ported lwIP in the following ways:
- reduced pbuf pool and tcp_sndbuf queue size
- non "raw" API's will not work due to NOSYS implementation
- hardware-specific USB CDC-ECM and NCM drivers

## Related Media ##
1. https://www.youtube.com/watch?v=fD2n7CzFeZU


# lwIP Stack Initialization #

Programs using lwIP as a dynamic library need to follow a specific initialization sequence to start up the stack and the link-layer. It is **extremely** important that you do things in the order shown to ensure that various callbacks and timers initialize in the correct order.

1. **Include the Necessary Headers**: The following headers are needed for things to work at all.

        #include <usbdrvce.h>                   // USB driver
        #include "drivers/usb-ethernet.h"       // CDC-Ethernet driver (ECM/NCM)
        #include "lwip/init.h"                  // lwIP initialization
        // If you use any other modules in your program
        // you'll need to include those headers too.
    
2. **Initialize the lwIP Memory System**: This is something you cannot skip. lwIP uses the project's custom allocator and memory pressure system. Initialize it before calling `lwip_init()` so the core pools can be created.

        #define LWIP_MAX_HEAP   (1024 * 32)
        if (!mem_init(LWIP_MAX_HEAP, malloc, free, realloc))
            goto exit;      // whatever your exit w/ error method is

3. **Initialize the lwIP Stack**: Fire up the IP stack after memory init.

        if(lwip_init() != ERR_OK)
            goto exit;      // whatever your exit w/ error method is
        
4. **Initialize the CDC-Ethernet Driver**: `eth_handle_usb_event` is the entry point to the data-link layer driver for Ethernet provided in this library. Initialize the calculator's USB hardware, passing that function as a callback as shown below.

        if (usb_Init(eth_handle_usb_event, NULL, NULL, USB_DEFAULT_INIT_FLAGS))
            goto exit;      // whatever your exit w/ error method is      

        
# Using the lwIP API # 

## Callback-Style API ##

I'll be direct. lwIP is not a trivial thing to use. As the TI-84+ CE does not possess what qualifies as an operating system for the purposes of lwIP, we are restricted to the use of the raw API, also called the *callback API*. In this framework you declare a resource for a connection, called a *protocol control block (PCB)* and you register callback functions to the PCB for various actions that may occur on that resource -- sent, recvd, connected, error, etc. lwIP handles the routing of those packets and processing of network events on the PCBs, executing the callbacks in response to appropriate events. This means you will need familiarity with callback/event-driven programming to use lwIP.

Some examples of this for TCP are:

        tcp_arg(pcb, arg)   <== Defines data argument *arg* to pass to all callbacks for *pcb*
        tcp_err(pcb, err)   <== Defines *err* as the error handling callback for *pcb*
        tcp_recv(pcb, func) <== Defines *func* as the callback to handle incoming packets on *pcb*
        tcp_sent(pcb, func) <== Defines *func* as the callback when packets sent on *pcb* are ACKd
        // There are more, but just some examples.

The full documentation for the callback-style API is here: https://www.nongnu.org/lwip/2_1_x/group__callbackstyle__api.html. As you will see if you spend any amount of time perusing the documentation you will find that in many places it tells you next to nothing about what functions do. If you require assistance with the API for lwIP, feel free to ask in the [Discord](https://discord.gg/kvcuygqU) or contact the lwIP authors directly using the link above. 

## Error Handling ##

To be fully stable your application needs to properly handle any errors that may arise. You, the end user, only need to focus on application-layer error handling as the IP stack and the link-layer Ethernet driver have robust error handling built in with the latter even having an error recovery system designed to reset a problematic USB device without losing lwIP state.

Many of the protocols, such as TCP or UDP, that you can implement provide a way to pass error handling functions to the PCB which allows you to react to errors on the connection. These errors may include rejected packets, connection failures, and memory-low errors. How you handle these errors is up to you.

## Proper Cleanup and Exit ##

The lwIP API is not something that should ideally just be `exit()`ed from. While exiting a program deallocates all resources, networks and servers don't react well when connections are not cleanly set down and the operating system of the calculator gets mad when certain resources aren't reset. Therefore I highly recommend that when you want to exit the program you:

1. Call `_close()` on any active PCBs.
2. Await acknolwedgement on that where applicable (eg: TCP/ALTCP).
3. De-register any registered network interfaces (`netif_remove()`).
4. Call `usb_Cleanup()` to reset USB state to TI-OS default. USB can behave weirdly after program exit if you don't do this.

At this point it is now safe to exit the program.
