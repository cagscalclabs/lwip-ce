<hr>

**Main CI**

![lwIP Main Build](https://github.com/cagscalclabs/lwip-ce/actions/workflows/build.yml/badge.svg?branch=master&cache=1)
![Unit Tests](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/cagscalclabs/lwip-ce/badges/unit-tests.json)

*The same workflow that generates the nightly release also runs the CI tests, however running this in this way causes the default GitHub badges to never update. To work around this, we export a badge for each test result to img.shield.io, hence the different aesthetic. You can still audit last run output and results from the actions tab.*

<hr>

**Code Quality**

![SAST](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/cagscalclabs/lwip-ce/badges/sast.json)
![DAST](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/cagscalclabs/lwip-ce/badges/dast.json)

*SAST uses `git diff` against upstream lwIP to filter out untouched upstream code and scans only targets unique to this repository. For upstream issues, file an issue with [nonGNU](https://savannah.nongnu.org/bugs/?group=lwip).*

*DAST uses a locally-run hardware-in-the-loop workflow because the current emulator does not support Ethernet devices. A helper program runs on the calculator and exposes the DAST target while a local script attaches to it, performs network probes, advances the calculator-side test state, and writes results to JSON. This workflow then parses the JSON report and updates the test state accordingly.*

*Unit Tests, SAST, and DAST badges are sourced from a custom `badges` branch updated by `build.yml`, since these workflows only ever run as `workflow_call` targets and GitHub's native badge.svg cannot see those runs (see build.yml's `update_badges` job).*

<hr>

**Cryptography Quality Checks**

![Timing Profiling](https://github.com/cagscalclabs/lwip-ce/actions/workflows/timing.yml/badge.svg?branch=master&cache=1)
![CAVP Primitive Validation](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/cagscalclabs/lwip-ce/badges/cavp.json)

<hr>





# lwIP-CE #


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
        #include "lwip_init_runtime.h"          // libload bootstrap (must come first)
        #include "drivers/usb-ethernet.h"       // CDC-Ethernet driver (ECM/NCM)
        #include "lwip/init.h"                  // lwIP initialization
        // If you use any other modules in your program
        // you'll need to include those headers too.

2. **Bootstrap the libload runtime**: This **must** be the very first lwIP call you make. It locates the lwIP flash app, verifies its export table, and patches the libload trampolines so that every other lwIP entry point becomes reachable. Nothing else will work if you skip this or call it out of order.

        uint8_t rt = lwip_init_runtime();
        // 0 = success, 1 = app not found, 2 = export table error
        if (rt != 0)
            goto exit;      // whatever your exit w/ error method is

3. **Initialize the lwIP Memory System**: This is something you cannot skip. lwIP uses the project's custom allocator and memory pressure system. Initialize it before calling `lwip_init()` so the core pools can be created.

        #define LWIP_MAX_HEAP   (1024 * 32)
        if (!mem_init(LWIP_MAX_HEAP, malloc, free, realloc))
            goto exit;      // whatever your exit w/ error method is

4. **Initialize the lwIP Stack**: Fire up the IP stack after memory init.

        if(lwip_init() != ERR_OK)
            goto exit;      // whatever your exit w/ error method is
        
5. **Initialize the CDC-Ethernet Driver**: `eth_handle_usb_event` is the entry point to the data-link layer driver for Ethernet provided in this library. Initialize the calculator's USB hardware, passing that function as a callback as shown below.

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
