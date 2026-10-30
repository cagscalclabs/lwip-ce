
# lwIP-CE

**lwIP** is a small networking stack built for low-resource embedded systems, maintained by [nonGNU](https://github.com/lwip-tcpip/lwip). **lwIP-CE** is a fork of it targeting the Texas Instruments TI-84+ CE graphing calculator, shipped as a dynamic library (libload) with a TLS 1.3 client stack, a USB CDC-ECM/NCM Ethernet driver, Wi-Fi through an ESP32-S3 or ESP32-P4 bridge (firmware in [`wifi_bridge/`](./wifi_bridge)), and an app-facing socket API. The original upstream readme is [here](./README-ORIG.md).

**Truststore Latest (required for TLS connections):** **https://github.com/cagscalclabs/lwip-ce/releases/tag/truststore-latest**

**Full documentation, API reference, and getting-started guide:** **https://cagscalclabs.github.io/lwip-ce/index.html**

**Whitepaper** (architecture, threat model, validation methodology): **https://github.com/cagscalclabs/lwip-ce/releases/tag/whitepaper-latest**
*It's long so prepare yourself. But I wanted a descriptive, forward facing document for technical auditing.*

## Quick orientation

- Programs link against lwIP-CE as a libload dynamic library, not by compiling `src/` in. See [Getting Started](https://cagscalclabs.github.io/lwip-ce/getting-started.html) for installation and the required init sequence (`lwip_start()` → `lwip_network_up()` → socket API).
- The app-facing API is `lwip_socket_*` (create/connect/read/write/close) — a small, fixed verb set over TCP/UDP/TLS. Lower-level lwIP primitives (raw `tcp_*`/`udp_*` PCB callbacks) are still available for advanced use; see `lwip.h` and the doc site for both layers.
- TLS, the custom allocator, the USB Ethernet driver, and the truststore/CI validation pipeline are all covered in depth in the whitepaper and the doc site — this README intentionally stays short.

## Related media

- First Beta Test: https://www.youtube.com/watch?v=fD2n7CzFeZU
- TCP and TLS Chat test: https://youtu.be/rX79owIVM-o
- Curated DAST test suite: https://www.youtube.com/shorts/APBYBo0O6sg
- IRC demo: https://www.youtube.com/watch?v=40q8J8R70nE

## Contributors

Special thanks to:

- commandblockguy (initial lwIP porting)
- beckadamtheinventor (SHA-256 assembly rewrite)
- jacobly (RSA-2048)
- _PT (X25519 ECDHE)
- calc84maniac (AES optimization, assembly rewrite)
- alessiodam (WiFi drivers and hardware - custom PCB and firmware)
- TIny_Hacker (fasmg to GAS conversion help)
- Zeroko (entropy analysis)
- acagliano (CDC Ethernet driver, memory subsystem, TLS implementation, RFC compliance)

And thanks to Adriweb for making weird sporadic CEmu feature additions to help me debug this insanity without wanting to fling myself (or my computer or calculator) out my window (though I can't confirm that didn't almost happen anyway).