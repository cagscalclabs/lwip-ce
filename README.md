<hr>

**Main CI**

![lwIP Main Build](https://github.com/cagscalclabs/lwip-ce/actions/workflows/build.yml/badge.svg?branch=master&cache=1)
![Unit Tests](https://github.com/cagscalclabs/lwip-ce/actions/workflows/tests.yml/badge.svg?branch=master&cache=1)
![SAST](https://github.com/cagscalclabs/lwip-ce/actions/workflows/sast.yml/badge.svg?branch=master&cache=1)
<br>
![Network Tests](https://github.com/cagscalclabs/lwip-ce/actions/workflows/net.yml/badge.svg?branch=master&cache=1)
![Host Tests and Fuzzing](https://github.com/cagscalclabs/lwip-ce/actions/workflows/host.yml/badge.svg?branch=master&cache=1)
<br>
![CAVP Primitive Validation](https://github.com/cagscalclabs/lwip-ce/actions/workflows/cavp.yml/badge.svg?branch=master&cache=1)
![Timing Profiling](https://github.com/cagscalclabs/lwip-ce/actions/workflows/timing.yml/badge.svg?branch=master&cache=1)

<hr>
**Code Quality**

SAST uses `git diff` against upstream lwIP to filter out untouched upstream code and scans only targets unique to this repository. For upstream issues, file an issue with [nonGNU](https://savannah.nongnu.org/bugs/?group=lwip).
<hr>
**Runtime and Robustness Testing**

Network Tests exercise the built library on a network-enabled CEmu instance, covering sockets, raw IPv4 and IPv6 APIs, TLS clients and servers, record limits, live DAST probes, and performance measurements.

Host Tests and Fuzzing run host-compiled regression tests with AddressSanitizer and UndefinedBehaviorSanitizer, then use libFuzzer to exercise parsers and network-facing protocol handlers with persistent corpora.

<hr>
**Cryptography Quality Checks**

CAVP selects 16 random samples from the NIST RSP datasets that match the primitives we provide (with the exception of SHA-256 Monte Carlo, which selects one) (totaling 185 samples covering AES-CBC, GCM, CCM, SHA-256, HMAC-SHA-256, PBKDF2, HKDF, RSA-PSS-RSAE-SHA256, RSA-PKCS1-SHA256, and X25519). Where NIST publishes no RSP for a primitive (or in the case of RSA with e=65537), the output of python3-cryptography is used instead. Our workflow caches the expected values and then serializes the inputs into an AppVar for transfer to the TI-84+ CE. The CAVP profiler runs on the calculator, dumping the on-device primitive output to an AppVar that gets fed back to the test environment. The AppVar is then parsed and graded against the expectations cached. This test does not constitute a formal NIST CAVP certification; it validates our implementations against samples drawn from NIST’s published CAVP validation-vector datasets.

Timing analysis checks for secret-dependent timing leaks: it samples repeated runs of a primitive across input classes designed to exercise different internal code paths (e.g. a bad MAC vs. a good one), then looks for variance in runtime that tracks the input class rather than noise. Some allowance is given for CPU jitter, computed via MAD-based sigma over the baseline class. This test does not prove the absence of secret-dependent timing leaks, but it provides statistical evidence that runtime stays consistent across all classes of input. Our test result is obtained by parsing the per-model stats committed to this repo at `statistics/timing`

<hr>


# lwIP-CE

**lwIP** is a small networking stack built for low-resource embedded systems, maintained by [nonGNU](https://github.com/lwip-tcpip/lwip). **lwIP-CE** is a fork of it targeting the Texas Instruments TI-84+ CE graphing calculator, shipped as a dynamic library (libload) with a TLS 1.3 client stack, a USB CDC-ECM/NCM Ethernet driver, Wi-Fi through an ESP32-S3 or ESP32-P4 bridge (firmware in [`wifi_bridge/`](./wifi_bridge)), and an app-facing socket API. The original upstream readme is [here](./README-ORIG.md).

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


