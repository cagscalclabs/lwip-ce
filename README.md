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

<hr>

**Cryptography Quality Checks**

![Timing Profiling](https://github.com/cagscalclabs/lwip-ce/actions/workflows/timing.yml/badge.svg?branch=master&cache=1)
![CAVP Primitive Validation](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/cagscalclabs/lwip-ce/badges/cavp.json)

*Timing analysis checks for secret-dependent timing leaks: it samples repeated runs of a primitive across input classes designed to exercise different internal code paths (e.g. a bad MAC vs. a good one), then looks for variance in runtime that tracks the input class rather than noise. Some allowance is given for CPU jitter, computed via MAD-based sigma over the baseline class. This test does not prove the absence of secret-dependent timing leaks, but it provides statistical evidence that runtime stays consistent across all classes of input.*

*CAVP selects 16 random samples from the NIST RSP datasets that match the primitives we provide (with the exception of SHA-256 Monte Carlo, which selects one). It caches the expected values and then serializes the inputs into an AppVar for transfer to the TI-84+ CE. The CAVP profiler runs on the calculator, dumping the on-device primitive output to an AppVar that gets fed back to the test environment. The AppVar is then parsed and graded against the expectations cached. This test does not constitute a formal NIST CAVP certification; it validates our implementations against a sample of the same published test vectors NIST CAVP uses.*

<hr>

*Workflow badges are sourced from a custom `badges` branch updated by `build.yml`, since these workflows only ever run as `workflow_call` targets and GitHub's native badge.svg cannot see those runs (see build.yml's `update_badges` job).*

<hr>


# lwIP-CE

**lwIP** is a small networking stack built for low-resource embedded systems, maintained by [nonGNU](https://github.com/lwip-tcpip/lwip). **lwIP-CE** is a fork of it targeting the Texas Instruments TI-84+ CE graphing calculator, shipped as a dynamic library (libload) with a TLS 1.3 client stack, a USB CDC-ECM/NCM Ethernet driver, and an app-facing socket API. The original upstream readme is [here](./README-ORIG.md).

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


