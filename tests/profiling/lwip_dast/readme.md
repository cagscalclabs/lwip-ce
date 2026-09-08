# lwIP-CE DAST harness

Dynamic security testing for the lwIP-CE stack against a calc on a **live
network**. Two halves that walk the same ordered test list in lockstep:

- **calc side** (this directory) — `LWDAST.8xp`. Brings the stack up (DHCP),
  shows its IP, then for each test enters the listener state the probe needs
  (`idle` / `udp_recv` / `tcp_listen`) and shows a live event counter.
- **host side** — `build-tools/dast/lwip-dast.sh` → `build-tools/dast/lwip-dast.py`.
  Sends the malformed / overflow / flood probe (scapy) at the calc, then
  prompts you for what the calc did, grades it, and writes `tests/dast.json`.

The single source of truth for the test set is
[`dast_tests.json`](dast_tests.json). The calc-side C list
(`src/dast_tests.h`) is generated from it:

```sh
python3 build-tools/dast/lwip-dast.py --gen-header
```

`lwip-dast.sh` regenerates the header automatically before each run, so the
two sides cannot drift.

## Running

1. Build and send the harness to a calc:
   ```sh
   cd tests/profiling/lwip_dast && make
   # send bin/LWDAST.8xp + the lwIP installer (build/appinst) to the calc
   ```
2. Run `LWDAST` on the calc. It shows its DHCP IP. Press `enter` to begin.
3. On the host (needs root / CAP_NET_RAW for raw packets):
   ```sh
   ./build-tools/dast/lwip-dast.sh --ip <calc-ip> [--iface en0]
   ```
4. For each test: when the host says so, set the calc to the named state
   (it does this automatically when you press `enter` to advance on the calc),
   let the probe fire, watch the calc, and report the outcome
   (`ALIVE` / `REPLY` / `ACCEPT` / `ABORT` / `RST` / `CRASH` / `HANG` / `SKIP`).

`CRASH` / `HANG` always fail. Other outcomes pass iff they are in the test's
`ok_responses`. The host also pings the calc between probes as a liveness hint.

## Grading and manual notes

Crash-vs-abort is a human call, so the runner asks you. Results land in
`tests/dast.json` (`test-run` id/name/command/intent, `calc-response`,
`grade`). You can hand-edit two fields and they survive re-runs (keyed by id):

- `notes` — free text shown in the report
- `grade_override` — force a final grade (e.g. you confirmed a crash)

## CI gate

`.github/workflows/dast.yml` renders the committed `tests/dast.json` to the
job summary and **fails the run if any test is graded `fail`**. It does not
run probes (CI has no calc); it gates whatever report you commit.
Run the same renderer locally with `python3 build-tools/dast/dast_report.py`.

## Dependencies

- host: `python3`, `scapy` (`pip install scapy`), root for raw sockets
- dry run with no deps/root: `python3 build-tools/dast/lwip-dast.py --ip x --self-test`
