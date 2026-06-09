# Changelog

Bug reports and fixes against lwIP-CE, newest first.

Format per entry:

```
## Bug #<n> — <YYYY-MM-DD>
**Reported by:** <name / channel>
**Issue:** <one-paragraph description of the symptom and where it surfaces>
**Fix:** <one-paragraph description of what changed and why it resolves the symptom>
**Fixed in:** <commit hash>
```

---

## Bug #1 — 2026-06-01
**Reported by:** TIny_Hacker via Codex (triage for lwftp-ce FTP-download stalls)

**Issue:** Sustained TCP downloads stalled for 15–30 seconds at a time and
sometimes hung permanently. 

**Suspected Cause:** Two contributing defects in the NCM ethernet
driver: (a) every outbound frame allocated and transmitted `ETHERNET_MTU +
NCM_HBUF_SIZE` (~1578 B) regardless of payload size, so 40-byte TCP ACKs
on a download burned ~15× the necessary memory and USB bandwidth; (b) the
RX callback re-armed only on transient errors, leaving RX continuity
entirely to the master-tick dispatcher. When `MEM_PRESSURE_CRITICAL`
disabled the dispatcher and an in-flight RX completed, no path re-armed
the next receive; recovery from CRITICAL did not kick a one-shot
re-schedule, so RX could stay idle indefinitely.

**Fix:** (a) `ncm_bulk_transmit` now sizes the NTB to `NCM_HBUF_SIZE +
p->tot_len` for the alloc, the on-wire `wBlockLength`, and the
`schedule_transfer` length. (b) `eth_set_rx_throttle` kicks a one-shot
`eth_schedule_rx_for_netifs()` when transitioning out of CRITICAL.
`ecm_receive_callback` and `ncm_receive_callback` also self-re-arm at
their exit points (success and malformed-frame bail-outs) when pressure
is non-CRITICAL, making the dispatcher a safety net rather than the sole
RX-continuity mechanism.

**Fixed in:** 365c6343e
