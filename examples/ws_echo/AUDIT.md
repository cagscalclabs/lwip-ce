WS/WSS audit — 2026-09-08

The current source had a deterministic handshake failure: the response scanner
compared the Connection header name against `connctionn`. A normal server's
`Connection: Upgrade` could never pass. This affects both WS and WSS. The
12-byte comparison against `HTTP/1.1 101` was correct; the patch additionally
checks the following space so `1010` cannot pass.

This establishes a reason for failed connection establishment, but does not
prove the precise on-calculator crash sequence. In particular, the supplied
source cannot complete a normal upgrade before this fix. If the calculator
reported “WS handshake OK,” its installed resident library likely differs from
this source. Rebuild and transfer both the resident library and example before
comparing traces.

Fixed in this audit:

- Correct Connection header spelling.
- Return immediately when parsing during poll aborts and frees the wrapper.
- Respect ERR_ABRT from application receive/EOF callbacks without accessing
  freed state or returning ERR_OK to the lower transport.
- Retain the caller's input pbuf when a receive-copy allocation fails. Previously
  it was freed and ERR_MEM returned, inviting lower-layer reuse/double free.
- Retry refused application data on poll, stop parsing while it is refused, and
  deliver pending data before EOF. Notify EOF once.
- Abort the actual transport if writing the upgrade fails; previously only the
  upper error callback ran, leaving an orphaned transport while returning ABRT.
- Restore polling when graceful close fails and callbacks are reattached.
- Reject receive/transmit frame-length overflow before allocation or copying.
  Receive frames are capped at the TCP receive window because this parser waits
  for a whole frame before returning receive credit. Oversized frames previously
  could stall indefinitely or wrap a 16-bit total length.
- Reject masked server frames, reserved bits, invalid fragmentation sequences,
  malformed control lengths, and writes after Close. Deliver fragment payloads
  incrementally through the byte-stream API to avoid unbounded message assembly.
- Present example debug graphics immediately. Previously the debug callback only
  drew, so a crash before the next presentation could hide the last diagnostics.

Remaining findings, in priority order:

1. Handshake validation is incomplete. Sec-WebSocket-Accept is never verified;
   response protocol/extension selections are not validated. Header matching is
   substring-based and only examines 512 bytes, accepting misleading names or
   values and rejecting valid responses with required headers later in the block.
   Replace it with bounded line/token parsing and validate the accept challenge.
2. Pong and Close writes ignore ERR_MEM/output failures. Close is marked sent
   even if it was never queued. Under pressure, a lost Pong can produce exactly
   the server timeout/disconnect symptom. Queue control responses for retry;
   mark Close sent only after successful enqueue.
3. Sent-byte accounting is incorrect: HTTP upgrade and control-frame bytes are
   reported to the application, and pooling all frame headers ahead of all
   payloads misreports partial ACKs across multiple writes. Track wire/payload
   spans in send order.
4. Receive credit is returned before application consumption. Refused data now
   retries correctly, but additional ingress can still accumulate up to the
   pbuf-chain limit. A streaming frame decoder should return header/control
   credit separately and payload credit only on application recved(). It would
   also permit larger frames without requiring a full-frame allocation.
5. UTF-8, Close status codes, and minimal extended-length encoding remain
   unchecked. Closing sends FIN immediately instead of waiting for a peer Close
   with a bounded timeout. These are protocol robustness gaps.
6. Efficiency: ingress is copied into RAM and payload is copied again; outgoing
   data is allocated/masked then copied by the transport. HTTP termination scans
   restart at the beginning on every receive/poll and traverse pbufs repeatedly.
7. Socket-generated Host omits nondefault ports (the example uses 8080). Some
   virtual-host servers will reject/reroute it. Config strings are borrowed;
   callers must retain them through connection lifetime. The new_tls header's
   claim that it owns tls_conf conflicts with socket-managed config cleanup.

Protocol reference: RFC 6455, sections 4.1, 5.2–5.5, 7 and 8:
https://www.rfc-editor.org/rfc/rfc6455.html

Validation:

- `python3 tests/host/altcp_ws/run.py`: production parser/callback code with mock
  lower transport under AddressSanitizer and UndefinedBehaviorSanitizer. Covers
  split valid upgrades, abort during poll/receive, allocation refusal ownership,
  refused payload followed by Close, duplicate EOF prevention, oversized input
  and output, masked frames, fragmentation, and upgrade write failure.
- `make -j2`: resident application build passed.
- `make -C examples/ws_echo -j2`: example build passed. Shared-header unused
  function warnings and assembler GNU-stack warnings remain.

The host harness does not exercise eZ80 ABI/relocations, physical USB/network
I/O, or real TLS encryption and callbacks. No on-calculator runtime verification
was available. This is an audit and targeted stability patch, not certification
of complete RFC conformance or resolution of every finding above.

Follow-up: calculator trace after handshake fixes

The supplied photo reaches the WARN immediately before tls_random_bytes(mask, 4)
inside altcp_ws_write, but not the marker after it. Inspection found a shared
assembly bug in src/tls/core/random.s: a final chunk shorter than eight bytes
stored len-8 as the remaining 24-bit length and used its low byte as the copy
count. For len=4, this copies 252 bytes from an eight-byte source into a four-byte
mask and continues with remaining=0xfffffc. This explains why the 16-byte HTTP
nonce worked while the first mask stalled and corrupted memory. The later server
timeout is consistent with the client no longer making progress; the precise
hardware fault timing is not established by this source inspection.

Fixed the partial-chunk branch to copy the original remainder and set the
remaining count to zero. Entropy generation is unchanged. The host instruction
simulation in tests/host/tls_random/test_lengths.py passes 263 lengths including
0..256 and larger block boundaries. Reinstating the old branch in the simulation
reproduces the 252-byte overread for len=4. The resident build and WS sanitizer
regressions pass. This simulation does not replace an on-device test; transfer
the rebuilt bin/lwIP.8ek resident application to test the actual assembly.
