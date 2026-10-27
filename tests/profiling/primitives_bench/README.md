# TLS primitive cycle benchmark

Measures the primitives behind the handshake and record paths under
cemu-autotester. Results are appended as `name,ticks,units` lines to the
`TLSBENCH` AppVar, which the host converts with convbin:

    make && make test
    ~/CEdev/bin/convbin -i TLSBENCH.8xv -o /tmp/bench.bin -j 8x -k bin

`clock()` counts 32768 Hz OS timer ticks (roughly 1465 CPU cycles each at
48 MHz), so single measurements are repeated enough times to stay well above
one tick. Only ratios between builds are meaningful.

`baselines/baseline_preload.txt` is the pre-optimization run and
`baselines/after_p256_reloc.txt` is the run after the P-256 hot loops were
relocated into fast RAM: keygen 285,773 -> 170,454 ticks, sign 345,974 ->
230,770, verify 245,283 -> 153,214 (-40%, -33%, -38%). The handshake-level wins from that comparison are structural and
do not show up here: the benchmark calls primitives directly, so it cannot see
that `tls_handshake_init` no longer computes an unused P-256 keypair or that
the record decrypter stopped allocating a 2 KiB scratch per record.
