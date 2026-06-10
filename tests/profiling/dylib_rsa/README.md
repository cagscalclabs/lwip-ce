# lwIP dylib RSA probe

Build:

```sh
make -C tests/profiling/dylib_rsa
```

Install the resident lwIP app first by sending the contents of `build/` to
CEmu/the calculator and running `lwIPINST`. Then send:

```text
tests/profiling/dylib_rsa/bin/DYLRSA.8xp
```

Run `DYLRSA`. It pauses before and after each exported dylib call. If it
crashes inside RSA, use the resident app map at `bin/lwIP.map` for the crash
address; the caller-side map is `tests/profiling/dylib_rsa/bin/DYLRSA.map`.
