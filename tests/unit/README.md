# Running calculator units locally

The unit runner uses the same prepared CEmu image in CI and on a developer
machine. You need a calculator ROM that you are authorized to use; the ROM is
not stored in this repository and the preparation script never deletes it.

Build the current lwIP release, then prepare a CEmu state containing it:

```sh
make dylib
python3 .github/scripts/prepare_cemu_image.py \
  --rom /path/to/ce.rom \
  --release build \
  --output /tmp/lwip-ce-patched.ce \
  --autotester-output /tmp/cemu-autotester-image \
  --work-dir /tmp/lwip-ce-cemu-build
```

The script reads the pinned CEmu revision from `.github/ci-versions.env`,
applies `build-tools/meta/cemu-autotester.patch`, builds the headless tools,
downloads `clibs.8xg` unless `--clibs` is supplied, sends the release files,
runs the installer, and saves the resulting state. It requires `git`, `make`,
`cmake`, and `ninja`, plus the platform dependencies needed to build CEmu.

Install the generated autotester in `PATH`, or invoke the unit runner with the
CEdev binary directory containing it:

```sh
install -m755 /tmp/cemu-autotester-image "$CEDEV/bin/cemu-autotester"
AUTOTESTER_IMAGE=/tmp/lwip-ce-patched.ce \
  python3 .github/scripts/run_unit_tests.py tests/unit \
    --output /tmp/results-unit.json
```

Pass `--clibs /path/to/clibs.8xg` for a fully offline run after the pinned CEmu
checkout and its submodules have already been populated in `--work-dir`.

To build lwIP, prepare the image, and run the complete locally reproducible
test workflow in one command:

```sh
AUTOTESTER_ROM=/path/to/ce.rom make run-tests
```

This runs calculator units, host tests, ACVP host validation, all fuzz targets,
and the informational primitive benchmark. The fuzz duration matches CI's
five-minute default; set `FUZZ_SECONDS=30` for a shorter development pass.

The live network, calculator ACVP, and DAST-style stages require Linux root
network namespaces and the truststore signing key. Enable those explicitly:

```sh
AUTOTESTER_ROM=/path/to/ce.rom \
TRUSTSTORE_SIGNER_FILE=/secure/path/to/key.pem \
LOCAL_NETWORK_TESTS=1 \
make run-tests
```

CodeQL, GitHub artifact lifecycle checks, and PR-context RFC review remain
CI-only because they depend on GitHub services rather than repository tools.
