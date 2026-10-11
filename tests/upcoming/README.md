# Upcoming tests

Tests in this directory describe APIs that are not part of the current
lwIP-CE release. Normal unit-test discovery is rooted at `tests/unit`, so these
targets are intentionally not built or run by CI.

Move a target into `tests/unit` only after its implementation is linked into
the resident library and exported through the public API manifest.
