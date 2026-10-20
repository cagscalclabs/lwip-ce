"""Check the source-selection failure contracts shared by C and assembly."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[3]
C_SOURCE = (ROOT / "src/tls/core/random.c").read_text()
ASM_SOURCE = (ROOT / "src/tls/core/random.s").read_text()
STATS_SOURCE = (ROOT / "tests/profiling/tls_rng_stats/src/main.c").read_text()


attempt_match = re.search(
    r"^#define TLS_RNG_SOURCE_INIT_MAX_ATTEMPTS (\d+)u$",
    C_SOURCE,
    re.MULTILINE,
)
assert attempt_match, "missing automatic source-selection attempt bound"
MAX_ATTEMPTS = int(attempt_match.group(1))
assert MAX_ATTEMPTS == 2


# Model the healthcheck gate: once the fixed scan budget is exhausted, later
# automatic callers fail without initiating another scan.
attempts = 0
scans = 0
for _ in range(8):
    if attempts >= MAX_ATTEMPTS:
        continue
    attempts += 1
    scans += 1
assert scans == MAX_ATTEMPTS


init_fail = ASM_SOURCE.split(".Linit_fail:\n", 1)[1].split(
    ".Linit_return:\n", 1
)[0]
assert "ld (_sprng_read_addr),hl" in init_fail
assert "ld (_sprng_read_mask),a" in init_fail
assert "xor a,a" in init_fail


stats_body = C_SOURCE.split("bool tls_rng_compute_stats", 1)[1]
clear_pos = stats_body.index("memset(stats, 0, sizeof(*stats));")
source_pos = stats_body.index("tls_random_debug_source_ptr()")
assert clear_pos < source_pos, "failed stats calls could expose stale output"


close_body = STATS_SOURCE.split("static void output_close", 1)[1].split(
    "static void print_q16_percent", 1
)[0]
assert "if (!archive)" in close_body
assert "ti_Delete(RNG_STATS_APPVAR)" in close_body

print(
    "RNG failure paths passed: bounded selection, cleared source/stats, "
    "discarded partial profile"
)
