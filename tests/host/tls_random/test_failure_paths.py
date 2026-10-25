"""Check the source-selection failure contracts shared by C and assembly."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[3]
C_SOURCE = (ROOT / "src/tls/core/random.c").read_text()
ASM_SOURCE = (ROOT / "src/tls/core/random.s").read_text()
LOG_SOURCE = (ROOT / "src/core/log_file.c").read_text()
STATS_SOURCE = (ROOT / "tests/profiling/tls_rng_stats/src/main.c").read_text()


timeout_match = re.search(
    r"^#define TLS_RNG_READY_TIMEOUT_MS (\d+)u$",
    C_SOURCE,
    re.MULTILINE,
)
assert timeout_match, "missing RNG readiness deadline"
assert int(timeout_match.group(1)) == 15000


# Source selection happens once in tls_init(); the asynchronous lifecycle
# waits for a valid source only until its absolute readiness deadline.
assert "TLS_RNG_SOURCE_INIT_MAX_ATTEMPTS" not in C_SOURCE
healthcheck = C_SOURCE.split("bool tls_rng_healthcheck", 1)[1].split(
    "static bool tls_rng_drive_initialization", 1
)[0]
healthcheck_code = healthcheck.split("/* Source not valid", 1)[0]
assert "tls_random_init_entropy()" not in healthcheck_code
assert "g_tls_rng_source_init_attempts" not in healthcheck

lifecycle = C_SOURCE.split("static bool tls_rng_drive_initialization", 2)[2].split(
    "tls_rng_state_t tls_rng_status", 1
)[0]
assert "tls_rng_deadline_expired()" in lifecycle
assert "TLS_RNG_FAILURE_TIMEOUT" in lifecycle
assert "TLS_RNG_DRBG_SEEDING" in lifecycle

gather = C_SOURCE.split("static bool tls_drbg_entropy_gather_step", 1)[1].split(
    "static bool tls_drbg_apply_entropy_reserve", 1
)[0]
assert "TLS_RNG_DRBG_READY_128" in gather
assert "g_tls_drbg_upgrade" in gather
assert "TLS_RNG_STRENGTH_192" in gather


init_fail = ASM_SOURCE.split(".Linit_fail:\n", 1)[1].split(
    ".Linit_return:\n", 1
)[0]
assert "ld (_sprng_read_addr),hl" in init_fail
assert "ld (_sprng_read_mask),a" in init_fail
assert "xor a,a" in init_fail

health_log = C_SOURCE.split("static void tls_rng_log_health_failure", 1)[1].split(
    "static bool g_tls_rng_entropy_timer_running", 1
)[0]
assert "WARN_CODE(mask);" in health_log
assert "ERROR_CODE" not in health_log
assert "ERROR_INFO" not in health_log
assert '"%lu: EVT: ERR: %s %s\\n"' in LOG_SOURCE


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
    "RNG failure paths passed: readiness deadline, staged DRBG promotion, "
    "cleared source/stats, discarded partial profile"
)
