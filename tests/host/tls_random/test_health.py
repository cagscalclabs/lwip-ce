"""Model the SP 800-90B binary RCT/APT parameters used by random.s.

This verifies threshold behavior and keeps the documented constants tied to
the assembly source. Hardware tests remain responsible for exercising the
actual SRAM read path and candidate replacement logic.
"""
from pathlib import Path
import math
import re


ROOT = Path(__file__).resolve().parents[3]
SOURCE = (ROOT / "src/tls/core/primitives/random.s").read_text()
C_SOURCE = (ROOT / "src/tls/core/random.c").read_text()
HEADER = (ROOT / "src/tls/includes/random.h").read_text()


def constant(name: str) -> int:
    match = re.search(rf"^\.equ\s+{re.escape(name)},\s*(\d+)\s*$", SOURCE, re.MULTILINE)
    assert match, f"missing assembly constant {name}"
    return int(match.group(1))


RCT_CUTOFF = constant("_sprng_rct_cutoff")
APT_WINDOW = constant("_sprng_apt_window")
APT_CUTOFF = constant("_sprng_apt_cutoff")
STARTUP_BYTES = constant("_sprng_startup_bytes")
STARTUP_LAG_COUNT = constant("_sprng_startup_lag_count")

assert (RCT_CUTOFF, APT_WINDOW, APT_CUTOFF) == (76, 952, 844)
assert f"#define TLS_RNG_STATS_RCT_CUTOFF {RCT_CUTOFF}u" in HEADER
assert f"#define TLS_RNG_STATS_APT_WINDOW {APT_WINDOW}u" in HEADER
assert f"#define TLS_RNG_STATS_APT_CUTOFF {APT_CUTOFF}u" in HEADER
for lag, low, high in (
    (1, 136, 815),
    (2, 136, 814),
    (3, 135, 814),
    (4, 135, 813),
):
    assert f"#define TLS_RNG_STATS_LAG{lag}_MISMATCH_MIN {low}u" in HEADER
    assert f"#define TLS_RNG_STATS_LAG{lag}_MISMATCH_MAX {high}u" in HEADER
assert STARTUP_BYTES * 8 == APT_WINDOW
assert STARTUP_LAG_COUNT == 4
assert "#define TLS_ENTROPY_HMIN_Q16 UINT32_C(17630)" in C_SOURCE
assert "#define TLS_HASH_DRBG_ENTROPY_BYTES 24u" in C_SOURCE

# Tie both cutoffs to the configured Q16 entropy floor and alpha=2^-20.
h_min = 17630 / 65536
p_max = 2 ** -h_min
alpha = 2 ** -20
assert (952 * 17630) >> 16 == 256
assert 1 + math.ceil(20 / h_min) == RCT_CUTOFF
tail_at_cutoff = sum(
    math.comb(APT_WINDOW, k)
    * p_max**k
    * (1 - p_max) ** (APT_WINDOW - k)
    for k in range(APT_CUTOFF, APT_WINDOW + 1)
)
tail_below_cutoff = tail_at_cutoff + (
    math.comb(APT_WINDOW, APT_CUTOFF - 1)
    * p_max ** (APT_CUTOFF - 1)
    * (1 - p_max) ** (APT_WINDOW - APT_CUTOFF + 1)
)
assert tail_at_cutoff <= alpha < tail_below_cutoff
assert "call .Lstartup_lag_tests" in SOURCE
gather = SOURCE.split("_tls_entropy_gather192:", 1)[1].split(".Lsample_bits:", 1)[0]
assert ".Lstartup_lag_tests" not in gather
assert ".Lrandom_post_fail" not in SOURCE
assert "_sprng_markov_max_q8" not in SOURCE
assert "ld (_sprng_last_health_mask),a" in SOURCE
assert "and a,$FF-_sprng_test_rct_pass" in SOURCE
assert "and a,$FF-_sprng_test_apt_pass" in SOURCE
validation = SOURCE.split(".Linit_validate_candidate:", 1)[1].split(
    "; Clear the bit-sliced", 1
)[0]
assert validation.count("call .Lsample_health_check") == 2
assert validation.count("call .Linit_startup_marginal_check") == 2
assert "ld b,4" in SOURCE
assert "lea iy,iy+6" in SOURCE
assert ".zero 24" in SOURCE


def selection_rank(ones, disagreements):
    """Return the assembly selector's lexicographic score, or None."""
    if not 128 <= ones <= 384 or not 64 <= disagreements <= 192:
        return None
    return (
        min(ones, 512 - ones) - 128,
        min(disagreements, 256 - disagreements),
    )


# A balanced tap wins even when the biased tap has a perfect transition score.
assert selection_rank(256, 112) > selection_rank(160, 128)
assert selection_rank(255, 120) > selection_rank(250, 128)
assert selection_rank(256, 128) > selection_rank(256, 120)
assert selection_rank(127, 128) is None
assert selection_rank(256, 193) is None


def health_ok(bits):
    previous = None
    run = 0
    apt_reference = None
    apt_matches = 0
    apt_other = 0
    apt_position = 0

    for bit in bits:
        if bit == previous:
            run += 1
        else:
            previous = bit
            run = 1
        if run >= RCT_CUTOFF:
            return False

        if apt_position == 0:
            apt_reference = bit
            apt_matches = 1
            apt_other = 0
            apt_position = 1
            continue

        if bit == apt_reference:
            apt_matches += 1
            if apt_matches >= APT_CUTOFF:
                return False
        else:
            apt_other += 1
            if apt_other >= APT_CUTOFF:
                return False

        apt_position += 1
        if apt_position == APT_WINDOW:
            apt_position = 0

    return True


assert health_ok([0, 1] * 2048)
assert health_ok([1] * (RCT_CUTOFF - 1))
assert not health_ok([1] * RCT_CUTOFF)

# APT counts are per collection/window, not lifetime totals. Across two
# individually healthy windows either symbol may occur more than the cutoff.
balanced_window = [0, 1, 0, 1, 0] * 190 + [0, 0]
assert len(balanced_window) == APT_WINDOW
assert health_ok(balanced_window * 2)

# Strongly biased without a long repeated run: exercises the APT rather than RCT.
# With H=0.269, APT_CUTOFF=844; a 19:1 pattern gives about 904 matches
# without approaching the RCT cutoff.
biased = ([0] * 19 + [1]) * 52
assert max(len(run) for run in "".join(map(str, biased)).split("1")) < RCT_CUTOFF
assert not health_ok(biased)

print("RNG health model passed: RCT=76, binary APT W=952/C=844")
