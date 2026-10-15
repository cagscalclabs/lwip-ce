"""Model the SP 800-90B binary RCT/APT parameters used by random.s.

This verifies threshold behavior and keeps the documented constants tied to
the assembly source. Hardware tests remain responsible for exercising the
actual SRAM read path and candidate replacement logic.
"""
from pathlib import Path
import re


SOURCE = (Path(__file__).resolve().parents[3] / "src/tls/core/random.s").read_text()


def constant(name: str) -> int:
    match = re.search(rf"^\.equ\s+{re.escape(name)},\s*(\d+)\s*$", SOURCE, re.MULTILINE)
    assert match, f"missing assembly constant {name}"
    return int(match.group(1))


RCT_CUTOFF = constant("_sprng_rct_cutoff")
APT_WINDOW = constant("_sprng_apt_window")
APT_CUTOFF = constant("_sprng_apt_cutoff")

assert (RCT_CUTOFF, APT_WINDOW, APT_CUTOFF) == (51, 1024, 840)


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

# Strongly biased without a long repeated run: exercises the APT rather than RCT.
biased = ([0] * 5 + [1]) * 171
assert max(len(run) for run in "".join(map(str, biased)).split("1")) < RCT_CUTOFF
assert not health_ok(biased)

print("RNG health model passed: RCT=51, binary APT W=1024/C=840")
