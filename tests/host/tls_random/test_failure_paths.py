"""Check the source-selection failure contracts shared by C and assembly."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[3]
C_SOURCE = (ROOT / "src/tls/core/random.c").read_text()
ASM_SOURCE = (ROOT / "src/tls/core/primitives/random.s").read_text()
SHA_SOURCE = (ROOT / "src/tls/core/primitives/sha256.s").read_text()
LOG_SOURCE = (ROOT / "src/core/log_file.c").read_text()
SYS_SOURCE = (ROOT / "src/arch/sys_arch.c").read_text()
STATS_SOURCE = (ROOT / "tests/profiling/tls_rng_stats/src/main.c").read_text()


timeout_match = re.search(
    r"^#define TLS_RNG_READY_TIMEOUT_MS (\d+)u$",
    C_SOURCE,
    re.MULTILINE,
)
assert timeout_match, "missing RNG readiness deadline"
assert int(timeout_match.group(1)) == 15000


# SP 800-90A Table 2 limits each Hash_DRBG Generate request to 2^19 bits.
assert "#define TLS_HASH_DRBG_MAX_REQUEST_BITS (UINT32_C(1) << 19)" in C_SOURCE
assert "#define TLS_HASH_DRBG_MAX_REQUEST_BYTES (TLS_HASH_DRBG_MAX_REQUEST_BITS / 8u)" in C_SOURCE
assert '#error "SHA-256 Hash_DRBG request limit must be exactly 2^19 bits"' in C_SOURCE
assert "#define TLS_HASH_DRBG_RESEED_INTERVAL (UINT64_C(1) << 48)" in C_SOURCE


# SP 800-90A 10.1.1.1 Hash_DRBG/SHA-256 working-state shape.
assert "#define TLS_HASH_DRBG_SEED_BITS 440u" in C_SOURCE
assert "#define TLS_HASH_DRBG_SEED_BYTES (TLS_HASH_DRBG_SEED_BITS / 8u)" in C_SOURCE
assert '#error "SHA-256 Hash_DRBG seedlen must be exactly 440 bits"' in C_SOURCE
drbg_state = C_SOURCE.split("struct tls_hash_drbg_state", 1)[1].split("};", 1)[0]
assert "uint8_t v[TLS_HASH_DRBG_SEED_BYTES];" in drbg_state
assert "uint8_t c[TLS_HASH_DRBG_SEED_BYTES];" in drbg_state
assert "uint64_t reseed_counter;" in drbg_state
assert "uint16_t strength_bits;" in drbg_state
assert "bool seeded;" in drbg_state


# SP 800-90A 10.1.1.2 instantiation order and fail-closed state commit.
make_c = C_SOURCE.split("static bool tls_hash_drbg_make_c", 1)[1].split(
    "static bool tls_hash_drbg_instantiate", 1
)[0]
assert "material[0] = 0u;" in make_c
assert "memcpy(material + 1u, drbg->v, sizeof(drbg->v));" in make_c
assert "tls_hash_df(material, sizeof(material), drbg->c)" in make_c
assert make_c.count("tls_secure_memzero(material, sizeof(material));") == 2

instantiate = C_SOURCE.split("static bool tls_hash_drbg_instantiate", 1)[1].split(
    "static bool tls_hash_drbg_reseed", 1
)[0]
assert instantiate.count("tls_hash_drbg_reset(drbg);") == 2
assert "tls_hash_df(seed_material, seed_material_len, drbg->v)" in instantiate
assert "tls_hash_drbg_make_c(drbg)" in instantiate
assert instantiate.index("tls_hash_df(seed_material") < instantiate.index(
    "tls_hash_drbg_make_c(drbg)"
)
assert instantiate.index("tls_hash_drbg_make_c(drbg)") < instantiate.index(
    "drbg->reseed_counter = 1u;"
)
assert instantiate.index("drbg->reseed_counter = 1u;") < instantiate.index(
    "drbg->seeded = true;"
)


# SP 800-90A 10.1.1.3 reseed construction, commit order, and cleanup.
reseed = C_SOURCE.split("static bool tls_hash_drbg_reseed", 1)[1].split(
    "static bool tls_hash_drbg_hashgen", 1
)[0]
assert "drbg == NULL || entropy == NULL || !drbg->seeded" in reseed
assert "material[0] = 1u;" in reseed
assert "memcpy(material + 1u, drbg->v, sizeof(drbg->v));" in reseed
assert "memcpy(material + 1u + sizeof(drbg->v), entropy," in reseed
assert "tls_hash_df(material, sizeof(material), new_v)" in reseed
assert reseed.index("tls_hash_df(material") < reseed.index(
    "memcpy(drbg->v, new_v, sizeof(drbg->v));"
)
assert reseed.index("memcpy(drbg->v, new_v") < reseed.index(
    "tls_hash_drbg_make_c(drbg)"
)
assert reseed.index("tls_hash_drbg_make_c(drbg)") < reseed.index(
    "drbg->reseed_counter = 1u;"
)
assert reseed.count("tls_secure_memzero(material, sizeof(material));") == 2
assert reseed.count("tls_secure_memzero(new_v, sizeof(new_v));") == 2
assert "tls_hash_drbg_reset(drbg);" in reseed


# Hash_DRBG uninstantiation must not leave enough SHA residue to reconstruct
# the last generated block from 0x03 || V_prev.
sha_buf = C_SOURCE.split("static bool tls_sha256_buf", 1)[1].split(
    "static void tls_store_u64_be", 1
)[0]
assert sha_buf.count("tls_secure_memzero(&hctx, sizeof hctx);") == 2

hash_df = C_SOURCE.split("static bool tls_hash_df", 1)[1].split(
    "static void tls_hash_drbg_add", 1
)[0]
assert hash_df.count("tls_secure_memzero(&ctx, sizeof ctx);") == 2
assert hash_df.count("tls_secure_memzero(digest,") == 2

hashgen = C_SOURCE.split("static bool tls_hash_drbg_hashgen", 1)[1].split(
    "static bool tls_drbg_generate_bytes", 1
)[0]
assert hashgen.count("tls_secure_memzero(data, sizeof(data));") == 2
assert hashgen.count("tls_secure_memzero(digest, sizeof(digest));") == 2

generate = C_SOURCE.split("static bool tls_drbg_generate_bytes", 1)[1].split(
    "#define TLS_DRBG_GATHER_MAX_EPOCH_CHANGES", 1
)[0]
generate_signature = generate.split("{", 1)[0]
assert "additional_input" not in generate_signature
assert "Generate-time additional input is not supported" in generate
assert "drbg->reseed_counter > TLS_HASH_DRBG_RESEED_INTERVAL" in generate
assert generate.index("tls_hash_drbg_hashgen(drbg, out, len)") < generate.index(
    "material[0] = 3u;"
)
state_update_steps = [
    "material[0] = 3u;",
    "memcpy(material + 1u, drbg->v, sizeof(drbg->v));",
    "tls_sha256_buf(material, sizeof(material), h)",
    "tls_hash_drbg_add(drbg->v, h, sizeof(h));",
    "tls_hash_drbg_add(drbg->v, drbg->c, sizeof(drbg->c));",
    "tls_store_u64_be(drbg->reseed_counter, counter_be);",
    "tls_hash_drbg_add(drbg->v, counter_be, sizeof(counter_be));",
    "drbg->reseed_counter++;",
]
assert all(step in generate for step in state_update_steps)
assert [generate.index(step) for step in state_update_steps] == sorted(
    generate.index(step) for step in state_update_steps
)
assert generate.count("tls_secure_memzero(material, sizeof(material));") == 2
assert generate.count("tls_secure_memzero(h, sizeof(h));") == 2

digest_asm = SHA_SOURCE.split("_tls_sha256_digest:", 1)[1].split(
    "_sha256_transform:", 1
)[0]
assert "lea de, ix-_sha256ctx_size" in digest_asm
assert "ld bc,_sha256ctx_size" in digest_asm

transform_asm = SHA_SOURCE.split("_sha256_transform:", 1)[1].split(
    "_sha256_state_init:", 1
)[0]
assert "lea de, ix + ._round_frame_offset - ._spill_size" in transform_asm
assert "ld bc,-._round_frame_offset + ._spill_size" in transform_asm
assert "ld de,_sha256_m_buffer" in transform_asm
assert "ld bc,256" in transform_asm


# sys_now must retain fractional ticks and span the raw 32-bit clock wrap.
assert "#if CLOCKS_PER_SEC != 32768UL" in SYS_SOURCE
assert "u32_t elapsed = ticks - last_ticks;" in SYS_SOURCE
assert "remainder += elapsed % CLOCKS_PER_SEC * 1000;" in SYS_SOURCE

clock_hz = 32768
mask32 = (1 << 32) - 1
last_ticks = 0
elapsed_total = 0
milliseconds = 0
remainder = 0
for ticks in (0, 1, 32767, 32768, 32769, 0xFFFFFF00, 0x20, 0x10020):
    elapsed = (ticks - last_ticks) & mask32
    last_ticks = ticks
    elapsed_total += elapsed
    milliseconds = (milliseconds + (elapsed // clock_hz) * 1000) & mask32
    remainder += (elapsed % clock_hz) * 1000
    milliseconds = (milliseconds + remainder // clock_hz) & mask32
    remainder %= clock_hz
    assert milliseconds == ((elapsed_total * 1000) // clock_hz) & mask32


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
    "state-residue erasure, wrap-safe timebase, cleared source/stats, "
    "discarded partial profile"
)
