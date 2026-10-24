
/**
 * @file random.h
 * @author Anthony Cagliano
 * @author Adam Beckingham
 * @author Codex 5.5 (DRBG async call-path assistance)
 * @brief Module providing a TRNG for use with TLS and other secure applications.
 *
 * @par References
 * - NIST SP 800-90B
 * - NIST SP 800-90A
 * - RFC 4086
 *
 * @warning Use this module for all applications requiring cryptographic
 * randomness. The toolchain @b rand() functions are not suitable for
 * cryptographic or security-sensitive purposes.
 */

#ifndef tls_random_h
#define tls_random_h

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/** Values reported in lwip_event.data.code.extra for RNG error events. */
typedef enum tls_rng_failure
{
    TLS_RNG_FAILURE_SOURCE_INIT = 1, /**< No usable entropy tap could be selected. */
    TLS_RNG_FAILURE_SOURCE_HEALTH,   /**< A continuous health test replaced the tap. */
    TLS_RNG_FAILURE_COLLECTION,      /**< Conditioned entropy collection failed. */
    TLS_RNG_FAILURE_ACCOUNTING,      /**< Internal reserve length/credit mismatch. */
    TLS_RNG_FAILURE_INSTANTIATE,     /**< Hash_DRBG instantiation failed. */
    TLS_RNG_FAILURE_RESEED,          /**< Hash_DRBG reseeding failed. */
    TLS_RNG_FAILURE_GENERATE,        /**< Hash_DRBG output generation failed. */
    TLS_RNG_FAILURE_BUSY,            /**< tls_random_bytes called while async request active. */
    TLS_RNG_FAILURE_TIMEOUT          /**< RNG did not become ready before its deadline. */
} tls_rng_failure_t;

/**
 * Pass bits retained for the most recent raw-source health failure.
 * Log output prints bit 6 first, so `0b1111110` means RCT failed and every
 * other test passed:
 *
 *   bit 6  distribution qualification (marginal + pair disagreement)
 *   bit 5  lag-4 qualification
 *   bit 4  lag-3 qualification
 *   bit 3  lag-2 qualification
 *   bit 2  lag-1 qualification
 *   bit 1  adaptive proportion test
 *   bit 0  repetition count test
 */
#define TLS_RNG_HEALTH_RCT_PASS           (1u << 0)
#define TLS_RNG_HEALTH_APT_PASS           (1u << 1)
#define TLS_RNG_HEALTH_LAG1_PASS          (1u << 2)
#define TLS_RNG_HEALTH_LAG2_PASS          (1u << 3)
#define TLS_RNG_HEALTH_LAG3_PASS          (1u << 4)
#define TLS_RNG_HEALTH_LAG4_PASS          (1u << 5)
#define TLS_RNG_HEALTH_DISTRIBUTION_PASS  (1u << 6)
#define TLS_RNG_HEALTH_ALL_PASS           0x7Fu

/** Lifecycle state of the asynchronous RNG service. */
typedef enum tls_rng_state
{
    TLS_RNG_STOPPED = 0,
    TLS_RNG_AWAITING_INIT,
    TLS_RNG_DRBG_SEEDING,
    TLS_RNG_DRBG_READY_128,
    TLS_RNG_DRBG_READY_192,
    TLS_RNG_FAILED
} tls_rng_state_t;

/** Minimum supported security-strength request. */
#define TLS_RNG_STRENGTH_128 128u
/** Maximum supported security-strength request. */
#define TLS_RNG_STRENGTH_192 192u

/*************************************************************************************
 * @brief Initializes the cryptographic TRNG within this module.
 * @returns @b true if generator initialization succeeded, @b false if failed.
 * @warning DO NOT USE the toolchain @b rand functions with the TLS functions of lwIP-CE. They are not secure
 * for cryptography. Use this module instead.
 */
bool tls_random_init_entropy(void);

/*************************************************************************************
 * @brief Deprecated compatibility wrapper returning a random 64-bit integer.
 * @returns A secure 64-bit random integer, or zero if source health fails and
 * recovery is impossible. Since zero is also a valid random result, callers
 * requiring explicit failure reporting should use @ref tls_random_bytes.
 * @deprecated Use @ref tls_random_bytes for an unambiguous failure result.
 */
uint64_t tls_random(void);

/*************************************************************************************
 * @brief Fills a buffer from the 192-bit-strength SHA-256 Hash_DRBG.
 * @param buffer    Pointer to a buffer to fill with random bytes.
 * @param len    Length of buffer to fill.
 * If the 192-bit DRBG is not yet instantiated, this call synchronously drives
 * source initialization, 128-bit availability, and fresh 192-bit promotion.
 * A complete timer-prepared reseed reserve is incorporated before output is
 * generated.
 * @returns @p buffer on success, or NULL if instantiation/reseeding fails or
 * the RNG request engine is busy. On failure, the destination is zeroized.
 * @warning The calculator cannot isolate or securely persist DRBG state.
 * Callers must not assume resistance to an attacker capable of reading or
 * modifying process memory or restoring prior machine state.
 */
void *tls_random_bytes(void *buffer, size_t len);

/**
 * Fill a buffer using a DRBG instantiated at no less than @p strength_bits.
 *
 * A call made before that strength is ready drives initialization
 * synchronously for compatibility with existing direct crypto callers. TLS
 * sockets normally avoid this path by waiting asynchronously for 128-bit
 * readiness before constructing their TLS PCB.
 *
 * @param buffer Destination buffer.
 * @param len Number of bytes to generate.
 * @param strength_bits Either @ref TLS_RNG_STRENGTH_128 or
 *        @ref TLS_RNG_STRENGTH_192.
 * @return @p buffer on success, otherwise NULL with the destination zeroized.
 */
void *tls_random_bytes_ex(void *buffer, size_t len, uint16_t strength_bits);

/**
 * Fill a buffer with prediction-resistance enabled (SP 800-90A §9.3.1).
 *
 * Equivalent to @ref tls_random_bytes_ex but forces an immediate reseed from
 * the entropy reserve before generating. Fails if the reserve is not ready,
 * guaranteeing that output is never produced from a state that has not been
 * freshly reseeded on this call.
 *
 * @param buffer Destination buffer.
 * @param len Number of bytes to generate.
 * @param strength_bits Either @ref TLS_RNG_STRENGTH_128 or
 *        @ref TLS_RNG_STRENGTH_192.
 * @return @p buffer on success, otherwise NULL with the destination zeroized.
 */
void *tls_random_bytes_pr(void *buffer, size_t len, uint16_t strength_bits);

/** Return the current asynchronous RNG lifecycle state. */
tls_rng_state_t tls_rng_status(void);

/** Return the currently available DRBG security strength: 0, 128, or 192. */
uint16_t tls_rng_available_strength(void);

/** Return the terminal failure reason, or zero if none is recorded. */
tls_rng_failure_t tls_rng_last_failure(void);

/*************************************************************************************
 * @brief Debug/test hook: returns the current sampled entropy source address.
 * @return Pointer used by the RNG sampler after @ref tls_random_init_entropy .
 * @warning Intended for diagnostics/tests only.
 */
void *tls_random_debug_source_ptr(void);

/*************************************************************************************
 * @brief Statistics for the selected raw entropy-source bit.
 *
 * Rates use unsigned Q16 fixed-point notation: 65536 represents 1.0.
 * These observations characterize a finite sample and are not a min-entropy
 * estimate or a substitute for formal entropy-source validation.
 */
struct tls_rng_stats
{
    /** Selected raw SRAM byte address. */
    uintptr_t source_address;
    /** Number of selected-bit observations represented below. */
    uint32_t sample_count;
    /** Observations for which the selected bit was one. */
    uint32_t ones;
    /** Observations for which the selected bit was zero. */
    uint32_t zeros;
    /** Changes between adjacent selected-bit observations. */
    uint32_t transitions;
    /** Adjacent observation pairs with values 0 then 0. */
    uint32_t pairs_00;
    /** Adjacent observation pairs with values 0 then 1. */
    uint32_t pairs_01;
    /** Adjacent observation pairs with values 1 then 0. */
    uint32_t pairs_10;
    /** Adjacent observation pairs with values 1 then 1. */
    uint32_t pairs_11;
    /** Longest run of either value. */
    uint32_t longest_run;
    /** Longest run of zeroes. */
    uint32_t longest_zero_run;
    /** Longest run of ones. */
    uint32_t longest_one_run;
    /** Proportion of ones in unsigned Q16 notation. */
    uint32_t p1_q16;
    /** Absolute distance of @ref p1_q16 from 0.5, in unsigned Q16. */
    uint32_t bias_q16;
    /** Adjacent-bit transition proportion in unsigned Q16 notation. */
    uint32_t transition_rate_q16;
    /** One-hot mask selecting the sampled bit within @ref source_address. */
    uint8_t source_mask;
    /** Differing observation pairs at lags 1 through 4, respectively. */
    uint32_t lag_mismatches[4];
    /** Health/qualification tests for which at least one complete window was evaluated. */
    uint8_t health_tests_evaluated;
    /** Evaluated tests which passed every diagnostic window. */
    uint8_t health_tests_passed;
    /** Runs which reached the production RCT cutoff. */
    uint32_t rct_failure_runs;
    /** Complete production-sized APT windows evaluated. */
    uint32_t apt_windows;
    /** APT windows in which either symbol reached the cutoff. */
    uint32_t apt_failures;
    /** Minimum and maximum one counts among complete APT windows. */
    uint32_t apt_min_ones;
    uint32_t apt_max_ones;
    /** Production-sized windows outside the startup marginal gate. */
    uint32_t startup_marginal_failures;
    /** Qualification-window failures for lags 1 through 4. */
    uint32_t lag_window_failures[4];
    /** Minimum lag mismatch count among complete qualification windows. */
    uint32_t lag_window_min_mismatches[4];
    /** Maximum lag mismatch count among complete qualification windows. */
    uint32_t lag_window_max_mismatches[4];
    /** Complete 1024-sample distribution windows evaluated. */
    uint32_t distribution_windows;
    /** Distribution windows failing either marginal or pair-disagreement gate. */
    uint32_t distribution_failures;
    /** One-count extrema among complete distribution windows. */
    uint32_t distribution_min_ones;
    uint32_t distribution_max_ones;
    /** Disjoint adjacent-pair disagreement extrema among distribution windows. */
    uint32_t distribution_min_disagreements;
    uint32_t distribution_max_disagreements;
};

#define TLS_RNG_STATS_LAG_COUNT 4u
#define TLS_RNG_STATS_MIN_SAMPLES 256u
#define TLS_RNG_STATS_MAX_SAMPLES 65535u
#define TLS_RNG_STATS_Q16_ONE 65536u
#define TLS_RNG_STATS_RCT_CUTOFF 76u
#define TLS_RNG_STATS_APT_WINDOW 952u
#define TLS_RNG_STATS_APT_CUTOFF 844u
#define TLS_RNG_STATS_STARTUP_ONES_MIN 238u
#define TLS_RNG_STATS_STARTUP_ONES_MAX 714u
#define TLS_RNG_STATS_LAG1_MISMATCH_MIN 136u
#define TLS_RNG_STATS_LAG1_MISMATCH_MAX 815u
#define TLS_RNG_STATS_LAG2_MISMATCH_MIN 136u
#define TLS_RNG_STATS_LAG2_MISMATCH_MAX 814u
#define TLS_RNG_STATS_LAG3_MISMATCH_MIN 135u
#define TLS_RNG_STATS_LAG3_MISMATCH_MAX 814u
#define TLS_RNG_STATS_LAG4_MISMATCH_MIN 135u
#define TLS_RNG_STATS_LAG4_MISMATCH_MAX 813u
#define TLS_RNG_STATS_DISTRIBUTION_WINDOW 1024u
#define TLS_RNG_STATS_DISTRIBUTION_ONES_MIN 256u
#define TLS_RNG_STATS_DISTRIBUTION_ONES_MAX 768u
#define TLS_RNG_STATS_DISTRIBUTION_DISAGREEMENTS_MIN 128u
#define TLS_RNG_STATS_DISTRIBUTION_DISAGREEMENTS_MAX 384u

/*************************************************************************************
 * @brief Samples the selected raw SRAM bit and computes diagnostic statistics.
 * @param sample_count Number of raw-bit observations to collect (256--65535).
 * @param stats        Destination for the resulting statistics.
 * @return true on success; false for invalid arguments, an uninitialized source,
 *         or while the RNG request engine is busy.
 *
 * @warning This is a blocking developer diagnostic. It samples the raw source
 * directly, before conditioning, and changes the physical source's observation
 * history. Do not use its output as generated randomness or as an entropy claim.
 */
bool tls_rng_compute_stats(size_t sample_count, struct tls_rng_stats *stats);

/***************************************************************************
 * @brief Ensures that a validated raw entropy source is available.
 *
 * SP 800-90B repetition-count and adaptive-proportion tests run continuously
 * inside the raw sampling path. This function reports whether a source is
 * ready and performs source initialization when necessary; it does not draw a
 * separate diagnostic sample. The lifecycle dispatcher retries source
 * initialization until its 15-second readiness deadline; after a terminal
 * timeout, restart the lwIP/RNG lifecycle before requesting output again.
 *
 * @return @b true if RNG health is currently acceptable, @b false otherwise.
 */
bool tls_rng_healthcheck(void);

/***************************************************************************
 * @brief Callback invoked when an RNG request completes.
 *
 * @param ok      true on success, false on failure.
 * @param arg     Opaque caller pointer supplied to tls_request_random_bytes().
 */
typedef void (*tls_random_request_cb_t)(bool ok, void *arg);

/***************************************************************************
 * @brief Request random data for TLS usage.
 *
 * Output is generated by the same SHA-256 Hash_DRBG used by
 * @ref tls_random_bytes. If instantiation or mandatory reseeding needs entropy,
 * @p blocking selects immediate collection or timer-driven completion.
 *
 * Only one request can be active at a time.
 *
 * @param out      Caller-provided destination buffer.
 * @param len      Number of random bytes requested.
 * @param cb       Optional completion callback.
 * @param arg      Opaque user context passed to @p cb.
 * @param blocking true for immediate completion path, false for async timer path.
 * @return true if request started/completed successfully, false on failure.
 * @note If @p blocking is true, this function may take a long time only when
 * the DRBG must gather entropy for instantiation or mandatory reseeding.
 * The caller is responsible for ensuring that @b out remains valid until the request completes, especially in the async case where @p cb may be invoked later.
 */
bool tls_request_random_bytes(uint8_t *out, size_t len, tls_random_request_cb_t cb, void *arg, bool blocking);

/***************************************************************************
 * @brief Returns whether the TLS RNG request engine currently has an active request.
 * @return true if a request is in progress, false otherwise.
 */
bool tls_rng_is_busy(void);

/** Credits bytes from an external full-entropy source (the Wi-Fi bridge TRNG).
 * 48 bytes (entropy input and nonce) instantiate a fresh 192-bit DRBG from them
 * together with output of the current one, so the result is no more
 * predictable than either source; this needs the DRBG already seeded. 24 bytes
 * reseed it. Any other length is rejected. */
bool tls_random_add_entropy(const uint8_t *data, size_t len);

/** While set, the local SRAM source stops gathering in the background and the
 * external source feeds the DRBG. The local source still steps in if the DRBG
 * ever needs entropy that has not arrived. */
void tls_random_set_external(bool external);

/* Internal lifecycle hooks used by tls.c. They are intentionally not part of
 * the release API surface. */
/** Start RNG health monitoring and entropy gathering.
 *
 * The first 50 ms callback performs blocking source selection. Later callbacks
 * instantiate at 128 bits, construct a separate 192-bit instance from fresh
 * material, and maintain its reseed reserve. The first ready state must be
 * reached within 15 seconds. Operations may use tls_random_bytes()
 * synchronously or tls_request_random_bytes() asynchronously; both fail
 * closed if entropy cannot be obtained when required.
 */
void tls_rng_start(void);
void tls_rng_cleanup(void);

#endif
