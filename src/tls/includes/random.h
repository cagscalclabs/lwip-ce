
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

/** Lifecycle state of the asynchronous RNG service. */
typedef enum tls_rng_state
{
    TLS_RNG_STOPPED = 0,
    TLS_RNG_AWAITING_INIT,
    TLS_RNG_DRBG_SEEDING,
    TLS_RNG_DRBG_READY_128,
    TLS_RNG_DRBG_READY_256,
    TLS_RNG_FAILED
} tls_rng_state_t;

/** Minimum supported security-strength request. */
#define TLS_RNG_STRENGTH_128 128u
/** Maximum supported security-strength request. */
#define TLS_RNG_STRENGTH_256 256u

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
 * @brief Fills a buffer from the 256-bit-strength SHA-256 Hash_DRBG.
 * @param buffer    Pointer to a buffer to fill with random bytes.
 * @param len    Length of buffer to fill.
 * If the 256-bit DRBG is not yet instantiated, this call synchronously drives
 * source initialization, 128-bit availability, and fresh 256-bit promotion.
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
 *        @ref TLS_RNG_STRENGTH_256.
 * @return @p buffer on success, otherwise NULL with the destination zeroized.
 */
void *tls_random_bytes_ex(void *buffer, size_t len, uint16_t strength_bits);

/** Return the current asynchronous RNG lifecycle state. */
tls_rng_state_t tls_rng_status(void);

/** Return the currently available DRBG security strength: 0, 128, or 256. */
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
};

#define TLS_RNG_STATS_MIN_SAMPLES 256u
#define TLS_RNG_STATS_MAX_SAMPLES 65535u
#define TLS_RNG_STATS_Q16_ONE 65536u

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

/* Internal lifecycle hooks used by tls.c. They are intentionally not part of
 * the release API surface. */
/** Start RNG health monitoring and entropy gathering.
 *
 * The first 50 ms callback performs blocking source selection. Later callbacks
 * instantiate at 128 bits, construct a separate 256-bit instance from fresh
 * material, and maintain its reseed reserve. The first ready state must be
 * reached within 15 seconds. Operations may use tls_random_bytes()
 * synchronously or tls_request_random_bytes() asynchronously; both fail
 * closed if entropy cannot be obtained when required.
 */
void tls_rng_start(void);
void tls_rng_cleanup(void);

#endif
