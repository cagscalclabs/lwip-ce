[u][b]Unofficial Cemetech Programming Contest[/b][/u]
[b]x25519 Key Exchange[/b]
[i]Calling all efficient ez80 asm programmers...[/i]


[b]Overview[/b]
x25519 KEX is the last remaining algorithm needed for a functional, bare-minimum TLS 1.3 implementation within lwIP-CE. Rather than do it in slow and unoptimized in ez80 or C myself,or just post and ask for someone to do it, I decided to try to turn it into a contest to boost engagement and challenge the community.


[b]Objective[/b]
We're looking for the [u]fastest, most efficient, and most timing-consistent implementation[/u] of x25519 key exchange (and the required field arithmetic) for the TI-84+ CE calculator.


[b]Timeline:[/b] Contest closes February 21st.

[b]Prizes:[/b]
First Place: $150 Gift Card to Retailer of Your Choice
Second place: $75 Gift Card to Retailer of Your Choice
[i]Amazon, Steam, Best Buy, Target, or any major retailer[/i]


-----

[b]What is X25519?[/b]
X25519 is a Diffie-Hellman key exchange algorithm using Curve25519, one of the most widely-used elliptic curves for modern TLS connections. It allows two hosts to negotiate a shared key for encryption with forward secrecy.

-----

[b]What You Need to Implement[/b]

Implement these two functions according to RFC 7748:

[code]
/**
 * @brief X25519 scalar multiplication (compute shared secret)
 *
 * @param shared_secret Output shared secret (32 bytes, little-endian)
 * @param my_private    Our private scalar (32 bytes, will be clamped internally)
 * @param their_public  Peer's public key point (32 bytes, u-coordinate)
 * @param yield_fn      Optional: callback for cooperative multitasking (may be NULL)
 * @param yield_data    Optional: context passed to yield_fn (may be NULL)
 * @return true on success, false on error (e.g., low-order point)
 */
bool tls_x25519_secret(
    uint8_t shared_secret[32],
    const uint8_t my_private[32],
    const uint8_t their_public[32],
    void (*yield_fn)(void *),
    void *yield_data
);

/**
 * @brief Generate X25519 public key from private key
 *
 * @param public_key  Output public key (32 bytes, u-coordinate)
 * @param private_key Input private scalar (32 bytes, will be clamped internally)
 * @param yield_fn    Optional: callback for cooperative multitasking (may be NULL)
 * @param yield_data  Optional: context passed to yield_fn (may be NULL)
 */
bool tls_x25519_publickey(
    uint8_t public_key[32],
    const uint8_t private_key[32],
    void (*yield_fn)(void *),
    void *yield_data
);
[/code]
[b]Note:[/b] The [i]yield_fn[/i] callback is for network keepalives during long computations. It will be NULL during testing, but should be called every 5-10 seconds during production use. Contestant should implement the logic to call yield_fn, or at least leave a note to indicate where it should be added.

[b]Key Requirements:[/b]
[list]
[*]Pass ALL RFC 7748 test vectors (100% correctness required) => Failing any test vector disqualifies your submission.
[*]Handle edge cases (low-order points, clamping, etc.)
[*][b]No Hardcoded Secrets:[/b] No precomputed values specific to test vectors (algorithm constants like curve parameters are allowed).
[*]Optional: Constant-time implementation (timing attack resistance).
[*][b]Documentation:[/b] Include brief implementation notes explaining your approach and optimizations
[*][b]Open Source:[/b] Code must be contributed under a permissive license (MIT/BSD compatible)
[/list]


[b]Scoring Rubric[/b]

Submissions are ranked by total points. [b]Highest score wins the $150 prize.[/b]

[table]
[tr][th]Category[/th][th]Max Points[/th][th]Criteria[/th][/tr]
[tr][td][b]Speed Performance[/b][/td][td]40 pts[/td][td]< 30s = 10pts, < 25s = 20pts, < 20s = 30pts, < 15s = 40pts[/td][/tr]
[tr][td][b]Timing Consistency[/b][/td][td]20 pts[/td][td]Based on your own run-time std dev: ≤50% = 5pts, ≤25% = 10pts, ≤12.5% = 20pts[/td][/tr]
[tr][td][b]Code Size[/b][/td][td]15 pts[/td][td]≤8KB = 5pts, ≤4KB = 10pts, ≤2KB = 15pts[/td][/tr]
[tr][td][b]Memory Usage[/b][/td][td]15 pts[/td][td]≤8KB = 5pts, ≤4KB = 10pts, ≤2KB = 15pts[/td][/tr]
[tr][td][b]Code Quality[/b][/td][td]up to 10 pts[/td][td]Readability, documentation, clever optimizations[/td][/tr]
[/table]
[i]Benchmarking and testing will be done using the CEmu autotester, but submission must be verified working on hardware as well.[/i]
[i]Code size is computed as your compiled size minus skeleton test size (9760 bytes).[/i]

[b]Bonus Points:[/b]
[list]
[*][b]+10 points:[/b] Tightest timing consistency (lowest std dev) among all contestants
[/list]

[b]Total Possible:[/b] 100 points
[b]Tie-breaker:[/b] If two submissions have identical scores, the faster implementation wins


[b]Submission Format[/b]

Submit your entry as a GitHub repository or archive containing:

[code]
src/x25519.c        - \
src/x25519.asm      - | Source files
includes/x25519.h   - Header file matching API
README.md      - Brief writeup (1-2 pages)
[/code]


[b]Test Suite[/b]

The test suite is provided in the contest repository:
[code]
contest/tests/x25519/
├── src/main.c        - Test harness with RFC 7748 vectors
├── Makefile          - Build configuration
└── autotest.json     - Automated testing config
[/code]

[b]Test Vectors:[/b]
[list]
[*]6 RFC 7748 test vectors (various edge cases)
[*]2 performance benchmarks: 5x pubkey generations, 6x secret computation.
[*]Automated verification via CEmu with screen hash checking
[/list]

[b]Running Tests:[/b]
[code]
cd contest/tests/x25519
make test
# Transfer to calculator or run in CEmu with autotest.json
[/code]

[hr]

[b]Resources[/b]

[b]Documentation:[/b]
[list]
[*][url=https://tools.ietf.org/html/rfc7748]RFC 7748 - Elliptic Curves for Security[/url] (official spec)
[*][url=https://www.cl.cam.ac.uk/teaching/2122/Crypto/curve25519.pdf]Implementing Curve25519/X25519 - Cambridge Tutorial[/url] (implementation guide)
[*][url=https://cr.yp.to/ecdh.html]Curve25519: New Diffie-Hellman Speed Records[/url] (original paper)
[/list]


[u][b]FAQ[/b][/u]

[b]Q: Can I use external libraries?[/b]
A: No. All code must be written by you. You may reference specifications and papers, but no copy-paste from other implementations.

[b]Q: What if I find a bug in the test suite?[/b]
A: Report it immediately via GitHub issues. If confirmed, the deadline may be extended for all participants.

[b]Q: Can I use lookup tables?[/b]
A: Yes. Precomputed constants that are part of the algorithm (curve parameters, reduction constants) are allowed. What's NOT allowed is hardcoding values specific to test vectors.

[b]Q: Do I need to implement constant-time operations?[/b]
A: It is not strictly required, you only need to pass RFC 7748 test vectors. But it's a fairly large component of the score.

[b]Q: How do I clamp the scalar?[/b]
A: RFC 7748 Section 5 requires: [font=courier]scalar[0] &= 0xF8[/font] (clear bits 0,1,2), [font=courier]scalar[31] &= 0x7F[/font] (clear bit 255), [font=courier]scalar[31] |= 0x40[/font] (set bit 254). This ensures the scalar is a multiple of 8 and in range 2^254 - 2^255.


[b]Judging Process[/b]

[list=1]
[*][b]Automated Testing:[/b] All submissions run through test suite (pass/fail)
[*][b]Performance Benchmarking:[/b] Speed, timing consistency, code size, memory measured automatically
[*][b]Code Review:[/b] Manual review for quality, security, and integration
[*][b]Scoring:[/b] Points tallied according to rubric above
[*][b]Winner Selection:[/b] Highest score wins $150 gift card. Runner up wins $75 gift card.
[/list]


[b]Ready to Compete?[/b]

[b]Repository:[/b] [url=https://github.com/cagscalclabs/lwip-ce]github.com/cagscalclabs/lwip-ce[/url]
[b]Test Vectors:[/b] [font=courier]contest/ (in TLS branch)[/font]
[b]Questions?[/b] Contact [i]info@cagscalclabs.net[/i]

[b]Good luck, and may the best implementation win! [/b]
