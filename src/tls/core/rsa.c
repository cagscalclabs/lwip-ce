
#include <stdint.h>
#include <string.h>
#include "../includes/bytes.h"
#include "../includes/random.h"
#include "../includes/hash.h"
#include "../includes/rsa.h"

#define    ENCODE_START     0
#define ENCODE_SALT     (1 + ENCODE_START)
bool tls_rsa_encode_oaep(const uint8_t* inbuf, size_t in_len, uint8_t* outbuf,
                           size_t modulus_len, const char *auth, uint8_t hash_alg){
    
    // initial sanity checks
    if((modulus_len > RSA_MODULUS_MAX_SUPPORTED) ||
       (modulus_len < RSA_MODULUS_MIN_SUPPORTED) ||
       (inbuf == NULL) ||
       (outbuf == NULL) ||
       (in_len == 0)
    ) return false;
    
    struct tls_hash_context hash;
    if(!tls_hash_context_init(&hash, hash_alg)) return false;
    size_t min_padding_len = (hash.digestlen<<1) + 2;
    size_t ps_len = modulus_len - in_len - min_padding_len;
    size_t db_len = modulus_len - hash.digestlen - 1;
    size_t encode_lhash = ENCODE_SALT + hash.digestlen;
    size_t encode_ps = encode_lhash + hash.digestlen;
    uint8_t mgf1_digest[RSA_MODULUS_MAX_SUPPORTED];
    
    if((in_len + min_padding_len) > modulus_len) return false;
    
    // set first byte to 00
    outbuf[ENCODE_START] = 0x00;
    // seed next 32 bytes
    tls_random_bytes(&outbuf[ENCODE_SALT], hash.digestlen);
    
    // hash the authentication string
    if(auth != NULL) hash.update(&hash._private, auth, strlen(auth));
    hash.digest(&hash._private, &outbuf[encode_lhash]);    // nothing to actually hash
    
    memset(&outbuf[encode_ps], 0, ps_len);        // write padding zeros
    outbuf[encode_ps + ps_len] = 0x01;            // write 0x01
    memcpy(&outbuf[encode_ps + ps_len + 1], inbuf, in_len);        // write plaintext to end of output
    
    // hash the salt with MGF1, return hash length of db
    tls_mgf1(&outbuf[ENCODE_SALT], hash.digestlen, mgf1_digest, db_len, hash_alg);
    
    // XOR hash with db
    for(size_t i=0; i < db_len; i++)
        outbuf[encode_lhash + i] ^= mgf1_digest[i];
    
    // hash db with MGF1, return hash length of RSA_SALT_SIZE
    tls_mgf1(&outbuf[encode_lhash], db_len, mgf1_digest, hash.digestlen, hash_alg);
    
    // XOR hash with salt
    for(size_t i=0; i<hash.digestlen; i++)
        outbuf[ENCODE_SALT + i] ^= mgf1_digest[i];
    
    // Return the static size of 256
    return true;
}


size_t tls_rsa_decode_oaep(const uint8_t *inbuf, size_t in_len, uint8_t* outbuf, const char *auth, uint8_t hash_alg){
    
    if((in_len > RSA_MODULUS_MAX_SUPPORTED) ||
       (in_len < RSA_MODULUS_MIN_SUPPORTED) ||
       (inbuf == NULL) ||
       (outbuf == NULL)) return 0;
    
    struct tls_hash_context hash;
    if(!tls_hash_context_init(&hash, hash_alg)) return false;
    
    size_t db_len = in_len - hash.digestlen - 1;
    uint8_t sha256_digest[TLS_SHA256_DIGEST_LEN];
    size_t encode_lhash = ENCODE_SALT + hash.digestlen;
    size_t encode_ps = encode_lhash + hash.digestlen;
    uint8_t mgf1_digest[RSA_MODULUS_MAX_SUPPORTED];
    size_t i;
    uint8_t tmp[RSA_MODULUS_MAX_SUPPORTED];
    
    memcpy(tmp, inbuf, in_len);
    
    // Copy last 16 bytes of input buf to salt to get encoded salt
    // memcpy(salt, &in[len-RSA_SALT_SIZE-1], RSA_SALT_SIZE);
    
    // SHA-256 hash db
    tls_mgf1(&tmp[encode_lhash], db_len, mgf1_digest, hash.digestlen, hash_alg);
    
    // XOR hash with encoded salt to return salt
    for(i = 0; i < TLS_SHA256_DIGEST_LEN; i++)
        tmp[ENCODE_SALT + i] ^= mgf1_digest[i];
    
    // MGF1 hash the salt
    tls_mgf1(&tmp[ENCODE_SALT], hash.digestlen, mgf1_digest, db_len, hash_alg);
    
    // XOR MGF1 of salt with encoded message to get decoded message
    for(i = 0; i < db_len; i++)
        tmp[encode_lhash + i] ^= mgf1_digest[i];
    
    // verify authentication
    if(auth != NULL) hash.update(&hash._private, auth, strlen(auth));
    hash.digest(&hash._private, &outbuf[encode_lhash]);
    
    if(!tls_bytes_compare(sha256_digest, outbuf, TLS_SHA256_DIGEST_LEN)) return 0;
    
    for(i = encode_ps; i < in_len; i++)
        if(tmp[i] == 0x01) break;
    if(i==in_len) return false;
    i++;
    memcpy(outbuf, &tmp[i], in_len-i);
    
    
    return in_len-i;
}

void powmod_exp_u24(uint8_t size, uint8_t *restrict base, uint24_t exp, const uint8_t *restrict mod);
#define RSA_PUBLIC_EXP  65537
bool tls_rsa_encrypt(const uint8_t* inbuf, size_t in_len, uint8_t *outbuf,
                     const uint8_t* pubkey, size_t keylen, uint8_t hash_alg){
    size_t spos = 0;
    if((inbuf==NULL) ||
       (pubkey==NULL) ||
       (outbuf==NULL) ||
       (in_len==0) ||
       (keylen<RSA_MODULUS_MAX_SUPPORTED) ||
       (keylen>RSA_MODULUS_MIN_SUPPORTED) ||
       (!(pubkey[keylen-1]&1))) return false;
    
    while(pubkey[spos]==0) {outbuf[spos++] = 0;}
    if(!tls_rsa_encode_oaep(inbuf, in_len, &outbuf[spos], keylen-spos, NULL, hash_alg)) return false;
    powmod_exp_u24((uint8_t)keylen, outbuf, RSA_PUBLIC_EXP, pubkey);
    return true;
}

/* internal: count significant bits in big-endian modulus */
static uint16_t tls_rsa_mod_bitlen(const uint8_t *mod, size_t mod_len){
    size_t i = 0;
    while(i < mod_len && mod[i] == 0) i++;
    if(i == mod_len) return 0;
    uint8_t msb = mod[i];
    uint8_t bits = 8;
    while(bits && ((msb >> (bits-1)) == 0)) bits--;
    return (uint16_t)((mod_len - i - 1) * 8 + bits);
}

/* big-endian comparison: returns -1,0,1 */
static int tls_big_cmp_be(const uint8_t *a, const uint8_t *b, size_t len){
    for(size_t i = 0; i < len; i++){
        if(a[i] != b[i]) return (a[i] > b[i]) ? 1 : -1;
    }
    return 0;
}

/* big-endian subtract: assumes a >= b, stores into a */
static void tls_big_sub_be(uint8_t *a, const uint8_t *b, size_t len){
    int borrow = 0;
    for(size_t i = 0; i < len; i++){
        size_t idx = len - 1 - i;
        int diff = (int)a[idx] - (int)b[idx] - borrow;
        if(diff < 0){
            diff += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        a[idx] = (uint8_t)diff;
    }
}

/* shift remainder left by 8 and add byte */
static void tls_big_shift8_add(uint8_t *r, size_t len, uint8_t byte){
    memmove(r, r + 1, len - 1);
    r[len - 1] = byte;
}

/* shift-left by one byte (8 bits) modulo mod (all big-endian, len bytes) */
static void tls_big_lshift8_mod(uint8_t *val, const uint8_t *mod, size_t len){
    uint16_t carry = 0;
    for(size_t i = 0; i < len; i++){
        size_t idx = len - 1 - i;
        uint16_t v = ((uint16_t)val[idx] << 8) | carry;
        val[idx] = (uint8_t)v;
        carry = (uint8_t)(v >> 8);
    }
    if(tls_big_cmp_be(val, mod, len) >= 0)
        tls_big_sub_be(val, mod, len);
}

/* Compute (a * b) mod mod (all big-endian, same length).
 * scratch: prod[2*len] || rem[len]
 */
static void tls_big_mul_mod_be(const uint8_t *a, const uint8_t *b, size_t len,
                               const uint8_t *mod, uint8_t *out,
                               uint8_t *scratch){
    uint8_t *prod = scratch;
    uint8_t *rem = prod + (len << 1);
    memset(prod, 0, (len << 1));
    /* schoolbook mul */
    for(size_t i = 0; i < len; i++){
        uint32_t carry = 0;
        uint8_t ai = a[len - 1 - i];
        for(size_t j = 0; j < len; j++){
            size_t idx = (len << 1) - 1 - (i + j);
            uint32_t sum = (uint32_t)prod[idx] + (uint32_t)ai * b[len - 1 - j] + carry;
            prod[idx] = (uint8_t)sum;
            carry = sum >> 8;
        }
        size_t k = (len << 1) - 1 - (i + len);
        while(carry){
            uint32_t sum = (uint32_t)prod[k] + carry;
            prod[k] = (uint8_t)sum;
            carry = sum >> 8;
            if(k == 0) break;
            k--;
        }
    }
    /* modulo via long division */
    memset(rem, 0, len);
    for(size_t idx = 0; idx < (len << 1); idx++){
        tls_big_shift8_add(rem, len, prod[idx]);
        while(tls_big_cmp_be(rem, mod, len) >= 0){
            tls_big_sub_be(rem, mod, len);
        }
    }
    memcpy(out, rem, len);
}

/* (base^65537 mod mod) with big-endian inputs; scratch = prod(2n)+rem(n)+x(n)+tmp(n) */
/* Montgomery modexp: scratch layout
 * [be_tmp(len)] [be_mod(len)] [R(len)] [R2(len)] [le_base(len)] [le_mod(len)] [acc(len+1)] [tmp(len+1)]
 */
extern void tls_mont_mul_le(uint8_t *t, const uint8_t *a, const uint8_t *b,
                            const uint8_t *n, uint8_t n0inv, uint16_t len);

static void tls_compute_R_and_R2(const uint8_t *mod, size_t len, uint8_t *R, uint8_t *R2, uint8_t *scratch){
    /* scratch: be_tmp(len) */
    uint8_t *tmp = scratch;
    memset(tmp, 0, len);
    tmp[len - 1] = 1; /* value = 1 */
    /* compute R = 2^(8*len) mod n by shifting len times */
    for(size_t i = 0; i < len; i++)
        tls_big_lshift8_mod(tmp, mod, len);
    memcpy(R, tmp, len);
    /* compute R2 = R shifted len more bytes (i.e., 2^(16*len) mod n) */
    for(size_t i = 0; i < len; i++)
        tls_big_lshift8_mod(tmp, mod, len);
    memcpy(R2, tmp, len);
}

static bool tls_modexp65537_be(const uint8_t *base, const uint8_t *mod, size_t len,
                               uint8_t *out, uint8_t *scratch, size_t scratch_len){
    /* need: be_tmp len + be_mod len + R len + R2 len + le_base len + le_mod len + acc len+1 + tmp len+1 */
    size_t need = (len * 6) + (len + 1) * 2;
    if(scratch_len < need || len == 0) return false;
    uint8_t *be_tmp = scratch;
    uint8_t *be_mod = be_tmp + len;
    uint8_t *R      = be_mod + len;
    uint8_t *R2     = R + len;
    uint8_t *le_base = R2 + len;
    uint8_t *le_mod  = le_base + len;
    uint8_t *acc     = le_mod + len;
    uint8_t *tmp     = acc + (len + 1);

    memcpy(be_mod, mod, len);
    tls_compute_R_and_R2(be_mod, len, R, R2, be_tmp);

    /* convert base/mod/R2 to little-endian for montgomery mul */
    for(size_t i = 0; i < len; i++){
        le_base[i] = base[len - 1 - i];
        le_mod[i]  = be_mod[len - 1 - i];
        tmp[i]     = R2[len - 1 - i]; /* reuse tmp as le_R2 */
    }
    uint8_t *le_R2 = tmp;

    /* n0inv = -n[0]^{-1} mod 256 */
    uint8_t n0 = le_mod[0];
    if((n0 & 1u) == 0) return false;
    uint8_t n0inv = 1;
    for(int i = 0; i < 8; i++) n0inv *= (2 - n0 * n0inv);
    n0inv = (uint8_t)(-n0inv);

    /* acc = 1 in Montgomery domain: acc = mont(1, R2) => R mod n */
    memset(acc, 0, len + 1);
    acc[0] = 1;
    tls_mont_mul_le(acc, acc, le_R2, le_mod, n0inv, (uint16_t)len);

    /* tmp = mont(base, R2) => base in Montgomery domain */
    memcpy(tmp, le_base, len);
    tmp[len] = 0;
    tls_mont_mul_le(tmp, tmp, le_R2, le_mod, n0inv, (uint16_t)len);

    /* exponentiation e = 65537 (0x10001): 16 squares, then multiply by base */
    for(int i = 0; i < 16; i++)
        tls_mont_mul_le(tmp, tmp, tmp, le_mod, n0inv, (uint16_t)len);
    tls_mont_mul_le(tmp, tmp, le_base, le_mod, n0inv, (uint16_t)len);

    /* convert out of Montgomery: tmp = mont(tmp, 1) */
    memset(acc, 0, len + 1);
    acc[0] = 1;
    tls_mont_mul_le(tmp, tmp, acc, le_mod, n0inv, (uint16_t)len);

    for(size_t i = 0; i < len; i++)
        out[i] = tmp[len - 1 - i];
    return true;
}

/* Caller must supply scratch; see tls_rsa_pss_verify for sizing guidance. */
bool tls_rsa_pss_verify(const uint8_t *signature, size_t sig_len,
                        const uint8_t *modulus, size_t mod_len,
                        const uint8_t *mhash, size_t mhash_len,
                        uint8_t hash_alg, uint8_t *scratch, size_t scratch_len){
    if(signature == NULL || modulus == NULL || mhash == NULL || scratch == NULL) return false;
    if(sig_len == 0 || mod_len == 0 || sig_len != mod_len) return false;
    if(mod_len < RSA_MODULUS_MIN_SUPPORTED || mod_len > RSA_MODULUS_MAX_SUPPORTED) return false;

    struct tls_hash_context hash;
    if(!tls_hash_context_init(&hash, hash_alg)) return false;
    if(mhash_len != hash.digestlen) return false; /* enforce TLS 1.3 salt length rule */

    size_t db_len = mod_len - hash.digestlen - 1;
    /* scratch layout: [modexp(5*mod_len)] [em (mod_len)] [mask/db (db_len)] [tmp (8+2*h)] */
    size_t modexp_need = (mod_len << 1) + (mod_len * 3); /* prod2 + rem + x + tmp */
    size_t other_need = mod_len + db_len + (8 + (hash.digestlen << 1));
    if(scratch_len < (modexp_need + other_need)) return false;

    uint8_t *modexp_scratch = scratch;
    uint8_t *em = scratch + modexp_need;
    uint8_t *db_mask = em + mod_len;
    uint8_t *tmp = db_mask + db_len;

    if(!tls_modexp65537_be(signature, modulus, mod_len, em, modexp_scratch, modexp_need)) return false;

    /* RFC 8017: emBits = modBits - 1 */
    uint16_t mod_bits = tls_rsa_mod_bitlen(modulus, mod_len);
    if(mod_bits == 0) return false;
    uint16_t em_bits = mod_bits - 1;
    uint8_t unused = (uint8_t)(mod_len * 8 - em_bits);
    if(unused > 8 || unused == 0) return false;
    uint8_t top_mask = (uint8_t)(0xFFu >> unused);

    if((em[0] & ~top_mask) != 0) return false;
    em[0] &= top_mask;
    if(em[mod_len - 1] != 0xBC) return false;

    uint8_t *H = &em[mod_len - 1 - hash.digestlen];
    uint8_t *DB = em;

    /* unmask DB */
    if(!tls_mgf1(H, hash.digestlen, db_mask, db_len, hash_alg)) return false;
    for(size_t i = 0; i < db_len; i++) DB[i] ^= db_mask[i];
    DB[0] &= top_mask;
    if((DB[0] & ~top_mask) != 0) return false;

    /* find 0x01 separator */
    size_t ps_end = 0;
    while(ps_end < db_len && DB[ps_end] == 0) ps_end++;
    if(ps_end >= db_len || DB[ps_end] != 0x01) return false;
    ps_end++;
    if(db_len - ps_end != hash.digestlen) return false; /* enforce salt length == hLen */
    uint8_t *salt = &DB[ps_end];

    /* H' = Hash(0x00*8 || mHash || salt) */
    memset(tmp, 0, 8);
    memcpy(&tmp[8], mhash, hash.digestlen);
    memcpy(&tmp[8 + hash.digestlen], salt, hash.digestlen);

    hash.update(&hash._private, tmp, 8 + (hash.digestlen << 1));
    hash.digest(&hash._private, db_mask); /* reuse db_mask buffer for H' */

    return tls_bytes_compare(db_mask, H, hash.digestlen);
}
