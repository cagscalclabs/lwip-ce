#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "../includes/hmac.h"
#include "../includes/passwords.h"
#include "../includes/bytes.h"
#include "../includes/scratch.h"

#define LWIP_DBG_FILE_ID LWIP_FILE_PASSWORDS
#define LWIP_DBG_MODULE  LWIP_DBG_MOD_TLS
#include "lwip/logging.h"

#define MIN(x, y)   ((x) < (y)) ? (x) : (y)
/* PBKDF2 is hash-agnostic; size for the largest registered digest (SHA-512). */
#define HASH_BLOCK_OUT_MAX  TLS_HASH_MAX_DIGEST_LEN
/* Bounds the blocking work a malicious encrypted-key file can demand. */
#define TLS_PBKDF2_MAX_ROUNDS 1000000u

bool tls_pbkdf2(const char* password, size_t passlen,
                const uint8_t* salt, size_t saltlen,
                uint8_t *key, size_t keylen,
                size_t rounds, uint8_t algorithm){
    
    if((password==NULL) ||
       (key==NULL) ||
       (salt==NULL) ||
       (passlen==0) ||
       (saltlen==0) ||
       (keylen==0) ||
       (rounds==0) ||
       (rounds > TLS_PBKDF2_MAX_ROUNDS)) { ERROR(); return false; }
       
    struct {
        uint8_t hash_buffer[HASH_BLOCK_OUT_MAX];
        uint8_t hash_composite[HASH_BLOCK_OUT_MAX];
        struct tls_hmac_context initial, counter, state;
    } *t;
    uint8_t c[4] = {0};
    size_t outlen;
    uint32_t ctr = 1;

    t = tls_scratch_alloc(sizeof(*t));
    if (!t) { ERROR(); return false; }
    memset(t, 0, sizeof(*t));

    // DK = T(i) for i in 0 => (keylen/HASH), concat; HASH is the selected
    // algorithm (SHA-256, SHA-384, or SHA-512).
    if(!tls_hmac_context_init(&t->initial, algorithm,
                              (const uint8_t *)password, passlen)) {
        tls_scratch_free(t, sizeof(*t));
        ERROR();
        return false;
    }

    size_t hash_len = t->initial.digestlen;
    if (hash_len == 0 || hash_len > HASH_BLOCK_OUT_MAX)
    {
        tls_scratch_free(t, sizeof(*t));
        ERROR();
        return false;
    }

    // make a copy of initial to counter and update it with salt
    memcpy(&t->counter, &t->initial, sizeof t->counter);
    t->counter.update(&t->counter, salt, saltlen);

    for(outlen = 0; outlen < keylen; outlen+=hash_len, ctr++){
        //T(i) = F(password, salt, c, i) = U1 xor U2 xor ... xor Uc
        //U1 = PRF1(Password, Salt + INT_32_BE(i))
        //U2 = PRF(Password, U1)
        //⋮
        //Uc = PRF(Password, Uc)
        size_t copylen = MIN(keylen-outlen, hash_len);
        c[0] = (ctr >> 24) & 0xff;
        c[1] = (ctr >> 16) & 0xff;
        c[2] = (ctr >> 8) & 0xff;
        c[3] = ctr & 0xff;
        memcpy(&t->state, &t->counter, sizeof t->state);
        t->state.update(&t->state, c, sizeof c);
        t->state.digest(&t->state, t->hash_buffer);
        memcpy(t->hash_composite, t->hash_buffer, hash_len);
        for(size_t ic=1; ic<rounds; ic++){
            memcpy(&t->state, &t->initial, sizeof t->state);
            t->state.update(&t->state, t->hash_buffer, hash_len);
            t->state.digest(&t->state, t->hash_buffer);
            for(size_t j=0; j < hash_len; j++)
                t->hash_composite[j] ^= t->hash_buffer[j];
        }
        memcpy(&key[outlen], t->hash_composite, copylen);
    }
    tls_scratch_free(t, sizeof(*t));
    tls_secure_memzero(c, sizeof c);
    return true;
}
