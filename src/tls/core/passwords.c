#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "../includes/hmac.h"
#include "../includes/passwords.h"

#define LWIP_DBG_FILE_ID LWIP_FILE_PASSWORDS
#define LWIP_DBG_MODULE  LWIP_DBG_MOD_TLS
#include "lwip/logging.h"

#define MIN(x, y)   ((x) < (y)) ? (x) : (y)
#define HASH_BLOCK_OUT_MAX  32

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
       (rounds==0)) { ERROR(); return false; }
       
    uint8_t hash_buffer[HASH_BLOCK_OUT_MAX],
            hash_composite[HASH_BLOCK_OUT_MAX];
    uint8_t c[4];
    struct tls_hmac_context initial, counter, state;
    size_t outlen;
    uint32_t ctr = 1;
    
    //HASH = sha256
    // DK = T(i) for i in 0 => (keylen/HASH), concat
    if(!tls_hmac_context_init(&initial, algorithm, password, passlen)) { ERROR(); return false; }
    
    size_t hash_len = initial.digestlen;
    
    // make a copy of initial to counter and update it with salt
    memcpy(&counter, &initial, sizeof counter);
    counter._update(&counter._private, salt, saltlen);
    
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
        memcpy(&state, &counter, sizeof state);
        state._update(&state._private, c, sizeof c);
        state.digest(&state, hash_buffer);
        memcpy(hash_composite, hash_buffer, hash_len);
        for(size_t ic=1; ic<rounds; ic++){
            memcpy(&state, &initial, sizeof state);
            state._update(&state._private, hash_buffer, hash_len);
            state.digest(&state, hash_buffer);
            for(uint8_t j=0; j < hash_len; j++)
                hash_composite[j] ^= hash_buffer[j];
        }
        memcpy(&key[outlen], hash_composite, copylen);
    }
    return true;
}
