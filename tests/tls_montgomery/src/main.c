#include <ti/screen.h>
#include <ti/getkey.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#include "rsa.h" /* for tls_mont_mul_le prototype */

/* Simple big-endian helpers for small test vectors */
static int be_cmp(const uint8_t *a, const uint8_t *b, size_t len){
    for(size_t i = 0; i < len; i++){
        if(a[i] != b[i]) return (a[i] > b[i]) ? 1 : -1;
    }
    return 0;
}

static void be_sub(uint8_t *a, const uint8_t *b, size_t len){
    int borrow = 0;
    for(size_t i = 0; i < len; i++){
        size_t idx = len - 1 - i;
        int diff = (int)a[idx] - (int)b[idx] - borrow;
        if(diff < 0){ diff += 256; borrow = 1; } else borrow = 0;
        a[idx] = (uint8_t)diff;
    }
}

static void be_shift8_add(uint8_t *r, size_t len, uint8_t byte){
    memmove(r, r + 1, len - 1);
    r[len - 1] = byte;
}

static void be_lshift8_mod(uint8_t *val, const uint8_t *mod, size_t len){
    uint16_t carry = 0;
    for(size_t i = 0; i < len; i++){
        size_t idx = len - 1 - i;
        uint16_t v = ((uint16_t)val[idx] << 8) | carry;
        val[idx] = (uint8_t)v;
        carry = (uint8_t)(v >> 8);
    }
    if(be_cmp(val, mod, len) >= 0) be_sub(val, mod, len);
}

static void be_mul_mod(const uint8_t *a, const uint8_t *b, const uint8_t *mod, size_t len, uint8_t *out, uint8_t *scratch){
    uint8_t *prod = scratch;        /* 2*len */
    uint8_t *rem  = prod + (len<<1);/* len */
    memset(prod, 0, len<<1);
    for(size_t i = 0; i < len; i++){
        uint32_t carry = 0;
        uint8_t ai = a[len - 1 - i];
        for(size_t j = 0; j < len; j++){
            size_t idx = (len<<1) - 1 - (i + j);
            uint32_t sum = prod[idx] + (uint32_t)ai * b[len - 1 - j] + carry;
            prod[idx] = (uint8_t)sum;
            carry = sum >> 8;
        }
        size_t k = (len<<1) - 1 - (i + len);
        while(carry){
            uint32_t sum = prod[k] + carry;
            prod[k] = (uint8_t)sum;
            carry = sum >> 8;
            if(k == 0) break;
            k--;
        }
    }
    memset(rem, 0, len);
    for(size_t idx = 0; idx < (len<<1); idx++){
        be_shift8_add(rem, len, prod[idx]);
        while(be_cmp(rem, mod, len) >= 0)
            be_sub(rem, mod, len);
    }
    memcpy(out, rem, len);
}

static uint8_t inv_byte(uint8_t x){
    /* compute x^{-1} mod 256 assuming x odd */
    uint8_t y = 1;
    for(int i = 0; i < 8; i++) y *= (uint8_t)(2 - x * y);
    return y;
}

static void be_to_le(const uint8_t *be, uint8_t *le, size_t len){
    for(size_t i = 0; i < len; i++) le[i] = be[len - 1 - i];
}

static bool test_mont_mul(void){
    /* 128-bit test vector */
    uint8_t mod[16] = {0xF1,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x99};
    uint8_t a[16]   = {0x01,0x23,0x45,0x67,0x89,0x10,0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10,0xEE,0xFF};
    uint8_t b[16]   = {0xDE,0xAD,0xBE,0xEF,0x12,0x34,0x56,0x78,0x9A,0xBC,0xDE,0xF0,0x0F,0x1E,0x2D,0x3C};
    uint8_t ref[16], scratch[(16<<1)+16] = {0};
    be_mul_mod(a, b, mod, 16, ref, scratch);

    uint8_t le_mod[16], le_R2[16], le_a[16], acc[17], tmp[17];
    be_to_le(mod, le_mod, 16);

    /* compute R2 = (1<<(16*len)) mod n in BE then convert to LE */
    uint8_t be_tmp[16] = {0};
    be_tmp[15] = 1;
    for(int i=0;i<16;i++) be_lshift8_mod(be_tmp, mod, 16);
    for(int i=0;i<16;i++) be_lshift8_mod(be_tmp, mod, 16);
    be_to_le(be_tmp, le_R2, 16);
    be_to_le(a, le_a, 16);

    uint8_t n0inv = (uint8_t)(-inv_byte(le_mod[0]));

    /* encode a: tmp = mont(a, R2) */
    memcpy(tmp, le_a, 16); tmp[16]=0;
    tls_mont_mul_le(tmp, tmp, le_R2, le_mod, n0inv, 16);

    /* encode b: acc = mont(b, R2) */
    be_to_le(b, acc, 16); acc[16]=0;
    tls_mont_mul_le(acc, acc, le_R2, le_mod, n0inv, 16);

    /* mont multiply: tmp = tmp * acc */
    tls_mont_mul_le(tmp, tmp, acc, le_mod, n0inv, 16);

    /* decode: tmp = mont(tmp, 1) */
    memset(acc, 0, 17); acc[0]=1;
    tls_mont_mul_le(tmp, tmp, acc, le_mod, n0inv, 16);

    /* compare */
    for(size_t i=0;i<16;i++){
        if(tmp[16-1-i] != ref[i]) return false;
    }
    return true;
}

int main(void){
    os_ClrHome();
    bool ok = test_mont_mul();
    if(ok){
        printf("MONT OK");
    } else {
        printf("MONT FAIL");
    }
    os_GetKey();
    return 0;
}
