#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../../src/tls/includes/hash.h"

/* Correctness-oriented reference implementation.  This translation unit is
 * deliberately outside src/ and is not linked into lwIP-CE. */

typedef uint8_t u256[32];

typedef struct {
    u256 x, y, z;
} p256_point;

static const u256 P = {
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0xff,0xff,0xff,0xff
};
static const u256 P_R = {
    0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,0xff,0xff,0xff,0x00,0x00,0x00,0x00
};
static const u256 P_R2 = {
    0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xfb,0xff,0xff,0xff,
    0xfe,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfd,0xff,0xff,0xff,0x04,0x00,0x00,0x00
};
static const u256 P_MINUS_2_BE = {
    0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfd
};
static const u256 P_B_R = {
    0xdf,0xbd,0xc4,0x29,0x62,0xdf,0x9c,0xd8,0x90,0x30,0x84,0x78,0xcd,0x05,0xf0,0xac,
    0xd6,0x2e,0x21,0xf7,0xab,0x20,0xa2,0xe5,0x34,0x48,0x87,0x04,0x1d,0x06,0x30,0xdc
};
static const u256 P_GX_R = {
    0x3c,0x14,0xa9,0x18,0xd4,0x30,0xe7,0x79,0x01,0xb6,0xed,0x5f,0xfc,0x95,0xba,0x75,
    0x10,0x25,0x62,0x77,0x2b,0x73,0xfb,0x79,0xc6,0x55,0x37,0xa5,0x76,0x5f,0x90,0x18
};
static const u256 P_GY_R = {
    0x0a,0x56,0x95,0xce,0x57,0x53,0xf2,0xdd,0x5c,0xe4,0x19,0xba,0xe4,0xb8,0x4a,0x8b,
    0x25,0xf3,0x21,0xdd,0x88,0x86,0xe8,0xd2,0x85,0x5d,0x88,0x25,0x18,0xff,0x71,0x85
};

static const u256 N = {
    0x51,0x25,0x63,0xfc,0xc2,0xca,0xb9,0xf3,0x84,0x9e,0x17,0xa7,0xad,0xfa,0xe6,0xbc,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff
};
static const u256 N_R = {
    0xaf,0xda,0x9c,0x03,0x3d,0x35,0x46,0x0c,0x7b,0x61,0xe8,0x58,0x52,0x05,0x19,0x43,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00
};
static const u256 N_R2 = {
    0xa2,0xee,0x79,0xbe,0x95,0x4c,0x24,0x83,0xa6,0x6f,0xbd,0x49,0x9c,0x79,0x99,0x46,
    0x59,0xec,0x6b,0x2b,0x39,0xb2,0x45,0x28,0x20,0x56,0xd9,0xf3,0x94,0x2d,0xe1,0x66
};
static const u256 N_MINUS_2_BE = {
    0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xbc,0xe6,0xfa,0xad,0xa7,0x17,0x9e,0x84,0xf3,0xb9,0xca,0xc2,0xfc,0x63,0x25,0x4f
};

/* One shared workspace keeps the calculator stack bounded.  Public entry
 * points are intentionally non-reentrant, like the existing X25519 engine. */
static uint8_t mont_t[34];
static u256 f[14];
static p256_point r0, r1, rt, saved0, saved1, add_result, double_result;
static struct tls_sha256_context sha_ctx;
static uint8_t sha_pad[64], sha_inner[32], rfc_buf[97];

static uint8_t ct_is_zero(const uint8_t *a, uint8_t len)
{
    uint8_t x = 0;
    while (len--) x |= *a++;
    return (uint8_t)(0U - (uint8_t)(x == 0));
}

static uint8_t raw_ge(const u256 a, const u256 m)
{
    uint8_t borrow = 0;
    uint8_t i = 0;
    do {
        uint16_t d = (uint16_t)a[i] - m[i] - borrow;
        borrow = (uint8_t)(d >> 15);
        ++i;
    } while (i != 32);
    return (uint8_t)(borrow ^ 1U);
}

static void raw_sub(u256 out, const u256 a, const u256 b)
{
    uint8_t borrow = 0;
    uint8_t i = 0;
    do {
        uint16_t d = (uint16_t)a[i] - b[i] - borrow;
        out[i] = (uint8_t)d;
        borrow = (uint8_t)(d >> 15);
        ++i;
    } while (i != 32);
}

static void raw_reduce_once(u256 a, const u256 m)
{
    raw_sub(f[13], a, m);
    uint8_t mask = (uint8_t)(0U - raw_ge(a, m));
    for (uint8_t i = 0; i != 32; ++i)
        a[i] ^= mask & (a[i] ^ f[13][i]);
}

static bool import_be_raw(u256 out, const uint8_t in[32], const u256 modulus,
                          bool reject_zero)
{
    for (uint8_t i = 0; i != 32; ++i) out[i] = in[31U - i];
    if (raw_ge(out, modulus)) return false;
    if (reject_zero && ct_is_zero(out, 32) == 0xff) return false;
    return true;
}

/* Coarsely integrated operand scanning Montgomery multiply, radix 2^8.
 * n0 is -modulus^-1 mod 256 (1 for p, 0x4f for n). */
__attribute__((noinline))
static void mont_mul(u256 out, const u256 a, const u256 b,
                     const u256 modulus, uint8_t n0)
{
    memset(mont_t, 0, sizeof mont_t);
    for (uint8_t i = 0; i != 32; ++i) {
        uint16_t carry = 0;
        for (uint8_t j = 0; j != 32; ++j) {
            uint16_t v = (uint16_t)a[j] * b[i] + mont_t[j] + carry;
            mont_t[j] = (uint8_t)v;
            carry = v >> 8;
        }
        uint16_t v = (uint16_t)mont_t[32] + carry;
        mont_t[32] = (uint8_t)v;
        mont_t[33] = (uint8_t)(mont_t[33] + (v >> 8));

        uint8_t q = (uint8_t)(mont_t[0] * n0);
        carry = 0;
        for (uint8_t j = 0; j != 32; ++j) {
            v = (uint16_t)q * modulus[j] + mont_t[j] + carry;
            if (j) mont_t[j - 1] = (uint8_t)v;
            carry = v >> 8;
        }
        v = (uint16_t)mont_t[32] + carry;
        mont_t[31] = (uint8_t)v;
        mont_t[32] = (uint8_t)(mont_t[33] + (v >> 8));
        mont_t[33] = 0;
    }
    memcpy(out, mont_t, 32);
    raw_sub(f[13], out, modulus);
    uint8_t use_sub = (uint8_t)(0U - (uint8_t)(mont_t[32] != 0 || raw_ge(out, modulus)));
    for (uint8_t i = 0; i != 32; ++i)
        out[i] ^= use_sub & (out[i] ^ f[13][i]);
}

static void mod_add(u256 out, const u256 a, const u256 b, const u256 modulus)
{
    uint8_t carry = 0;
    for (uint8_t i = 0; i != 32; ++i) {
        uint16_t v = (uint16_t)a[i] + b[i] + carry;
        out[i] = (uint8_t)v;
        carry = v >> 8;
    }
    raw_sub(f[13], out, modulus);
    uint8_t use_sub = (uint8_t)(0U - (uint8_t)(carry || raw_ge(out, modulus)));
    for (uint8_t i = 0; i != 32; ++i)
        out[i] ^= use_sub & (out[i] ^ f[13][i]);
}

static void mod_sub(u256 out, const u256 a, const u256 b, const u256 modulus)
{
    uint8_t borrow = 0;
    for (uint8_t i = 0; i != 32; ++i) {
        uint16_t v = (uint16_t)a[i] - b[i] - borrow;
        out[i] = (uint8_t)v;
        borrow = (uint8_t)(v >> 15);
    }
    uint8_t mask = (uint8_t)(0U - borrow);
    uint8_t carry = 0;
    for (uint8_t i = 0; i != 32; ++i) {
        uint16_t v = (uint16_t)out[i] + (modulus[i] & mask) + carry;
        out[i] = (uint8_t)v;
        carry = v >> 8;
    }
}

static void mod_inv(u256 out, const u256 a, const u256 modulus, uint8_t n0,
                    const u256 one_r, const uint8_t exponent_be[32])
{
    memcpy(f[11], one_r, 32);
    memcpy(f[12], a, 32);
    for (uint16_t bit = 0; bit != 256; ++bit) {
        mont_mul(f[11], f[11], f[11], modulus, n0);
        if ((exponent_be[bit >> 3] >> (7U - (bit & 7U))) & 1U)
            mont_mul(f[11], f[11], f[12], modulus, n0);
    }
    memcpy(out, f[11], 32);
}

static void fe_mul(u256 o, const u256 a, const u256 b) { mont_mul(o,a,b,P,1); }
static void fe_sq(u256 o, const u256 a) { mont_mul(o,a,a,P,1); }
static void fe_add(u256 o, const u256 a, const u256 b) { mod_add(o,a,b,P); }
static void fe_sub(u256 o, const u256 a, const u256 b) { mod_sub(o,a,b,P); }

static void point_inf(p256_point *p)
{
    memset(p->x, 0, 32); memcpy(p->y, P_R, 32); memset(p->z, 0, 32);
}

static void point_select(p256_point *o, const p256_point *a,
                         const p256_point *b, uint8_t mask)
{
    const uint8_t *ap = (const uint8_t *)a, *bp = (const uint8_t *)b;
    uint8_t *op = (uint8_t *)o;
    for (uint8_t i = 0; i != 96; ++i) op[i] = ap[i] ^ (mask & (ap[i] ^ bp[i]));
}

static void point_cswap(p256_point *a, p256_point *b, uint8_t mask)
{
    uint8_t *ap = (uint8_t *)a, *bp = (uint8_t *)b;
    for (uint8_t i = 0; i != 96; ++i) {
        uint8_t t = mask & (ap[i] ^ bp[i]); ap[i] ^= t; bp[i] ^= t;
    }
}

/* Jacobian doubling specialized for a=-3. */
static void point_double(p256_point *o, const p256_point *p)
{
    fe_sq(f[0],p->z);                         /* delta */
    fe_sq(f[1],p->y);                         /* gamma */
    fe_mul(f[2],p->x,f[1]);                   /* beta */
    fe_sub(f[3],p->x,f[0]);
    fe_add(f[4],p->x,f[0]);
    fe_mul(f[3],f[3],f[4]);
    fe_add(f[4],f[3],f[3]); fe_add(f[3],f[4],f[3]); /* alpha */
    fe_sq(rt.x,f[3]);
    fe_add(f[4],f[2],f[2]); fe_add(f[4],f[4],f[4]);
    fe_add(f[5],f[4],f[4]);                  /* 8 beta */
    fe_sub(rt.x,rt.x,f[5]);
    fe_add(f[6],p->y,p->z); fe_sq(f[6],f[6]);
    fe_sub(f[6],f[6],f[1]); fe_sub(rt.z,f[6],f[0]);
    fe_sub(f[4],f[4],rt.x); fe_mul(f[4],f[3],f[4]);
    fe_sq(f[1],f[1]);
    fe_add(f[1],f[1],f[1]); fe_add(f[1],f[1],f[1]); fe_add(f[1],f[1],f[1]);
    fe_sub(rt.y,f[4],f[1]);
    p256_point inf; point_inf(&inf);
    point_select(o,&rt,&inf,ct_is_zero(p->z,32));
}

/* Complete wrapper around the standard Jacobian addition formula. */
static void point_add(p256_point *o, const p256_point *p, const p256_point *q)
{
    fe_sq(f[0],p->z); fe_sq(f[1],q->z);
    fe_mul(f[2],p->x,f[1]); fe_mul(f[3],q->x,f[0]); /* U1,U2 */
    fe_mul(f[4],q->z,f[1]); fe_mul(f[4],p->y,f[4]);
    fe_mul(f[5],p->z,f[0]); fe_mul(f[5],q->y,f[5]); /* S1,S2 */
    fe_sub(f[6],f[3],f[2]);                       /* H */
    fe_add(f[7],f[6],f[6]); fe_sq(f[7],f[7]);     /* I */
    fe_mul(f[8],f[6],f[7]);                       /* J */
    fe_sub(f[9],f[5],f[4]); fe_add(f[9],f[9],f[9]); /* r */
    fe_mul(f[10],f[2],f[7]);                      /* V */
    fe_sq(rt.x,f[9]); fe_sub(rt.x,rt.x,f[8]);
    fe_add(f[11],f[10],f[10]); fe_sub(rt.x,rt.x,f[11]);
    fe_sub(f[11],f[10],rt.x); fe_mul(f[11],f[9],f[11]);
    fe_mul(f[12],f[4],f[8]); fe_add(f[12],f[12],f[12]);
    fe_sub(rt.y,f[11],f[12]);
    fe_add(f[11],p->z,q->z); fe_sq(f[11],f[11]);
    fe_sub(f[11],f[11],f[0]); fe_sub(f[11],f[11],f[1]);
    fe_mul(rt.z,f[11],f[6]);

    uint8_t p_inf = ct_is_zero(p->z,32), q_inf = ct_is_zero(q->z,32);
    uint8_t h_zero = ct_is_zero(f[6],32), r_zero = ct_is_zero(f[9],32);
    memcpy(&add_result,&rt,sizeof rt);
    point_double(&double_result,p);
    p256_point inf; point_inf(&inf);
    point_select(&rt,&add_result,&double_result,(uint8_t)(h_zero & r_zero));
    point_select(&rt,&rt,&inf,(uint8_t)(h_zero & (uint8_t)~r_zero));
    point_select(&rt,&rt,q,p_inf);
    point_select(o,&rt,p,q_inf);
}

static void scalar_mul(p256_point *out, const uint8_t scalar_be[32], const p256_point *point)
{
    point_inf(&r0); memcpy(&r1,point,sizeof r1);
    uint8_t previous = 0;
    for (uint16_t bit = 0; bit != 256; ++bit) {
        uint8_t value = (scalar_be[bit >> 3] >> (7U - (bit & 7U))) & 1U;
        point_cswap(&r0,&r1,(uint8_t)(0U - (uint8_t)(value ^ previous)));
        memcpy(&saved0,&r0,sizeof r0); memcpy(&saved1,&r1,sizeof r1);
        point_add(&r1,&saved0,&saved1);
        point_double(&r0,&saved0);
        previous = value;
    }
    point_cswap(&r0,&r1,(uint8_t)(0U - previous));
    memcpy(out,&r0,sizeof *out);
}

static bool affine_export(uint8_t x_be[32], uint8_t *y_be, const p256_point *p)
{
    if (ct_is_zero(p->z,32) == 0xff) return false;
    mod_inv(f[0],p->z,P,1,P_R,P_MINUS_2_BE);
    fe_sq(f[1],f[0]); fe_mul(f[2],p->x,f[1]);
    if (y_be) { fe_mul(f[1],f[1],f[0]); fe_mul(f[3],p->y,f[1]); }
    memset(f[4],0,32); f[4][0]=1;
    mont_mul(f[2],f[2],f[4],P,1);
    if (y_be) mont_mul(f[3],f[3],f[4],P,1);
    for (uint8_t i=0;i!=32;++i) { x_be[i]=f[2][31U-i]; if(y_be)y_be[i]=f[3][31U-i]; }
    return true;
}

static bool point_import(p256_point *q, const uint8_t public_key[65])
{
    if (!public_key || public_key[0] != 4) return false;
    if (!import_be_raw(f[0],public_key+1,P,false) ||
        !import_be_raw(f[1],public_key+33,P,false)) return false;
    mont_mul(q->x,f[0],P_R2,P,1); mont_mul(q->y,f[1],P_R2,P,1); memcpy(q->z,P_R,32);
    fe_sq(f[2],q->y);
    fe_sq(f[3],q->x); fe_mul(f[3],f[3],q->x);
    fe_add(f[4],q->x,q->x); fe_add(f[4],f[4],q->x);
    fe_sub(f[3],f[3],f[4]); fe_add(f[3],f[3],P_B_R);
    return memcmp(f[2],f[3],32)==0;
}

static bool scalar_valid(const uint8_t scalar[32])
{
    return import_be_raw(f[0],scalar,N,true);
}

bool tls_p256_publickey(uint8_t public_key[65], const uint8_t private_key[32])
{
    if (!public_key || !private_key || !scalar_valid(private_key)) return false;
    p256_point g; memcpy(g.x,P_GX_R,32); memcpy(g.y,P_GY_R,32); memcpy(g.z,P_R,32);
    scalar_mul(&saved0,private_key,&g);
    public_key[0]=4;
    return affine_export(public_key+1,public_key+33,&saved0);
}

bool tls_p256_secret(uint8_t shared_secret[32], const uint8_t private_key[32],
                     const uint8_t peer_public[65])
{
    p256_point q;
    if (!shared_secret || !private_key || !scalar_valid(private_key) ||
        !point_import(&q,peer_public)) return false;
    scalar_mul(&saved0,private_key,&q);
    return affine_export(shared_secret,NULL,&saved0);
}

static void hmac256(uint8_t out[32], const uint8_t key[32], const uint8_t *msg, uint8_t len)
{
    // no need for this, just use hmac api
    memset(sha_pad,0x36,64); for(uint8_t i=0;i!=32;++i)sha_pad[i]^=key[i];
    tls_sha256_init(&sha_ctx); tls_sha256_update(&sha_ctx,sha_pad,64);
    tls_sha256_update(&sha_ctx,msg,len); tls_sha256_digest(&sha_ctx,sha_inner);
    memset(sha_pad,0x5c,64); for(uint8_t i=0;i!=32;++i)sha_pad[i]^=key[i];
    tls_sha256_init(&sha_ctx); tls_sha256_update(&sha_ctx,sha_pad,64);
    tls_sha256_update(&sha_ctx,sha_inner,32); tls_sha256_digest(&sha_ctx,out);
}

static bool deterministic_k(uint8_t k[32], const uint8_t hash[32], const uint8_t priv[32])
{
    uint8_t K[32],V[32],h1[32]; memset(K,0,32); memset(V,1,32);
    if(!import_be_raw(f[0],hash,N,false)){ for(uint8_t i=0;i!=32;++i)f[0][i]=hash[31U-i]; raw_reduce_once(f[0],N); }
    for(uint8_t i=0;i!=32;++i)h1[i]=f[0][31U-i];
    memcpy(rfc_buf,V,32); rfc_buf[32]=0; memcpy(rfc_buf+33,priv,32); memcpy(rfc_buf+65,h1,32);
    hmac256(K,K,rfc_buf,97); hmac256(V,K,V,32);
    memcpy(rfc_buf,V,32); rfc_buf[32]=1; memcpy(rfc_buf+33,priv,32); memcpy(rfc_buf+65,h1,32);
    hmac256(K,K,rfc_buf,97); hmac256(V,K,V,32);
    for(;;){ hmac256(V,K,V,32); memcpy(k,V,32); if(scalar_valid(k))return true;
        memcpy(rfc_buf,V,32); rfc_buf[32]=0; hmac256(K,K,rfc_buf,33); hmac256(V,K,V,32); }
}

static void order_import(u256 o,const uint8_t be[32])
{
    for(uint8_t i=0;i!=32;++i)f[0][i]=be[31U-i]; raw_reduce_once(f[0],N);
    mont_mul(o,f[0],N_R2,N,0x4f);
}

static void order_export(uint8_t be[32],const u256 a)
{
    memset(f[0],0,32);f[0][0]=1;mont_mul(f[1],a,f[0],N,0x4f);
    for(uint8_t i=0;i!=32;++i)be[i]=f[1][31U-i];
}

bool tls_p256_sign(uint8_t sig[64], const uint8_t msg_hash[32], const uint8_t private_key[32])
{
    uint8_t k[32],x[32];
    if(!sig||!msg_hash||!private_key||!scalar_valid(private_key)||
       !deterministic_k(k,msg_hash,private_key))return false;
    p256_point g;memcpy(g.x,P_GX_R,32);memcpy(g.y,P_GY_R,32);memcpy(g.z,P_R,32);
    scalar_mul(&saved0,k,&g);if(!affine_export(x,NULL,&saved0))return false;
    order_import(f[2],x);order_import(f[3],private_key);order_import(f[4],msg_hash);order_import(f[5],k);
    mont_mul(f[6],f[2],f[3],N,0x4f);mod_add(f[6],f[6],f[4],N);
    mod_inv(f[7],f[5],N,0x4f,N_R,N_MINUS_2_BE);mont_mul(f[6],f[6],f[7],N,0x4f);
    if(ct_is_zero(f[2],32)==0xff||ct_is_zero(f[6],32)==0xff)return false;
    order_export(sig,f[2]);order_export(sig+32,f[6]);return true;
}

bool tls_p256_verify(const uint8_t sig[64], const uint8_t msg_hash[32],
                     const uint8_t public_key[65])
{
    p256_point q,g,a,b,sum;
    if(!sig||!msg_hash||!public_key||!point_import(&q,public_key)||
       !import_be_raw(f[0],sig,N,true)||!import_be_raw(f[1],sig+32,N,true))return false;
    order_import(f[2],sig);order_import(f[3],sig+32);order_import(f[4],msg_hash);
    mod_inv(f[5],f[3],N,0x4f,N_R,N_MINUS_2_BE);
    mont_mul(f[6],f[4],f[5],N,0x4f);mont_mul(f[7],f[2],f[5],N,0x4f);
    order_export(rfc_buf,f[6]);order_export(rfc_buf+32,f[7]);
    memcpy(g.x,P_GX_R,32);memcpy(g.y,P_GY_R,32);memcpy(g.z,P_R,32);
    scalar_mul(&a,rfc_buf,&g);scalar_mul(&b,rfc_buf+32,&q);point_add(&sum,&a,&b);
    if(!affine_export(rfc_buf,NULL,&sum))return false;
    for(uint8_t i=0;i!=32;++i)f[8][i]=rfc_buf[31U-i];raw_reduce_once(f[8],N);
    for(uint8_t i=0;i!=32;++i)if(f[8][i]!=sig[31U-i])return false;
    return true;
}
