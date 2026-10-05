#!/usr/bin/env python3
"""Test production import against OpenSSL PEM/DER keys, with platform allocation
mocked. PBES2 decryption is excluded; this suite tests unencrypted key parsing.
Requires cc and openssl. No generated private keys leave the temporary directory.
"""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[3]
s = (root / 'src/tls/core/key.c').read_text()
s = s[s.index('static const uint8_t OID_RSA_ENCRYPTION'):s.index('/* ---------------------------------------------------------------------------\n * tls_key_verify /')]
a = s.index('static tls_key_import_result_t\nkey_decrypt_pbes2')
b = s.index('\n}', a) + 2
s = s[:a] + '''static tls_key_import_result_t key_decrypt_pbes2(
const uint8_t *der, size_t n, const char *password, uint8_t *buf,
const uint8_t **out, size_t *len) { return TLS_KEY_IMPORT_UNSUPPORTED_ENC; }
''' + s[b:]
prefix = '''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
typedef uint32_t uint24_t;
#include "key.h"
#include "../core/key_internal.h"
#include "asn1.h"
#include "base64.h"
static void *tls_fileio_alloc(size_t n) { void *p = malloc(n); if(p) memset(p, 0xa5, n); return p; }
static void tls_fileio_free(void *p) { free(p); }
static void tls_secure_memzero(void *p, size_t n) { memset(p, 0, n); }
void rmemcpy(void *dst, void *src, size_t n) { for(size_t i=0;i<n;i++) ((uint8_t *)dst)[i]=((uint8_t *)src)[n-i-1]; }
'''
test = '''
int main(int argc, char **argv) {
 assert(argc == 4);
 FILE *f=fopen(argv[1], "rb"); assert(f); fseek(f,0,SEEK_END); size_t n=ftell(f); rewind(f);
 uint8_t *data=malloc(n); assert(fread(data,1,n,f)==n); fclose(f);
 tls_key_type_t expected=atoi(argv[3]);
 struct tls_key *key=NULL;
 tls_key_import_result_t rc=tls_key_import(&key,data,n,atoi(argv[2]),NULL);
 if(expected==TLS_KEY_TYPE_UNKNOWN) { assert(rc!=TLS_KEY_IMPORT_OK && key==NULL); free(data); return 0; }
 assert(rc==TLS_KEY_IMPORT_OK && key && key->allocated && key->type==expected);
 if(expected==TLS_KEY_TYPE_RSA) { assert(key->rsa.mod_len==128); assert(key->rsa.exp_len==3); assert(key->rsa.exponent[0]==1 && key->rsa.exponent[1]==0 && key->rsa.exponent[2]==1); }
 else { assert(key->ec.len==65 && key->ec.data[0]==4); }
 tls_alg_t choices[]={TLS_ALG_RSA_PSS_RSAE_SHA256,TLS_ALG_RSA_PKCS1_SHA256,TLS_ALG_RSA_OAEP_SHA256,TLS_ALG_ECDSA_SECP256R1_SHA256,TLS_ALG_AES_128_GCM};
 for(size_t i=0;i<sizeof(choices)/sizeof(*choices);i++) {
  bool compatible=expected==TLS_KEY_TYPE_RSA ? i<3 : i==3;
  assert(tls_key_supports_operation(key, choices[i])==compatible);
  assert(key->type==expected);
 }
 tls_key_free(key);
 key=(void *)1; assert(tls_key_import(&key,data,n,99,NULL)==TLS_KEY_IMPORT_INVALID_ARG && key==NULL);
 free(data); return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='key-import-') as d:
    p=Path(d)
    (p/'test.c').write_text(prefix+s+test)
    subprocess.run(['cc','-std=c99','-g','-fsanitize=address,undefined','-I'+str(root/'src/tls/includes'),str(p/'test.c'),str(root/'src/tls/core/asn1.c'),str(root/'src/tls/core/base64.c'),'-o',str(p/'test')],check=True)
    def openssl(*args):
        subprocess.run(['openssl',*args],cwd=p,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    openssl('genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:1024','-out','rsa.pem')
    openssl('genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:P-256','-out','ec.pem')
    count=0
    for family, expected in [('rsa',1),('ec',2)]:
        for fmt in ['PEM','DER']:
            jobs=[('pkey','-pubout'),('pkcs8','-topk8','-nocrypt')]
            jobs += [('rsa','-traditional'),('rsa','-RSAPublicKey_out')] if family=='rsa' else [('ec',)]
            for i,job in enumerate(jobs):
                out=f'{family}-{fmt}-{i}'
                openssl(*job,'-in',family+'.pem','-outform',fmt,'-out',out)
                subprocess.run([str(p/'test'),str(p/out),str(fmt=='DER' and 1 or 0),str(expected)],check=True)
                count+=1
    openssl('genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:P-384','-out','p384.pem')
    openssl('pkey','-in','p384.pem','-pubout','-out','p384-pub.pem')
    for name in ['p384.pem','p384-pub.pem']:
        subprocess.run([str(p/'test'),str(p/name),'0','0'],check=True)
    print(f'Passed {count} OpenSSL import formats, operation compatibility, and unsupported curves')
