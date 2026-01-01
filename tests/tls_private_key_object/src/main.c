#include <ti/screen.h>
#include <ti/getkey.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "lwip/mem.h"

#include "keyobject.h"

// test vectors

// A 4096 bit private key
uint8_t test1[] = "-----BEGIN RSA PRIVATE KEY-----\n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\n-----END RSA PRIVATE KEY-----";

uint8_t test2[] = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgE+iaNHQrugEeZSwfmIt5O0hwKeYk+VriH9XmcAvve62hRANCAATfWf2INnnKwVStFSrv7R0aTKiPljJhVxl9jpfAa/Nbl5W5zd5B6Q7A5byFE93ISfBURpYwLFRATfoPPmprOEDR\n-----END PRIVATE KEY-----";

uint8_t test3[] = "-----BEGIN PRIVATE KEY-----\nMIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDSyjGXPVTLIaUSP3/UtgZArt+LRy4IbREISzSmrGxa2HMCzz/i3+H2RgimflCVxBf3j8yNZ3y8O+9FouQirmU0oZs+7WkpuWMpGFkuJJGbWd5AO4UOdM3TGAorii0Y6f4bJg2SGK09hXzVhWQiXxbto3940/lpjsti804+0PhQKjgSOY0awb/GOfxw+2VEsjzXwPXx5p+bkje4mf35J9r5g9HjVDyZORQKrEy4E7TXADR49PNf7xWhAkZahNhbmKmwOeGReGokcVFujif+z/i9XvEUloU7rqbOdVv/3sTHPDjMPfir06jGHOSJhaHvzF+wNbYedIcIsRpAK/cm+j/dAgMBAAECggEAHIT0zrSim1UzA1QKFJqIIApI/owj40n2avvZ5M8hXe05KmEmEKkf5nU1SGmAt7KvV3RiRaOB0en+BpryaOrVkJho68utVdLaYr4DmuWhubYgBurGpt0Q2AXBooBwd5V5Ju0wGtsx3UgJSs5gbPIWpRJg9dUgQrLqO7oVlRQq9JVy2YLHQb0GWHHk8Ba3TJmGKjLbuOR/sUfCpJY7uiUP+CKPfPicPlNzBVai9X58Q5XI49QSrE9+8S+2YVFk9jyPrYbTfkkCC47WscPmU3lCCmf/EaciBVzRorbipI1R2AQsIox4P3oGL0cMKdbmSX924riTTHWjWhkPXoya0qu2dQKBgQDwPsa/nnmeFT863hYuHTl20eCABuLCbt/EQQz1eAriL8XJPR9ZWwzrAqMNSKQNGGjGDASq4XG+otGWu0igad0ERYc8K7kIzpycS7wPplM2hBJ4Sl0U7e/291xVA5cL2lrnBl7sUUaPLoWdSRm8GKp0sC6tAdvUYU2SlWweniEz8wKBgQDgnOvz1xojNTsoERJx+/87ptyB74M58Z0eFcwFWLMgibDhI2OJg2oMxdDTOQBV1c1ved+5voy4h1Z9pTBuWRrzvdUAilASlmPX2bsVCydX1/G+wTX0Z0zn696yhl8nfe2V1IU1EEILfo2QncntZKMMHCJ2aqpuHxr2oUBl6IpA7wKBgQC0TGicJjLfkNKDO2kp8oTNx3TUoFZN1SfaAXfYQN7qITAudtCwHsTzGmeD8KAts8Pt3dci506V41un46X9vXVBX2y+m5GiKm0eXzgkBo8surGh1S1GJ8uPbNS+eJNDMfxGpWFXuSdbDW75O4M0xs4mBJMDBAIWwW+WMs2RrNr+QQKBgQDL3+OTuuTwnDqLzaMubwtmu7hfAGXeTF7Olf5PxAkjOZehYxvQD8ZMvakkcBLL1nrX+omF8V2NiNqKxUvGfX6nSuFx0hmIJZWOsQTMvwkBBPNar8knhDQcNs42wRzRnc3vN62JUq5//GjGoVJN9hDAxzDIx1zXA8jXn9nyJjaHZQKBgQDL7po5d+AWArY98BYcaYlfUARJhDpcUlZraJYXdIZejLK6THsncTBv7+lH8cUuV6Hura2Fnwq/7lBsYyNcVQp6y4aygt2FDQS02+dE/ZWqGllxrxlwN46eYAbsV6Cjek+GQ1usOZcsThYWFnxYm3f9OQ/bjVm0Ao8DGtK70h699Q==\n-----END PRIVATE KEY-----";

uint8_t test4[] = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFNDBeBgkqhkiG9w0BBQ0wUTAwBgkqhkiG9w0BBQwwIwQQhujZEW3F0NJMHwLtKIxS0QIBZDAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBAgQQ44XgBep2XL0Dj/majjKoIgSCBNBrfsH1joRn1k99sqkURfdxWcKJVjRxJbfQ3/4Wg0lm6pK8jLUvqz6rBXL/vCIwRRF4kR/E2CmTPp7751qnCKm/VbUIFOKB1an9FHHsMarlOqWSTv/B33QjsKKpu5k+l96Qj5HclCGvcBrEN26n45EVPp2k1FCm3ZQFZwY9J8bg3qLGQpjfx/8fVoj3vY82AyF/XQnDNlt2Z0XEOHY3G6quVBK6JtoqOyhfKN3AYr+FklYMSlpANWAJRwLRPM7JvSvdM+KaMSwvQ6hmDuaLN7TnoBmwbPVodz6O+3mGgW+2ELXcYiRFF8K6LeHcp4Nzd+9mZlC9LXMSgwOq1UDrOrB9n3cyjVGKNLN4sNEkGlqJBQ7tP0cKJegf/bVTGmPmxVQWQbxTeqUSXI7UPKehiAQswVCbFwzS6uaKniJACgerfQPpwS5ufUNUvxJSHNntwwPv85ZxkM92bJy/DTyhE9uoavXfulXOQJPz/fu+PFnTtCpmUeJDNnBfElP5k3hFCgf57ssqRlllvATWRirSRBfjr8oa3YenDTpIkZxiJHFkyp46Q3JrTARidevBtLZOSVVH7jOebLW4DFNuQXU6J1UbL9QxSvtYhCI7emHFWBAk7lrscxwyr50tcCsyHkV8lhQQhupLr4Bj8F9Gca51wRmVnmm74+y6oNGAgRlFDCuucH83vCpkkvtDoP9gx+rqSE1oXnDPq6s6la3juEvAL88SvG2GCC3Dif8NhMrMusbOArhZKdGt/sOdJX2pJGjdDXFEqjgld36ArdskM4uOc8Ifq18B2pb2wB6/Op0cflSo9OCqJndK4m/spRtLEGLqj1d18iwg5zt66VlQf5vm8B8lO3jvfapjm4x+ZhDh0H7l/aHSAHL34f3eJjTobeDVO3i4DTS32XSPbJBIo/s1B4vbOJFEAohCiNElRuNT2qJlTpmZTj3hKSKgiSoEE2HnYfPas+R2ncY+AG7QRz3olh3e4Fn80JoIyvA7IgiWfb+RmgK3WkKfHg6FXlmO+bAunGE2ouho2MroatGCYzJ9DcEXCkmEwOETtUYtjuH+0kWuQO32ZtgceQtEUxbjDVQhiR6cNatPnKD3qJxNPrDTFELbqZ8vlRwIckx5isScViTT6REyGzw8YVw7vCYGLKRjhwGFpnfwCawpKBm91IvEelkAYC0YRGLzvO702aafCITHKqhOgbahDIaK1hlxnYCRnscHCVnWnnQY2p+quOWRNDPi2ISSnFXpMRhBBeZADz+lubnbNbCLoNzd3X9UngrzxeEnQV+GC50hfb7wmG4n/th//wMstU+n73DhXwBYAbxcskCWvnLF/HXnsxGqMu7ufSUX+pliGsFQ041Zjpk7jfZQ1tvQ904FEEPVklwFKg2TLllKEbPOU4y95IkKTJ8gq9RWkVE918KJPnbKHGc04HLjPQvOgSAfPxcHFe9WJFei74qerCPHNMruFQZ+32MYlxX/b97tcBjDHxGfwhR8j5LKK0fTQpJ9RP4DFit0TaEdLR+gPY2Z3eStmNvKx/+M+9MfEipMYUjqIOVmVEaz3T4a87mDl0AAMYWdMICzfFhZTv3uDlN3UrYjMzNy/tr412PDsWy/+k9BU4DW4aAKEAw7VxzGVxpT6M4L7Z43e30PUg==\n-----END ENCRYPTED PRIVATE KEY-----";


/* Main function, called first */
int main(void)
{
    /* Clear the homescreen */
    os_ClrHome();
    os_FontSelect(os_SmallFont);
    
    struct mem_configurator conf = {
        MEM_CONFIGURATOR_V1,
        malloc,
        free,
        1024*12
    };
    
    char buf[128];
    mem_configure(&conf);
    
    // PKCS#1 RSA key
    struct tls_keyobject *pk = tls_keyobject_import_private(test1, strlen(test1), NULL);
    if(pk==NULL){
        printf("error");
        os_GetKey();
        os_ClrHome();
        return 1;
    }
    for(int i=0; i < 8; i++){
        sprintf(buf, "%s:tag=%u, size=%u: %02x%02x..%02x%02x",
                pk->meta.privkey.rsa.fields[i].name,
                pk->meta.privkey.rsa.fields[i].tag,
                pk->meta.privkey.rsa.fields[i].len,
                pk->meta.privkey.rsa.fields[i].data[0],
                pk->meta.privkey.rsa.fields[i].data[1],
                pk->meta.privkey.rsa.fields[i].data[pk->meta.privkey.rsa.fields[i].len - 2],
                pk->meta.privkey.rsa.fields[i].data[pk->meta.privkey.rsa.fields[i].len - 1]
                );
        os_FontDrawText(buf, 5, 40+i*12);
    }
    tls_keyobject_destroy(pk);
    
    os_GetKey();
    os_ClrHome();
    
    
    // PKCS#8 EC key
    pk = tls_keyobject_import_private(test2, strlen(test2), NULL);
    if(pk==NULL){
        printf("error");
        os_GetKey();
        os_ClrHome();
        return 1;
    }
    for(int i=0; i < 3; i++){
        sprintf(buf, "%s:tag=%u, size=%u: %02x%02x..%02x%02x",
                pk->meta.privkey.ec.fields[i].name,
                pk->meta.privkey.ec.fields[i].tag,
                pk->meta.privkey.ec.fields[i].len,
                pk->meta.privkey.ec.fields[i].data[0],
                pk->meta.privkey.ec.fields[i].data[1],
                pk->meta.privkey.ec.fields[i].data[pk->meta.privkey.ec.fields[i].len - 2],
                pk->meta.privkey.ec.fields[i].data[pk->meta.privkey.ec.fields[i].len - 1]
                );
        os_FontDrawText(buf, 5, 40+i*12);
    }
    tls_keyobject_destroy(pk);
    
    os_GetKey();
    os_ClrHome();
    
    // PKCS#8 RSA private key
    pk = tls_keyobject_import_private(test3, strlen(test3), NULL);
    if(pk==NULL){
        printf("error");
        os_GetKey();
        os_ClrHome();
        return 1;
    }
    for(int i=0; i < 8; i++){
        sprintf(buf, "%s:tag=%u, size=%u: %02x%02x..%02x%02x",
                pk->meta.privkey.rsa.fields[i].name,
                pk->meta.privkey.rsa.fields[i].tag,
                pk->meta.privkey.rsa.fields[i].len,
                pk->meta.privkey.rsa.fields[i].data[0],
                pk->meta.privkey.rsa.fields[i].data[1],
                pk->meta.privkey.rsa.fields[i].data[pk->meta.privkey.rsa.fields[i].len - 2],
                pk->meta.privkey.rsa.fields[i].data[pk->meta.privkey.rsa.fields[i].len - 1]
                );
        os_FontDrawText(buf, 5, 40+i*12);
    }
    tls_keyobject_destroy(pk);
    
    os_GetKey();
    os_ClrHome();
    
    // PKCS#8 RSA encrypted private key
    pk = tls_keyobject_import_private(test4, strlen(test4), "science");
    if(pk==NULL){
        printf("error");
        os_GetKey();
        os_ClrHome();
        return 1;
    }
    for(int i=0; i < 8; i++){
        sprintf(buf, "%s:tag=%u, size=%u: %02x%02x..%02x%02x",
                pk->meta.privkey.rsa.fields[i].name,
                pk->meta.privkey.rsa.fields[i].tag,
                pk->meta.privkey.rsa.fields[i].len,
                pk->meta.privkey.rsa.fields[i].data[0],
                pk->meta.privkey.rsa.fields[i].data[1],
                pk->meta.privkey.rsa.fields[i].data[pk->meta.privkey.rsa.fields[i].len - 2],
                pk->meta.privkey.rsa.fields[i].data[pk->meta.privkey.rsa.fields[i].len - 1]
                );
        os_FontDrawText(buf, 5, 40+i*12);
    }
    tls_keyobject_destroy(pk);
    
    os_GetKey();
    os_ClrHome();
    
    return 0;
}
