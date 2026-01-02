#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include "../includes/asn1.h"

void rmemcpy(void *dest, void *src, size_t len);

bool tls_asn1_decoder_init(struct tls_asn1_decoder_context *ctx, const uint8_t *data, size_t len){
    if((ctx==NULL) ||
       (data==NULL) ||
       (len==0)) return false;
    memset(ctx, 0, sizeof(struct tls_asn1_decoder_context));
    ctx->node[0].start = data;
    ctx->node[0].next = data + len;
    return true;
}


bool tls_asn1_decode_next(struct tls_asn1_decoder_context *ctx, const struct tls_asn1_schema *schema,
                          uint8_t *tag, uint8_t **data, size_t *len, uint8_t *depth){
   
    if(ctx==NULL)
        return false;
    
    uint8_t this_tag;
    size_t this_len;
    uint8_t *asn1_current;
    uint8_t *tag_start;  /* For raw_output mode: points to tag byte */
    bool has_result = false;

restart:
    asn1_current = (uint8_t*)ctx->node[ctx->depth].start;
    this_len = 0;

    while(*asn1_current == 0){
        // remove leading 0s
        asn1_current++;
    }

    if(ctx->depth >= ASN1_MAX_DEPTH)
        return false;

    // get tag of element (save position for raw_output)
    tag_start = asn1_current;  /* Save tag position before advancing */
    this_tag = *asn1_current++;

    if(asn1_current > ctx->node[ctx->depth].next){
        if(--ctx->depth==0)
            return false;
        goto restart;
    }
    
    // get byte 2 => size or size of size
    uint8_t byte_2nd = *asn1_current++;
    if((byte_2nd>>7) & 1){
        uint8_t size_len = byte_2nd & 0x7f;
        if(size_len > 3) return false;
        rmemcpy((uint8_t*)&this_len, asn1_current, size_len);
        asn1_current += size_len;
    }
    else
        this_len = byte_2nd;
            
    if(schema == NULL) goto skip_checks;   // if no schema passed just return what we have
     
    if((schema->tag != this_tag) || (schema->depth != ctx->depth)){
        // if the tag is null, depth is expected, and null is allowed
        if(schema->allow_null && (this_tag==ASN1_NULL) && (schema->depth == ctx->depth))
            goto skip_checks;
        // if the tag and depth does not match schema provided
        
        if(schema->mode == ASN1_SEEK)
            goto seek_next;
        
        if(schema->optional==false)
            return false;    // stop with error if schema mismatch
        // if tag is optional
        if(data) *data = NULL;
        if(tag) *tag = 0;
        if(len) *len = 0;
        if(depth) *depth = -1;
        return true;
        // if schema doesn't match, this may match the next field in the schema
        // so exit without updating the context state
    }

skip_checks:
    has_result = true;
    if((schema==NULL) || (schema && schema->output)){
        /* If raw_output is set, return pointer to tag byte and include tag+length in size */
        if(schema && schema->raw_output){
            /* Use tag_start captured at line 45 before advancing past tag */
            if(data) *data = tag_start;
            if(tag) *tag = this_tag;
            /* Length includes tag + length encoding + content */
            if(len) *len = (asn1_current - tag_start) + this_len;
        } else {
            /* Normal output: just the content */
            if(data) *data = asn1_current;
            if(tag) *tag = this_tag;
            if(len) *len = this_len;
        }
        if(depth) *depth = ctx->depth;
    }
seek_next:
    ctx->node[ctx->depth].start = asn1_current + this_len;
    if(tls_asn1_getform(this_tag)){
        ctx->depth++;
        ctx->node[ctx->depth].start = asn1_current;
        ctx->node[ctx->depth].next = asn1_current + this_len;
    }
    if((!has_result) && (schema->mode == ASN1_SEEK))
        goto restart;
    
    return true;
}

size_t tls_asn1_encode(uint8_t tag, const uint8_t *data, size_t len, uint8_t *output){
    if((data==NULL) ||
       (len==0) ||
       (output==NULL)) return 0;
    
    // if sequence or set, constructed should be set
    if(((tag & 0b11111) == ASN1_SEQUENCE) ||
        ((tag & 0b11111) == ASN1_SET))
        tag |= ASN1_CONSTRUCTED;
    
    
    size_t pos = 0;
    output[pos++] = tag;
    if(len > (0b1111111)){
        // generate weird length format
        uint8_t size_len = (len > 0xffff) + (len > 0xFF) + 1;
        output[pos++] = size_len | 0b10000000;
        rmemcpy((uint8_t*)&output[pos], (uint8_t*)&len, size_len);
        pos += size_len;
    }
    else
        output[pos++] = len;
    
    memcpy(&output[pos], data, len);
    return pos+len;
}
