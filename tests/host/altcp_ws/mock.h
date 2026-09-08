#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint16_t u16_t;
typedef uint8_t u8_t;
typedef int err_t;
typedef int ip_addr_t;
#define ERR_OK 0
#define ERR_MEM -1
#define ERR_ABRT -13
#define ERR_VAL -6
#define ERR_CONN -11
#define TCP_WND 8192u
#define TCP_WRITE_FLAG_COPY 1
#define PBUF_RAM 0
#define PBUF_RAW 0
#define ERROR() ((void)0)
#define ERROR_CODE(x) ((void)(x))
#define WARN() ((void)0)
#define WARN_CODE(x) ((void)(x))
struct pbuf { struct pbuf *next; void *payload; u16_t tot_len, len; };
struct altcp_pcb;
typedef void (*altcp_err_fn)(void *, err_t);
typedef err_t (*altcp_connected_fn)(void *, struct altcp_pcb *, err_t);
struct altcp_pcb {
 void *arg, *state;
 struct altcp_pcb *inner_conn;
 err_t (*recv)(void *,struct altcp_pcb *,struct pbuf *,err_t);
 err_t (*sent)(void *,struct altcp_pcb *,u16_t);
 err_t (*poll)(void *,struct altcp_pcb *);
 altcp_connected_fn connected;
 altcp_err_fn err;
 u8_t pollinterval;
};
typedef struct { const char *host, *path, *subprotocol; } altcp_ws_config_t;
static int fail_alloc, aborted, write_result, closes, delivered, refuse;
static void *mem_malloc(size_t n) { if (fail_alloc) return NULL; return malloc(n); }
#define mem_free free
static struct pbuf *pbuf_alloc(int type,u16_t n,int kind) {
 (void)type;(void)kind;
 struct pbuf *p=mem_malloc(sizeof(*p)); if(!p)return NULL;
 p->payload=malloc(n ? n:1);p->next=NULL;p->len=p->tot_len=n;return p;
}
static void pbuf_free(struct pbuf *p) { while(p){struct pbuf *n=p->next;free(p->payload);free(p);p=n;} }
static u16_t pbuf_copy_partial(const struct pbuf *p,void *out,u16_t n,u16_t off) {
 u16_t copied=0;
 for(;p && n;p=p->next){if(off>=p->len){off-=p->len;continue;}
 u16_t k=p->len-off;if(k>n)k=n;memcpy((char*)out+copied,(char*)p->payload+off,k);copied+=k;n-=k;off=0;}return copied;
}
static void pbuf_copy(struct pbuf *d,const struct pbuf *s){assert(pbuf_copy_partial(s,d->payload,s->tot_len,0)==s->tot_len);}
static void pbuf_cat(struct pbuf *p,struct pbuf *q){for(;;){p->tot_len+=q->tot_len;if(!p->next){p->next=q;return;}p=p->next;}}
static struct pbuf *pbuf_free_header(struct pbuf *p,u16_t n){
 while(p && n>=p->len){struct pbuf *q=p->next;n-=p->len;p->next=NULL;pbuf_free(p);p=q;}
 if(p && n){memmove(p->payload,(char*)p->payload+n,p->len-n);p->len-=n;p->tot_len-=n;}return p;
}
static void *tls_random_bytes(void *p,size_t n){memset(p,42,n);return p;}
static void altcp_arg(struct altcp_pcb *p,void *arg){p->arg=arg;}
#define altcp_recv(p,f) ((p)->recv=(f))
#define altcp_sent(p,f) ((p)->sent=(f))
#define altcp_err(p,f) ((p)->err=(f))
static void altcp_poll(struct altcp_pcb *p,err_t (*f)(void*,struct altcp_pcb*),u8_t i){p->poll=f;p->pollinterval=i;}
static void altcp_recved(struct altcp_pcb *p,u16_t n){(void)p;(void)n;}
static err_t altcp_write(struct altcp_pcb *p,const void *d,u16_t n,u8_t f){(void)p;(void)d;(void)n;(void)f;return write_result;}
static err_t altcp_output(struct altcp_pcb *p){(void)p;return ERR_OK;}
static void altcp_ws_dealloc(struct altcp_pcb *p);
static void altcp_free(struct altcp_pcb *p){altcp_ws_dealloc(p);free(p);}
static void altcp_abort(struct altcp_pcb *p){altcp_err_fn fn=p->err;void *arg=p->arg;aborted++;free(p);if(fn)fn(arg,ERR_ABRT);}
static err_t altcp_close(struct altcp_pcb *p){free(p);return ERR_OK;}
static u16_t altcp_sndbuf(struct altcp_pcb *p){(void)p;return 8192;}
#define altcp_default_sndbuf altcp_sndbuf
#define altcp_mss altcp_sndbuf
static err_t altcp_connect(struct altcp_pcb *p,const ip_addr_t *ip,u16_t port,altcp_connected_fn f){(void)p;(void)ip;(void)port;(void)f;return ERR_OK;}
