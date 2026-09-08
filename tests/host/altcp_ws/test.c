static err_t receive(void *arg,struct altcp_pcb *p,struct pbuf *b,err_t e){
 (void)arg;(void)p;(void)e;if(!b){closes++;return ERR_OK;}
 if(refuse)return ERR_MEM;delivered+=b->tot_len;pbuf_free(b);return ERR_OK;
}
static err_t abort_receive(void *arg,struct altcp_pcb *p,struct pbuf *b,err_t e){
 (void)arg;(void)e;if(b)pbuf_free(b);altcp_ws_abort(p);return ERR_ABRT;
}
static int connected;
static err_t on_connect(void *arg,struct altcp_pcb *p,err_t e){(void)arg;(void)p;assert(e==ERR_OK);connected++;return ERR_OK;}
static struct altcp_pcb *make_conn(bool upgraded){
 struct altcp_pcb *p=calloc(1,sizeof(*p));p->inner_conn=calloc(1,sizeof(*p));
 altcp_ws_state_t *s=calloc(1,sizeof(*s));p->state=s;s->conn=p;
 static altcp_ws_config_t cfg={"localhost","/",NULL};s->conf=&cfg;
 if(upgraded)s->flags=ALTCP_WS_FLAGS_UPGRADE_DONE;
 p->recv=receive;p->connected=on_connect;altcp_ws_setup_callbacks(p,p->inner_conn);return p;
}
static struct pbuf *bytes(const void *data,u16_t len){struct pbuf *p=pbuf_alloc(0,len,0);memcpy(p->payload,data,len);return p;}
static err_t feed(struct altcp_pcb *p,const void *data,u16_t len){return altcp_ws_lower_recv(p,p->inner_conn,bytes(data,len),ERR_OK);}
int main(void){
 const char *response="HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
 struct altcp_pcb *p=make_conn(false);
 assert(feed(p,response,17)==ERR_OK);assert(!connected);
 assert(feed(p,response+17,strlen(response)-17)==ERR_OK);assert(connected==1);altcp_ws_close(p);
 p=make_conn(false);((altcp_ws_state_t*)p->state)->rx=bytes("HTTP/1.1 400 Bad\r\n\r\n",20);
 assert(altcp_ws_lower_poll(p,p->inner_conn)==ERR_ABRT); /* ASan: poll must not use freed p */
 p=make_conn(true);struct pbuf *b=bytes("\x82\x01x",3);fail_alloc=1;
 assert(altcp_ws_lower_recv(p,p->inner_conn,b,ERR_OK)==ERR_MEM);
 assert(b->tot_len==3);fail_alloc=0;pbuf_free(b);altcp_ws_close(p);
 p=make_conn(true);p->recv=abort_receive;assert(feed(p,"\x82\x01x",3)==ERR_ABRT);
 p=make_conn(true);refuse=1;assert(feed(p,"\x82\x01x\x88\x00",5)==ERR_OK);assert(!closes);
 refuse=0;assert(altcp_ws_lower_poll(p,p->inner_conn)==ERR_OK);assert(delivered==1 && closes==1);
 assert(altcp_ws_lower_poll(p,p->inner_conn)==ERR_OK);assert(closes==1);altcp_ws_close(p);
 p=make_conn(true);assert(feed(p,"\x82\x7e\xff\xff",4)==ERR_ABRT);
 p=make_conn(true);assert(altcp_ws_write(p,"x",65535,0)==ERR_VAL);altcp_ws_close(p);
 p=make_conn(true);assert(feed(p,"\x82\x80",2)==ERR_ABRT);
 p=make_conn(true);assert(feed(p,"\x80\x00",2)==ERR_ABRT);
 p=make_conn(true);assert(feed(p,"\x02\x01x\x80\x01y",6)==ERR_OK);assert(delivered==3);altcp_ws_close(p);
 p=make_conn(false);write_result=ERR_MEM;assert(altcp_ws_lower_connected(p,p->inner_conn,ERR_OK)==ERR_ABRT);write_result=0;
 puts("WS callback/parser regressions passed (ASan + UBSan)");return 0;
}
