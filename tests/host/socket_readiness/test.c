static void wait_on(struct lwip_socket *c, const char *host) {
    c->status=LWIP_STATUS_WAITING_SERVICES;
    c->pending_host=malloc(strlen(host)+1);strcpy(c->pending_host,host);
    c->pending_port=80;c->connect_deadline=1000;
}
int main(void) {
    struct netif clock_netif={true,true,true,false,0};
    assert(!netif_service_ready(&clock_netif,LWIP_SOCKET_SVC_SNTP));
    sntp_running=true;
    assert(!netif_service_ready(&clock_netif,LWIP_SOCKET_SVC_SNTP));
    sntp_synced=true;
    assert(netif_service_ready(&clock_netif,LWIP_SOCKET_SVC_SNTP));
    sntp_running=false;
    assert(!netif_service_ready(&clock_netif,LWIP_SOCKET_SVC_SNTP));
    struct lwip_socket c={0};g_conn_registry=&c;
    struct netif n={0};
    assert(socket_required_services(&c,"192.0.2.1")==LWIP_SOCKET_SVC_DHCP);
    assert(socket_required_services(&c,"example.com")==3);
    c.has_addrinfo=true;
    assert(socket_required_services(&c,"192.0.2.1")==0);
    c.protocol=LWIP_SOCKET_ALTCP_TLS;
    assert(socket_required_services(&c,"example.com")==6);
    c.bind_descriptor=LWIP_NETIF_LOOP;
    assert(socket_required_services(&c,"example.com")==0);
    c.bind_descriptor=0;c.protocol=0;
    wait_on(&c,"192.0.2.1");services_arm();
    unsigned initial=period_sets;services_arm();assert(period_sets==initial);
    services_dispatch();assert(!c.netif && !connects);
    available=&n;socket_netif_changed(&n,1,NULL);
    assert(g_services_dirty && !connects);
    services_dispatch();assert(c.netif==&n && !connects);
    n.up=true;n.address=true;
    services_dispatch();assert(!connects); /* link is still down */
    n.link=true;socket_netif_changed(&n,4,NULL);services_dispatch();
    assert(connects==1 && !c.pending_host && !period);
    c.status=LWIP_STATUS_INIT;c.static_applied=true;
    g_netif_service_requests[0].netif=&n;
    socket_netif_changed(&n,LWIP_NSC_NETIF_REMOVED,NULL);
    assert(!c.netif && !c.static_applied && !g_netif_service_requests[0].netif);
    available=NULL;services_dispatch();assert(!c.netif);
    struct netif replacement={true,true,true,false,0};available=&replacement;
    socket_netif_changed(&replacement,1,NULL);services_dispatch();
    assert(c.netif==&replacement); /* idle socket also discovers registration */
    c.has_addrinfo=false;wait_on(&c,"example.com");services_arm();
    services_dispatch();assert(connects==1);
    replacement.ready=3;services_dispatch();assert(connects==2);
    wait_on(&c,"example.com");replacement.ready=0;now=1000;
    services_dispatch();assert(c.status==LWIP_STATUS_ERROR && !c.pending_host);
    now=0;wait_on(&c,"example.com");apply_error=9;
    services_dispatch();assert(c.status==LWIP_STATUS_ERROR && !c.pending_host);
    assert(starts);puts("Socket readiness regressions passed (ASan + UBSan)");
    return 0;
}
