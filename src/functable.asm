section .rodata
public _app_library_table
extern app

_app_library_table:
    dl _eth_get_interfaces - app
    dl _eth_usb_event_callback - app
    dl _mem_buffer_capacity - app
    dl _mem_buffer_create - app
    dl _mem_buffer_destroy - app
    dl _mem_buffer_free - app
    dl _mem_buffer_len - app
    dl _mem_buffer_malloc - app
    dl _mem_buffer_pop - app
    dl _mem_buffer_push - app
    dl _mem_buffer_set_grow - app
    dl _mem_buffer_set_max_size - app
    dl _mem_buffer_set_shrink - app
    dl _mem_buffer_space - app
    dl _mem_init - app
    dl _etharp_acd_announce - app
    dl _etharp_acd_probe - app
    dl _etharp_cleanup_netif - app
    dl _etharp_find_addr - app
    dl _etharp_get_entry - app
    dl _etharp_input - app
    dl _etharp_output - app
    dl _etharp_query - app
    dl _etharp_request - app
    dl _etharp_tmr - app
    dl _ethip6_output - app
    dl _igmp_init - app
    dl _igmp_input - app
    dl _igmp_joingroup - app
    dl _igmp_joingroup_netif - app
    dl _igmp_leavegroup - app
    dl _igmp_leavegroup_netif - app
    dl _igmp_lookfor_group - app
    dl _igmp_report_groups - app
    dl _igmp_start - app
    dl _igmp_stop - app
    dl _igmp_tmr - app
    dl _stats_display - app
    dl _stats_display_igmp - app
    dl _stats_display_mem - app
    dl _stats_display_memp - app
    dl _stats_display_proto - app
    dl _stats_display_sys - app
    dl _stats_init - app
    dl _ip4_input - app
    dl _ip4_output - app
    dl _ip4_output_if - app
    dl _ip4_output_if_opt - app
    dl _ip4_output_if_opt_src - app
    dl _ip4_output_if_src - app
    dl _ip4_route - app
    dl _ip4_set_default_multicast_netif - app
    dl _ip4_addr_isbroadcast_u32 - app
    dl _ip4_addr_netmask_valid - app
    dl _ip4addr_aton - app
    dl _ip4addr_ntoa - app
    dl _ip4addr_ntoa_r - app
    dl _ipaddr_addr - app
    dl _ip4_frag - app
    dl _ip4_reass - app
    dl _ip_reass_tmr - app
    dl _ip6_input - app
    dl _ip6_options_add_hbh_ra - app
    dl _ip6_output - app
    dl _ip6_output_if - app
    dl _ip6_output_if_src - app
    dl _ip6_route - app
    dl _ip6_select_source_address - app
    dl _ip6addr_aton - app
    dl _ip6addr_ntoa - app
    dl _ip6addr_ntoa_r - app
    dl _ip6_frag - app
    dl _ip6_reass - app
    dl _ip6_reass_tmr - app
    dl _ip_input - app
    dl _ipaddr_aton - app
    dl _ipaddr_ntoa - app
    dl _ipaddr_ntoa_r - app
    dl _autoip_accept_packet - app
    dl _autoip_network_changed_link_down - app
    dl _autoip_network_changed_link_up - app
    dl _autoip_remove_struct - app
    dl _autoip_set_struct - app
    dl _autoip_start - app
    dl _autoip_stop - app
    dl _autoip_supplied_address - app
    dl _pbuf_add_header - app
    dl _pbuf_add_header_force - app
    dl _pbuf_alloc - app
    dl _pbuf_alloc_reference - app
    dl _pbuf_alloced_custom - app
    dl _pbuf_cat - app
    dl _pbuf_chain - app
    dl _pbuf_clen - app
    dl _pbuf_clone - app
    dl _pbuf_coalesce - app
    dl _pbuf_copy - app
    dl _pbuf_copy_partial - app
    dl _pbuf_copy_partial_pbuf - app
    dl _pbuf_dechain - app
    dl _pbuf_free - app
    dl _pbuf_free_header - app
    dl _pbuf_free_ooseq - app
    dl _pbuf_get_at - app
    dl _pbuf_get_contiguous - app
    dl _pbuf_header - app
    dl _pbuf_header_force - app
    dl _pbuf_memcmp - app
    dl _pbuf_memfind - app
    dl _pbuf_put_at - app
    dl _pbuf_realloc - app
    dl _pbuf_ref - app
    dl _pbuf_remove_header - app
    dl _pbuf_skip - app
    dl _pbuf_strstr - app
    dl _pbuf_take - app
    dl _pbuf_take_at - app
    dl _pbuf_try_get_at - app
    dl _custom_calloc - app
    dl _custom_free - app
    dl _custom_malloc - app
    dl _mem_calloc - app
    dl _mem_free - app
    dl _mem_malloc - app
    dl _mem_trim - app
    dl _memp_free - app
    dl _memp_init - app
    dl _memp_malloc - app
    dl _lwip_init - app
    dl _lwip_init_runtime - app
    dl _netif_add - app
    dl _netif_add_ext_callback - app
    dl _netif_add_ip6_address - app
    dl _netif_add_noaddr - app
    dl _netif_alloc_client_data_id - app
    dl _netif_create_ip6_linklocal_address - app
    dl _netif_find - app
    dl _netif_get_by_index - app
    dl _netif_get_ip6_addr_match - app
    dl _netif_index_to_name - app
    dl _netif_init - app
    dl _netif_input - app
    dl _netif_invoke_ext_callback - app
    dl _netif_ip6_addr_set - app
    dl _netif_ip6_addr_set_parts - app
    dl _netif_ip6_addr_set_state - app
    dl _netif_loop_output - app
    dl _netif_name_to_index - app
    dl _netif_poll - app
    dl _netif_poll_all - app
    dl _netif_remove - app
    dl _netif_remove_ext_callback - app
    dl _netif_set_addr - app
    dl _netif_set_default - app
    dl _netif_set_down - app
    dl _netif_set_gw - app
    dl _netif_set_ipaddr - app
    dl _netif_set_link_callback - app
    dl _netif_set_link_down - app
    dl _netif_set_link_up - app
    dl _netif_set_netmask - app
    dl _netif_set_remove_callback - app
    dl _netif_set_status_callback - app
    dl _netif_set_up - app
    dl _dhcp_cleanup - app
    dl _dhcp_coarse_tmr - app
    dl _dhcp_fine_tmr - app
    dl _dhcp_inform - app
    dl _dhcp_network_changed_link_up - app
    dl _dhcp_release - app
    dl _dhcp_release_and_stop - app
    dl _dhcp_renew - app
    dl _dhcp_set_struct - app
    dl _dhcp_start - app
    dl _dhcp_stop - app
    dl _dhcp_supplied_address - app
    dl _dns_gethostbyname - app
    dl _dns_gethostbyname_addrtype - app
    dl _dns_getserver - app
    dl _dns_init - app
    dl _dns_setserver - app
    dl _dns_tmr - app
    dl _nd6_adjust_mld_membership - app
    dl _nd6_cleanup_netif - app
    dl _nd6_clear_destination_cache - app
    dl _nd6_find_route - app
    dl _nd6_get_destination_mtu - app
    dl _nd6_get_next_hop_addr_or_queue - app
    dl _nd6_input - app
    dl _nd6_reachability_hint - app
    dl _nd6_restart_netif - app
    dl _nd6_tmr - app
    dl _raw_bind - app
    dl _raw_bind_netif - app
    dl _raw_connect - app
    dl _raw_disconnect - app
    dl _raw_new - app
    dl _raw_new_ip_type - app
    dl _raw_recv - app
    dl _raw_remove - app
    dl _raw_send - app
    dl _raw_sendto - app
    dl _raw_sendto_if_src - app
    dl _tcp_abort - app
    dl _tcp_accept - app
    dl _tcp_arg - app
    dl _tcp_backlog_accepted - app
    dl _tcp_backlog_delayed - app
    dl _tcp_bind - app
    dl _tcp_bind_netif - app
    dl _tcp_close - app
    dl _tcp_connect - app
    dl _tcp_err - app
    dl _tcp_listen_with_backlog - app
    dl _tcp_listen_with_backlog_and_err - app
    dl _tcp_new - app
    dl _tcp_new_ip_type - app
    dl _tcp_output - app
    dl _tcp_poll - app
    dl _tcp_recv - app
    dl _tcp_recved - app
    dl _tcp_sent - app
    dl _tcp_setprio - app
    dl _tcp_shutdown - app
    dl _tcp_tcp_get_tcp_addrinfo - app
    dl _tcp_write - app
    dl _altcp_abort - app
    dl _altcp_accept - app
    dl _altcp_arg - app
    dl _altcp_bind - app
    dl _altcp_close - app
    dl _altcp_connect - app
    dl _altcp_dbg_get_tcp_state - app
    dl _altcp_err - app
    dl _altcp_get_ip - app
    dl _altcp_get_port - app
    dl _altcp_get_tcp_addrinfo - app
    dl _altcp_listen_with_backlog_and_err - app
    dl _altcp_mss - app
    dl _altcp_nagle_disable - app
    dl _altcp_nagle_disabled - app
    dl _altcp_nagle_enable - app
    dl _altcp_new - app
    dl _altcp_new_ip6 - app
    dl _altcp_new_ip_type - app
    dl _altcp_output - app
    dl _altcp_poll - app
    dl _altcp_recv - app
    dl _altcp_recved - app
    dl _altcp_sent - app
    dl _altcp_setprio - app
    dl _altcp_shutdown - app
    dl _altcp_sndbuf - app
    dl _altcp_sndqueuelen - app
    dl _altcp_write - app
    dl _altcp_tcp_alloc - app
    dl _altcp_tcp_new_ip_type - app
    dl _altcp_tcp_wrap - app
    dl _tcp_debug_state_str - app
    dl _udp_bind - app
    dl _udp_bind_netif - app
    dl _udp_connect - app
    dl _udp_disconnect - app
    dl _udp_init - app
    dl _udp_input - app
    dl _udp_netif_ip_addr_changed - app
    dl _udp_new - app
    dl _udp_new_ip_type - app
    dl _udp_recv - app
    dl _udp_remove - app
    dl _udp_send - app
    dl _udp_sendto - app
    dl _udp_sendto_if - app
    dl _udp_sendto_if_src - app
    dl _tls_random - app
    dl _tls_random_bytes - app
    dl _tls_random_init_entropy - app
    dl _tls_hash_context_init - app
    dl _tls_hash_digest - app
    dl _tls_hash_update - app
    dl _tls_mgf1 - app
    dl _tls_sha256_digest - app
    dl _tls_sha256_init - app
    dl _tls_sha256_update - app
    dl _tls_rsa_decode_oaep - app
    dl _tls_rsa_decrypt_signature - app
    dl _tls_rsa_encode_oaep - app
    dl _tls_rsa_encrypt - app
    dl _tls_rsa_pss_verify - app
    dl _tls_bytes_compare - app
    dl _tls_pbkdf2 - app
    dl _tls_aes_decrypt - app
    dl _tls_aes_digest - app
    dl _tls_aes_encrypt - app
    dl _tls_aes_init - app
    dl _tls_aes_update_aad - app
    dl _tls_aes_verify - app
    dl _tls_hmac_context_init - app
    dl _tls_hmac_digest - app
    dl _tls_hmac_update - app
    dl _tls_keyobject_destroy - app
    dl _tls_keyobject_import_certificate - app
    dl _tls_keyobject_import_private - app
    dl _tls_keyobject_import_public - app
    dl _tls_derive_secret - app
    dl _tls_hkdf_expand - app
    dl _tls_hkdf_expand_label - app
    dl _tls_hkdf_extract - app
    dl _tls_decrypt_data - app
    dl _tls_derive_application_keys - app
    dl _tls_derive_handshake_keys - app
    dl _tls_encrypt_data - app
    dl _tls_handshake_cleanup - app
    dl _tls_handshake_init - app
    dl _tls_process_record - app
    dl _tls_recv_certificate - app
    dl _tls_recv_finished - app
    dl _tls_recv_server_hello - app
    dl _tls_send_alert - app
    dl _tls_send_client_hello - app
    dl _tls_send_finished - app
    dl _tls_asn1_encode - app
    dl _tls_base64_decode - app
    dl _tls_base64_encode - app
    dl _tls_cleanup - app
    dl _tls_init - app
    dl _tls_truststore_init - app
    dl _tls_truststore_lookup - app


extern _eth_get_interfaces
extern _eth_usb_event_callback
extern _mem_buffer_capacity
extern _mem_buffer_create
extern _mem_buffer_destroy
extern _mem_buffer_free
extern _mem_buffer_len
extern _mem_buffer_malloc
extern _mem_buffer_pop
extern _mem_buffer_push
extern _mem_buffer_set_grow
extern _mem_buffer_set_max_size
extern _mem_buffer_set_shrink
extern _mem_buffer_space
extern _mem_init
extern _etharp_acd_announce
extern _etharp_acd_probe
extern _etharp_cleanup_netif
extern _etharp_find_addr
extern _etharp_get_entry
extern _etharp_input
extern _etharp_output
extern _etharp_query
extern _etharp_request
extern _etharp_tmr
extern _ethip6_output
extern _igmp_init
extern _igmp_input
extern _igmp_joingroup
extern _igmp_joingroup_netif
extern _igmp_leavegroup
extern _igmp_leavegroup_netif
extern _igmp_lookfor_group
extern _igmp_report_groups
extern _igmp_start
extern _igmp_stop
extern _igmp_tmr
extern _stats_display
extern _stats_display_igmp
extern _stats_display_mem
extern _stats_display_memp
extern _stats_display_proto
extern _stats_display_sys
extern _stats_init
extern _ip4_input
extern _ip4_output
extern _ip4_output_if
extern _ip4_output_if_opt
extern _ip4_output_if_opt_src
extern _ip4_output_if_src
extern _ip4_route
extern _ip4_set_default_multicast_netif
extern _ip4_addr_isbroadcast_u32
extern _ip4_addr_netmask_valid
extern _ip4addr_aton
extern _ip4addr_ntoa
extern _ip4addr_ntoa_r
extern _ipaddr_addr
extern _ip4_frag
extern _ip4_reass
extern _ip_reass_tmr
extern _ip6_input
extern _ip6_options_add_hbh_ra
extern _ip6_output
extern _ip6_output_if
extern _ip6_output_if_src
extern _ip6_route
extern _ip6_select_source_address
extern _ip6addr_aton
extern _ip6addr_ntoa
extern _ip6addr_ntoa_r
extern _ip6_frag
extern _ip6_reass
extern _ip6_reass_tmr
extern _ip_input
extern _ipaddr_aton
extern _ipaddr_ntoa
extern _ipaddr_ntoa_r
extern _autoip_accept_packet
extern _autoip_network_changed_link_down
extern _autoip_network_changed_link_up
extern _autoip_remove_struct
extern _autoip_set_struct
extern _autoip_start
extern _autoip_stop
extern _autoip_supplied_address
extern _pbuf_add_header
extern _pbuf_add_header_force
extern _pbuf_alloc
extern _pbuf_alloc_reference
extern _pbuf_alloced_custom
extern _pbuf_cat
extern _pbuf_chain
extern _pbuf_clen
extern _pbuf_clone
extern _pbuf_coalesce
extern _pbuf_copy
extern _pbuf_copy_partial
extern _pbuf_copy_partial_pbuf
extern _pbuf_dechain
extern _pbuf_free
extern _pbuf_free_header
extern _pbuf_free_ooseq
extern _pbuf_get_at
extern _pbuf_get_contiguous
extern _pbuf_header
extern _pbuf_header_force
extern _pbuf_memcmp
extern _pbuf_memfind
extern _pbuf_put_at
extern _pbuf_realloc
extern _pbuf_ref
extern _pbuf_remove_header
extern _pbuf_skip
extern _pbuf_strstr
extern _pbuf_take
extern _pbuf_take_at
extern _pbuf_try_get_at
extern _custom_calloc
extern _custom_free
extern _custom_malloc
extern _mem_calloc
extern _mem_free
extern _mem_malloc
extern _mem_trim
extern _memp_free
extern _memp_init
extern _memp_malloc
extern _lwip_init
extern _lwip_init_runtime
extern _netif_add
extern _netif_add_ext_callback
extern _netif_add_ip6_address
extern _netif_add_noaddr
extern _netif_alloc_client_data_id
extern _netif_create_ip6_linklocal_address
extern _netif_find
extern _netif_get_by_index
extern _netif_get_ip6_addr_match
extern _netif_index_to_name
extern _netif_init
extern _netif_input
extern _netif_invoke_ext_callback
extern _netif_ip6_addr_set
extern _netif_ip6_addr_set_parts
extern _netif_ip6_addr_set_state
extern _netif_loop_output
extern _netif_name_to_index
extern _netif_poll
extern _netif_poll_all
extern _netif_remove
extern _netif_remove_ext_callback
extern _netif_set_addr
extern _netif_set_default
extern _netif_set_down
extern _netif_set_gw
extern _netif_set_ipaddr
extern _netif_set_link_callback
extern _netif_set_link_down
extern _netif_set_link_up
extern _netif_set_netmask
extern _netif_set_remove_callback
extern _netif_set_status_callback
extern _netif_set_up
extern _dhcp_cleanup
extern _dhcp_coarse_tmr
extern _dhcp_fine_tmr
extern _dhcp_inform
extern _dhcp_network_changed_link_up
extern _dhcp_release
extern _dhcp_release_and_stop
extern _dhcp_renew
extern _dhcp_set_struct
extern _dhcp_start
extern _dhcp_stop
extern _dhcp_supplied_address
extern _dns_gethostbyname
extern _dns_gethostbyname_addrtype
extern _dns_getserver
extern _dns_init
extern _dns_setserver
extern _dns_tmr
extern _nd6_adjust_mld_membership
extern _nd6_cleanup_netif
extern _nd6_clear_destination_cache
extern _nd6_find_route
extern _nd6_get_destination_mtu
extern _nd6_get_next_hop_addr_or_queue
extern _nd6_input
extern _nd6_reachability_hint
extern _nd6_restart_netif
extern _nd6_tmr
extern _raw_bind
extern _raw_bind_netif
extern _raw_connect
extern _raw_disconnect
extern _raw_new
extern _raw_new_ip_type
extern _raw_recv
extern _raw_remove
extern _raw_send
extern _raw_sendto
extern _raw_sendto_if_src
extern _tcp_abort
extern _tcp_accept
extern _tcp_arg
extern _tcp_backlog_accepted
extern _tcp_backlog_delayed
extern _tcp_bind
extern _tcp_bind_netif
extern _tcp_close
extern _tcp_connect
extern _tcp_err
extern _tcp_listen_with_backlog
extern _tcp_listen_with_backlog_and_err
extern _tcp_new
extern _tcp_new_ip_type
extern _tcp_output
extern _tcp_poll
extern _tcp_recv
extern _tcp_recved
extern _tcp_sent
extern _tcp_setprio
extern _tcp_shutdown
extern _tcp_tcp_get_tcp_addrinfo
extern _tcp_write
extern _altcp_abort
extern _altcp_accept
extern _altcp_arg
extern _altcp_bind
extern _altcp_close
extern _altcp_connect
extern _altcp_dbg_get_tcp_state
extern _altcp_err
extern _altcp_get_ip
extern _altcp_get_port
extern _altcp_get_tcp_addrinfo
extern _altcp_listen_with_backlog_and_err
extern _altcp_mss
extern _altcp_nagle_disable
extern _altcp_nagle_disabled
extern _altcp_nagle_enable
extern _altcp_new
extern _altcp_new_ip6
extern _altcp_new_ip_type
extern _altcp_output
extern _altcp_poll
extern _altcp_recv
extern _altcp_recved
extern _altcp_sent
extern _altcp_setprio
extern _altcp_shutdown
extern _altcp_sndbuf
extern _altcp_sndqueuelen
extern _altcp_write
extern _altcp_tcp_alloc
extern _altcp_tcp_new_ip_type
extern _altcp_tcp_wrap
extern _tcp_debug_state_str
extern _udp_bind
extern _udp_bind_netif
extern _udp_connect
extern _udp_disconnect
extern _udp_init
extern _udp_input
extern _udp_netif_ip_addr_changed
extern _udp_new
extern _udp_new_ip_type
extern _udp_recv
extern _udp_remove
extern _udp_send
extern _udp_sendto
extern _udp_sendto_if
extern _udp_sendto_if_src
extern _tls_random
extern _tls_random_bytes
extern _tls_random_init_entropy
extern _tls_hash_context_init
extern _tls_hash_digest
extern _tls_hash_update
extern _tls_mgf1
extern _tls_sha256_digest
extern _tls_sha256_init
extern _tls_sha256_update
extern _tls_rsa_decode_oaep
extern _tls_rsa_decrypt_signature
extern _tls_rsa_encode_oaep
extern _tls_rsa_encrypt
extern _tls_rsa_pss_verify
extern _tls_bytes_compare
extern _tls_pbkdf2
extern _tls_aes_decrypt
extern _tls_aes_digest
extern _tls_aes_encrypt
extern _tls_aes_init
extern _tls_aes_update_aad
extern _tls_aes_verify
extern _tls_hmac_context_init
extern _tls_hmac_digest
extern _tls_hmac_update
extern _tls_keyobject_destroy
extern _tls_keyobject_import_certificate
extern _tls_keyobject_import_private
extern _tls_keyobject_import_public
extern _tls_derive_secret
extern _tls_hkdf_expand
extern _tls_hkdf_expand_label
extern _tls_hkdf_extract
extern _tls_decrypt_data
extern _tls_derive_application_keys
extern _tls_derive_handshake_keys
extern _tls_encrypt_data
extern _tls_handshake_cleanup
extern _tls_handshake_init
extern _tls_process_record
extern _tls_recv_certificate
extern _tls_recv_finished
extern _tls_recv_server_hello
extern _tls_send_alert
extern _tls_send_client_hello
extern _tls_send_finished
extern _tls_asn1_encode
extern _tls_base64_decode
extern _tls_base64_encode
extern _tls_cleanup
extern _tls_init
extern _tls_truststore_init
extern _tls_truststore_lookup
