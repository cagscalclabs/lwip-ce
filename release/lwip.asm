; lwip.asm — libload library stub for lwIP. Generated 2026-06-03.
; Author: Anthony Cagliano
; Do not edit by hand. Sources: tools/functable.py,
; tools/lwip_init_runtime.asm.

include 'library.inc'
include 'include_library.inc'

library LWIP, 0

	include_library 'usbdrvce.lib'

	public _fn_imports_table
_fn_imports_table:
	; host CRT (populated at load time by lwip_init_runtime)
	dl 0
	dl 0
	dl 0
	; USB vtable (populated at link time by include_library)
	dl usb_ResetDevice
	dl usb_DisableDevice
	dl usb_RefDevice
	dl usb_UnrefDevice
	dl usb_SetDeviceData
	dl usb_GetDeviceData
	dl usb_GetRole
	dl usb_GetDeviceFlags
	dl usb_ScheduleTransfer
	dl usb_ControlTransfer
	dl usb_GetConfigurationDescriptorTotalLength
	dl usb_GetDescriptor
	dl usb_GetStringDescriptor
	dl usb_SetConfiguration
	dl usb_SetInterface
	dl usb_GetDeviceEndpoint
	dl usb_SetEndpointData
	dl usb_GetEndpointData
	dl usb_SetEndpointFlags
	dl usb_SetEndpointHalt
	dl usb_Init
	dl usb_HandleEvents
	dl usb_Cleanup
_fn_imports_table_end:

	export lwip_start
	export lwip_init_runtime_internal
	export lwip_poll_network_events
	export lwip_conn_create
	export lwip_conn_destroy
	export lwip_conn_connect
	export lwip_conn_write
	export lwip_conn_recved
	export lwip_conn_shutdown
	export lwip_conn_close
	export lwip_conn_abort
	export lwip_conn_set_arg
	export lwip_conn_set_connected
	export lwip_conn_set_recv
	export lwip_conn_set_sent
	export lwip_conn_set_err
	export lwip_conn_set_poll
	export lwip_conn_set_closed
	export lwip_conn_set_callbacks
	export tls_aes_init
	export tls_aes_ccm_init
	export tls_aes_ccm_encrypt
	export tls_aes_ccm_decrypt
	export tls_aes_update_aad
	export tls_aes_encrypt
	export tls_aes_update_ciphertext
	export tls_aes_digest
	export tls_aes_decrypt
	export tls_aes_verify
	export tls_asn1_cursor_init
	export tls_asn1_next
	export tls_asn1_child_cursor
	export tls_asn1_tag_number
	export tls_asn1_tag_class
	export tls_asn1_tag_constructed
	export tls_base64_encode
	export tls_base64_decode
	export tls_bytes_compare
	export tls_secure_memzero
	export tls_sha256_init
	export tls_sha256_update
	export tls_sha256_digest
	export tls_hash_context_init
	export tls_hash_update
	export tls_hash_digest
	export tls_mgf1
	export tls_hkdf_extract
	export tls_hkdf_expand
	export tls_hkdf_expand_label
	export tls_derive_secret
	export tls_hmac_context_init
	export tls_hmac_update
	export tls_hmac_digest
	export tls_keyobject_import_private
	export tls_keyobject_import_public
	export tls_keyobject_import_certificate
	export tls_x509_has_required_ca_constraints
	export tls_keyobject_destroy
	export tls_pbkdf2
	export tls_pkcs8_strerror
	export tls_pkcs8_import
	export tls_pkcs8_import_private
	export tls_pkcs8_import_public
	export tls_pkcs8_object_import_private
	export tls_pkcs8_object_import_public
	export tls_pkcs8_object_destroy
	export tls_random_init_entropy
	export tls_random
	export tls_random_bytes
	export tls_rng_healthcheck
	export tls_request_random_bytes
	export tls_rng_is_busy
	export tls_rsa_encode_oaep
	export tls_rsa_decode_oaep
	export tls_rsa_encrypt
	export tls_rsa_decrypt_signature
	export tls_rsa_pss_verify
	export tls_truststore_init
	export tls_truststore_lookup
	export tls_x509_has_valid_constraints
	export tls_x509_parse_certificate
	export tls_x509_import_and_parse_certificate
	export tls_x509_import_certificate
	export tls_x509_object_destroy
	export acd_add
	export acd_remove
	export acd_start
	export acd_stop
	export acd_arp_reply
	export acd_network_changed_link_down
	export acd_netif_ip_addr_changed
	export altcp_new
	export altcp_new_ip6
	export altcp_new_ip_type
	export altcp_arg
	export altcp_accept
	export altcp_recv
	export altcp_sent
	export altcp_poll
	export altcp_err
	export altcp_recved
	export altcp_bind
	export altcp_connect
	export altcp_listen_with_backlog_and_err
	export altcp_abort
	export altcp_close
	export altcp_shutdown
	export altcp_write
	export altcp_output
	export altcp_mss
	export altcp_sndbuf
	export altcp_sndqueuelen
	export altcp_nagle_disable
	export altcp_nagle_enable
	export altcp_nagle_disabled
	export altcp_setprio
	export altcp_get_tcp_addrinfo
	export altcp_get_ip
	export altcp_get_port
	export altcp_tls_create_config_server
	export altcp_tls_config_server_add_privkey_cert
	export altcp_tls_create_config_server_privkey_cert
	export altcp_tls_create_config_client
	export altcp_tls_create_config_client_2wayauth
	export altcp_tls_configure_alpn_protocols
	export altcp_tls_free_config
	export altcp_tls_wrap
	export altcp_tls_new
	export altcp_tls_alloc
	export autoip_set_struct
	export autoip_remove_struct
	export autoip_start
	export autoip_stop
	export autoip_network_changed_link_up
	export autoip_network_changed_link_down
	export autoip_supplied_address
	export autoip_accept_packet
	export lwip_htons
	export lwip_htonl
	export lwip_itoa
	export lwip_strnicmp
	export lwip_stricmp
	export lwip_strnstr
	export lwip_strnistr
	export lwip_memcmp_consttime
	export dhcp_set_struct
	export dhcp_cleanup
	export dhcp_start
	export dhcp_renew
	export dhcp_release
	export dhcp_stop
	export dhcp_release_and_stop
	export dhcp_inform
	export dhcp_network_changed_link_up
	export dhcp_supplied_address
	export dns_setserver
	export dns_getserver
	export dns_gethostbyname
	export dns_gethostbyname_addrtype
	export etharp_find_addr
	export etharp_get_entry
	export etharp_output
	export etharp_query
	export etharp_request
	export etharp_cleanup_netif
	export etharp_acd_probe
	export etharp_acd_announce
	export etharp_input
	export icmp_input
	export icmp_dest_unreach
	export icmp_time_exceeded
	export icmp6_input
	export icmp6_dest_unreach
	export icmp6_packet_too_big
	export icmp6_time_exceeded
	export icmp6_time_exceeded_with_addrs
	export icmp6_param_problem
	export igmp_start
	export igmp_stop
	export igmp_report_groups
	export igmp_lookfor_group
	export igmp_input
	export igmp_joingroup
	export igmp_joingroup_netif
	export igmp_leavegroup
	export igmp_leavegroup_netif
	export inet_chksum
	export inet_chksum_pbuf
	export inet_chksum_pseudo
	export inet_chksum_pseudo_partial
	export ip6_chksum_pseudo
	export ip6_chksum_pseudo_partial
	export ip_chksum_pseudo
	export ip_chksum_pseudo_partial
	export lwip_init
	export ip_input
	export ip4_route
	export ip4_input
	export ip4_output
	export ip4_output_if
	export ip4_output_if_src
	export ip4_output_if_opt
	export ip4_output_if_opt_src
	export ip4_set_default_multicast_netif
	export ip4_addr_isbroadcast_u32
	export ip4_addr_netmask_valid
	export ipaddr_addr
	export ip4addr_aton
	export ip4addr_ntoa
	export ip4addr_ntoa_r
	export ip4_reass
	export ip4_frag
	export ip6_route
	export ip6_select_source_address
	export ip6_input
	export ip6_output
	export ip6_output_if
	export ip6_output_if_src
	export ip6_options_add_hbh_ra
	export ip6addr_aton
	export ip6addr_ntoa
	export ip6addr_ntoa_r
	export ip6_reass
	export ip6_frag
	export ipaddr_ntoa
	export ipaddr_ntoa_r
	export ipaddr_aton
	export mem_trim
	export mem_malloc
	export mem_calloc
	export mem_free
	export memp_malloc
	export memp_free
	export mld6_stop
	export mld6_report_groups
	export mld6_lookfor_group
	export mld6_input
	export mld6_joingroup
	export mld6_joingroup_netif
	export mld6_leavegroup
	export mld6_leavegroup_netif
	export nd6_input
	export nd6_clear_destination_cache
	export nd6_find_route
	export nd6_get_next_hop_addr_or_queue
	export nd6_get_destination_mtu
	export nd6_reachability_hint
	export nd6_cleanup_netif
	export nd6_adjust_mld_membership
	export nd6_restart_netif
	export netif_alloc_client_data_id
	export netif_add_noaddr
	export netif_add
	export netif_set_addr
	export netif_remove
	export netif_find
	export netif_set_default
	export netif_set_ipaddr
	export netif_set_netmask
	export netif_set_gw
	export netif_set_up
	export netif_set_down
	export netif_set_status_callback
	export netif_set_remove_callback
	export netif_set_link_up
	export netif_set_link_down
	export netif_set_link_callback
	export netif_loop_output
	export netif_poll
	export netif_poll_all
	export netif_input
	export netif_ip6_addr_set
	export netif_ip6_addr_set_parts
	export netif_ip6_addr_set_state
	export netif_get_ip6_addr_match
	export netif_create_ip6_linklocal_address
	export netif_add_ip6_address
	export netif_name_to_index
	export netif_index_to_name
	export netif_get_by_index
	export netif_add_ext_callback
	export netif_remove_ext_callback
	export pbuf_free_ooseq
	export pbuf_alloc
	export pbuf_alloc_reference
	export pbuf_alloced_custom
	export pbuf_realloc
	export pbuf_header
	export pbuf_header_force
	export pbuf_add_header
	export pbuf_add_header_force
	export pbuf_remove_header
	export pbuf_free_header
	export pbuf_ref
	export pbuf_free
	export pbuf_clen
	export pbuf_cat
	export pbuf_chain
	export pbuf_dechain
	export pbuf_copy
	export pbuf_copy_partial_pbuf
	export pbuf_copy_partial
	export pbuf_get_contiguous
	export pbuf_take
	export pbuf_take_at
	export pbuf_skip
	export pbuf_coalesce
	export pbuf_clone
	export pbuf_get_at
	export pbuf_try_get_at
	export pbuf_put_at
	export pbuf_memcmp
	export pbuf_memfind
	export pbuf_strstr
	export raw_new
	export raw_new_ip_type
	export raw_remove
	export raw_bind
	export raw_bind_netif
	export raw_connect
	export raw_disconnect
	export raw_sendto
	export raw_sendto_if_src
	export raw_send
	export raw_recv
	export lwip_sntp_set_timezone_offset
	export lwip_sntp_set_dst_enabled
	export lwip_sntp_set_time
	export lwip_sntp_reset_flag
	export lwip_sntp_time_was_set
	export lwip_sntp_get_unix_time
	export sys_timeout
	export sys_untimeout
	export tcp_new
	export tcp_new_ip_type
	export tcp_arg
	export tcp_recv
	export tcp_sent
	export tcp_err
	export tcp_accept
	export tcp_poll
	export tcp_backlog_delayed
	export tcp_backlog_accepted
	export tcp_recved
	export tcp_bind
	export tcp_bind_netif
	export tcp_connect
	export tcp_listen_with_backlog_and_err
	export tcp_listen_with_backlog
	export tcp_abort
	export tcp_close
	export tcp_shutdown
	export tcp_write
	export tcp_setprio
	export tcp_output
	export tcp_tcp_get_tcp_addrinfo
	export udp_new
	export udp_new_ip_type
	export udp_remove
	export udp_bind
	export udp_bind_netif
	export udp_connect
	export udp_disconnect
	export udp_recv
	export udp_sendto_if
	export udp_sendto_if_src
	export udp_sendto
	export udp_send
	export udp_input
	export udp_netif_ip_addr_changed
	export ethernet_input
	export ethernet_output
	export eth_get_interfaces
	export netif_is_link_error
	export eth_usb_event_callback
	export tls_x25519_publickey
	export tls_x25519_secret

_lwip_jp_table_start:
lwip_start:	jp 0
lwip_init_runtime_internal:	jp 0
lwip_poll_network_events:	jp 0
lwip_conn_create:	jp 0
lwip_conn_destroy:	jp 0
lwip_conn_connect:	jp 0
lwip_conn_write:	jp 0
lwip_conn_recved:	jp 0
lwip_conn_shutdown:	jp 0
lwip_conn_close:	jp 0
lwip_conn_abort:	jp 0
lwip_conn_set_arg:	jp 0
lwip_conn_set_connected:	jp 0
lwip_conn_set_recv:	jp 0
lwip_conn_set_sent:	jp 0
lwip_conn_set_err:	jp 0
lwip_conn_set_poll:	jp 0
lwip_conn_set_closed:	jp 0
lwip_conn_set_callbacks:	jp 0
tls_aes_init:	jp 0
tls_aes_ccm_init:	jp 0
tls_aes_ccm_encrypt:	jp 0
tls_aes_ccm_decrypt:	jp 0
tls_aes_update_aad:	jp 0
tls_aes_encrypt:	jp 0
tls_aes_update_ciphertext:	jp 0
tls_aes_digest:	jp 0
tls_aes_decrypt:	jp 0
tls_aes_verify:	jp 0
tls_asn1_cursor_init:	jp 0
tls_asn1_next:	jp 0
tls_asn1_child_cursor:	jp 0
tls_asn1_tag_number:	jp 0
tls_asn1_tag_class:	jp 0
tls_asn1_tag_constructed:	jp 0
tls_base64_encode:	jp 0
tls_base64_decode:	jp 0
tls_bytes_compare:	jp 0
tls_secure_memzero:	jp 0
tls_sha256_init:	jp 0
tls_sha256_update:	jp 0
tls_sha256_digest:	jp 0
tls_hash_context_init:	jp 0
tls_hash_update:	jp 0
tls_hash_digest:	jp 0
tls_mgf1:	jp 0
tls_hkdf_extract:	jp 0
tls_hkdf_expand:	jp 0
tls_hkdf_expand_label:	jp 0
tls_derive_secret:	jp 0
tls_hmac_context_init:	jp 0
tls_hmac_update:	jp 0
tls_hmac_digest:	jp 0
tls_keyobject_import_private:	jp 0
tls_keyobject_import_public:	jp 0
tls_keyobject_import_certificate:	jp 0
tls_x509_has_required_ca_constraints:	jp 0
tls_keyobject_destroy:	jp 0
tls_pbkdf2:	jp 0
tls_pkcs8_strerror:	jp 0
tls_pkcs8_import:	jp 0
tls_pkcs8_import_private:	jp 0
tls_pkcs8_import_public:	jp 0
tls_pkcs8_object_import_private:	jp 0
tls_pkcs8_object_import_public:	jp 0
tls_pkcs8_object_destroy:	jp 0
tls_random_init_entropy:	jp 0
tls_random:	jp 0
tls_random_bytes:	jp 0
tls_rng_healthcheck:	jp 0
tls_request_random_bytes:	jp 0
tls_rng_is_busy:	jp 0
tls_rsa_encode_oaep:	jp 0
tls_rsa_decode_oaep:	jp 0
tls_rsa_encrypt:	jp 0
tls_rsa_decrypt_signature:	jp 0
tls_rsa_pss_verify:	jp 0
tls_truststore_init:	jp 0
tls_truststore_lookup:	jp 0
tls_x509_has_valid_constraints:	jp 0
tls_x509_parse_certificate:	jp 0
tls_x509_import_and_parse_certificate:	jp 0
tls_x509_import_certificate:	jp 0
tls_x509_object_destroy:	jp 0
acd_add:	jp 0
acd_remove:	jp 0
acd_start:	jp 0
acd_stop:	jp 0
acd_arp_reply:	jp 0
acd_network_changed_link_down:	jp 0
acd_netif_ip_addr_changed:	jp 0
altcp_new:	jp 0
altcp_new_ip6:	jp 0
altcp_new_ip_type:	jp 0
altcp_arg:	jp 0
altcp_accept:	jp 0
altcp_recv:	jp 0
altcp_sent:	jp 0
altcp_poll:	jp 0
altcp_err:	jp 0
altcp_recved:	jp 0
altcp_bind:	jp 0
altcp_connect:	jp 0
altcp_listen_with_backlog_and_err:	jp 0
altcp_abort:	jp 0
altcp_close:	jp 0
altcp_shutdown:	jp 0
altcp_write:	jp 0
altcp_output:	jp 0
altcp_mss:	jp 0
altcp_sndbuf:	jp 0
altcp_sndqueuelen:	jp 0
altcp_nagle_disable:	jp 0
altcp_nagle_enable:	jp 0
altcp_nagle_disabled:	jp 0
altcp_setprio:	jp 0
altcp_get_tcp_addrinfo:	jp 0
altcp_get_ip:	jp 0
altcp_get_port:	jp 0
altcp_tls_create_config_server:	jp 0
altcp_tls_config_server_add_privkey_cert:	jp 0
altcp_tls_create_config_server_privkey_cert:	jp 0
altcp_tls_create_config_client:	jp 0
altcp_tls_create_config_client_2wayauth:	jp 0
altcp_tls_configure_alpn_protocols:	jp 0
altcp_tls_free_config:	jp 0
altcp_tls_wrap:	jp 0
altcp_tls_new:	jp 0
altcp_tls_alloc:	jp 0
autoip_set_struct:	jp 0
autoip_remove_struct:	jp 0
autoip_start:	jp 0
autoip_stop:	jp 0
autoip_network_changed_link_up:	jp 0
autoip_network_changed_link_down:	jp 0
autoip_supplied_address:	jp 0
autoip_accept_packet:	jp 0
lwip_htons:	jp 0
lwip_htonl:	jp 0
lwip_itoa:	jp 0
lwip_strnicmp:	jp 0
lwip_stricmp:	jp 0
lwip_strnstr:	jp 0
lwip_strnistr:	jp 0
lwip_memcmp_consttime:	jp 0
dhcp_set_struct:	jp 0
dhcp_cleanup:	jp 0
dhcp_start:	jp 0
dhcp_renew:	jp 0
dhcp_release:	jp 0
dhcp_stop:	jp 0
dhcp_release_and_stop:	jp 0
dhcp_inform:	jp 0
dhcp_network_changed_link_up:	jp 0
dhcp_supplied_address:	jp 0
dns_setserver:	jp 0
dns_getserver:	jp 0
dns_gethostbyname:	jp 0
dns_gethostbyname_addrtype:	jp 0
etharp_find_addr:	jp 0
etharp_get_entry:	jp 0
etharp_output:	jp 0
etharp_query:	jp 0
etharp_request:	jp 0
etharp_cleanup_netif:	jp 0
etharp_acd_probe:	jp 0
etharp_acd_announce:	jp 0
etharp_input:	jp 0
icmp_input:	jp 0
icmp_dest_unreach:	jp 0
icmp_time_exceeded:	jp 0
icmp6_input:	jp 0
icmp6_dest_unreach:	jp 0
icmp6_packet_too_big:	jp 0
icmp6_time_exceeded:	jp 0
icmp6_time_exceeded_with_addrs:	jp 0
icmp6_param_problem:	jp 0
igmp_start:	jp 0
igmp_stop:	jp 0
igmp_report_groups:	jp 0
igmp_lookfor_group:	jp 0
igmp_input:	jp 0
igmp_joingroup:	jp 0
igmp_joingroup_netif:	jp 0
igmp_leavegroup:	jp 0
igmp_leavegroup_netif:	jp 0
inet_chksum:	jp 0
inet_chksum_pbuf:	jp 0
inet_chksum_pseudo:	jp 0
inet_chksum_pseudo_partial:	jp 0
ip6_chksum_pseudo:	jp 0
ip6_chksum_pseudo_partial:	jp 0
ip_chksum_pseudo:	jp 0
ip_chksum_pseudo_partial:	jp 0
lwip_init:	jp 0
ip_input:	jp 0
ip4_route:	jp 0
ip4_input:	jp 0
ip4_output:	jp 0
ip4_output_if:	jp 0
ip4_output_if_src:	jp 0
ip4_output_if_opt:	jp 0
ip4_output_if_opt_src:	jp 0
ip4_set_default_multicast_netif:	jp 0
ip4_addr_isbroadcast_u32:	jp 0
ip4_addr_netmask_valid:	jp 0
ipaddr_addr:	jp 0
ip4addr_aton:	jp 0
ip4addr_ntoa:	jp 0
ip4addr_ntoa_r:	jp 0
ip4_reass:	jp 0
ip4_frag:	jp 0
ip6_route:	jp 0
ip6_select_source_address:	jp 0
ip6_input:	jp 0
ip6_output:	jp 0
ip6_output_if:	jp 0
ip6_output_if_src:	jp 0
ip6_options_add_hbh_ra:	jp 0
ip6addr_aton:	jp 0
ip6addr_ntoa:	jp 0
ip6addr_ntoa_r:	jp 0
ip6_reass:	jp 0
ip6_frag:	jp 0
ipaddr_ntoa:	jp 0
ipaddr_ntoa_r:	jp 0
ipaddr_aton:	jp 0
mem_trim:	jp 0
mem_malloc:	jp 0
mem_calloc:	jp 0
mem_free:	jp 0
memp_malloc:	jp 0
memp_free:	jp 0
mld6_stop:	jp 0
mld6_report_groups:	jp 0
mld6_lookfor_group:	jp 0
mld6_input:	jp 0
mld6_joingroup:	jp 0
mld6_joingroup_netif:	jp 0
mld6_leavegroup:	jp 0
mld6_leavegroup_netif:	jp 0
nd6_input:	jp 0
nd6_clear_destination_cache:	jp 0
nd6_find_route:	jp 0
nd6_get_next_hop_addr_or_queue:	jp 0
nd6_get_destination_mtu:	jp 0
nd6_reachability_hint:	jp 0
nd6_cleanup_netif:	jp 0
nd6_adjust_mld_membership:	jp 0
nd6_restart_netif:	jp 0
netif_alloc_client_data_id:	jp 0
netif_add_noaddr:	jp 0
netif_add:	jp 0
netif_set_addr:	jp 0
netif_remove:	jp 0
netif_find:	jp 0
netif_set_default:	jp 0
netif_set_ipaddr:	jp 0
netif_set_netmask:	jp 0
netif_set_gw:	jp 0
netif_set_up:	jp 0
netif_set_down:	jp 0
netif_set_status_callback:	jp 0
netif_set_remove_callback:	jp 0
netif_set_link_up:	jp 0
netif_set_link_down:	jp 0
netif_set_link_callback:	jp 0
netif_loop_output:	jp 0
netif_poll:	jp 0
netif_poll_all:	jp 0
netif_input:	jp 0
netif_ip6_addr_set:	jp 0
netif_ip6_addr_set_parts:	jp 0
netif_ip6_addr_set_state:	jp 0
netif_get_ip6_addr_match:	jp 0
netif_create_ip6_linklocal_address:	jp 0
netif_add_ip6_address:	jp 0
netif_name_to_index:	jp 0
netif_index_to_name:	jp 0
netif_get_by_index:	jp 0
netif_add_ext_callback:	jp 0
netif_remove_ext_callback:	jp 0
pbuf_free_ooseq:	jp 0
pbuf_alloc:	jp 0
pbuf_alloc_reference:	jp 0
pbuf_alloced_custom:	jp 0
pbuf_realloc:	jp 0
pbuf_header:	jp 0
pbuf_header_force:	jp 0
pbuf_add_header:	jp 0
pbuf_add_header_force:	jp 0
pbuf_remove_header:	jp 0
pbuf_free_header:	jp 0
pbuf_ref:	jp 0
pbuf_free:	jp 0
pbuf_clen:	jp 0
pbuf_cat:	jp 0
pbuf_chain:	jp 0
pbuf_dechain:	jp 0
pbuf_copy:	jp 0
pbuf_copy_partial_pbuf:	jp 0
pbuf_copy_partial:	jp 0
pbuf_get_contiguous:	jp 0
pbuf_take:	jp 0
pbuf_take_at:	jp 0
pbuf_skip:	jp 0
pbuf_coalesce:	jp 0
pbuf_clone:	jp 0
pbuf_get_at:	jp 0
pbuf_try_get_at:	jp 0
pbuf_put_at:	jp 0
pbuf_memcmp:	jp 0
pbuf_memfind:	jp 0
pbuf_strstr:	jp 0
raw_new:	jp 0
raw_new_ip_type:	jp 0
raw_remove:	jp 0
raw_bind:	jp 0
raw_bind_netif:	jp 0
raw_connect:	jp 0
raw_disconnect:	jp 0
raw_sendto:	jp 0
raw_sendto_if_src:	jp 0
raw_send:	jp 0
raw_recv:	jp 0
lwip_sntp_set_timezone_offset:	jp 0
lwip_sntp_set_dst_enabled:	jp 0
lwip_sntp_set_time:	jp 0
lwip_sntp_reset_flag:	jp 0
lwip_sntp_time_was_set:	jp 0
lwip_sntp_get_unix_time:	jp 0
sys_timeout:	jp 0
sys_untimeout:	jp 0
tcp_new:	jp 0
tcp_new_ip_type:	jp 0
tcp_arg:	jp 0
tcp_recv:	jp 0
tcp_sent:	jp 0
tcp_err:	jp 0
tcp_accept:	jp 0
tcp_poll:	jp 0
tcp_backlog_delayed:	jp 0
tcp_backlog_accepted:	jp 0
tcp_recved:	jp 0
tcp_bind:	jp 0
tcp_bind_netif:	jp 0
tcp_connect:	jp 0
tcp_listen_with_backlog_and_err:	jp 0
tcp_listen_with_backlog:	jp 0
tcp_abort:	jp 0
tcp_close:	jp 0
tcp_shutdown:	jp 0
tcp_write:	jp 0
tcp_setprio:	jp 0
tcp_output:	jp 0
tcp_tcp_get_tcp_addrinfo:	jp 0
udp_new:	jp 0
udp_new_ip_type:	jp 0
udp_remove:	jp 0
udp_bind:	jp 0
udp_bind_netif:	jp 0
udp_connect:	jp 0
udp_disconnect:	jp 0
udp_recv:	jp 0
udp_sendto_if:	jp 0
udp_sendto_if_src:	jp 0
udp_sendto:	jp 0
udp_send:	jp 0
udp_input:	jp 0
udp_netif_ip_addr_changed:	jp 0
ethernet_input:	jp 0
ethernet_output:	jp 0
eth_get_interfaces:	jp 0
netif_is_link_error:	jp 0
eth_usb_event_callback:	jp 0
tls_x25519_publickey:	jp 0
tls_x25519_secret:	jp 0
_lwip_jp_table_end:

; lwip_init_runtime_opaque(malloc, free, realloc)
;   Stores the three CRTs in _fn_imports_table, locates the lwIP app via
;   FindAppStart, verifies the export-table magic, and patches each in-lib
;   trampoline (jp 0) to point at its real in-app function address.
;
; __lwip_fn_table_off is the byte offset from app base to _fn_exports_table.
; The phase-2 build greps it from bin/lwIP.map and substitutes the literal
; below before fasmg runs.

ti.FindAppStart      := 0x021100
__lwip_fn_table_off  := 0x000000

	export lwip_init_runtime_opaque

__lwip_app_name:
	db "lwIP", 0

lwip_init_runtime_opaque:
	call ti._frameset0

	ld hl, (ix + 6)
	ld (_fn_imports_table + 0), hl		; malloc
	ld hl, (ix + 9)
	ld (_fn_imports_table + 3), hl		; free
	ld hl, (ix + 12)
	ld (_fn_imports_table + 6), hl		; realloc

	ld hl, __lwip_app_name
	call ti.FindAppStart			; HL <- app base, carry on not-found
	jr c, .table_fail

	push hl
	pop de					; DE = app base, held through the loop

	push de
	ld de, __lwip_fn_table_off
	add hl, de				; HL -> _fn_exports_table
	pop de

	; Magic: 'L','W','I','P','T','B'
	ld a, (hl) : cp a, 'L' : jr nz, .table_fail : inc hl
	ld a, (hl) : cp a, 'W' : jr nz, .table_fail : inc hl
	ld a, (hl) : cp a, 'I' : jr nz, .table_fail : inc hl
	ld a, (hl) : cp a, 'P' : jr nz, .table_fail : inc hl
	ld a, (hl) : cp a, 'T' : jr nz, .table_fail : inc hl
	ld a, (hl) : cp a, 'B' : jr nz, .table_fail : inc hl

	ld bc, (hl)				; count
	inc hl : inc hl : inc hl		; HL -> first entry

	push ix
	ld ix, _lwip_jp_table_start + 1		; first trampoline operand
.patch_loop:
	ld a, b : or a, c
	jr z, .patch_done

	push hl
	ld hl, (hl)				; entry: offset from app base
	add hl, de				; -> real in-app address
	ld (ix + 0), hl				; patch trampoline operand
	pop hl

	inc hl : inc hl : inc hl		; entry stride 3
	lea ix, ix + 4				; jp stride 4
	dec bc
	jr .patch_loop
.patch_done:
	pop ix

	; Trampolines are live — call into the app to do BSS/.data init and
	; copy our imports table into its reserved fn_imports_table.
	;   void lwip_init_runtime_internal(const void *src, size_t len);
	ld hl, _fn_imports_table_end - _fn_imports_table
	push hl					; arg2: len
	ld hl, _fn_imports_table
	push hl					; arg1: src
	call lwip_init_runtime_internal
	pop hl
	pop hl

	pop ix
	ld a, 1
	ret

.table_fail:
	; TODO: decide failure surface (return status vs abort with message).
	pop ix
	ld a, 0
	ret
