; ===============================================================
; File:        lwip.s
; Author:      Anthony Cagliano
; Generated:   2026-05-26 (by `make dylib`)
;
; LIBLOAD custom dispatcher for loading lwIP from an app.
;
; Changes to this file will not persist across rebuild.
;   - To edit the runtime patcher, modify tools/lwip_init_runtime.s.
;   - To edit the export/import table, modify tools/functable.py.
; ===============================================================

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

	export lwip_start
	export lwip_poll_network_events
	export lwip_conn_create
	export lwip_conn_destroy
	export lwip_conn_connect
	export lwip_conn_write
	export lwip_conn_recved
	export lwip_conn_shutdown
	export lwip_conn_close
	export lwip_conn_set_arg
	export lwip_conn_set_connected
	export lwip_conn_set_recv
	export lwip_conn_set_sent
	export lwip_conn_set_err
	export lwip_conn_set_poll
	export lwip_conn_set_closed
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
	export altcp_dbg_get_tcp_state
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
	export eth_set_rx_throttle
	export eth_set_rx_drain_interval_ms
	export eth_get_interfaces
	export eth_usb_event_callback

; Dummy bodies for every exported symbol. The labels exist solely
; so the library macro can emit each export's slot; libload patches
; the real addresses in when an app dispatches through this stub.
lwip_start:
lwip_poll_network_events:
lwip_conn_create:
lwip_conn_destroy:
lwip_conn_connect:
lwip_conn_write:
lwip_conn_recved:
lwip_conn_shutdown:
lwip_conn_close:
lwip_conn_set_arg:
lwip_conn_set_connected:
lwip_conn_set_recv:
lwip_conn_set_sent:
lwip_conn_set_err:
lwip_conn_set_poll:
lwip_conn_set_closed:
tls_aes_init:
tls_aes_ccm_init:
tls_aes_ccm_encrypt:
tls_aes_ccm_decrypt:
tls_aes_update_aad:
tls_aes_encrypt:
tls_aes_update_ciphertext:
tls_aes_digest:
tls_aes_decrypt:
tls_aes_verify:
tls_asn1_cursor_init:
tls_asn1_next:
tls_asn1_child_cursor:
tls_asn1_tag_number:
tls_asn1_tag_class:
tls_asn1_tag_constructed:
tls_base64_encode:
tls_base64_decode:
tls_bytes_compare:
tls_secure_memzero:
tls_sha256_init:
tls_sha256_update:
tls_sha256_digest:
tls_hash_context_init:
tls_hash_update:
tls_hash_digest:
tls_mgf1:
tls_hkdf_extract:
tls_hkdf_expand:
tls_hkdf_expand_label:
tls_derive_secret:
tls_hmac_context_init:
tls_hmac_update:
tls_hmac_digest:
tls_keyobject_import_private:
tls_keyobject_import_public:
tls_keyobject_import_certificate:
tls_x509_has_required_ca_constraints:
tls_keyobject_destroy:
tls_pbkdf2:
tls_pkcs8_strerror:
tls_pkcs8_import:
tls_pkcs8_import_private:
tls_pkcs8_import_public:
tls_pkcs8_object_import_private:
tls_pkcs8_object_import_public:
tls_pkcs8_object_destroy:
tls_random_init_entropy:
tls_random:
tls_random_bytes:
tls_rng_healthcheck:
tls_request_random_bytes:
tls_rng_is_busy:
tls_rsa_encode_oaep:
tls_rsa_decode_oaep:
tls_rsa_encrypt:
tls_rsa_decrypt_signature:
tls_rsa_pss_verify:
tls_truststore_init:
tls_truststore_lookup:
tls_x509_has_valid_constraints:
tls_x509_parse_certificate:
tls_x509_import_and_parse_certificate:
tls_x509_import_certificate:
tls_x509_object_destroy:
acd_add:
acd_remove:
acd_start:
acd_stop:
acd_arp_reply:
acd_network_changed_link_down:
acd_netif_ip_addr_changed:
altcp_new:
altcp_new_ip6:
altcp_new_ip_type:
altcp_arg:
altcp_accept:
altcp_recv:
altcp_sent:
altcp_poll:
altcp_err:
altcp_recved:
altcp_bind:
altcp_connect:
altcp_listen_with_backlog_and_err:
altcp_abort:
altcp_close:
altcp_shutdown:
altcp_write:
altcp_output:
altcp_mss:
altcp_sndbuf:
altcp_sndqueuelen:
altcp_nagle_disable:
altcp_nagle_enable:
altcp_nagle_disabled:
altcp_setprio:
altcp_get_tcp_addrinfo:
altcp_get_ip:
altcp_get_port:
altcp_dbg_get_tcp_state:
altcp_tls_create_config_server:
altcp_tls_config_server_add_privkey_cert:
altcp_tls_create_config_server_privkey_cert:
altcp_tls_create_config_client:
altcp_tls_create_config_client_2wayauth:
altcp_tls_configure_alpn_protocols:
altcp_tls_free_config:
altcp_tls_wrap:
altcp_tls_new:
altcp_tls_alloc:
autoip_set_struct:
autoip_remove_struct:
autoip_start:
autoip_stop:
autoip_network_changed_link_up:
autoip_network_changed_link_down:
autoip_supplied_address:
autoip_accept_packet:
lwip_htons:
lwip_htonl:
lwip_itoa:
lwip_strnicmp:
lwip_stricmp:
lwip_strnstr:
lwip_strnistr:
lwip_memcmp_consttime:
dhcp_set_struct:
dhcp_cleanup:
dhcp_start:
dhcp_renew:
dhcp_release:
dhcp_stop:
dhcp_release_and_stop:
dhcp_inform:
dhcp_network_changed_link_up:
dhcp_supplied_address:
dns_setserver:
dns_getserver:
dns_gethostbyname:
dns_gethostbyname_addrtype:
etharp_find_addr:
etharp_get_entry:
etharp_output:
etharp_query:
etharp_request:
etharp_cleanup_netif:
etharp_acd_probe:
etharp_acd_announce:
etharp_input:
icmp_input:
icmp_dest_unreach:
icmp_time_exceeded:
icmp6_input:
icmp6_dest_unreach:
icmp6_packet_too_big:
icmp6_time_exceeded:
icmp6_time_exceeded_with_addrs:
icmp6_param_problem:
igmp_start:
igmp_stop:
igmp_report_groups:
igmp_lookfor_group:
igmp_input:
igmp_joingroup:
igmp_joingroup_netif:
igmp_leavegroup:
igmp_leavegroup_netif:
inet_chksum:
inet_chksum_pbuf:
inet_chksum_pseudo:
inet_chksum_pseudo_partial:
ip6_chksum_pseudo:
ip6_chksum_pseudo_partial:
ip_chksum_pseudo:
ip_chksum_pseudo_partial:
lwip_init:
ip_input:
ip4_route:
ip4_input:
ip4_output:
ip4_output_if:
ip4_output_if_src:
ip4_output_if_opt:
ip4_output_if_opt_src:
ip4_set_default_multicast_netif:
ip4_addr_isbroadcast_u32:
ip4_addr_netmask_valid:
ipaddr_addr:
ip4addr_aton:
ip4addr_ntoa:
ip4addr_ntoa_r:
ip4_reass:
ip4_frag:
ip6_route:
ip6_select_source_address:
ip6_input:
ip6_output:
ip6_output_if:
ip6_output_if_src:
ip6_options_add_hbh_ra:
ip6addr_aton:
ip6addr_ntoa:
ip6addr_ntoa_r:
ip6_reass:
ip6_frag:
ipaddr_ntoa:
ipaddr_ntoa_r:
ipaddr_aton:
mem_trim:
mem_malloc:
mem_calloc:
mem_free:
memp_malloc:
memp_free:
mld6_stop:
mld6_report_groups:
mld6_lookfor_group:
mld6_input:
mld6_joingroup:
mld6_joingroup_netif:
mld6_leavegroup:
mld6_leavegroup_netif:
nd6_input:
nd6_clear_destination_cache:
nd6_find_route:
nd6_get_next_hop_addr_or_queue:
nd6_get_destination_mtu:
nd6_reachability_hint:
nd6_cleanup_netif:
nd6_adjust_mld_membership:
nd6_restart_netif:
netif_alloc_client_data_id:
netif_add_noaddr:
netif_add:
netif_set_addr:
netif_remove:
netif_find:
netif_set_default:
netif_set_ipaddr:
netif_set_netmask:
netif_set_gw:
netif_set_up:
netif_set_down:
netif_set_status_callback:
netif_set_remove_callback:
netif_set_link_up:
netif_set_link_down:
netif_set_link_callback:
netif_loop_output:
netif_poll:
netif_poll_all:
netif_input:
netif_ip6_addr_set:
netif_ip6_addr_set_parts:
netif_ip6_addr_set_state:
netif_get_ip6_addr_match:
netif_create_ip6_linklocal_address:
netif_add_ip6_address:
netif_name_to_index:
netif_index_to_name:
netif_get_by_index:
netif_add_ext_callback:
netif_remove_ext_callback:
pbuf_free_ooseq:
pbuf_alloc:
pbuf_alloc_reference:
pbuf_alloced_custom:
pbuf_realloc:
pbuf_header:
pbuf_header_force:
pbuf_add_header:
pbuf_add_header_force:
pbuf_remove_header:
pbuf_free_header:
pbuf_ref:
pbuf_free:
pbuf_clen:
pbuf_cat:
pbuf_chain:
pbuf_dechain:
pbuf_copy:
pbuf_copy_partial_pbuf:
pbuf_copy_partial:
pbuf_get_contiguous:
pbuf_take:
pbuf_take_at:
pbuf_skip:
pbuf_coalesce:
pbuf_clone:
pbuf_get_at:
pbuf_try_get_at:
pbuf_put_at:
pbuf_memcmp:
pbuf_memfind:
pbuf_strstr:
raw_new:
raw_new_ip_type:
raw_remove:
raw_bind:
raw_bind_netif:
raw_connect:
raw_disconnect:
raw_sendto:
raw_sendto_if_src:
raw_send:
raw_recv:
lwip_sntp_set_timezone_offset:
lwip_sntp_set_dst_enabled:
lwip_sntp_set_time:
lwip_sntp_reset_flag:
lwip_sntp_time_was_set:
lwip_sntp_get_unix_time:
sys_timeout:
sys_untimeout:
tcp_new:
tcp_new_ip_type:
tcp_arg:
tcp_recv:
tcp_sent:
tcp_err:
tcp_accept:
tcp_poll:
tcp_backlog_delayed:
tcp_backlog_accepted:
tcp_recved:
tcp_bind:
tcp_bind_netif:
tcp_connect:
tcp_listen_with_backlog_and_err:
tcp_listen_with_backlog:
tcp_abort:
tcp_close:
tcp_shutdown:
tcp_write:
tcp_setprio:
tcp_output:
tcp_tcp_get_tcp_addrinfo:
udp_new:
udp_new_ip_type:
udp_remove:
udp_bind:
udp_bind_netif:
udp_connect:
udp_disconnect:
udp_recv:
udp_sendto_if:
udp_sendto_if_src:
udp_sendto:
udp_send:
udp_input:
udp_netif_ip_addr_changed:
ethernet_input:
ethernet_output:
eth_set_rx_throttle:
eth_set_rx_drain_interval_ms:
eth_get_interfaces:
eth_usb_event_callback:
	ret

; ----------------------------------------------
; lwIP LIBLOAD runtime patch
;
; Called once by the consumer app via:
;   lwip_init_runtime_opaque(malloc, free, realloc)
; exposed via macro to user:
;	#define lwip_init_runtime() \
;		lwip_init_runtime_opaque((malloc), (free), (realloc))
;
; This function should:
;   1. Store the three CRT pointers into the first three slots
;      of fn_imports_table (at _fn_imports_table + 0, +3, +6).
;      The remaining 22 slots (USB vtable) are already populated
;      at link time by the generated `dl usb_Foo` block above —
;      libload patches the jp stubs at load time, so reading
;      fn_imports_table.usb.foo already dispatches correctly.
;   2. TODO: Call memory initialization for bss and data of lwIP.
;   3. TODO: Anything else required before lwIP-internal code can run.
;
; eZ80 calling convention (cedev), after __frameset0 :
;   (ix + 0)  saved old IX
;   (ix + 3)  return address
;   (ix + 6)  arg1: malloc ptr
;   (ix + 9)  arg2: free ptr
;   (ix + 12) arg3: realloc ptr

	extern __frameset0
	export lwip_init_runtime_opaque

lwip_init_runtime_opaque:
	call ti._frameset0

	; slot 0: malloc
	ld hl, (ix + 6)
	ld (_fn_imports_table + 0), hl

	; slot 1: free
	ld hl, (ix + 9)
	ld (_fn_imports_table + 3), hl

	; slot 2: realloc
	ld hl, (ix + 12)
	ld (_fn_imports_table + 6), hl

	pop ix
	ret
