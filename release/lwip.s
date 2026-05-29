; ===============================================================
; File:        lwip.s
; Author:      Anthony Cagliano
; Generated:   2026-05-29 (by `make dylib`)
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
	dl usb_Cleanup

	export lwip_start
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
	export eth_set_rx_throttle
	export eth_set_rx_drain_interval_ms
	export eth_get_interfaces
	export eth_usb_event_callback
	export tls_x25519_publickey
	export tls_x25519_secret

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
;   2. Locate the consumer app's export table and verify its magic.
;   3. TODO: Call memory initialization for bss and data of lwIP.
;   4. TODO: Anything else required before lwIP-internal code can run.
;
; eZ80 calling convention (cedev), after __frameset0 :
;   (ix + 0)  saved old IX
;   (ix + 3)  return address
;   (ix + 6)  arg1: malloc ptr
;   (ix + 9)  arg2: free ptr
;   (ix + 12) arg3: realloc ptr
;
; Build-emitted symbol (written into release/lwip.s by the map-scrape
; step; see the build sequence):
;   __lwip_fn_table_off  : d24 offset of _fn_exports_table from the app
;                          image base (== link-time addr, LOAD_ADDR = 0).
;

; lwIP is a flash APPLICATION, so it is located via the flash-app
; routines (FindApp / FindAppStart), not the VAT appvar lookup
; (ChkFindSym) that crt0's libload path uses for the LWIP lib appvar.
	.equ ti.FindApp, 0x0210FC
	.equ ti.FindAppStart, 0x021100
	.equ ti.Mov9ToOP1, 0x020320
	.equ ti.OP1, 0xD005F8

	extern __lwip_fn_table_off
	export lwip_init_runtime_opaque

; Consumer app name in Mov9ToOP1 form: a type byte followed by a 9-byte
; name field (NUL-padded). Mov9ToOP1 copies the 9 name bytes from
; __lwip_app_name into OP1+1; the type byte at __lwip_app_name - 1 lands
; in OP1+0. For a flash app the OS uses the AppObj type 0x24.
__lwip_app_name_type:
	db 0x24				; OS_TYPE app (flash application)
__lwip_app_name:
	db "lwIP", 0, 0, 0, 0, 0		; 9 bytes total

; 6-byte table magic, ascending memory order: 'L','W','I','P','T','B'.
; Must match the db sequence emitted at _fn_exports_table by functable.py.

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

	; Set OP1 = type byte + 9-byte name via Mov9ToOP1, then the type byte.
	ld hl, __lwip_app_name
	call ti.FindAppStart
	jr c, .L.table_fail

	; hl = app start address (assumed == __app_base).
	ld de, (__lwip_fn_table_off)
	add hl, de			; HL -> _fn_exports_table (pending ABI confirm)

	; Verify the 6 magic bytes: 'L','W','I','P','T','B'.
	ld a, (hl)
	cp a, 'L'
	jr nz, .L.table_fail
	inc hl
	ld a, (hl)
	cp a, 'W'
	jr nz, .L.table_fail
	inc hl
	ld a, (hl)
	cp a, 'I'
	jr nz, .L.table_fail
	inc hl
	ld a, (hl)
	cp a, 'P'
	jr nz, .L.table_fail
	inc hl
	ld a, (hl)
	cp a, 'T'
	jr nz, .L.table_fail
	inc hl
	ld a, (hl)
	cp a, 'B'
	jr nz, .L.table_fail
	inc hl

	; Magic OK — table located and build-matched.
	push hl
		ld hl, (hl)
		push hl
		pop bc		; size to bc
	pop hl			; get proc location back
	inc hl 			; hl now at start of function table
	ld de, <ptr_to_libload_lookup_table>



	pop ix
	ret

.L.table_fail:
	; Mismatched/stale app paired with this lib, or app not installed.
	; TODO(toolchain): decide the failure surface — return an error code to
	; the caller (changes the init ABI to return a status), or abort like
	; crt0's .L.notfound (ClrScrn/PutS/GetKey). Skeleton just returns for now.
	pop ix
	ret
