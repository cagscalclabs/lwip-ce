#!/bin/bash

# Explicitly include headers
declare -a include_headers=(
    "drivers/usb_ethernet.h"
    "drivers/mem.h"
    "include/lwip/etharp.h"
    "include/lwip/ethip6.h"
    "include/lwip/igmp.h"
    "include/lwip/snmp.h"
    "include/lwip/stats.h"
    "include/lwip/ip4.h"
    "include/lwip/ip4_addr.h"
    "include/lwip/ip4_frag.h"
    "include/lwip/ip6.h"
    "include/lwip/ip6_addr.h"
    "include/lwip/ip6_frag.h"
    "include/lwip/ip6_zone.h"
    "include/lwip/ip.h"
    "include/lwip/ip_addr.h"
    "include/lwip/autoip.h"
    "include/lwip/pbuf.h"
    "include/lwip/mem.h"
    "include/lwip/memp.h"
    "include/lwip/init.h"
    "include/lwip/netif.h"
    "include/lwip/dhcp.h"
    "include/lwip/dns.h"
    "include/lwip/nd6.h"
    "include/lwip/raw.h"
    "include/lwip/tcp.h"
    "include/lwip/altcp.h"
    "include/lwip/altcp_tcp.h"
    "include/lwip/tcpbase.h"
    "include/lwip/udp.h"
    "tls/includes/random.h"
    "tls/includes/hash.h"
    "tls/includes/rsa.h"
    "tls/includes/bytes.h"
    "tls/includes/passwords.h"
    "tls/includes/aes.h"
    "tls/includes/hmac.h"
    "tls/includes/keyobject.h"
    "tls/includes/hkdf.h"
    "tls/includes/handshake.h"
    "tls/includes/asn1.h"
    "tls/includes/base64.h"
    "tls/includes/tls.h"
    "tls/includes/truststore.h"
)

# Remove any prototypes disabled by macros to avoid errors
declare -a excluded_functions=(
    "etharp_add_static_entry"
    "etharp_remove_static_entry"
    "mib2_add_arp_entry"
    "mib2_add_ip4"
    "mib2_add_route_ip4"
    "mib2_netif_added"
    "mib2_netif_removed"
    "mib2_remove_arp_entry"
    "mib2_remove_ip4"
    "mib2_remove_route_ip4"
    "mib2_udp_bind"
    "mib2_udp_unbind"
    "ip4_debug_print"
    "ip4_output_hinted"
    "ip4_route_src"
    "ip6_debug_print"
    "ip6_output_hinted"
    "pbuf_fill_chksum"
    "pbuf_split_64k"
    "memp_malloc_fn"
    "netif_get_loopif"
    "dhcp_set_ntp_servers"
    "dns_local_addhost"
    "dns_local_iterate"
    "dns_local_lookup"
    "dns_local_removehost"
    "TCP_PCB_COMMON"
    "lwip_tcp_event"
    "tcp_ext_arg_alloc_id"
    "tcp_ext_arg_get"
    "tcp_ext_arg_set"
    "tcp_ext_arg_set_callbacks"
    "altcp_keepalive_disable"
    "altcp_keepalive_enable"
    "udp_debug_print"
    "udp_send_chksum"
    "udp_sendto_chksum"
    "udp_sendto_if_chksum"
    "udp_sendto_if_src_chksum"
    "ip_reass_init"     # for whatever reason this prototype doesn't have a C func
)

# output_functable keeps a running list of functions we have already put into the table
# the order of functions of the functable order cannot change for forward compatibility.
output_functable=src/functable.dat
temp_functable=$(mktemp)
temp_kept=$(mktemp)
temp_seen=$(mktemp)
# functable_c is the C code used to reserve the functiontable in the application
output_c=src/functable.asm
output_lib=libload/lwip.lib
output_stub=libload/lwip.asm

lib_name=${LWIP_LIB_NAME:-LWIP}
lib_version=${LWIP_LIB_VERSION:-0}
app_name=${LWIP_APP_NAME:-lwIP}
app_name_padded=$(printf '%-8s' "$app_name")
toolchain_include=${TOOLCHAIN_INCLUDE:-/Users/acagliano/Repositories/calc/toolchain/src/include}


[[ ! -f $output_functable ]] && touch $output_functable

# Function to process files
process_file() {
    local file="src/$1"     # access needs relative to this dir
    echo "Processing file: $file"
    /usr/local/bin/ctags -f- --kinds-C=p $file | awk '{ print $1; }' | while read -r line; do
        skip=0
        if ! grep -Fxq "$line" "$temp_functable"; then
            for exclude in "${excluded_functions[@]}"; do
                if [[ "$exclude" == $line ]]; then
                    echo "found $line in excluded_headers, skipping"
                    skip=1
                    break
                fi
            done
            if [ $skip -eq 0 ]; then
                echo "appending function: $line"
                echo "$line" >> "$temp_functable"
            fi
        fi
    done
}


# Logic
for file in "${include_headers[@]}"; do
    process_file "$file"
done

if [[ -f "$output_functable" ]]; then
    while read -r line; do
        if grep -Fxq "$line" "$temp_functable"; then
            echo "$line" >> "$temp_kept"
            echo "$line" >> "$temp_seen"
        fi
    done < "$output_functable"
fi

while read -r line; do
    if ! grep -Fxq "$line" "$temp_seen"; then
        echo "$line" >> "$temp_kept"
    fi
done < "$temp_functable"

mv "$temp_kept" "$output_functable"
rm -f "$temp_functable" "$temp_seen"

rm $output_c
echo "section .rodata" >> $output_c
echo "public _app_library_table" >> $output_c
echo "extern app" >> $output_c
echo "" >> $output_c
echo "_app_library_table:" >> $output_c
while read line; do
    echo "    dl _$line - app" >> $output_c
done < $output_functable
echo "" >> $output_c
echo "" >> $output_c
while read line; do
    echo "extern _$line" >> $output_c
done < $output_functable

rm -f "$output_lib"
echo -e "\tlibrary\t${lib_name}, ${lib_version}\n" >> "$output_lib"
while read -r line; do
    echo -e "\texport\t$line" >> "$output_lib"
done < "$output_functable"

func_count=$(wc -l < "$output_functable" | tr -d ' ')

rm -f "$output_stub"
cat <<EOF >> "$output_stub"
; Auto-generated library stub for lwIP LibLoad integration.
; Adjust the include path for library.inc as needed.
include '${toolchain_include}/library.inc'

library ${lib_name}, ${lib_version}

export lwip_app_init
EOF

while read -r line; do
    echo "export $line" >> "$output_stub"
done < "$output_functable"

cat <<EOF >> "$output_stub"

APP_HEADER_LIBTABLE_OFFSET := 33
LWIP_FUNC_COUNT := $func_count

lwip_app_init:
	ld	hl,app_name
	ld	(hl),ti.AppVarObj
	call	ti.Mov9ToOP1
	call	ti.ChkFindSym
	jr	c,.not_found
	call	ti.ChkInRam
	ex	de,hl
	jr	z,.in_ram
	ld	de,9
	add	hl,de
	ld	e,(hl)
	add	hl,de
	inc	hl
.in_ram:
	call	ti.LoadDEInd_s
	push	de
	pop	ix			; ix = app base

	push	ix
	pop	hl
	ld	de,APP_HEADER_LIBTABLE_OFFSET
	add	hl,de
	ld	de,(hl)			; de = table offset from app base
	push	ix
	pop	hl
	add	hl,de
	push	hl
	pop	iy			; iy = app function table

	ld	hl,lwip_stub_table
	ld	bc,LWIP_FUNC_COUNT
.loop:
	ld	de,(iy)
	push	hl
	push	ix
	pop	hl
	add	hl,de			; hl = app_base + func offset
	pop	de			; de = stub entry
	ex	de,hl			; hl = stub entry, de = target addr
	inc	hl
	ld	(hl),de
	inc	hl
	inc	hl
	inc	hl
	lea	iy,iy+3
	ex	de,hl
	dec	bc
	ld	a,b
	or	a,c
	jr	nz,.loop
	xor	a,a
	ret
.not_found:
	ld	a,1
	ret

app_name:
	db	0,"${app_name_padded}"

lwip_stub_table:
EOF

while read -r line; do
    cat <<EOF >> "$output_stub"
$line:
	jp	0
EOF
done < "$output_functable"
