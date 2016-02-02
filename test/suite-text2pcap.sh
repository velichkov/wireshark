#!/bin/bash
#
# Run the text2pcap unit tests
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

# Regex used to prase capinfos output
text2pcap_capinfos_regex="File type:.* - (.*)
File encapsulation:[[:blank:]]+(.*)
Number of packets:[[:blank:]]+(.*)
Data size:[[:blank:]]+([[:digit:]]+) bytes"

# Return information for the given pcap file
# arg1 = file name
#
# Set the following global variables
#   $text2pcap_capinfos_filetype    File type
#   $text2pcap_capinfos_encap       File encapsulation
#   $text2pcap_capinfos_packets     Number of packets
#   $text2pcap_capinfos_datasize    Data size
text2pcap_capinfos() {
	#Initialize return variables
	text2pcap_capinfos_filetype=""
	text2pcap_capinfos_encap=""
	text2pcap_capinfos_packets=""
	text2pcap_capinfos_datasize=""

	output=$($CAPINFOS -tEcdM $1)
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "exit status of capinfos: $RETURNVALUE"
		return 1
	fi

	if [[ "$output" =~ $text2pcap_capinfos_regex ]]
	then
		#Array length ${#BASH_REMATCH[@]}
		text2pcap_capinfos_filetype=${BASH_REMATCH[1]}
		text2pcap_capinfos_encap=${BASH_REMATCH[2]}
		text2pcap_capinfos_packets=${BASH_REMATCH[3]}
		text2pcap_capinfos_datasize=${BASH_REMATCH[4]}
		return 0
	fi

	echo "$output" > testout.txt
	test_step_failed "Cannot parse capinfos ouput"
	return 1
}

# common checking code:
# arg 1 = return value from text2pcap command
# arg 2 = file type string
# arg 3 = file encap
# arg 4 = number of file packets generated
text2pcap_common_check() {
	if [ ! $1 -eq $EXIT_OK ]; then
		echo
		cat ./testout.txt
		test_step_failed "exit status of text2pcap: $1"
		return
	fi

	grep -q "potential packet" testout.txt
	if [ ! $? -eq 0 ]; then
		cat ./testout.txt
		test_step_failed "text2pcap didn't complete"
	fi

	grep -q "Inconsistent offset" testout.txt
	if [ $? -eq 0 ]; then
		cat ./testout.txt
		test_step_failed "text2pcap detected inconsistent offset"
	fi

	text2pcap_capinfos "./testout.pcap"
	if [ ! $? -eq $EXIT_OK ]; then
		test_step_failed "text2pcap_capinfos return error"
		return 1
	fi

	if [ "$2" != "$text2pcap_capinfos_filetype" ]; then
		test_step_failed "text2pcap output file type is not '$2'"
		return 1
	fi

	if [ "$3" != "$text2pcap_capinfos_encap" ]; then
		test_step_failed "text2pcap output encapsulation type is not '$3'"
		return 1
	fi

	if [ "$4" != "$text2pcap_capinfos_packets" ]; then
		test_step_failed "text2pcap did not generate $4 packets"
		return 1
	fi

	if [ "$5" != "$text2pcap_capinfos_datasize" ]; then
		test_step_failed "text2pcap output Data size: is not $5 bytes"
		return 1
	fi
}

# common checking code for legacy PCAP output
# arg1=returnvalue, arg2=encap type, arg3=# of file pkts arg4=data size
text2pcap_common_pcap_check() {
	text2pcap_common_check "$1" 'pcap' "$2" "$3" "$4"
}

# common checking code for PCAPNG output
# arg1=returnvalue, arg2=encap type, arg3=# of file pkts arg4=data size
text2pcap_common_pcapng_check() {
	text2pcap_common_check "$1" 'pcapng' "$2" "$3" "$4"
}

# convert pcap file to text format suitable for text2pcap
text2pcap_generate_input() {
	$TSHARK -o 'gui.column.format:"Time","%t"' -tad -P -x -r $1 > testin.txt
	#$TSHARK -P -tad -u hms -x -r $1 > testin.txt
}

# Perfom the following actions
# - Get information for the input pcap file with capinfos
# - Generate an ASCII hexdump with text2pcap
# - Convert the ASCII hexdump back to pcap using text2pcap
# - Get information for the output pcap file with capinfs
# - Check that file type, encapsulation type, number of packets and data size
#   in the output file are the same as in the input file
#
# arg1=input file name arg2=# of file pkts arg3=data size
text2pcap_basic_test() {
	filename="${CAPTURE_DIR}$1"
	text2pcap_capinfos "$filename"
	if [ ! $? -eq $EXIT_OK ]; then
		test_step_failed "text2pcap_capinfos return error"
		return 1
	fi

	text2pcap_generate_input "$filename"
	#echo $text2pcap_capinfos_filetype
	#echo $text2pcap_capinfos_encap
	#echo $text2pcap_capinfos_packets
	#echo $text2pcap_capinfos_datasize

	#Overwrite number of packets or data size if optional parameters are present
	if [ "x$2" != "x" ]; then
		text2pcap_capinfos_packets=$2
	fi
	if [ "x$3" != "x" ]; then
		text2pcap_capinfos_datasize=$3
	fi

	# link_type values are defined in pcap/bpf.h and wiretap/pcap-common.c
	case "$text2pcap_capinfos_encap" in
		Ethernet)
			link_type="1"
			;;
		Raw\ IP)
			link_type="14"
			;;
		Linux\ cooked-mode\ capture)
			link_type="113"
			;;
		IEEE\ 802.11\ plus\ radiotap\ radio\ header)
			link_type="127"
			;;
		DVB-CI*)
			link_type="235"
			;;
		Per\ packet*)
			printf " Per packet encapsulation is not yet supported"
			test_step_skipped
			return
			;;
		*)
			printf " Unsupported link_type $text2pcap_capinfos_encap"
			test_step_skipped
			return
			;;
	esac
	case "$text2pcap_capinfos_filetype" in
		"pcap"|"pcap (gzip compressed)")
			$TEXT2PCAP -a -d -l $link_type -t "%Y-%m-%d %H:%M:%S."\
				testin.txt testout.pcap >testout.txt 2>&1
			text2pcap_common_pcap_check "$RETURNVALUE"\
				"$text2pcap_capinfos_encap"\
				"$text2pcap_capinfos_packets"\
				"$text2pcap_capinfos_datasize"
			test_step_ok
			;;
		"nanosecond libpcap"|"pcapng"|"pcapng (gzip compressed)")
			$TEXT2PCAP -a -n -d -l $link_type -t "%Y-%m-%d %H:%M:%S."\
				testin.txt testout.pcap >testout.txt 2>&1
			text2pcap_common_pcapng_check "$RETURNVALUE"\
				"$text2pcap_capinfos_encap"\
				"$text2pcap_capinfos_packets"\
				"$text2pcap_capinfos_datasize"
			test_step_ok
			;;
		*)
			printf " Unsupported filetype $text2pcap_capinfos_filetype"
			test_step_skipped
	esac
}

text2pcap_dhcp_pcap_test() {
	text2pcap_basic_test "dhcp.pcap"
}
text2pcap_dhcp_pcapng_test() {
	text2pcap_basic_test "dhcp.pcapng"
}
text2pcap_segmented_fpm_pcap_test() {
	text2pcap_basic_test "segmented_fpm.pcap"
}
text2pcap_c1222_std_example8_pcap_test() {
	text2pcap_basic_test "c1222_std_example8.pcap"
}
text2pcap_dhcp_nanosecond_pcap_test() {
	text2pcap_basic_test "dhcp-nanosecond.pcap"
}
text2pcap_dns_port_pcap_test() {
	text2pcap_basic_test "dns_port.pcap"
}
text2pcap_dvb_ci_UV1_0000_pcap_test() {
	text2pcap_basic_test "dvb-ci_UV1_0000.pcap"
}
text2pcap_empty_pcap_test() {
	text2pcap_basic_test "empty.pcap"
}
text2pcap_ikev1_certs_pcap() {
	text2pcap_basic_test "ikev1-certs.pcap"
}
text2pcap_rsa_p_lt_q_pcap() {
	text2pcap_basic_test "rsa-p-lt-q.pcap"
}
text2pcap_rsasnakeoil2_pcap() {
	text2pcap_basic_test "rsasnakeoil2.pcap"
}
text2pcap_sample_control4_2012_03_24_pcap_test() {
	# tshark currently output decrypted ZigBee packets and
	# as a result the number of packets and data size are different
	text2pcap_basic_test "sample_control4_2012-03-24.pcap" 239 10095
}
text2pcap_snakeoil_dtls_test() {
	text2pcap_basic_test "snakeoil-dtls.pcap"
}
text2pcap_wpa_eap_tls_pcap_gz_test() {
	# tshark reassemble some packets and because of this
	# the number of packets and data size are different
	text2pcap_basic_test "wpa-eap-tls.pcap.gz" 88 38872
}
text2pcap_wpa_induction_pcap_gz_test() {
	text2pcap_basic_test "wpa-Induction.pcap.gz"
}
text2pcap_dhcp_nanosecond_pcapng_test() {
	text2pcap_basic_test "dhcp-nanosecond.pcapng"
}
text2pcap_dhe1_pcapng_gz_test() {
	text2pcap_basic_test "dhe1.pcapng.gz"
}
text2pcap_dmgr_pcapng_test() {
	# linux cooked mode capture
	text2pcap_basic_test "dmgr.pcapng"
}
text2pcap_dns_icmp_pcapng_gz_test() {
	text2pcap_basic_test "dns+icmp.pcapng.gz"
}
text2pcap_packet_h2_14_headers_pcapng_test() {
	text2pcap_basic_test "packet-h2-14_headers.pcapng"
}
text2pcap_sip_pcapng_test() {
	# Raw IP encap
	text2pcap_basic_test "sip.pcapng"
}

text2pcap_step_hash_at_eol() {
	$TEXT2PCAP -n -d -t "%Y-%m-%d %H:%M:%S."\
		"${CAPTURE_DIR}/text2pcap_hash_eol.txt" testout.pcap > testout.txt 2>&1
	RETURNVALUE=$?

	grep -q "Inconsistent offset" testout.txt
	if [ $? -eq 0 ]; then
		cat ./testout.txt
		test_step_failed "text2pcap failed to parse the hash sign at the end of the line"
	fi

	#Check that #TEXT2PCAP is not prased as a comment
	grep -q "Directive \[ test_directive" testout.txt
	if [ $? -ne 0 ]; then
		cat ./testout.txt
		test_step_failed "text2pcap failed to parse #TEXT2PCAP test_directive"
	fi

	text2pcap_common_pcapng_check $RETURNVALUE "Ethernet" 1 96
	test_step_ok
}

#arg1=hex string arg2=data size
text2pcap_ascii_common() {
	echo "$1" | $TEXT2PCAP -a -n -dd - testout.pcap > testout.txt 2>&1
	RETURNVALUE=$?
	text2pcap_common_pcapng_check $RETURNVALUE "Ethernet" "1" $2
	test_step_ok
}
text2pcap_ascii_bug1723() {
	text2pcap_ascii_common \
		"0000  61 62 20 63 64 20 ab cd                           ab cd .." \
		"8"
}
text2pcap_ascii_2bytes_1space() {
	text2pcap_ascii_common \
		"0000  61 62 20 63 64 20                                 ab cd " \
		"6"
}
text2pcap_ascii_2bytes_2spaces() {
	text2pcap_ascii_common \
		"0000  61 62 20 20 63 64 20 20 ab cd                     ab  cd  .." \
		"10"
}
text2pcap_ascii_2bytes_3spaces() {
	text2pcap_ascii_common \
		"0000  61 62 20 20 20 63 64 20 20 20 ab cd               ab   cd   .." \
		"12"
}
text2pcap_ascii_2bytes_4spaces() {
	text2pcap_ascii_common \
		"0000  61 62 20 20 20 20 63 64 20 20 20 20 ab cd         ab    cd    .." \
		"14"
}
text2pcap_ascii_2bytes_1and2_spaces() {
	text2pcap_ascii_common \
		"0000  61 62 20 63 64 20 20 ab cd                        ab cd  .." \
		"9"
}
text2pcap_ascii_leading_space() {
	text2pcap_ascii_common \
		"0000  20 61 62 20 63 64 20 ab cd                         ab cd .." \
		"9"
}
text2pcap_ascii_leading_2spaces() {
	text2pcap_ascii_common \
		"0000  20 20 61 62 20 63 64 20 ab cd                       ab cd .." \
		"10"
}
text2pcap_ascii_leading_2spaces_2spaces() {
	text2pcap_ascii_common \
		"0000  20 20 61 62 20 20 63 64 20 20 ab cd                 ab  cd  .." \
		"12"
}
text2pcap_ascii_leading_3spaces() {
	text2pcap_ascii_common \
		"0000  20 20 20 61 62 20 63 64 20 ab cd                     ab cd .." \
		"11"
}
text2pcap_ascii_leading_3spaces_3spaces() {
	text2pcap_ascii_common \
		"0000  20 20 20 61 62 20 20 20 63 64 20 20 20 ab cd         ab   cd   .." \
		"15"
}
text2pcap_ascii_leading_1space_dots() {
	text2pcap_ascii_common \
		"0000  20 ab cd 20 61 62 20 63 64                         .. ab cd" \
		"9"
}
text2pcap_ascii_leading_1space_dots_inbetween() {
	text2pcap_ascii_common \
		"0000  20 61 62 20 ab cd 20 63 64                         ab .. cd" \
		"9"
}
text2pcap_ascii_tab() {
	text2pcap_ascii_common \
		"0000  32 32 09 35 35                                    22.55" \
		"5"
}
text2pcap_ascii_leading_tab() {
	text2pcap_ascii_common \
		"0000  09 31 32 09 31 32                                 .12.12" \
		"6"
}
text2pcap_ascii_faux_hex() {
	# See comments in http://code.wireshark.org/review/13294
	cat <<-EOF | $TEXT2PCAP -a -n -d - testout.pcap > testout.txt 2>&1
0000  30 31 20 32 33 20 34 35 20 36 37 20 38 39 20 61   01 23 45 67 89 a
0010  62 20 63 64 20 65 66 20 30 31 20 32 33 20 34 35   b cd ef 01 23 45
0020  20 36 37 20 38 39 20 41 42 20 43 44 20 45 46       67 89 AB CD EF
	EOF
	RETURNVALUE=$?
	text2pcap_common_pcapng_check $RETURNVALUE "Ethernet" 1 47
	test_step_ok
}
text2pcap_ascii_notext_1byte() {
	text2pcap_ascii_common "0000 30" "1"
}
text2pcap_ascii_notext_1byte_1space() {
	text2pcap_ascii_common "0000 30 20" "2"
}
text2pcap_ascii_notext_2bytes() {
	text2pcap_ascii_common "0000 30 31" "2"
}
text2pcap_ascii_notext_3rd_byte_match() {
	text2pcap_ascii_common "0000 30 31 01" "2"
}
text2pcap_ascii_notext_3bytes_1space_match() {
	text2pcap_ascii_common "0000 30 31 20 01" "3"
}
text2pcap_ascii_invalid_text() {
	# as the ascii text should be "01 .." and not "ff .."
	text2pcap_ascii_common "0000 30 31 20 01 00        ff .."  "6"
}
text2pcap_ascii_od_txCz() {
	# od -txCz temp.dat
	text2pcap_ascii_common \
		"0000000 20 36 37 20 38 39 20 61 62 20 63 64 20 65 66 20  > 67 89 ab cd ef <" \
		"16"
}

text2pcap_ascii_text_dump() {
	# See https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=1723
	# and comments in http://code.wireshark.org/review/13294
	test_step_add "Bug 1723" text2pcap_ascii_bug1723
	test_step_add "Bug 1723 - 2 bytes separated by 1 space"\
		text2pcap_ascii_2bytes_1space
	test_step_add "Bug 1723 - 2 bytes separated by 2 spaces"\
		text2pcap_ascii_2bytes_2spaces
	test_step_add "Bug 1723 - 2 bytes separated by 3 spaces"\
		text2pcap_ascii_2bytes_3spaces
	test_step_add "Bug 1723 - 2 bytes separated by 4 spaces"\
		text2pcap_ascii_2bytes_4spaces
	test_step_add "Bug 1723 - 2 bytes separated by 1 and 2 spaces"\
		text2pcap_ascii_2bytes_1and2_spaces
	test_step_add "Bug 1723 - leading space"\
		text2pcap_ascii_leading_space
	test_step_add "Bug 1723 - leading 2 spaces"\
		text2pcap_ascii_leading_2spaces
	test_step_add "Bug 1723 - leading 2 spaces separated by 2 spaces"\
		text2pcap_ascii_leading_2spaces_2spaces
	test_step_add "Bug 1723 - leading 3 spaces"\
		text2pcap_ascii_leading_3spaces
	test_step_add "Bug 1723 - leading 3 spaces separated by 3 spaces"\
		text2pcap_ascii_leading_3spaces_3spaces
	test_step_add "Bug 1723 - leading space and dots"\
		text2pcap_ascii_leading_1space_dots
	test_step_add "Bug 1723 - leading space with dots inbeetween"\
		text2pcap_ascii_leading_1space_dots_inbetween
	test_step_add "Bug 1723 - tab"\
		text2pcap_ascii_tab
	test_step_add "Bug 1723 - leading tab"\
		text2pcap_ascii_leading_tab
	test_step_add "faux-hex sequences (http://code.wireshark.org/review/13294)"\
		text2pcap_ascii_faux_hex
	test_step_add "No ASCII text - 1 byte"\
		text2pcap_ascii_notext_1byte
	test_step_add "No ASCII text - 1 byte and 1 space"\
		text2pcap_ascii_notext_1byte_1space
	test_step_add "No ASCII text - 2 bytes and no space"\
		text2pcap_ascii_notext_2bytes
	test_step_add "No ASCII text - 3rd byte match the first two"\
		text2pcap_ascii_notext_3rd_byte_match
	test_step_add "No ASCII text - 3 bytes and space, 4th match the first two"\
		text2pcap_ascii_notext_3bytes_1space_match
	test_step_add "invalid bytes in ASCII text"\
		text2pcap_ascii_invalid_text
	test_step_add "invalid bytes (od -txCz output)"\
		text2pcap_ascii_od_txCz
}


text2pcap_cleanup_step() {
	rm -f ./testin.txt
	rm -f ./testout.txt
	rm -f ./capinfo_testout.txt
	rm -f ./testout.pcap
}

text2pcap_suite() {
	test_step_set_pre text2pcap_cleanup_step
	test_step_set_post text2pcap_cleanup_step
	test_step_add "testing with empty.pcap" text2pcap_empty_pcap_test
	test_step_add "testing with dhcp.pcap" text2pcap_dhcp_pcap_test
	test_step_add "testing with dhcp.pcapng" text2pcap_dhcp_pcapng_test
	test_step_add "testing with dhcp-nanosecond.pcap" text2pcap_dhcp_nanosecond_pcap_test
	test_step_add "testing with dhcp-nanosecond.pcapng" text2pcap_dhcp_nanosecond_pcapng_test
	test_step_add "testing with segmented_fpm.pcap" text2pcap_segmented_fpm_pcap_test
	test_step_add "testing with c1222_std_example8.pcap" text2pcap_c1222_std_example8_pcap_test
	test_step_add "testing with dns_port.pcap" text2pcap_dns_port_pcap_test
	test_step_add "testing with dvb-ci_UV1_0000.pcap" text2pcap_dvb_ci_UV1_0000_pcap_test
	test_step_add "testing with ikev1-certs.pcap" text2pcap_ikev1_certs_pcap
	test_step_add "testing with rsa-p-lt-q.pcap" text2pcap_rsa_p_lt_q_pcap
	test_step_add "testing with rsasnakeoil2.pcap" text2pcap_rsasnakeoil2_pcap
	test_step_add "testing with sample_control4_2012-03-24.pcap" text2pcap_sample_control4_2012_03_24_pcap_test
	test_step_add "testing with snakeoil-dtls.pcap" text2pcap_snakeoil_dtls_test
	test_step_add "testing with wpa-eap-tls.pcap.gz" text2pcap_wpa_eap_tls_pcap_gz_test
	test_step_add "testing with wpa-Induction.pcap.gz" text2pcap_wpa_induction_pcap_gz_test
	test_step_add "testing with dhe1.pcapng.gz" text2pcap_dhe1_pcapng_gz_test
	test_step_add "testing with dmgr.pcapng" text2pcap_dmgr_pcapng_test
	test_step_add "testing with dns+icmp.pcapng.gz" text2pcap_dns_icmp_pcapng_gz_test
	test_step_add "testing with packet-h2-14_headers.pcapng" text2pcap_packet_h2_14_headers_pcapng_test
	test_step_add "testing with sip.pcapng" text2pcap_sip_pcapng_test
	test_step_add "hash sign at the end of the line" text2pcap_step_hash_at_eol
	test_suite_add "ASCII text dump identification (-a option)" text2pcap_ascii_text_dump
}

#
# Editor modelines  -  https://www.wireshark.org/tools/modelines.html
#
# Local variables:
# sh-basic-offset: 8
# tab-width: 8
# indent-tabs-mode: t
# End:
#
# vi: set shiftwidth=8 tabstop=8 noexpandtab:
# :indentSize=8:tabSize=8:noTabs=false:
#
