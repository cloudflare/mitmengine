#!/bin/bash
scriptdir=`dirname "$0"`
. "$scriptdir/gen_common.sh"

print_header

pcaps=`find testdata/browsers -type f -name "handshake.pcap"`
for pcapfile in $pcaps; do

	clear_record # clear bash variables

	info=$pcapfile
	info=${info%/*} # strip off '/handshake.pcap'
	info=${info##*/} # strip any other directory names
	IFS=- read device os os_vers br br_vers <<< $info
	plat=$os

	# handle some parsing exceptions
	if [ "$br" = "ipad" ]; then
		device="Tablet"
		os="iOS"
		plat="iPad"
		br="Safari"
	fi
	if [ "$br" = "iphone" ]; then
		device="Phone"
		os="iOS"
		plat="iPhone"
		br="Safari"
	fi
	# use os version for browser version if not known
	if [ "$br_vers" = "unk" ]; then
		br_vers=$os_vers
	fi

	ok=true
	# generate record fields
	gen_record

	if [ "$ok" = false ]; then
		continue
	fi

	print_record
done
