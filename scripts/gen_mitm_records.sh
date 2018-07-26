#!/bin/bash
scriptdir=`dirname "$0"`
. "$scriptdir/gen_common.sh"


print_header

pcaps=`find testdata/antivirus-run2 -type f -name "handshake.pcap"`
for pcapfile in $pcaps; do
	clear_record
	info=$pcapfile
	info=${info%/*} # strip off '/handshake.pcap'
	info=${info##*/} # strip any other directory names

	# filenames should conform to this format
	regex='^([^-]+)-([^-]+)-(.+)-([^-]+)-([^-]+)$'
	if [[ $info =~ $regex ]]; then
		os=${BASH_REMATCH[1]}
		os_vers=${BASH_REMATCH[2]}
		mitm_name=${BASH_REMATCH[3]}
		br=${BASH_REMATCH[4]}
		br_vers=${BASH_REMATCH[5]}
	else
		continue
	fi
	device="Computer"
	plat="$os"

	# handle some exceptions
	if [ "$br" = "android" ]; then
		plat="Linux"
		os="Android"
	fi
	if [ "$mitm_name" = "none" ]; then
		mitm_name=""
	else
		mitm_type="Antivirus"
	fi
	
	ok=true
	# generate record fields
	gen_record

	if [ "$ok" = false ]; then
		continue
	fi

	print_record
done

extra_records=$(cat << END
# add some additional records based on injected http headers
# Sources:
#  - https://jhalderm.com/pub/papers/interception-ndss17.pdf
#  - https://github.com/zakird/tlsfingerprints/blob/master/processing/browsers/browser.py#L131
:*:*:*:*:*barracuda:*|Barracuda|Proxy|
:*:*:*:*:*cuda_cliip:*|Barracuda|Proxy|
:*:*:*:*:*gdata-version:*|GData|Antivirus|F
:*:*:*:*:*gdataver:*|GData|Antivirus|F
:*:*:*:*:*pxyro-connection:*|Citrix|Proxy|
:*:*:*:*:*squixa-proxy:*|Squixa||
:*:*:*:*:*x-akamai-config-log-detail:*|Akamai|Proxy|
:*:*:*:*:*x-akamai-edgescape:*|Akamai|Proxy|
:*:*:*:*:*x-akamai-origin-hop:*|Akamai|Proxy|
:*:*:*:*:*x-akamai-prefetched-object:*|Akamai|Proxy|
:*:*:*:*:*x-barracuda-wf-agent:*|Barracuda|Proxy|
:*:*:*:*:*x-barracuda-wf-app:*|Barracuda|Proxy|
:*:*:*:*:*x-barracuda-wf-device:*|Barracuda|Proxy|
:*:*:*:*:*x-barracuda-wf-deviceid:*|Barracuda|Proxy|
:*:*:*:*:*x-barracuda-wf-domain-dns:*|Barracuda|Proxy|
:*:*:*:*:*x-barracuda-wf-domain:*|Barracuda|Proxy|
:*:*:*:*:*x-barracuda-wf-machine:*|Barracuda|Proxy|
:*:*:*:*:*x-barracuda-wf-os:*|Barracuda|Proxy|
:*:*:*:*:*x-barracuda-wf-user:*|Barracuda|Proxy|
:*:*:*:*:*x-bluecoat-user:*|BlueCoat|Proxy|
:*:*:*:*:*x-bluecoat-via:*|BlueCoat|Proxy|
:*:*:*:*:*x-citrix-am-credentialtypes:*|Citrix|Proxy|
:*:*:*:*:*x-citrix-am-labeltypes:*|Citrix|Proxy|
:*:*:*:*:*x-citrix-gateway:*|Citrix|Proxy|
:*:*:*:*:*x-citrix-via-vip:*|Citrix|Proxy|
:*:*:*:*:*x-citrix-via:*|Citrix|Proxy|
:*:*:*:*:*x-cybersitter-content-flag:*|Cybersitter|Proxy|
:*:*:*:*:*x-cybersitter-csvt-token:*|Cybersitter|Proxy|
:*:*:*:*:*x-cybersitter-oemid:*|Cybersitter|Proxy|
:*:*:*:*:*x-drweb-keynumber:*|DrWeb|Proxy|
:*:*:*:*:*x-drweb-matchate:*|DrWeb|Proxy|
:*:*:*:*:*x-drweb-syshash:*|DrWeb|Proxy|
:*:*:*:*:*x-eset-spread-control:*|ESET|Proxy|
:*:*:*:*:*x-eset-updateid:*|ESET|Proxy|
:*:*:*:*:*x-fcckv2:*|Fortinet|Antivirus|
:*:*:*:*:*x-gdata-device:*|GData|Antivirus|F
:*:*:*:*:*x-netnanny-ignore:*|NetNanny|Parental|
:*:*:*:*:*x-nod32-mode:*|ESET|Proxy|
:*:*:*:*:*x-sophos-filter:*|Sophos|Antivirus|
:*:*:*:*:*x-sophos-meta:*|Sophos|Antivirus|
:*:*:*:*:*x-sophos-wsa-clientip:*|Sophos|Antivirus|
:*:*:*:*:*x-websensehost:*|Forcepoint/WebSense||
:*:*:*:*:*x-websenseproxychannel:*|Forcepoint/WebSense||
:*:*:*:*:*x-websenseproxysslconnection:*|Forcepoint/WebSense||
:*:*:*:*:*x_bluecoat_user:*|BlueCoat|Proxy|
:*:*:*:*:*x_bluecoat_via:*|BlueCoat|Proxy|
:*:*:*:*:*xroxy-connection:*|Kerio-Winroute-Firewall||
:*:*:*:*:*z-forwarded-for:*|Zscaler||
:*:*:25,24,23:*:*client-ip,x-forwarded-for:*|Forcepoint/WebSense|Proxy|
# add signatures based on quirks that none of the supported browsers should ever have
:*:*:*:*:*:*badhost|||
:*:*:*:*:*:*badcase|||
:*:*:*:*:*:*badpath|||
:*:*:*:*:*:*badspace|||
:*:*:*:*:*:*badreferer|||
:*:*:*:*:*:*badxff|||
:*:*:*:*:*:*badhdr|||
END
)

while read -r line; do
	if [ "${line:0:1}" = '#' ]; then
		echo ${line}
		continue
	fi
	clear_record
	IFS='|' read req_part mitm_name mitm_type mitm_grade <<< $line
	ua_part="0::0:0::0:"
	gen_mitm_part
	print_record
done <<< "${extra_records}"

