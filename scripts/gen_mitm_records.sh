#!/bin/bash

echo "# generated by $0"
ua_header="<browser_name>:<browser_version>:<os_platform>:<os_name>:<os_version>:<device_type>:<quirks>"
req_header="<tls_version>:<cipher_suites>:<extension_names>:<curves>:<ec_point_fmts>:<http_headers>:<quirks>"
mitm_header="<mitm_name>:<mitm_type>:<mitm_grade>"
echo "# ${ua_header}|${req_header}|${mitm_header}"

pcaps=`find testdata/pcaps/antivirus-run2 -type f -name "handshake.pcap"`
for pcapfile in $pcaps; do
	scripts/filename_to_fingerprint.py --mitm $pcapfile
done

cat << END
# add some additional records based on injected http headers
# Sources:
# - https://jhalderm.com/pub/papers/interception-ndss17.pdf
# - https://github.com/zakird/tlsfingerprints/blob/master/processing/browsers/browser.py#L131
0::0:0::0:|:*:*:*:*:*barracuda:*|Barracuda:5:0
0::0:0::0:|:*:*:*:*:*cuda_cliip:*|Barracuda:5:0
0::0:0::0:|:*:*:*:*:*gdata-version:*|GData:1:4
0::0:0::0:|:*:*:*:*:*gdataver:*|GData:1:4
0::0:0::0:|:*:*:*:*:*pxyro-connection:*|Citrix:5:0
0::0:0::0:|:*:*:*:*:*squixa-proxy:*|Squixa:0:0
0::0:0::0:|:*:*:*:*:*x-akamai-config-log-detail:*|Akamai:5:0
0::0:0::0:|:*:*:*:*:*x-akamai-edgescape:*|Akamai:5:0
0::0:0::0:|:*:*:*:*:*x-akamai-origin-hop:*|Akamai:5:0
0::0:0::0:|:*:*:*:*:*x-akamai-prefetched-object:*|Akamai:5:0
0::0:0::0:|:*:*:*:*:*x-barracuda-wf-agent:*|Barracuda:5:0
0::0:0::0:|:*:*:*:*:*x-barracuda-wf-app:*|Barracuda:5:0
0::0:0::0:|:*:*:*:*:*x-barracuda-wf-device:*|Barracuda:5:0
0::0:0::0:|:*:*:*:*:*x-barracuda-wf-deviceid:*|Barracuda:5:0
0::0:0::0:|:*:*:*:*:*x-barracuda-wf-domain-dns:*|Barracuda:5:0
0::0:0::0:|:*:*:*:*:*x-barracuda-wf-domain:*|Barracuda:5:0
0::0:0::0:|:*:*:*:*:*x-barracuda-wf-machine:*|Barracuda:5:0
0::0:0::0:|:*:*:*:*:*x-barracuda-wf-os:*|Barracuda:5:0
0::0:0::0:|:*:*:*:*:*x-barracuda-wf-user:*|Barracuda:5:0
0::0:0::0:|:*:*:*:*:*x-bluecoat-user:*|BlueCoat:5:0
0::0:0::0:|:*:*:*:*:*x-bluecoat-via:*|BlueCoat:5:0
0::0:0::0:|:*:*:*:*:*x-citrix-am-credentialtypes:*|Citrix:5:0
0::0:0::0:|:*:*:*:*:*x-citrix-am-labeltypes:*|Citrix:5:0
0::0:0::0:|:*:*:*:*:*x-citrix-gateway:*|Citrix:5:0
0::0:0::0:|:*:*:*:*:*x-citrix-via-vip:*|Citrix:5:0
0::0:0::0:|:*:*:*:*:*x-citrix-via:*|Citrix:5:0
0::0:0::0:|:*:*:*:*:*x-cybersitter-content-flag:*|Cybersitter:5:0
0::0:0::0:|:*:*:*:*:*x-cybersitter-csvt-token:*|Cybersitter:5:0
0::0:0::0:|:*:*:*:*:*x-cybersitter-oemid:*|Cybersitter:5:0
0::0:0::0:|:*:*:*:*:*x-drweb-keynumber:*|DrWeb:5:0
0::0:0::0:|:*:*:*:*:*x-drweb-matchate:*|DrWeb:5:0
0::0:0::0:|:*:*:*:*:*x-drweb-syshash:*|DrWeb:5:0
0::0:0::0:|:*:*:*:*:*x-eset-spread-control:*|ESET:5:0
0::0:0::0:|:*:*:*:*:*x-eset-updateid:*|ESET:5:0
0::0:0::0:|:*:*:*:*:*x-fcckv2:*|Fortinet:1:0
0::0:0::0:|:*:*:*:*:*x-gdata-device:*|GData:1:4
0::0:0::0:|:*:*:*:*:*x-netnanny-ignore:*|NetNanny:4:0
0::0:0::0:|:*:*:*:*:*x-nod32-mode:*|ESET:5:0
0::0:0::0:|:*:*:*:*:*x-sophos-filter:*|Sophos:1:0
0::0:0::0:|:*:*:*:*:*x-sophos-meta:*|Sophos:1:0
0::0:0::0:|:*:*:*:*:*x-sophos-wsa-clientip:*|Sophos:1:0
0::0:0::0:|:*:*:*:*:*x-websensehost:*|Forcepoint/WebSense:0:0
0::0:0::0:|:*:*:*:*:*x-websenseproxychannel:*|Forcepoint/WebSense:0:0
0::0:0::0:|:*:*:*:*:*x-websenseproxysslconnection:*|Forcepoint/WebSense:0:0
0::0:0::0:|:*:*:*:*:*x_bluecoat_user:*|BlueCoat:5:0
0::0:0::0:|:*:*:*:*:*x_bluecoat_via:*|BlueCoat:5:0
0::0:0::0:|:*:*:*:*:*xroxy-connection:*|Kerio-Winroute-Firewall:0:0
0::0:0::0:|:*:*:*:*:*z-forwarded-for:*|Zscaler:0:0
0::0:0::0:|:*:*:25,24,23:*:*client-ip,x-forwarded-for:*|Forcepoint/WebSense:5:0
# add signatures based on quirks that none of the supported browsers should ever have
0::0:0::0:|:*:*:*:*:*:*badhost|:0:0
0::0:0::0:|:*:*:*:*:*:*badcase|:0:0
0::0:0::0:|:*:*:*:*:*:*badpath|:0:0
0::0:0::0:|:*:*:*:*:*:*badspace|:0:0
0::0:0::0:|:*:*:*:*:*:*badreferer|:0:0
0::0:0::0:|:*:*:*:*:*:*badxff|:0:0
0::0:0::0:|:*:*:*:*:*:*badhdr|:0:0
END
