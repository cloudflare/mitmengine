#!/bin/bash

# clean up browser
clean_br() {
	br=${br/chrome/Chrome}
	br=${br/firefox/Firefox}
	br=${br/safari/Safari}
	br=${br/android/Android}
	br=${br/opera/Opera}
	br=${br/silk/Silk}
	br=${br/ie/IE}
	br=${br/edge/IE}
}

# clean up browser version
clean_br_vers() {
	regex="^([0-9]+)\.([0-9]+)\.([0-9]+)$"
	if [[ $br_vers =~ $regex ]]; then
		br_vers="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.${BASH_REMATCH[3]}"
		return
	fi
	regex="^([0-9]+)\.([0-9]+)$"
	if [[ $br_vers =~ $regex ]]; then
		br_vers="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}"
		return
	fi
	regex="^([0-9]+)$"
	if [[ $br_vers =~ $regex ]]; then
		br_vers="${BASH_REMATCH[1]}"
		return
	fi
	br_vers="-1.-1.-1"
}

# clean up device
clean_device() {
	if [ "$br" = "Android" ]; then
		device="Phone" # some of these could be tablets, but w/e
	fi
	device=${device/computer/Computer}
}

# clean up platform
clean_plat() {
	plat=${plat/android/Linux}
	plat=${plat/ipod/iPod}
	plat=${plat/ipad/iPad}
	plat=${plat/iphone/iPhone}
	plat=${plat/OS_X/Mac}
	plat=${plat/mac/Mac}
	plat=${plat/windows/Windows}
}

# clean up OS
clean_os() {
	os=${os/OS_X/MacOSX}
	os=${os/mac/MacOSX}
	os=${os/ios/iOS}
	os=${os/android/Android}
	os=${os/windows/Windows}
}

# clean up OS version
clean_os_vers() {
	if [ "$os" = "Windows" ]; then
		os_vers=${os_vers/XP/5.1.0}
		os_vers=${os_vers/7/6.1.0}
		os_vers=${os_vers/8.1/6.3.0}
		os_vers=${os_vers/8/6.2.0}
		os_vers=${os_vers/10/10.0.0}
	fi
	if [ "$os" = "MacOSX" ]; then
		os_vers=${os_vers/El_Capitan/10.11.0}
		os_vers=${os_vers/Yosemite/10.10.0}
		os_vers=${os_vers/Mavericks/10.9.0}
		os_vers=${os_vers/Mountain_Lion/10.8.0}
		os_vers=${os_vers/Lion/10.7.0}
		os_vers=${os_vers/Snow_Leopard/10.6.0}
	fi
	regex="^([0-9]+)\.([0-9]+)\.([0-9]+)$"
	if [[ $os_vers =~ $regex ]]; then
		os_vers="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.${BASH_REMATCH[3]}"
		return
	fi
	regex="^([0-9]+)\.([0-9]+)$"
	if [[ $os_vers =~ $regex ]]; then
		os_vers="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}"
		return
	fi
	regex="^([0-9]+)$"
	if [[ $os_vers =~ $regex ]]; then
		os_vers="${BASH_REMATCH[1]}"
		return
	fi
	os_vers="-1.-1.-1"
}

br_to_int() {
	case $br in
	Chrome)
	br=1
	;;
	IE)
	br=2
	;;
	Safari)
	br=3
	;;
	Firefox)
	br=4
	;;
	Android)
	br=5
	;;
	Opera)
	br=6
	;;
	Blackberry)
	br=7
	;;
	UCBrowser)
	br=8
	;;
	Silk)
	br=9
	;;
	Nokia)
	br=10
	;;
	NetFront)
	br=11
	;;
	QQ)
	br=12
	;;
	Maxthon)
	br=13
	;;
	SogouExplorer)
	br=14
	;;
	Spotify)
	br=15
	;;
	Bot)
	br=16
	;;
	AppleBot)
	br=17
	;;
	BaiduBot)
	br=18
	;;
	BingBot)
	br=19
	;;
	DuckDuckGoBot)
	br=20
	;;
	FacebookBot)
	br=21
	;;
	GoogleBot)
	br=22
	;;
	LinkedInBot)
	br=23
	;;
	MsnBot)
	br=24
	;;
	PingdomBot)
	br=25
	;;
	TwitterBot)
	br=26
	;;
	YandexBot)
	br=27
	;;
	YahooBot)
	br=28
	;;
	*)
	br=0
	;;
	esac
}

os_to_int() {
	case $os in
	WindowsPhone)
	os=1
	;;
	Windows)
	os=2
	;;
	MacOSX)
	os=3
	;;
	iOS)
	os=4
	;;
	Android)
	os=5
	;;
	Blackberry)
	os=6
	;;
	ChromeOS)
	os=7
	;;
	Kindle)
	os=8
	;;
	WebOS)
	os=9
	;;
	Linux)
	os=10
	;;
	Playstation)
	os=11
	;;
	Xbox)
	os=12
	;;
	Nintendo)
	os=13
	;;
	Bot)
	os=14
	;;
	*)
	os=0
	;;
	esac
}

plat_to_int() {
	case $plat in
	Windows)
	plat=1
	;;
	Mac)
	plat=2
	;;
	Linux)
	plat=3
	;;
	iPad)
	plat=4
	;;
	iPhone)
	plat=5
	;;
	iPod)
	plat=6
	;;
	Blackberry)
	plat=7
	;;
	WindowsPhone)
	plat=8
	;;
	Playstation)
	plat=9
	;;
	Xbox)
	plat=10
	;;
	Nintendo)
	plat=11
	;;
	Bot)
	plat=12
  	;;
	*)
	plat=0
	;;
	esac
}

device_to_int() {
	case $device in
	Computer)
	device=1
	;;
	Tablet)
	device=2
	;;
	Phone)
	device=3
	;;
	Console)
	device=4
	;;
	Wearable)
	device=5
	;;
	TV)
	device=6
	;;
	*)
	device=0
	;;
	esac
}

mitm_type_to_int() {
	case $mitm_type in
	Antivirus)
	mitm_type=1
	;;
	FakeBrowser)
	mitm_type=2
	;;
	Malware)
	mitm_type=3
	;;
	Parental)
	mitm_type=4
	;;
	Proxy)
	mitm_type=5
	;;
	*)
	mitm_type=0
	;;
	esac
}

mitm_grade_to_int() {
	case $mitm_grade in
	A)
	mitm_grade=1
	;;
	B)
	mitm_grade=2
	;;
	C)
	mitm_grade=3
	;;
	F)
	mitm_grade=4
	;;
	*)
	mitm_grade=0
	;;
	esac
}

# generate user agent part
gen_ua_part() {
	# normalize user agent fields
	clean_br
	clean_br_vers
	clean_device
	clean_plat
	clean_os
	clean_os_vers

	# convert user agent fields to enums defined in uasurfer
	br_to_int
	os_to_int
	plat_to_int
	device_to_int
	ua_part="${br}:${br_vers}:${plat}:${os}:${os_vers}:${device}:${ua_quirk}"
}

gen_req_part() {
	tmpfile=$(mktemp /tmp/XXXXXXXX.p0f)
	# run p0f to generate signatures from pcaps
	scripts/p0f -f /dev/null -r $pcapfile -o $tmpfile > /dev/null
	# select the first ssl record (skipping ssl2 signatures)
	raw_sig=`cat $tmpfile | grep "mod=ssl" | grep -v "v2" | head -1`
	rm $tmpfile

	raw_sig=${raw_sig#*raw_sig=} # remove text before raw signature
	req_ssl=${raw_sig%:*} # remove flags from p0f signature
	if [ -z "${req_ssl}" ]; then
		ok="false"
	fi
	ssl_flags=${raw_sig##:*}
	if [[ $ssl_flags =~ .*compr.* ]]; then
		req_quirk=${req_quirk:+$req_quirk,}compr
	fi
	req_part="${req_ssl}:${req_http}:${req_quirk}"
}

gen_mitm_part() {
	mitm_type_to_int
	mitm_grade_to_int
	mitm_part="${mitm_name}:${mitm_type}:${mitm_grade}"
}

gen_record() {
	gen_ua_part
	gen_req_part
	gen_mitm_part
}

print_header() {
	echo "# generated by $0"
	ua_header="<browser_name>:<browser_version>:<os_platform>:<os_name>:<os_version>:<device_type>:<quirks>"
	req_header="<tls_version>:<cipher_suites>:<extension_names>:<curves>:<ec_point_fmts>:<http_headers>:<quirks>"
	mitm_header="<mitm_name>:<mitm_type>:<mitm_grade>"
	echo "# ${ua_header}|${req_header}|${mitm_header}"
}


clear_record() {
	br=""
	br_vers=""
	plat=""
	os=""
	os_vers=""
	ua_quirk=""
	req_ssl=""
	req_http=""
	req_quirk=""
	mitm_name=""
	mitm_type=""
	mitm_grade=""
	req_header=""
	ua_header=""
	mitm_header=""
}


print_record() {
	echo -e "${ua_part}|${req_part}|${mitm_part}"
}
