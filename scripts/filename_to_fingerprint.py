#!/usr/bin/env python3
import re
import sys
import os
import subprocess
from collections import defaultdict
from lxml import etree

t = {
        "Chrome": 1,
        "IE": 2,
        "Safari": 3,
        "Firefox": 4,
        "Android": 5,
        "Opera": 6,
        "Blackberry": 7,
        "UCBrowser": 8,
        "Silk": 9,
        "Nokia": 10,
        "NetFront": 11,
        "QQ": 12,
        "Maxthon": 13,
        "SogouExplorer": 14,
        "Spotify": 15,
        "Bot": 16,
        "AppleBot": 17,
        "BaiduBot": 18,
        "BingBot": 19,
        "DuckDuckGoBot": 20,
        "FacebookBot": 21,
        "GoogleBot": 22,
        "LinkedInBot": 23,
        "MsnBot": 24,
        "PingdomBot": 25,
        "TwitterBot": 26,
        "YandexBot": 27,
        "YahooBot": 28,
        }
browser_to_int = defaultdict(int)
for k,v in t.items():
    browser_to_int[k] = v

t = {
        "WindowsPhone": 1,
        "Windows": 2,
        "MacOSX": 3,
        "iOS": 4,
        "Android": 5,
        "Blackberry": 6,
        "ChromeOS": 7,
        "Kindle": 8,
        "WebOS": 9,
        "Linux": 10,
        "Playstation": 11,
        "Xbox": 12,
        "Nintendo": 13,
        "Bot": 14,
        }
os_to_int = defaultdict(int)
for k,v in t.items():
    os_to_int[k] = v

t = {
        "Windows": 1,
        "Mac": 2,
        "Linux": 3,
        "iPad": 4,
        "iPhone": 5,
        "iPod": 6,
        "Blackberry": 7,
        "WindowsPhone": 8,
        "Playstation": 9,
        "Xbox": 10,
        "Nintendo": 11,
        "Bot": 12,
        }
platform_to_int = defaultdict(int)
for k,v in t.items():
    platform_to_int[k] = v

t = {
        "Computer": 1,
        "Tablet": 2,
        "Phone": 3,
        "Console": 4,
        "Wearable": 5,
        "TV": 6,
        }
device_to_int = defaultdict(int)
for k,v in t.items():
    device_to_int[k] = v

t = {
        "Antivirus": 1,
        "FakeBrowser": 2,
        "Malware": 3,
        "Parental": 4,
        "Proxy": 5,
        }
mitm_type_to_int = defaultdict(int)
for k,v in t.items():
    mitm_type_to_int[k] = v

t = {
        "A": 1,
        "B": 2,
        "C": 3,
        "F": 4,
        }
mitm_grade_to_int = defaultdict(int)
for k,v in t.items():
    mitm_grade_to_int[k] = v

class MitmFingerprint:
    def __init__(self):
        self.ua_fp = UserAgentFingerprint()
        self.mitm_name = ""
        self.mitm_grade = ""
        self.mitm_type = ""

    def __str__(self):
        return "{mitm_name}:{mitm_type}:{mitm_grade}".format(
                mitm_name=self.mitm_name,
                mitm_type=self.mitm_type,
                mitm_grade=self.mitm_grade)

    def set_fields(self, mitm_name, mitm_type, mitm_grade):
        self.mitm_name = mitm_name
        self.mitm_type = mitm_type_to_int[mitm_type]
        self.mitm_grade = mitm_type_to_int[mitm_grade]


class UserAgentFingerprint:
    def __init__(self):
        self.browser = ""
        self.browser_version = ""
        self.platform = ""
        self.os = ""
        self.os_version = ""
        self.device = ""
        self.quirks = []

    def __str__(self):
        return "{browser}:{browser_version}:{platform}:{os}:{os_version}:{device}:{quirks}".format(
                browser=self.browser,
                browser_version=self.browser_version,
                platform=self.platform,
                os=self.os,
                os_version=self.os_version,
                device=self.device,
                quirks=",".join(self.quirks))

    def set_fields(self, device, os, os_version, browser, browser_version, platform):
        # handle some parsing exceptions
        if browser == "ipad":
            device="Tablet"
            os = "iOS"
            platform = "iPad"
            browser = "Safari"

        if browser == "iphone":
            device="Phone"
            os="iOS"
            platform="iPhone"
            browser="Safari"
        
        # use os version for browser version if not known
        if browser_version == "":
            browser_version = os_version

        # normalize browser
        browser = browser.replace("chrome", "Chrome")
        browser = browser.replace("firefox", "Firefox")
        browser = browser.replace("safari", "Safari")
        browser = browser.replace("android", "Android")
        browser = browser.replace("opera", "Opera")
        browser = browser.replace("silk", "Silk")
        browser = browser.replace("ie", "IE")
        browser = browser.replace("edge", "IE")

        # normalize browser version
        if not (re.match("^([0-9]+)\.([0-9]+)\.([0-9]+)$", browser_version)
            or re.match("^([0-9]+)\.([0-9]+)$", browser_version)
            or re.match("^([0-9]+)$", browser_version)):
            browser_version = "-1.-1.-1"

        # normalize device
        if browser == "Android":
            device="Phone" # some of these could be tablets, but w/e
        device = device.replace("computer", "Computer")

        # normalize platform
        platform = platform.replace("android", "Linux")
        platform = platform.replace("ipod", "iPod")
        platform = platform.replace("ipad", "iPad")
        platform = platform.replace("iphone", "iPhone")
        platform = platform.replace("OS_X", "Mac")
        platform = platform.replace("mac", "Mac")
        platform = platform.replace("windows", "Windows")

        # normalize os
        os = os.replace("OS_X", "MacOSX")
        os = os.replace("mac", "MacOSX")
        os = os.replace("ios", "iOS")
        os = os.replace("android", "Android")
        os = os.replace("windows", "Windows")

        # normalize os version
        if os == "Windows":
            os_version = os_version.replace("XP", "5.1.0")
            os_version = os_version.replace("7", "6.1.0")
            os_version = os_version.replace("8.1", "6.3.0")
            os_version = os_version.replace("8", "6.2.0")
            os_version = os_version.replace("10", "10.0.0")
        elif os == "MacOSX":
            os_version = os_version.replace("El_Capitan", "10.11.0")
            os_version = os_version.replace("Yosemite", "10.10.0")
            os_version = os_version.replace("Mavericks", "10.9.0")
            os_version = os_version.replace("Mountain_Lion", "10.8.0")
            os_version = os_version.replace("Lion", "10.7.0")
            os_version = os_version.replace("Snow_Leopard", "10.6.0")
        if not (re.match("^([0-9]+)\.([0-9]+)\.([0-9]+)$", browser_version)
            or re.match("^([0-9]+)\.([0-9]+)$", browser_version)
            or re.match("^([0-9]+)$", browser_version)):
            os_version = "-1.-1.-1"

        self.browser = browser_to_int[browser]
        self.browser_version = browser_version
        self.os = os_to_int[os]
        self.os_version = os_version
        self.platform = platform_to_int[platform]
        self.device = device_to_int[device]

class RequestFingerprint:
    def __init__(self):
        self.clear()

    def clear(self):
        self.record_tls_version = ""
        self.tls_version = ""
        self.ciphersuites = []
        self.compression_methods = []
        self.signature_algorithms = []
        self.extensions = []
        self.elliptic_curves = []
        self.ec_point_formats = []
        self.headers = []
        self.quirks = []
        self.parsed = False

    def __str__(self):
        if not self.parsed:
            return ""
        if len(self.compression_methods) > 1:
            self.quirks.append("compr")
        return "{version}:{ciphersuites}:{extensions}:{elliptic_curves}:{ec_point_formats}:{headers}:{quirks}".format(
            version="{:x}".format(int(self.tls_version,16)),
            ciphersuites=",".join("{:x}".format(int(x,16)) for x in self.ciphersuites),
            extensions=",".join("{:x}".format(int(x,16)) for x in self.extensions),
            elliptic_curves=",".join("{:x}".format(int(x,16)) for x in self.elliptic_curves),
            ec_point_formats=",".join("{:x}".format(int(x,16)) for x in self.ec_point_formats),
            headers=",".join(self.headers),
            quirks=",".join(self.quirks))

    def parse(self, filename):
        self.clear()
        pdml = subprocess.run(["tshark", "-r", filename, "-T", "pdml"], capture_output=True, encoding='utf-8').stdout
        # tshark may omit closing tag on incomplete pcaps
        if '</pdml>' not in pdml:
            pdml += '</pdml>'
        root = etree.fromstring(pdml)
        for pkt in root:
            for proto in pkt:
                if proto.get("name") != "ssl":
                    continue
                # TODO: skip SSLv2 records
                for field0 in proto:
                    if field0.get("name") != "ssl.record":
                        continue
                    # only want the final client hello, so clear fields 
                    self.clear()
                    # parse record version
                    for field1 in field0:
                        if field1.get("name") == "ssl.record.version":
                            self.record_tls_version = field1.get("value")
                    # parse record
                    for field1 in field0:
                        # check record type
                        if field1.get("name") != "ssl.handshake":
                            continue
                        # check handshake type
                        is_client_hello = False
                        for field2 in field1:
                            if field2.get("name") == "ssl.handshake.type" and field2.get("value") == "01":
                                is_client_hello = True
                        if not is_client_hello:
                            continue
                        # parse version
                        for field2 in field1:
                            if field2.get("name") == "ssl.handshake.version":
                                self.tls_version = field2.get("value")
                        # parse ciphersuites
                        for field2 in field1:
                            if field2.get("name") != "ssl.handshake.ciphersuites":
                                continue
                            for field3 in field2:
                                if field3.get("name") != "ssl.handshake.ciphersuite":
                                    continue # unexpected
                                self.ciphersuites.append(field3.get("value"))
                        # parse compression methods
                        for field2 in field1:
                            if field2.get("name") != "ssl.handshake.comp_methods":
                                continue
                            for field3 in field2:
                                if field3.get("name") != "ssl.handshake.comp_method":
                                    continue # unexpected
                                self.compression_methods.append(field3.get("value"))
                        # parse extensions 
                        for field2 in field1:
                            if field2.get("name") == "": # extensions, etc.
                                # find the extension type
                                is_elliptic_curves = False
                                is_ec_point_formats = False
                                is_signature_algorithms = False
                                for field3 in field2:
                                    if field3.get("name") == "ssl.handshake.extension.type":
                                        if field3.get("value") == "000a":
                                            is_elliptic_curves = True
                                        if field3.get("value") == "000b":
                                            is_ec_point_formats = True
                                        if field3.get("value") == "000d":
                                            is_signature_algorithms = True
                                        self.extensions.append(field3.get("value"))
                                if is_elliptic_curves:
                                    for field3 in field2:
                                        if field3.get("name") != "ssl.handshake.extensions_elliptic_curves":
                                            continue
                                        for field4 in field3:
                                            if field4.get("name") != "ssl.handshake.extensions_elliptic_curve":
                                                continue # unexpected
                                            self.elliptic_curves.append(field4.get("value"))
                                if is_ec_point_formats:
                                    for field3 in field2:
                                        if field3.get("name") != "ssl.handshake.extensions_elliptic_curves": # accounting for bug in tshark?
                                            continue
                                        for field4 in field3:
                                            if field4.get("name") != "ssl.handshake.extensions_ec_point_format":
                                                continue # unexpected
                                            self.ec_point_formats.append(field4.get("value"))
                                if is_signature_algorithms:
                                    for field3 in field2:
                                        if field3.get("name") != "ssl.handshake.extensions_signature_algorithms":
                                            continue
                                        for field4 in field3:
                                            if field4.get("name") != "ssl.handshake.extensions_signature_algorithm":
                                                continue # unexpected
                                            self.signature_algorithms.append(field4.get("value"))
                        self.parsed = True
                        return 

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("filename", type=str, help="pcap containing TLS client hello")
    parser.add_argument("--mitm", action="store_true", help="parse pcap as MITM fingerprint file")
    args = parser.parse_args()

    ua_fp = UserAgentFingerprint()
    req_fp = RequestFingerprint()
    mitm_fp = MitmFingerprint()

    # parse user agent/mitm info from from file name
    description = args.filename.split('/')[-2]
    if not args.mitm:
        # filenames should conform to this format
        m = re.match('^([^-]+)-([^-]+)-([^-]+)-([^-]+)-([^-]+)$', description)
        if not m:
            sys.exit(1)
        device = m.group(1)
        os = m.group(2)
        os_version = m.group(3)
        browser = m.group(4)
        browser_version = m.group(5)
        platform = os
        ua_fp.set_fields(device, os, os_version, browser, browser_version, platform)

    else: # parse mitm file
        # mitm description should conform to this format (middle field can contain '-')
        m = re.match('^([^-]+)-([^-]+)-(.+)-([^-]+)-([^-]+)$', description)
        if not m:
            sys.exit(1) 
        os = m.group(1)
        os_version = m.group(2)
        mitm_name = m.group(3)
        browser = m.group(4)
        browser_version = m.group(5)
        mitm_type = ""
        mitm_grade = ""

        device="Computer"
        platform = os

        # handle some exceptions
        if browser == "android":
            platform = "Linux"
            os = "Android"
        if mitm_name == "none":
            mitm_name = ""
        else:
            mitm_type = "Antivirus"

        mitm_fp.set_fields(mitm_name, mitm_type, mitm_grade)
        ua_fp.set_fields(device, os, os_version, browser, browser_version, platform)

    # parse request fingerprint from pcap
    req_fp.parse(args.filename)
    if not req_fp.parsed:
        sys.exit(1)

    full_fp = "{ua}|{req}|{mitm}".format(ua=ua_fp,req=req_fp,mitm=mitm_fp)
    print(full_fp)
