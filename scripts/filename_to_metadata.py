#!/usr/bin/env python3
import re
import sys
import os.path as ospath
import subprocess
from collections import defaultdict
from lxml import etree
import json

class MiddlewareFingerprint:
    def __init__(self, middleware_name, middleware_type):
        if middleware_name == "none":
            middleware_name = ""
            middleware_type = ""
        self.raw_ua = ""
        self.name = middleware_name
        self.type = middleware_type

class UserAgentFingerprint:
    def __init__(self, device, os, os_version, browser, browser_version, platform):
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
            browser_version = ""

        # normalize device
        if browser == "Android":
            device = "Phone" # some of these could be tablets, but w/e
            platform = "Linux"
            os = "Android"
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
            os_version = ""

        self.browser = browser
        self.browser_version = browser_version
        self.os = os
        self.os_version = os_version
        self.platform = platform
        self.device = device

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
    args = parser.parse_args()

    record = {}

    # metadata fields
    desc = ""
    os = ""
    os_version = ""
    browser = ""
    browser_version = ""
    device = ""
    platform = ""
    middleware_name = ""
    middleware_version = ""
    middleware_type = ""

    # only process files named handshake.pcap
    dirname, basename = ospath.split(args.filename)
    if basename != "handshake.pcap":
        sys.exit(1)

    # the lowest level directory contains a description
    _, desc = ospath.split(dirname)

    metadata = {}
    metadata["desc"] = desc
    metadata["comment"] = "generated by {}".format(sys.argv[0])
    metadata["handshake_pcap"] = args.filename

    # check if accompanying header pcap is present
    header_pcap = ospath.join(dirname, "header.pcap")
    if ospath.exists(header_pcap):
        metadata["header_pcap"] = header_pcap

    if "browsers" in dirname:
        # browser filenames should conform to this format
        m = re.match('^([^-]+)-([^-]+)-([^-]+)-([^-]+)-([^-]+)$', desc)
        if not m:
            sys.exit(1)
        device = m.group(1)
        os = m.group(2)
        os_version = m.group(3)
        browser = m.group(4)
        browser_version = m.group(5)
        platform = os

        ua_fp = UserAgentFingerprint(device, os, os_version, browser, browser_version, platform)
        metadata["ua_fingerprint"] = ua_fp.__dict__

    elif "antivirus-run2" in dirname:
        # middleware description should conform to this format (middle field can contain '-')
        m = re.match('^([^-]+)-([^-]+)-(.+)-([^-]+)-([^-]+)$', desc)
        if not m:
            sys.exit(1) 
        os = m.group(1)
        os_version = m.group(2)
        browser = m.group(4)
        browser_version = m.group(5)
        device = "Computer"
        middleware_name = m.group(3)
        middleware_type = "Antivirus"

        middleware_fp = MiddlewareFingerprint(middleware_name, middleware_type)
        ua_fp = UserAgentFingerprint(device, os, os_version, browser, browser_version, platform)
        metadata["ua_fingerprint"] = ua_fp.__dict__
        metadata["middleware_fingerprint"] = middleware_fp.__dict__

    elif "middleboxes" in dirname:
        middleware_type = "Proxy"
        middleware_name = desc
        middleware_fp = MiddlewareFingerprint(middleware_name, middleware_type)
        ua_fp = UserAgentFingerprint(device, os, os_version, browser, browser_version, platform)
        metadata["ua_fingerprint"] = ua_fp.__dict__
        metadata["middleware_fingerprint"] = middleware_fp.__dict__

        pass

    print(json.dumps(metadata))
