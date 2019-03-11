#!/usr/bin/env python3
import re
import sys
import os
import subprocess
from collections import defaultdict
from lxml import etree

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
            headers=",".join(self.headers), quirks=",".join(self.quirks)) 
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

    req_fp = RequestFingerprint()

    # parse request fingerprint from pcap
    req_fp.parse(args.filename)
    if not req_fp.parsed:
        sys.exit(1)

    full_fp = "{req}".format(req=req_fp)
    print(full_fp)
