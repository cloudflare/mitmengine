#!/usr/bin/env python3
# requires: TShark (Wireshark) >= v3.0.0

import sys
import subprocess
import json

class RequestFingerprint:
    def __init__(self):
        self.record_tls_version = ""
        self.tls_version = ""
        self.ciphersuites = []
        self.compression_methods = []
        self.signature_algorithms = []
        self.extensions = []
        self.supported_groups = []
        self.ec_point_formats = []
        self.headers = []
        self.quirks = []

    def __str__(self):
        if len(self.compression_methods) > 1:
            self.quirks.append("compr")
        return "{version}:{ciphersuites}:{extensions}:{supported_groups}:{ec_point_formats}:{headers}:{quirks}".format(
            version="{:x}".format(int(self.tls_version,16)),
            ciphersuites=",".join("{:x}".format(int(x)) for x in self.ciphersuites),
            extensions=",".join("{:x}".format(int(x)) for x in self.extensions),
            supported_groups=",".join("{:x}".format(int(x,16)) for x in self.supported_groups),
            ec_point_formats=",".join("{:x}".format(int(x)) for x in self.ec_point_formats),
            #signature_algorithms=",".join("{:x}".format(int(x,16)) for x in self.signature_algorithms), # not currently used in fingerprint
            headers=",".join(self.headers), quirks=",".join(self.quirks)) 

    def parse(self, filename):
        json_str = subprocess.run(["tshark", "-r", filename, "-Y", "tls.handshake.type == 1", "-T", "json",
            "-e", "tls.record.version",
            "-e", "tls.handshake.version",
            "-e", "tls.handshake.ciphersuite",
            "-e", "tls.handshake.comp_method",
            "-e", "tls.handshake.extension.type",
            "-e", "tls.handshake.extensions_supported_group",
            "-e", "tls.handshake.extensions_ec_point_format",
            "-e", "tls.handshake.sig_hash_alg"], capture_output=True, encoding='utf-8').stdout
        pkts = json.loads(json_str)
        # use the last TLS Client Hello in the pcap
        record = pkts[-1]["_source"]["layers"]
        self.record_tls_version = record["tls.record.version"][0]
        self.tls_version = record["tls.handshake.version"][0]
        self.ciphersuites = record["tls.handshake.ciphersuite"]
        self.compression_methods = record["tls.handshake.comp_method"]
        self.extensions = record["tls.handshake.extension.type"]
        if '10' in self.extensions:
            self.supported_groups = record["tls.handshake.extensions_supported_group"]
        if '11' in self.extensions:
            self.ec_point_formats = record["tls.handshake.extensions_ec_point_format"]
        if '13' in self.extensions:
            self.signature_algorithms = record["tls.handshake.sig_hash_alg"]

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("filename", type=str, help="pcap containing TLS client hello")
    args = parser.parse_args()

    req_fp = RequestFingerprint()

    # parse request fingerprint from pcap
    try:
        req_fp.parse(args.filename)
    except IndexError as e:
        print(args.filename, e, file=sys.stderr)
        sys.exit(1)
    except KeyError as e:
        print(args.filename, e, file=sys.stderr)
        sys.exit(1)

    print(req_fp)
