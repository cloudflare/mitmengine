# MITMEngine

[![Build Status](https://travis-ci.org/cloudflare/mitmengine.svg?branch=master)](https://travis-ci.org/cloudflare/mitmengine)

## DEPRECATION NOTICE: This software is no longer maintained.

The goal of this project is to allow for accurate detection of HTTPS interception and robust TLS fingerprinting.
This project is based off of [The Security Impact of HTTPS Interception](https://zakird.com/papers/https_interception.pdf), and started as a port to Go of [their processing scripts and fingerprints](https://github.com/zakird/tlsfingerprints).

More context about MITMEngine is available in this [Cloudflare blog post](https://blog.cloudflare.com/monsters-in-the-middleboxes/).
Quick Links:
- [Signatures and Fingerprints: Core Definitions](#signature-and-fingerprints)
- [MITM Detection Methodology](#mitm-detection-methodology)
- [API](#api)
- [Example Usage](#example-usage)
- [Building and Testing](#building-and-testing)
- [How to Contribute](#how-to-contribute)
- [mergeDB utility](#mergedb-utility)

## Requirements

- Go
- Wireshark 3.0.0 (`wireshark -v` to check)

## Documentation
Detailed documentation lives with the code (copy package to $(GOPATH)/src/github.com/cloudflare/mitmengine first).

	godoc -http=:6060

http://localhost:6060/pkg/github.com/cloudflare/mitmengine

### Signature and Fingerprints
In this project, fingerprints map to concrete instantiations of an object, while signatures can represent multiple objects. We use this convention because a fingerprint is usually an inherent property of an object, while a signature can be chosen. In the same way, an actual client request seen by a server would have a fingerprint, while the software generating the request can choose it's own signature (e.g., by choosing which cipher suites it supports).

### Client Request
A client request fingerprint is derived from a client request to a server, and contains both TLS and HTTP features. A client request signature represents all of the possible fingerprints that a piece of software can generate. The aim is to make each signature specific enough that it can uniquely identify a piece of software.

### User Agent
A User Agent signature represent a set of User Agents generated by a browser. A User Agent signature for a browser allows for a range of browser versions, and allows for specifying the OS name, OS platform, OS version range, and device type for creating more fine-grained signatures.

### Browser
A browser signature contains both a User Agent signature and a client request signature. This allows for a signature to represent all of the possible fingerprints generated by Chrome 31-38 on Windows 10, for example.

### MITM
A MITM signature contains a client request signature along with additional details about the MITM software, including a security grade which can be affected by factors outside of the client request, such as whether or not the software validates certificates.

## MITM Detection Methodology
We consider an HTTPS connection to be intercepted when there is a mismatch
between the expected client request signature corresponding to the browser
identified by the User Agent, and the actual client request fingerprint of the
request.

### False positives
If a signature is inaccurate or outdated for a given piece of client software,
it is possible that the signature will falsely flag a connection as being
intercepted.

### False negatives
If a proxy closely mimics the request of the client, then we may not expect to
detect a mismatch. If the browser signatures are overly broad, we will also
fail to detect interception.

### Production fingerprints
The reference browser and MITM software fingerprints used in [MALCOLM](https://malcolm.cloudflare.com) can be found in `reference_fingerprints/mitmengine/`.
This set of fingerprints is a combination of what is pulled from the TLS Client Hello pcaps in `reference_fingerprints/pcaps/`, as well as the top 500 User Agents + TLS Client Hello
pairs observed on Cloudflare's network and labeled with a high trustworthiness rating (that is, traffic corresponding to human and friendly bot activity).

Ideally, we don't have to rely on reference fingerprints sampled from Cloudflare's network; instead, we would have a comprehensive
set of pcaps to build our set of reference TLS Client Hellos. Interested in helping us build out our dataset? See how [you can contribute](#submit-a-pull-request)!

## API
First, a user must create a `mitmengine.Config` struct to pass into `mitmengine.NewProcessor`. A `mitmengine.Config`
struct can specify filenames of files containing browser fingerprints, MITM fingerprints, and MITM
headers. Alternatively, it can also specify a configuration file for reading the previously mentioned files from any
other source; right now, MITMEngine supports reading these files from Amazon S3 client-compatible databases (including
Amazon S3 and Ceph). Additional file readers for databases (which we call "loaders") can be defined in the `loaders`
package, and as long as new loaders implement the Loader interface, they should work with the rest of MITMEngine out of the
box.

The intended entrypoint to the MITMEngine package is through the `Processor.Check` function, which takes a User Agent and client request fingerprint, and returns a mitm detection report. Additional API functions will be added in the future to allow for adding new signatures to a running process, for example.

## Example Usage
An example use of the API is below. A more complete application is available at `cmd/demo/main.go`, and can be built by running `make bin/demo`.

	rawUa := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.119 Safari/537.36"
	requestFingerprintString := "303:dada,1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,9c,9d,2f,35,a:aaaa,0,17,ff01,a,b,23,10,5,d,12,33,2d,2b,1b,dada,15:9a9a,1d,17,18:0::"
	uaFingerprintString := "1:72.0.3626:2:3:10.14.3:1:"
	requestFingerprint, _ := fp.NewRequestFingerprint(requestFingerprintString)
	uaFingerprint, _ := fp.NewUAFingerprint(uaFingerprintString)
	report := mitmProcessor.Check(uaFingerprint, rawUa, requestFingerprint)

The TLS requestFingerprintString has the following format:

	<tls_version>:<cipher_suites>:<extension_names>:<curves>:<ec_point_fmts>:<http_headers>:<quirks>

The uaFingerprint has the following format:

	# <browser_name>:<browser_version>:<os_platform>:<os_name>:<os_version>:<device_type>:<quirks>

An example of how to parse User Agents into the format for uaFingerprint is in the `cmd/demo/main.go` file.

## Webserver Integration API

An alternate entrypoint to the MITMEngine, `Processor.CheckRequest`,  is also available which is designed to integrate directly with webservers. It eliminates the need for users to build compatible request fingerprint strings or User-Agent fingerprint strings. It generates the needed signatures from a [*tls.ClientHelloInfo](https://golang.org/pkg/crypto/tls/#ClientHelloInfo) and a [*http.Request](https://golang.org/pkg/net/http/#Request). It returns a mitm detection report.

**_NOTE:_** The tradeoff for ease-of-use is that CheckRequest() lacks visibility into the set of TLS extensions advertised by the client, lacks custom tagging of client quirks, and assumes the connection is using the highest advertised TLS version. This is due to limitations in what the tls.ClientHelloInfo structure exposes. If you want full functionality, use Check().

A simple webserver using this entrypoint is provided at `cmd/webserver_integration_demo/main.go` and can be compiled with:

	make bin/webserver_integration_demo 

This will also use `openssl` to create a self-signed TLS certificate and private key for testing in `/bin` for convenience. The server may be run with:

	./bin/webserver_integration_demo

You can then send requests to https://localhost:8443 and see the mitm report rendered with some HTML formatting. Note that the self-signed certificate will be (rightly) rejected by clients by default.

If the report indicates that your client or MITM is not recognized by mitmengine's reference fingerprint set (e.g. `ERROR: unknown_user_agent`), consider [contributing new fingerprints](#how-to-contribute) to our set of reference fingerprints.

## Building and Testing
To use MITMEngine, remember to pull in its dependencies.
You'll likely want to run vendoring or gomod logic before running tests on MITMEngine.

To test, run `make test` and to see code coverage, run `make cover`.

## How to Contribute
As browser and mitm fingerprints quickly become outdated, we are actively seeking to update the fingerprint repository with new samples.

By contributing a fingerprint sample (the "Sample"), you (on your own behalf or on behalf of the organization you represent or are sponsored by (if any)) grant Cloudflare, Inc. and its subsidiaries and affiliates a perpetual, irrevocable, nonexclusive, royalty-free, worldwide right and license under all intellectual property rights in the Sample, to: (1) copy, publish, display, and distribute the Sample; and (2) prepare derivative works that are based on or part of the Sample."

To contribute fingerprint samples, please follow these steps:

### Generate a fingerprint sample
(tested on macOS Mojave 10.14.3)

Create server RSA certificate and key pair:

	openssl req -new -x509 -sha256 -out server.crt -nodes -keyout server.pem -subj /CN=localhost

Start server on port 4433:

	openssl s_server -www -cipher AES256-SHA -key server.pem -cert server.crt

Start TShark capture to decrypt HTTP headers (TShark >= 3.0.0):

	tshark -i loopback -o tls.keys_list:"127.0.0.1,4433,http,server.pem" -Tjson -e http.request.line -Y http > header.json

Start TShark capture of TLS Client Hello:

	tshark -i loopback -f "tcp port 4433" -w handshake.pcap

Visit `https://localhost:4433` from the TLS client you wish to fingerprint. For example,

	echo -e "GET /test HTTP/1.1\r\nHost:example.com\r\n\r\n" | openssl s_client -connect localhost:4433


### Submit a pull request
- Generate a fingerprint sample (`header.json`, `handshake.pcap`) as described above, and place in the directory `reference_fingerprints/pcaps/<desc>`, where `<desc>` is a unique and descriptive name.
- Add a line to `reference_fingerprints/fingerprint_metadata.jsonl` with the below fields. Recognized options for the `os`, `device`, `platform`, and `browser` fields are those defined in the `uasurfer` package. Recognized options for `mitm_fingerprint.type` are listed below. See `reference_fingerprints/fingerprint_metadata.jsonl` for examples; any unknown fields can be left blank or omitted.

	{ "desc": "<unique and descriptive name for sample>", "comment": "<additional information about the sample>", "handshake_pcap": "<path to pcap containing a TLS Client Hello>", "header_json": "<(optional) path to file containing the client HTTP request", "ua_fingerprint": {"raw_ua": "<raw User Agent string>", "os": "<WindowsPhone|Windows|MacOSX|iOS|Android|...>", "os_version": "<major>.<minor>.<patch>", "device": "<Windows|Mac|Linux|...>", "platform": "<Computer|Tablet|Phone|...>", "browser": "<Chrome|IE|Safari|Firefox|...>", "browser_version": "<major>.<minor>.<patch>"}, "mitm_fingerprint": { "name": "<description of mitm>", "type": "<Antivirus|FakeBrowser|Malware|Parental|Proxy>" }}

- Submit a pull request with above changes.

Other PRs and feature requests are welcome!

## mergeDB Utility
mergeDB (in `cmd/mergedb`) is a utility for merging similar TLS ClientHello fingerprints across multiple close versions of browsers or MITM software.
Use mergeDB to consolidate large lists of User Agent / Client Hello fingerprints:

	go run cmd/mergedb/main.go

By default, mergeDB will run on the fingerprints in the `reference_fingerprints/mitmengine` directory.
