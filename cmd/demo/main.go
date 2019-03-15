package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/avct/uasurfer"
	"github.com/cloudflare/mitmengine"
	fp "github.com/cloudflare/mitmengine/fputil"
)

func main() {
	browserFileName := flag.String("browser", filepath.Join("testdata", "mitmengine", "browser.txt"), "File containing browser signatures")
	mitmFileName := flag.String("mitm", filepath.Join("testdata", "mitmengine", "mitm.txt"), "File containing mitm signatures")
	badHeaderFileName := flag.String("badheader", filepath.Join("testdata", "mitmengine", "badheader.txt"), "File containing non-browser (bad) HTTP headers")
	handshakePcapFileName := flag.String("handshake", "handshake.pcap", "Pcap containing TLS Client Hello")
	headerJsonFileName := flag.String("header", "header.json", "Json file containing HTTP headers")
	flag.Parse()

	// Load config
	var err error
	mitmProcessor, err := mitmengine.NewProcessor(&mitmengine.Config{
		BrowserFileName:   *browserFileName,
		MitmFileName:      *mitmFileName,
		BadHeaderFileName: *badHeaderFileName,
	})

	if err != nil {
		log.Fatal(err)
	}
	// Read in TLS Client Hello fingerprint
	requestFingerprintString, err := exec.Command("scripts/pcap_to_request_fingerprint.py", *handshakePcapFileName).Output()
	if err != nil {
		log.Fatal(err)
	}
	requestFingerprint, err := fp.NewRequestFingerprint(string(requestFingerprintString))
	if err != nil {
		log.Fatal(err)
	}
	// Read in HTTP request fingerprint
	jsonStr, err := ioutil.ReadFile(*headerJsonFileName)
	if err != nil {
		log.Fatal(err)
	}
	var decoded []struct {
		Source struct {
			Layers struct {
				RequestLines []string `json:"http.request.line"`
			} `json:"layers"`
		} `json:"_source"`
	}
	if err = json.Unmarshal(jsonStr, &decoded); err != nil {
		log.Fatal(err)
	}
	rawUa := ""
	for _, pkt := range decoded {
		for _, requestLine := range pkt.Source.Layers.RequestLines {
			if strings.Contains(requestLine, "User-Agent:") {
				rawUa = strings.TrimSpace(strings.TrimPrefix(requestLine, "User-Agent:"))
				break
			}
		}
		if len(rawUa) > 0 {
			break
		}
	}
	// Convert uasurfer.UserAgent to fp.UAFingerprint
	ua := uasurfer.Parse(rawUa)
	uaFingerprint := fp.UAFingerprint{
		BrowserName:    int(ua.Browser.Name),
		BrowserVersion: fp.UAVersion(ua.Browser.Version),
		OSPlatform:     int(ua.OS.Platform),
		OSName:         int(ua.OS.Name),
		OSVersion:      fp.UAVersion(ua.OS.Version),
		DeviceType:     int(ua.DeviceType),
	}
	_ = mitmProcessor.Check(uaFingerprint, rawUa, requestFingerprint)
}
