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
	browserFileName := flag.String("browser", filepath.Join("reference_fingerprints", "mitmengine", "browser.txt"), "File containing browser signatures")
	mitmFileName := flag.String("mitm", filepath.Join("reference_fingerprints", "mitmengine", "mitm.txt"), "File containing mitm signatures")
	badHeaderFileName := flag.String("badheader", filepath.Join("reference_fingerprints", "mitmengine", "badheader.txt"), "File containing non-browser (bad) HTTP headers")
	handshakePcapFileName := flag.String("handshake", filepath.Join("reference_fingerprints", "pcaps", "misc", "ios5", "handshake.pcap"), "Pcap containing TLS Client Hello")
	headerJsonFileName := flag.String("header", filepath.Join("reference_fingerprints", "pcaps", "middleboxes", "barracuda", "barracuda-chrome48", "header.json"), "Json file containing HTTP headers")
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
	requestFingerprintString, err := exec.Command(filepath.Join("scripts", "pcap_to_request_fingerprint.py"), *handshakePcapFileName).Output()
	if err != nil {
		log.Fatal(err)
	}
	requestFingerprint, err := fp.NewRequestFingerprint(strings.TrimSpace(string(requestFingerprintString)))
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
	report := mitmProcessor.Check(uaFingerprint, rawUa, requestFingerprint)

	// Print out human-readable report
	if report.Error != nil {
		fmt.Printf("MITM results inconclusive: %v\n", report.Error)
		return
	}
	fmt.Printf("User agent fingerprint matched signature from database:\n\tua fp:\t%v\n\tua sig:\t%v\n", uaFingerprint, report.MatchedUASignature)
	fmt.Printf("Expect request fingerprint to match request signature from database:\n\trq fp:\t%v\n\trq sig:\t%v\n\tmatch:\t%v", requestFingerprint, report.BrowserSignature, report.BrowserSignatureMatch)
	if report.BrowserSignatureMatch == fp.MatchPossible {
		fmt.Printf("\n")
	} else {
		fmt.Printf("\n\treason:\t%v\n", report.Reason)
	}
	fmt.Printf("Security report:\n\tbrowser grade:\t%v\n\tactual grade:\t%v\n\tweak ciphers:\t%v\n\tloses pfs:\t%v\n", report.BrowserGrade, report.ActualGrade, report.WeakCiphers, report.LosesPfs)
	if len(report.MatchedMitmSignature) > 0 {
		fmt.Printf("Request fingerprint matched known MITM signature:\n\trq sig:\t%v\n\tname:\t%v\n\ttype:\t%v\n", report.MatchedMitmSignature, report.MatchedMitmName, report.MatchedMitmType)
	} else {
		fmt.Printf("Request fingerprint did not match any known MITM signatures\n")
	}
}
