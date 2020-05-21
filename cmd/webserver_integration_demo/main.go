package main

import (
	"crypto/tls"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"path/filepath"

	"github.com/cloudflare/mitmengine"
)

type tlsHandler struct {
	chi *tls.ClientHelloInfo
}

//https://forum.golangbridge.org/t/expose-tls-clienthelloinfo-in-http-handler/4554
// Save Client Hello Data from TLS Handshake
func (t *tlsHandler) GetClientInfo(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	t.chi = info
	return nil, nil
}

// Handle HTTPS requests and return an HTML rendering of the mitmengine report
func (t *tlsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	// Load default fingerprints
	browserFileName := filepath.Join("reference_fingerprints", "mitmengine", "browser.txt")
	mitmFileName := filepath.Join("reference_fingerprints", "mitmengine", "mitm.txt")
	badHeaderFileName := filepath.Join("reference_fingerprints", "mitmengine", "badheader.txt")

	// Load config
	var err error
	mitmProcessor, err := mitmengine.NewProcessor(&mitmengine.Config{
		BrowserFileName:   browserFileName,
		MitmFileName:      mitmFileName,
		BadHeaderFileName: badHeaderFileName,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Generate Report and return HTML
	mitmReport := mitmProcessor.CheckRequest(r, t.chi)
	if mitmReport.Error != nil {
		fmt.Fprintln(w, "ERROR: " + mitmReport.Error.Error())
	} else {
		err = GenerateHTMLReport(mitmReport, w)
		if err != nil {
			fmt.Fprintln(w, "ERROR: "+err.Error())
		}
	}
}

// Render mitmengine report as an HTML summary page
func GenerateHTMLReport(r mitmengine.Report, w http.ResponseWriter) error {

	//Define the HTML template
	t, err := template.New("Report").Parse(`
	<!DOCTYPE html>
	<html>
	<head>
		<meta charset="utf-8">
		<meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=yes">
		<title>MITM Engine Webserver Integration Demo</title>
	</head>
	<body>
		<div style="position: relative">
		<div style="position: absolute;margin: 0 auto;left: 0;right: 0;top: 0;bottom: 0;width: 800px">
			<h1 style="text-align: center"><i>mitmengine</i> Report:</h1>
			<br>
			<br>
			<h2>Is User-Agent Accurate?</h2>
			<h4><b>{{.BrowserSignatureMatch.String}}</b></h4>
			<p>{{.Reason}}</p>
			<h3>Details:</h3>
			<p>{{.ReasonDetails}}</p>
			<br>
			<br>
			<h2>Original Browser Security Grade: {{.BrowserGrade.String}}</h2>
			<h2>Actually Observed Security Grade: {{.ActualGrade.String}}</h2>
			<ul>
				<li>Weak Ciphers: {{.WeakCiphers}}</li>
				<li>Loses Perfect Forward Secrecy: {{.LosesPfs}}</li>
			</ul>
			<br>
			<br>
			<h2>User-Agent Signature</h2>
			<p>{{.MatchedUASignature}}</p>
			<br>
			<br>
			<h2>Browser Signature</h2>
			<p>{{.BrowserSignature}}</p>
			<br>
			<br>
			<h2>MITM Signature:</h2>
			<p>{{.MatchedMitmSignature}}</p>
			<br>
			<br>
			<h2>Errors</h2>
			<p>{{.Error}}</p>
			<br>
			<br>
		</div></div>
	</body>
	</html>
	`)
	if err != nil {
		return err
	}

	//Write the template response
	err = t.Execute(w, r)
	if err != nil {
		return err
	}
	return nil
}

func main() {

	handler := &tlsHandler{}

	// Grab ClientHelloInfo in Server
	s := &http.Server{
		Addr: ":8443",
		TLSConfig: &tls.Config{
			GetCertificate: handler.GetClientInfo,
		},
		Handler: handler,
	}

	// Serve HTTPS
	err := s.ListenAndServeTLS("bin/cert.crt", "bin/private.key")
	if err != nil {
		msg := err.Error()
		// https://golangcode.com/basic-https-server-with-certificate/
		keygen_instructions := "\nYou can generate one with: \n\topenssl genrsa -out private.key 2048\n\topenssl req -new -x509 -sha256 -key private.key -out cert.crt -days 3650"
		if msg == "open cert.crt: no such file or directory" {
			msg = "Demo could not find a TLS certificate (cert.crt) in the local directory."
			msg += keygen_instructions
		} else if msg == "open private.key: no such file or directory" {
			msg = "Demo could not find the private key (private.key) for TLS certificate (cert.crt) in the local directory."
			msg += keygen_instructions
		}
		log.Fatal(msg)
	} else {
		log.Println("MITMEngine Demo Server Terminated Gracefully")
	}
}
