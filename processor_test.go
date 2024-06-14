package mitmengine_test

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"crypto/tls"

	"github.com/cloudflare/mitmengine/loader"

	ua "github.com/avct/uasurfer"
	"github.com/cloudflare/mitmengine"
	"github.com/cloudflare/mitmengine/db"
	fp "github.com/cloudflare/mitmengine/fputil"
	"github.com/cloudflare/mitmengine/testutil"
)

func TestProcessorConfigEmpty(t *testing.T) {
	emptyConfig := mitmengine.Config{}
	t.Run("New", func(t *testing.T) { _, err := mitmengine.NewProcessor(&emptyConfig); testutil.Ok(t, err) })
}

func TestProcessorConfigFile(t *testing.T) {
	testConfigFile := mitmengine.Config{
		BrowserFileName:   filepath.Join("reference_fingerprints", "mitmengine", "browser.txt"),
		MitmFileName:      filepath.Join("reference_fingerprints", "mitmengine", "mitm.txt"),
		BadHeaderFileName: filepath.Join("reference_fingerprints", "mitmengine", "badheader.txt"),
	}
	t.Run("New", func(t *testing.T) { _, err := mitmengine.NewProcessor(&testConfigFile); testutil.Ok(t, err) })
	t.Run("CheckSequential", func(t *testing.T) { _TestProcessorCheckSequential(t, &testConfigFile) })
	t.Run("CheckConcurrent", func(t *testing.T) { _TestProcessorCheckConcurrent(t, &testConfigFile) })
	t.Run("GetByUASignatureBrowser", func(t *testing.T) { _TestProcessorGetByUASignatureBrowser(t, &testConfigFile) })
	t.Run("GetByRequestSignatureMitm", func(t *testing.T) { _TestProcessorGetByRequestSignatureMitm(t, &testConfigFile) })
	//t.Run("ProcessorKnownBrowserFingerprints", func(t *testing.T) { _TestProcessorKnownBrowserFingerprints(t, &testConfigFile)})
	//t.Run("ProcessorKnownMitmFingerprints", func(t *testing.T) { _TestProcessorKnownMitmFingerprints(t, &testConfigFile)})
}

// This test config tests the Loader interface that is implemented by the S3 struct. Anyone who
// contributes additional loaders can either add additional testConfigs here and/or write similar
// unit tests in the loader package.
func TestProcessorConfigS3(t *testing.T) {
	variables := []string{
		"AWS_SECRET_ACCESS_KEY",
		"AWS_ACCESS_KEY_ID",
		"AWS_ENDPOINT",
		"AWS_BUCKET_NAME",
	}
	skip := false
	for _, v := range variables {
		if _, ok := os.LookupEnv(v); !ok {
			skip = true
		}
	}
	if skip {
		t.Skipf("To run this test, set the following environment variables: %v", strings.Join(variables, ", "))
	}

	s3Instance, err := loader.NewS3Instance()
	if err != nil {
		t.Fatalf("loader.NewS3Instance(): '%v'", err)
	}
	testConfigS3 := mitmengine.Config{
		BrowserFileName:   "browser.txt",
		MitmFileName:      "mitm.txt",
		BadHeaderFileName: "badheader.txt",
		Loader:            s3Instance,
	}
	t.Run("New", func(t *testing.T) { _, err := mitmengine.NewProcessor(&testConfigS3); testutil.Ok(t, err) })
	t.Run("CheckSequential", func(t *testing.T) { _TestProcessorCheckSequential(t, &testConfigS3) })
	t.Run("CheckConcurrent", func(t *testing.T) { _TestProcessorCheckConcurrent(t, &testConfigS3) })
	t.Run("GetByUASignatureBrowser", func(t *testing.T) { _TestProcessorGetByUASignatureBrowser(t, &testConfigS3) })
	t.Run("GetByRequestSignatureMitm", func(t *testing.T) { _TestProcessorGetByRequestSignatureMitm(t, &testConfigS3) })
	//t.Run("ProcessorKnownBrowserFingerprints", func(t *testing.T) { _TestProcessorKnownBrowserFingerprints(t, &testConfigS3)})
	//t.Run("ProcessorKnownMitmFingerprints", func(t *testing.T) { _TestProcessorKnownMitmFingerprints(t, &testConfigS3)})
}

func uaSigToFin(signature fp.UASignature) (fp.UAFingerprint, error) {
	reg, _ := regexp.Compile("-[0-9.]*")
	return fp.NewUAFingerprint(reg.ReplaceAllString(signature.String(), ""))
}

func reqSigToFin(signature fp.RequestSignature) (fp.RequestFingerprint, error) {
	reg, _ := regexp.Compile("[*~!?]")
	max := signature.Version.Max
	signature.Version = fp.VersionSignature{Min: max, Exp: max, Max: max}
	return fp.NewRequestFingerprint(reg.ReplaceAllString(signature.String(), ""))
}

// Check that the fingerprints derived from pcaps match any updated signatures.
func _TestProcessorKnownBrowserFingerprints(t *testing.T, config *mitmengine.Config) {
	a, _ := mitmengine.NewProcessor(config)

	file, err := os.Open(filepath.Join("reference_fingerprints", "browser_fingerprints.txt"))
	testutil.Ok(t, err)
	var record db.Record
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		recordString := scanner.Text()
		if len(recordString) == 0 || recordString[0] == '#' {
			continue // skip comments and empty lines
		}
		err := record.Parse(recordString)
		testutil.Ok(t, err)
		requestFingerprint, err := reqSigToFin(record.RequestSignature)
		testutil.Ok(t, err)
		uaFingerprint, err := uaSigToFin(record.UASignature)
		testutil.Ok(t, err)
		report := a.Check(uaFingerprint, "", requestFingerprint)
		checkCheckRequestForEquivalence(t, requestFingerprint, "", report, a)
		testutil.Assert(t, report.BrowserSignatureMatch == fp.MatchPossible, fmt.Sprintf("exp: %v, got: %v", recordString, report))
	}
}

func _TestProcessorKnownMitmFingerprints(t *testing.T, config *mitmengine.Config) {
	a, _ := mitmengine.NewProcessor(config)

	file, err := os.Open(filepath.Join("reference_fingerprints", "mitm_fingerprints.txt"))
	testutil.Ok(t, err)
	var record db.Record
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		recordString := scanner.Text()
		if len(recordString) == 0 || recordString[0] == '#' {
			continue // skip comments and empty lines
		}
		err := record.Parse(recordString)
		testutil.Ok(t, err)
		requestFingerprint, err := reqSigToFin(record.RequestSignature)
		testutil.Ok(t, err)
		uaFingerprint, err := uaSigToFin(record.UASignature)
		testutil.Ok(t, err)
		report := a.Check(uaFingerprint, "", requestFingerprint)
		checkCheckRequestForEquivalence(t, requestFingerprint, "", report, a)
		testutil.Assert(t, report.BrowserSignatureMatch != fp.MatchPossible, fmt.Sprintf("exp %s, got: %v", record.MitmInfo, report))
		var actualMitmNameList fp.StringList
		err = actualMitmNameList.Parse(report.MatchedMitmName)
		testutil.Ok(t, err)
		testutil.Assert(t, record.MitmInfo.Match(fp.MitmInfo{NameList: actualMitmNameList}) != fp.MatchImpossible, fmt.Sprintf("exp: %s, got: %v", record, report))
	}
}

// Check that all fields of the processing report match as expected
func _TestProcessorCheckSequential(t *testing.T, config *mitmengine.Config) {
	var tests = []struct {
		rawUa       string
		fingerprint string
		out         mitmengine.Report
	}{
		// Empty browser
		{"", "::::::", mitmengine.Report{Error: mitmengine.ErrorUnknownUserAgent}},
		// Microsoft Edge -- real browser fingerprint
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36 Edge/17.17134", "0303:c02c,c02b,c030,c02f,c024,c023,c028,c027,c00a,c009,c014,c013,9d,9c,3d,3c,35,2f,0a:00,05,0a,0b,0d,23,10,17,18,ff01:1d,17,18:00:*:", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		// Chrome 70 -- real browser fingerprint
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,17,1b,23,29,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.80 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		// Chrome 49 -- real browser fingerprint
		{"Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36", "303:0a,2f,33,35,39,9c,9e,ff,c009,c00a,c013,c014,c02b,c02f,cc13,cc14,cc15,cca8:0,5,a,b,d,10,12,15,17,23,3374,7550,ff01:17,18:0:*:", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		// MITM
		{"Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko", "303:c02b,c02f,c023,c027,c00a,c009,c014,c013,3d,3c,35,2f,a,ff:0,b,a,d:e,d,19,b,c,18,9,a,16,17,8,6,7,14,15,4,5,12,13,1,2,3,f,10,11:0,1,2:host,x-bluecoat-via:", mitmengine.Report{BrowserSignatureMatch: fp.MatchImpossible}},
	}
	a, _ := mitmengine.NewProcessor(config)
	var userAgent ua.UserAgent
	for _, test := range tests {
		userAgent.Reset()
		ua.ParseUserAgent(test.rawUa, &userAgent)
		uaFingerprint := fp.UAFingerprint{
			BrowserName:    int(userAgent.Browser.Name),
			BrowserVersion: fp.UAVersion(userAgent.Browser.Version),
			OSPlatform:     int(userAgent.OS.Platform),
			OSName:         int(userAgent.OS.Name),
			OSVersion:      fp.UAVersion(userAgent.OS.Version),
			DeviceType:     int(userAgent.DeviceType),
		}
		fingerprint, err := fp.NewRequestFingerprint(test.fingerprint)
		testutil.Ok(t, err)
		actual := a.Check(uaFingerprint, test.rawUa, fingerprint)
		checkCheckRequestForEquivalence(t, fingerprint, test.rawUa, actual, a)
		testutil.Equals(t, test.out.Error, actual.Error)
		testutil.Equals(t, test.out.BrowserSignatureMatch, actual.BrowserSignatureMatch)
	}
}

func _TestProcessorCheckConcurrent(t *testing.T, config *mitmengine.Config) {
	type testParam struct {
		rawUa       string
		fingerprint string
		out         mitmengine.Report
	}
	var tests = []testParam{
		{"", "::::::", mitmengine.Report{Error: mitmengine.ErrorUnknownUserAgent}},
		// The tests below are intended to force multiple lookups over the same value from db; this tests our locking over intsets stored in the db.
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36 Edge/17.17134", "0303:c02c,c02b,c030,c02f,c024,c023,c028,c027,c00a,c009,c014,c013,9d,9c,3d,3c,35,2f,0a:00,05,0a,0b,0d,23,10,17,18,ff01:1d,17,18:00:*:", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36", "303:0a,2f,33,35,39,9c,9e,ff,c009,c00a,c013,c014,c02b,c02f,cc13,cc14,cc15,cca8:0,5,a,b,d,10,12,15,17,23,3374,7550,ff01:17,18:0:*:", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36 Edge/17.17134", "0303:c02c,c02b,c030,c02f,c024,c023,c028,c027,c00a,c009,c014,c013,9d,9c,3d,3c,35,2f,0a:00,05,0a,0b,0d,23,10,17,18,ff01:1d,17,18:00:*:", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36", "303:0a,2f,33,35,39,9c,9e,ff,c009,c00a,c013,c014,c02b,c02f,cc13,cc14,cc15,cca8:0,5,a,b,d,10,12,15,17,23,3374,7550,ff01:17,18:0:*:", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36", "303:0a,2f,33,35,39,9c,9e,ff,c009,c00a,c013,c014,c02b,c02f,cc13,cc14,cc15,cca8:0,5,a,b,d,10,12,15,17,23,3374,7550,ff01:17,18:0:*:", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36", "303:0a,2f,33,35,39,9c,9e,ff,c009,c00a,c013,c014,c02b,c02f,cc13,cc14,cc15,cca8:0,5,a,b,d,10,12,15,17,23,3374,7550,ff01:17,18:0:*:", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,17,1b,23,29,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.80 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,17,1b,23,29,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.80 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,17,1b,23,29,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.80 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,17,1b,23,29,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.80 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36", "0303:0a,2f,35,9c,9d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9:00,05,0a,0b,0d,10,12,15,17,1b,23,2b,2d,33,7550,ff01:1d,17,18:00:*:grease", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		// Chrome 49 -- real browser fingerprint
		{"Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36", "303:0a,2f,33,35,39,9c,9e,ff,c009,c00a,c013,c014,c02b,c02f,cc13,cc14,cc15,cca8:0,5,a,b,d,10,12,15,17,23,3374,7550,ff01:17,18:0:*:", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36", "303:0a,2f,33,35,39,9c,9e,ff,c009,c00a,c013,c014,c02b,c02f,cc13,cc14,cc15,cca8:0,5,a,b,d,10,12,15,17,23,3374,7550,ff01:17,18:0:*:", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36", "303:0a,2f,33,35,39,9c,9e,ff,c009,c00a,c013,c014,c02b,c02f,cc13,cc14,cc15,cca8:0,5,a,b,d,10,12,15,17,23,3374,7550,ff01:17,18:0:*:", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36", "303:0a,2f,33,35,39,9c,9e,ff,c009,c00a,c013,c014,c02b,c02f,cc13,cc14,cc15,cca8:0,5,a,b,d,10,12,15,17,23,3374,7550,ff01:17,18:0:*:", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36", "303:0a,2f,33,35,39,9c,9e,ff,c009,c00a,c013,c014,c02b,c02f,cc13,cc14,cc15,cca8:0,5,a,b,d,10,12,15,17,23,3374,7550,ff01:17,18:0:*:", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36", "303:0a,2f,33,35,39,9c,9e,ff,c009,c00a,c013,c014,c02b,c02f,cc13,cc14,cc15,cca8:0,5,a,b,d,10,12,15,17,23,3374,7550,ff01:17,18:0:*:", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36", "303:0a,2f,33,35,39,9c,9e,ff,c009,c00a,c013,c014,c02b,c02f,cc13,cc14,cc15,cca8:0,5,a,b,d,10,12,15,17,23,3374,7550,ff01:17,18:0:*:", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36", "303:0a,2f,33,35,39,9c,9e,ff,c009,c00a,c013,c014,c02b,c02f,cc13,cc14,cc15,cca8:0,5,a,b,d,10,12,15,17,23,3374,7550,ff01:17,18:0:*:", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36 Edge/17.17134", "0303:c02c,c02b,c030,c02f,c024,c023,c028,c027,c00a,c009,c014,c013,9d,9c,3d,3c,35,2f,0a:00,05,0a,0b,0d,23,10,17,18,ff01:1d,17,18:00:*:", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36 Edge/17.17134", "0303:c02c,c02b,c030,c02f,c024,c023,c028,c027,c00a,c009,c014,c013,9d,9c,3d,3c,35,2f,0a:00,05,0a,0b,0d,23,10,17,18,ff01:1d,17,18:00:*:", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36", "303:0a,2f,33,35,39,9c,9e,ff,c009,c00a,c013,c014,c02b,c02f,cc13,cc14,cc15,cca8:0,5,a,b,d,10,12,15,17,23,3374,7550,ff01:17,18:0:*:", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36", "303:0a,2f,33,35,39,9c,9e,ff,c009,c00a,c013,c014,c02b,c02f,cc13,cc14,cc15,cca8:0,5,a,b,d,10,12,15,17,23,3374,7550,ff01:17,18:0:*:", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36", "303:0a,2f,33,35,39,9c,9e,ff,c009,c00a,c013,c014,c02b,c02f,cc13,cc14,cc15,cca8:0,5,a,b,d,10,12,15,17,23,3374,7550,ff01:17,18:0:*:", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36", "303:0a,2f,33,35,39,9c,9e,ff,c009,c00a,c013,c014,c02b,c02f,cc13,cc14,cc15,cca8:0,5,a,b,d,10,12,15,17,23,3374,7550,ff01:17,18:0:*:", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36", "303:0a,2f,33,35,39,9c,9e,ff,c009,c00a,c013,c014,c02b,c02f,cc13,cc14,cc15,cca8:0,5,a,b,d,10,12,15,17,23,3374,7550,ff01:17,18:0:*:", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36", "303:0a,2f,33,35,39,9c,9e,ff,c009,c00a,c013,c014,c02b,c02f,cc13,cc14,cc15,cca8:0,5,a,b,d,10,12,15,17,23,3374,7550,ff01:17,18:0:*:", mitmengine.Report{BrowserSignatureMatch: fp.MatchPossible}},
		{"Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko", "303:c02b,c02f,c023,c027,c00a,c009,c014,c013,3d,3c,35,2f,a,ff:0,b,a,d:e,d,19,b,c,18,9,a,16,17,8,6,7,14,15,4,5,12,13,1,2,3,f,10,11:0,1,2:host,x-bluecoat-via:", mitmengine.Report{BrowserSignatureMatch: fp.MatchImpossible}},
	}
	a, _ := mitmengine.NewProcessor(config)
	var wg sync.WaitGroup
	for _, test := range tests {
		wg.Add(1)
		go func(testP testParam) {
			defer wg.Done()
			var userAgent ua.UserAgent
			ua.ParseUserAgent(testP.rawUa, &userAgent)
			uaFingerprint := fp.UAFingerprint{
				BrowserName:    int(userAgent.Browser.Name),
				BrowserVersion: fp.UAVersion(userAgent.Browser.Version),
				OSPlatform:     int(userAgent.OS.Platform),
				OSName:         int(userAgent.OS.Name),
				OSVersion:      fp.UAVersion(userAgent.OS.Version),
				DeviceType:     int(userAgent.DeviceType),
			}
			fingerprint, err := fp.NewRequestFingerprint(testP.fingerprint)
			testutil.Ok(t, err)
			actual := a.Check(uaFingerprint, testP.rawUa, fingerprint)
			checkCheckRequestForEquivalence(t, fingerprint, testP.rawUa, actual, a)
			testutil.Equals(t, testP.out.Error, actual.Error)
			testutil.Equals(t, testP.out.BrowserSignatureMatch, actual.BrowserSignatureMatch)
		}(test)
	}
	wg.Wait()
}

func _TestProcessorGetByUASignatureBrowser(t *testing.T, config *mitmengine.Config) {
	file, err := mitmengine.LoadFile(config.BrowserFileName, config.Loader)
	testutil.Ok(t, err)
	a, err := db.NewDatabase(file)
	testutil.Ok(t, err)
	for _, record := range a.Records {
		uaFingerprint, err := uaSigToFin(record.UASignature)
		testutil.Ok(t, err)
		actual := a.GetByUAFingerprint(uaFingerprint)
		testutil.Assert(t, len(actual) > 0, fmt.Sprintf("no records found for '%s'", uaFingerprint))
	}
}

func _TestProcessorGetByRequestSignatureMitm(t *testing.T, config *mitmengine.Config) {
	file, err := mitmengine.LoadFile(config.MitmFileName, config.Loader)
	testutil.Ok(t, err)
	a, err := db.NewDatabase(file)
	testutil.Ok(t, err)
	for _, record := range a.Records {
		requestFingerprint, err := reqSigToFin(record.RequestSignature)
		testutil.Ok(t, err)
		actualRecordIds := a.GetByRequestFingerprint(requestFingerprint)
		testutil.Assert(t, len(actualRecordIds) > 0, fmt.Sprintf("no records found for '%s'", requestFingerprint))
		found := false
		for _, id := range actualRecordIds {
			if a.Records[id].MitmInfo.Match(record.MitmInfo) != fp.MatchImpossible {
				found = true
			}
		}
		testutil.Assert(t, found, fmt.Sprintf("no record found with matching mitm info for '%s'", record.MitmInfo.NameList.String()))
	}
}

func BenchmarkProcessorCheckSequential(b *testing.B) {
	testConfigFile := mitmengine.Config{
		BrowserFileName:   filepath.Join("reference_fingerprints", "mitmengine", "browser.txt"),
		MitmFileName:      filepath.Join("reference_fingerprints", "mitmengine", "mitm.txt"),
		BadHeaderFileName: filepath.Join("reference_fingerprints", "mitmengine", "badheader.txt"),
	}
	var t *testing.T
	for n := 0; n < b.N; n++ {
		_TestProcessorCheckSequential(t, &testConfigFile)
	}
}

func BenchmarkProcessorCheckConcurrent(b *testing.B) {
	testConfigFile := mitmengine.Config{
		BrowserFileName:   filepath.Join("reference_fingerprints", "mitmengine", "browser.txt"),
		MitmFileName:      filepath.Join("reference_fingerprints", "mitmengine", "mitm.txt"),
		BadHeaderFileName: filepath.Join("reference_fingerprints", "mitmengine", "badheader.txt"),
	}
	var t *testing.T
	for n := 0; n < b.N; n++ {
		_TestProcessorCheckConcurrent(t, &testConfigFile)
	}
}

// Double Check that CheckRequest yields the same answer if we can
func checkCheckRequestForEquivalence(t *testing.T, f1 fp.RequestFingerprint, rawUa string, r1 mitmengine.Report, a mitmengine.Processor) {
	
	if len(f1.Quirk) == 0 {
		req, chi := convertFingerprintToRequest(t,f1,rawUa)
		r2 := a.CheckRequest(req,chi)
		same := compareReports(t,r1,r2)
		if !same {
			t.Error("Given Fingerprint: " + f1.String())
			t.Error("Report 1 matched to Browser: " + r1.BrowserSignature)
			t.Error("Report 1 matched to Browser: " + r2.BrowserSignature)
			f2, err := fp.FingerprintClientHello(chi, req)
			if err != nil {
				t.Error("Error parsing ClientHello to get Report2's view of the fingerprint")
				t.Error(err)
			} else {
				t.Error("Report 2's view of the fingerprint is: ", f2.String())
			}
		}
		testutil.Equals(t, true, same)
	}

}

// Check if a report generated by Check() is equivalent to a report generated by CheckRequest
// Ignores Headers, Quirks and Extensions 
func compareReports(t *testing.T,checkReport mitmengine.Report,checkReportRequest mitmengine.Report) bool {
	ok := true
	
	// Check if either one hit an error
	if checkReport.Error != nil || checkReportRequest.Error != nil {
		if checkReportRequest.Error.Error() != checkReport.Error.Error() {
			t.Error("Error Mismatch")
			t.Error(checkReport.Error)
			t.Error(checkReportRequest.Error)
		}
		return checkReport.Error == checkReportRequest.Error
	}

	// Check if we got a different match with the less strict request version
	if checkReportRequest.BrowserSignature == checkReport.BrowserSignature {
		if (checkReportRequest.Reason != checkReport.Reason) {
			t.Error("Reason Mismatch")
			t.Error(checkReport.Reason)
			t.Error(checkReportRequest.Reason)

			ok = false	
			if (checkReportRequest.ReasonDetails != checkReport.ReasonDetails) {
				t.Error("Reason Details Mismatch")
				t.Error(checkReportRequest.ReasonDetails)
				t.Error(checkReport.ReasonDetails)
				t.Error(checkReportRequest.BrowserSignature)
				t.Error(checkReport.BrowserSignature)
			}
		}
	}

	// Check if each matched a compatible UA Signature
	if (checkReportRequest.MatchedUASignature != checkReport.MatchedUASignature) {
		m1, err := fp.NewUAFingerprint(checkReport.MatchedUASignature)
		if err == nil {
			var s2 fp.UASignature
			s2.Parse(checkReportRequest.MatchedUASignature)
			if s2.Match(m1) != fp.MatchPossible {
				t.Error("UA Signature Mismatch")
				t.Error(checkReportRequest.MatchedUASignature)
				t.Error(checkReport.MatchedUASignature)
				ok = false
			}
		} else {
			m2, err := fp.NewUAFingerprint(checkReportRequest.MatchedUASignature)
			if err == nil {
				var s1 fp.UASignature
				s1.Parse(checkReport.MatchedUASignature)
				if s1.Match(m2) != fp.MatchPossible {
					t.Error("UA Signature Mismatch")
					t.Error(checkReportRequest.MatchedUASignature)
					t.Error(checkReport.MatchedUASignature)
					ok = false
				}
			} else {
				t.Error("UA Signature Mismatch")
				t.Error(checkReportRequest.MatchedUASignature)
				t.Error(checkReport.MatchedUASignature)
				ok = false
			}
		}
	}

	if (checkReportRequest.BrowserGrade != checkReport.BrowserGrade) {
		t.Error("Browser Grade Mismatch")
		t.Error(checkReport.BrowserGrade)
		t.Error(checkReportRequest.BrowserGrade)
		ok = false
	}
	if (checkReportRequest.ActualGrade != checkReport.ActualGrade) {
		t.Error("Actual Grade Mismatch")
		t.Error(checkReport.ActualGrade)
		t.Error(checkReportRequest.ActualGrade)
		ok = false
	}
	if (checkReportRequest.WeakCiphers != checkReport.WeakCiphers) {
		t.Error("Weak Ciphers Mismatch")
		t.Error(checkReport.WeakCiphers)
		t.Error(checkReportRequest.WeakCiphers)
		ok = false
	}
	if (checkReportRequest.LosesPfs != checkReport.LosesPfs) {
		t.Error("Loses PFS Mismatch")
		t.Error(checkReport.LosesPfs)
		t.Error(checkReportRequest.LosesPfs)
		ok = false
	}
	if (checkReportRequest.MatchedMitmSignature != checkReport.MatchedMitmSignature) {
		t.Error("Matched Mitm Signature Mismatch")
		t.Error(checkReport.MatchedMitmSignature)
		t.Error(checkReportRequest.MatchedMitmSignature)
		ok = false
	}
	if (checkReportRequest.MatchedMitmName != checkReport.MatchedMitmName) {
		t.Error("Matched Mitm Name Mismatch")
		t.Error(checkReport.MatchedMitmName)
		t.Error(checkReportRequest.MatchedMitmName)
		ok = false
	}
	if (checkReportRequest.MatchedMitmType != checkReport.MatchedMitmType) {
		t.Error("Matched MITM Type Mismatch")
		t.Error(checkReport.MatchedMitmType)
		t.Error(checkReportRequest.MatchedMitmType)
		ok = false
	}
	return ok
}

// Convert test cases for Check() to work also for CheckRequest()
// Ignores Headers, Quirks and Extensions 
func convertFingerprintToRequest(t *testing.T,  f fp.RequestFingerprint, ua string) (*http.Request, *tls.ClientHelloInfo) {
	r, _ := http.NewRequest("GET", "https://example.com", nil)
	var chi tls.ClientHelloInfo

	// Copy over TLS Version 
	chi.SupportedVersions = []uint16{uint16(f.Version)}
	
	// Copy over CipherSuites
	curves := []tls.CurveID{}
	for _, curve := range f.Curve {
		curves = append(curves, tls.CurveID(curve))
	}
	chi.SupportedCurves = curves

	// Copy over Supported Point Formats
	points := []uint8{}
	for _, point := range f.EcPointFmt {
		points = append(points, uint8(point))
	}
	chi.SupportedPoints = points

	// Copy over Ciphers
	ciphers := []uint16{}
	for _, cipher := range f.Cipher {
		ciphers = append(ciphers, uint16(cipher))
	}
	chi.CipherSuites = ciphers

	// Copy over Headers
	r.Header.Set("User-Agent", ua)
	for _, header := range f.Header {
		r.Header.Set(header, "Dummy Value")
	}

	return r, &chi
}