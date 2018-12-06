package mitmengine_test

import (
	"bufio"
	"fmt"
	"github.com/cloudflare/mitmengine/loader"
	"os"
	"path/filepath"
	"regexp"
	"testing"

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
		BrowserFileName:   filepath.Join("testdata", "mitmengine", "browser_clickhouse.txt"),
		MitmFileName:      filepath.Join("testdata", "mitmengine", "mitm.txt"),
		BadHeaderFileName: filepath.Join("testdata", "mitmengine", "badheader.txt"),
	}
	t.Run("New", func(t *testing.T) { _, err := mitmengine.NewProcessor(&testConfigFile); testutil.Ok(t, err) })
	t.Run("Check", func(t *testing.T) { _TestProcessorCheck(t, &testConfigFile) })
	t.Run("GetByUASignatureBrowser", func(t *testing.T) { _TestProcessorGetByUASignatureBrowser(t, &testConfigFile) })
	t.Run("GetByRequestSignatureMitm", func(t *testing.T) { _TestProcessorGetByRequestSignatureMitm(t, &testConfigFile) })
	//t.Run("ProcessorKnownBrowserFingerprints", func(t *testing.T) { _TestProcessorKnownBrowserFingerprints(t, &testConfigFile)})
	//t.Run("ProcessorKnownMitmFingerprints", func(t *testing.T) { _TestProcessorKnownMitmFingerprints(t, &testConfigFile)})
}

// This test config tests the Loader interface that is implemented by the S3 struct. Anyone who
// contributes additional loaders can either add additional testConfigs here and/or write similar
// unit tests in the loader package.
func TestProcessorConfigS3(t *testing.T) {
	s3Instance, err := loader.NewS3Instance("s3cfg.toml")
	if err != nil {
		t.Skip("s3cfg.toml either does not exist in project root directory or loader directory, or was malformed")
	}
	testConfigS3 := mitmengine.Config{
		BrowserFileName:   "browser.txt",
		MitmFileName:      "mitm.txt",
		BadHeaderFileName: "badheader.txt",
		Loader:            s3Instance,
	}
	t.Run("New", func(t *testing.T) { _, err := mitmengine.NewProcessor(&testConfigS3); testutil.Ok(t, err) })
	t.Run("Check", func(t *testing.T) { _TestProcessorCheck(t, &testConfigS3) })
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

	file, err := os.Open(filepath.Join("testdata", "browser_fingerprints.txt"))
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
		testutil.Assert(t, report.BrowserSignatureMatch == fp.MatchPossible, fmt.Sprintf("exp: %v, got: %v", recordString, report))
	}
}

func _TestProcessorKnownMitmFingerprints(t *testing.T, config *mitmengine.Config) {
	a, _ := mitmengine.NewProcessor(config)

	file, err := os.Open(filepath.Join("testdata", "mitm_fingerprints.txt"))
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
		testutil.Assert(t, report.BrowserSignatureMatch != fp.MatchPossible, fmt.Sprintf("exp %s, got: %v", record.MitmInfo, report))
		var actualMitmNameList fp.StringList
		err = actualMitmNameList.Parse(report.MatchedMitmName)
		testutil.Ok(t, err)
		testutil.Assert(t, record.MitmInfo.Match(fp.MitmInfo{NameList: actualMitmNameList}) != fp.MatchImpossible, fmt.Sprintf("exp: %s, got: %v", record, report))
	}
}

// Check that all fields of the processing report match as expected
func _TestProcessorCheck(t *testing.T, config *mitmengine.Config) {
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
		testutil.Equals(t, test.out.Error, actual.Error)
		testutil.Equals(t, test.out.BrowserSignatureMatch, actual.BrowserSignatureMatch)
	}
}

func _TestProcessorGetByUASignatureBrowser(t *testing.T, config *mitmengine.Config) {
	file, err := mitmengine.LoadFile(config.BrowserFileName, config.Loader)
	testutil.Ok(t, err)
	a, err := db.NewDatabase(file)
	testutil.Ok(t, err)
	for _, record := range a.RecordMap {
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
	for _, record := range a.RecordMap {
		requestFingerprint, err := reqSigToFin(record.RequestSignature)
		testutil.Ok(t, err)
		actualRecordIds := a.GetByRequestFingerprint(requestFingerprint)
		testutil.Assert(t, len(actualRecordIds) > 0, fmt.Sprintf("no records found for '%s'", requestFingerprint))
		found := false
		for _, id := range actualRecordIds {
			if a.RecordMap[id].MitmInfo.Match(record.MitmInfo) != fp.MatchImpossible {
				found = true
			}
		}
		testutil.Assert(t, found, fmt.Sprintf("no record found with matching mitm info for '%s'", record.MitmInfo.NameList.String()))
	}
}

func BenchmarkProcessorCheck(b *testing.B) {
	testConfigFile := mitmengine.Config{
		BrowserFileName:   filepath.Join("testdata", "mitmengine", "browser.txt"),
		MitmFileName:      filepath.Join("testdata", "mitmengine", "mitm.txt"),
		BadHeaderFileName: filepath.Join("testdata", "mitmengine", "badheader.txt"),
	}
	var t *testing.T
	for n := 0; n < b.N; n++ {
		_TestProcessorCheck(t, &testConfigFile)
	}
}