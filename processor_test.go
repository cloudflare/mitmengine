package mitmengine

import (
	"bufio"
	"fmt"
	"github.com/cloudflare/mitmengine/loader"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	ua "github.com/avct/uasurfer"
	"github.com/cloudflare/mitmengine/db"
	fp "github.com/cloudflare/mitmengine/fputil"
	"github.com/cloudflare/mitmengine/testutil"
)

var emptyConfig = Config{}

var testConfigFile = Config{
	BrowserFileName:   filepath.Join("testdata", "mitmengine", "browser.txt"),
	MitmFileName:      filepath.Join("testdata", "mitmengine", "mitm.txt"),
	BadHeaderFileName: filepath.Join("testdata", "mitmengine", "badheader.txt"),
}

// This test config tests the Loader interface that is extended by the S3 struct. Anyone who
// contributes additional loaders can either add additional testConfigs here and/or write similar
// unit tests in the loader package.
var testConfigS3 = Config{
	BrowserFileName:   "browser.txt",
	MitmFileName:      "mitm.txt",
	BadHeaderFileName: "badheader.txt",
}

func TestMain(m *testing.M) {
	// Setup for testConfigS3 (because loaer.NewS3Instance returns two values and thus cannot be called in a struct
	// declaration).
	// Only run if s3cfg.toml file exists in project root directory or loader directory.
	s3Instance, err := loader.NewS3Instance("s3cfg.toml")
	if err != nil {
		//t.Log("s3cfg.toml either does not exist in project root directory or loader directory, or was malformed")
		return
	}
	testConfigS3.Loader = s3Instance
	retCode := m.Run()
	os.Exit(retCode)
}

func uaSigToFin(signature fp.UASignature) (fp.UAFingerprint, error) {
	reg, _ := regexp.Compile("-[0-9.]*")
	return fp.NewUAFingerprint(reg.ReplaceAllString(signature.String(), ""))
}

func reqSigToFin(signature fp.RequestSignature) (fp.RequestFingerprint, error) {
	reg, _ := regexp.Compile("[*~!?]")
	max := signature.Version.Max
	signature.Version = fp.VersionSignature{max, max, max}
	return fp.NewRequestFingerprint(reg.ReplaceAllString(signature.String(), ""))
}

func TestNewProcessor(t *testing.T) {
	// Empty config
	_, err := NewProcessor(emptyConfig)
	testutil.Ok(t, err)
	// File config
	_, err = NewProcessor(testConfigFile)
	testutil.Ok(t, err)
	// Loader (s3, specifically) config
	_, err = NewProcessor(testConfigS3)
	testutil.Ok(t, err)
}

// Check that the fingerprints derived from pcaps match any updated signatures.
func _TestProcessorKnownBrowserFingerprints(t *testing.T) {
	a, _ := NewProcessor(testConfigFile)

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

func _TestProcessorKnownMitmFingerprints(t *testing.T) {
	a, _ := NewProcessor(testConfigFile)

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

// Functionality tests for config that specifies local files
func TestProcessorCheckConfigFile(t *testing.T) {
	_TestProcessorCheck(t, testConfigFile)
}

func TestProcessorGetByUASignatureBrowserConfigFile(t *testing.T) {
	_TestProcessorGetByUASignatureBrowser(t, testConfigFile)
}

func TestProcessorGetByRequestSignatureMitmConfigFile(t *testing.T) {
	_TestProcessorGetByRequestSignatureMitm(t, testConfigFile)
}

// Functionality tests for config that specifies files from s3 bucket
func TestProcessorCheckConfigS3(t *testing.T) {
	_TestProcessorCheck(t, testConfigS3)
}

func TestProcessorGetByUASignatureBrowserConfigS3(t *testing.T) {
	_TestProcessorGetByUASignatureBrowser(t, testConfigS3)
}

func TestProcessorGetByRequestSignatureMitmConfigS3(t *testing.T) {
	_TestProcessorGetByRequestSignatureMitm(t, testConfigS3)
}

// Check that all fields of the processing report match as expected
func _TestProcessorCheck(t *testing.T, config Config) {
	var tests = []struct {
		rawUa       string
		fingerprint string
		out         Report
	}{
		{"", "::::::", Report{Error: ErrorUnknownUserAgent}},
	}
	a, _ := NewProcessor(config)
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
		testutil.Equals(t, test.out, actual)
	}
}

func _TestProcessorGetByUASignatureBrowser(t *testing.T, config Config) {
	file, err := loadFile(config.BrowserFileName, config.Loader)
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

func _TestProcessorGetByRequestSignatureMitm(t *testing.T, config Config) {
	file, err := loadFile(config.MitmFileName, config.Loader)
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
