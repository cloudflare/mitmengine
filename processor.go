package mitmengine

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"github.com/cloudflare/mitmengine/db"
	"github.com/cloudflare/mitmengine/fputil"
	"github.com/cloudflare/mitmengine/loader"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

var (
	// ErrorUnknownUserAgent indicates that the user agent is not supported.
	ErrorUnknownUserAgent = errors.New("unknown_user_agent")
)

// A Processor generates heuristic-based man-in-the-middle (MiTM) detection
// reports for a TLS client hello and corresponding HTTP user agent.
type Processor struct {
	FileNameMap     map[string]string
	BrowserDatabase db.Database
	MitmDatabase    db.Database
	BadHeaderSet    fp.StringSet
}

// A Config contains information for initializing the processor such as the
// file names to read records from, as well as Loader information in the case
// the fingerprints are read from any datasource.
type Config struct {
	BrowserFileName   	string
	MitmFileName      	string
	BadHeaderFileName 	string
	Loader              loader.Loader
}

// NewProcessor returns a new Processor initialized from the config.
func NewProcessor(config Config) (Processor, error) {
	var a Processor
	err := a.Load(config)
	return a, err
}

// Load (or reload) the processor state from the provided configuration.
func (a *Processor) Load(config Config) error {
	browserFingerprints, err := loadFile(config.BrowserFileName, config.Loader)
	if err != nil {
		log.Printf("WARNING: loading file \"%s\" produced error \"%s\"", config.BrowserFileName, err)
		browserFingerprints = ioutil.NopCloser(bytes.NewReader(nil))
	}
	if a.BrowserDatabase, err = db.NewDatabase(browserFingerprints); err != nil {
		return err
	}
	browserFingerprints.Close()

	mitmFingerprints, err := loadFile(config.MitmFileName, config.Loader)
	if err != nil {
		log.Printf("WARNING: loading file \"%s\" produced error \"%s\"", config.MitmFileName, err)
		mitmFingerprints = ioutil.NopCloser(bytes.NewReader(nil))
	}
	if a.MitmDatabase, err = db.NewDatabase(mitmFingerprints); err != nil {
		return err
	}
	mitmFingerprints.Close()

	badHeaders, err := loadFile(config.BadHeaderFileName, config.Loader)
	if err != nil {
		log.Printf("WARNING: loading file \"%s\" produced error \"%s\"", config.BadHeaderFileName, err)
		badHeaders = ioutil.NopCloser(bytes.NewReader(nil))
	}
	scanner := bufio.NewScanner(badHeaders)
	var badHeaderList fp.StringList
	for scanner.Scan() {
		badHeaderList = append(badHeaderList, scanner.Text())
	}
	a.BadHeaderSet = badHeaderList.Set()
	badHeaders.Close()

	return nil
}

func loadFile (fileName string, dbReader loader.Loader) (io.ReadCloser, error) {
	var file io.ReadCloser
	var readErr error
	//log.Println("reader is", dbReader)
	if dbReader == nil { // read directly from file
		file, readErr = os.Open(fileName)
	} else {
		file, readErr = dbReader.LoadFile(fileName)
	}
	return file, readErr
}

// Check if the supplied client hello fields match the expected client hello
// fields for the the brower specified by the supplied user agent, and return a
// report including the mitm detection result, security details, and client
// hello fingerprints.
func (a *Processor) Check(uaFingerprint fp.UAFingerprint, rawUa string,
	actualReqFin fp.RequestFingerprint) Report {

	// Add user agent fingerprint quirks.
	if strings.Contains(rawUa, "Dragon/") {
		uaFingerprint.Quirk = append(uaFingerprint.Quirk, "dragon")
	}
	if strings.Contains(rawUa, "GSA/") {
		uaFingerprint.Quirk = append(uaFingerprint.Quirk, "gsa")
	}
	if strings.Contains(rawUa, "Silk-Accelerated=true") {
		uaFingerprint.Quirk = append(uaFingerprint.Quirk, "silk_accelerated")
	}
	if strings.Contains(rawUa, "PlayStation Vita") {
		uaFingerprint.Quirk = append(uaFingerprint.Quirk, "playstation")
	}

	// Remove grease ciphers, extensions, and curves from request fingerprint and add as quirk instead.
	hasGrease := false
	idx := 0
	for _, elem := range actualReqFin.Cipher {
		if (elem & 0x0f0f) == 0x0a0a {
			hasGrease = true
		} else {
			actualReqFin.Cipher[idx] = elem
			idx++
		}
	}
	actualReqFin.Cipher = actualReqFin.Cipher[:idx]
	idx = 0
	for _, elem := range actualReqFin.Extension {
		if (elem & 0x0f0f) == 0x0a0a {
			hasGrease = true
		} else {
			actualReqFin.Extension[idx] = elem
			idx++
		}
	}
	actualReqFin.Extension = actualReqFin.Extension[:idx]
	idx = 0
	for _, elem := range actualReqFin.Curve {
		if (elem & 0x0f0f) == 0x0a0a {
			hasGrease = true
		} else {
			actualReqFin.Curve[idx] = elem
			idx++
		}
	}
	actualReqFin.Curve = actualReqFin.Curve[:idx]
	if hasGrease {
		actualReqFin.Quirk = append(actualReqFin.Quirk, "grease")
	}

	// Check for 'bad' headers that browsers never send and add as quirk.
	hasBadHeader := false
	for _, elem := range actualReqFin.Header {
		if a.BadHeaderSet[elem] {
			hasBadHeader = true
		}
	}
	if hasBadHeader {
		actualReqFin.Quirk = append(actualReqFin.Quirk, "badhdr")
	}

	// Create mitm detection report
	var r Report

	// Find the browser record matching the user agent fingerprint
	browserRecordIds := a.BrowserDatabase.GetByUAFingerprint(uaFingerprint)
	if len(browserRecordIds) == 0 {
		return Report{Error: ErrorUnknownUserAgent}
	}
	var browserRecord db.Record
	match := false
	for _, id := range browserRecordIds {
		browserRecord = a.BrowserDatabase.RecordMap[id]
		if browserRecord.RequestSignature.Match(actualReqFin) == fp.MatchPossible {
			match = true
			break
		}
	}
	// use the first matched browser record, or otherwise the last browser record in the list
	browserReqSig := browserRecord.RequestSignature

	r.MatchedUASignature = browserRecord.UASignature.String()
	r.BrowserSignature = browserRecord.RequestSignature.String()
	r.BrowserGrade = browserReqSig.Grade()
	r.ActualGrade = actualReqFin.Version.Grade().Merge(fp.GlobalCipherCheck.Grade(actualReqFin.Cipher))

	// No need to add to the report if we have match.
	if match {
		r.BrowserSignatureMatch = fp.MatchPossible
		return r
	}

	// Find the heuristics that flagged the connection as invalid
	matchMap := browserReqSig.MatchMap(actualReqFin)
	var reason []string
	var reasonDetails []string
	switch {
	case matchMap["version"] == fp.MatchImpossible:
		r.BrowserSignatureMatch = fp.MatchImpossible
		reason = append(reason, "invalid_version")
		reasonDetails = append(reasonDetails, fmt.Sprintf("%s vs %s", browserReqSig.Version, actualReqFin.Version))
	case matchMap["cipher"] == fp.MatchImpossible:
		r.BrowserSignatureMatch = fp.MatchImpossible
		reason = append(reason, "invalid_cipher")
		reasonDetails = append(reasonDetails, fmt.Sprintf("%s vs %s", browserReqSig.Cipher, actualReqFin.Cipher))
	case matchMap["extension"] == fp.MatchImpossible:
		r.BrowserSignatureMatch = fp.MatchImpossible
		reason = append(reason, "invalid_extension")
		reasonDetails = append(reasonDetails, fmt.Sprintf("%s vs %s", browserReqSig.Extension, actualReqFin.Extension))
	case matchMap["curve"] == fp.MatchImpossible:
		r.BrowserSignatureMatch = fp.MatchImpossible
		reason = append(reason, "invalid_curve")
		reasonDetails = append(reasonDetails, fmt.Sprintf("%s vs %s", browserReqSig.Curve, actualReqFin.Curve))
	case matchMap["ecpointfmt"] == fp.MatchImpossible:
		r.BrowserSignatureMatch = fp.MatchImpossible
		reason = append(reason, "invalid_ecpointfmt")
		reasonDetails = append(reasonDetails, fmt.Sprintf("%s vs %s", browserReqSig.EcPointFmt, actualReqFin.EcPointFmt))
	case matchMap["header"] == fp.MatchImpossible:
		r.BrowserSignatureMatch = fp.MatchImpossible
		reason = append(reason, "invalid_header")
		reasonDetails = append(reasonDetails, fmt.Sprintf("%s vs %s", browserReqSig.Header, actualReqFin.Header))
	case matchMap["quirk"] == fp.MatchImpossible:
		r.BrowserSignatureMatch = fp.MatchImpossible
		reason = append(reason, "invalid_quirk")
		reasonDetails = append(reasonDetails, fmt.Sprintf("%s vs %s", browserReqSig.Quirk, actualReqFin.Quirk))
	// put 'unlikely' reasons after 'impossible' reasons
	case matchMap["version"] == fp.MatchUnlikely:
		r.BrowserSignatureMatch = fp.MatchUnlikely
		reason = append(reason, "unlikely_version")
		reasonDetails = append(reasonDetails, fmt.Sprintf("%s vs %s", browserReqSig.Version, actualReqFin.Version))
	case matchMap["cipher"] == fp.MatchUnlikely:
		r.BrowserSignatureMatch = fp.MatchUnlikely
		reason = append(reason, "unlikely_cipher")
		reasonDetails = append(reasonDetails, fmt.Sprintf("%s vs %s", browserReqSig.Cipher, actualReqFin.Cipher))
	case matchMap["extension"] == fp.MatchUnlikely:
		r.BrowserSignatureMatch = fp.MatchUnlikely
		reason = append(reason, "unlikely_extension")
		reasonDetails = append(reasonDetails, fmt.Sprintf("%s vs %s", browserReqSig.Extension, actualReqFin.Extension))
	case matchMap["curve"] == fp.MatchUnlikely:
		r.BrowserSignatureMatch = fp.MatchUnlikely
		reason = append(reason, "unlikely_curve")
		reasonDetails = append(reasonDetails, fmt.Sprintf("%s vs %s", browserReqSig.Curve, actualReqFin.Curve))
	case matchMap["ecpointfmt"] == fp.MatchUnlikely:
		r.BrowserSignatureMatch = fp.MatchUnlikely
		reason = append(reason, "unlikely_ecpointfmt")
		reasonDetails = append(reasonDetails, fmt.Sprintf("%s vs %s", browserReqSig.EcPointFmt, actualReqFin.EcPointFmt))
	case matchMap["header"] == fp.MatchUnlikely:
		r.BrowserSignatureMatch = fp.MatchUnlikely
		reason = append(reason, "unlikely_header")
		reasonDetails = append(reasonDetails, fmt.Sprintf("%s vs %s", browserReqSig.Header, actualReqFin.Header))
	case matchMap["quirk"] == fp.MatchUnlikely:
		r.BrowserSignatureMatch = fp.MatchUnlikely
		reason = append(reason, "unlikely_quirk")
		reasonDetails = append(reasonDetails, fmt.Sprintf("%s vs %s", browserReqSig.Quirk, actualReqFin.Quirk))
	default:
		r.BrowserSignatureMatch = fp.MatchPossible
	}
	r.Reason = strings.Join(reason, ",")
	r.ReasonDetails = strings.Join(reasonDetails, ",")

	// Check if MITM affects the connection security level
	switch r.BrowserSignatureMatch {
	case fp.MatchImpossible, fp.MatchUnlikely:
		if browserReqSig.IsPfs() && fp.GlobalCipherCheck.IsFirstPfs(actualReqFin.Cipher) {
			r.LosesPfs = true
		}
		mitmRecordIds := a.MitmDatabase.GetByRequestFingerprint(actualReqFin)
		if len(mitmRecordIds) == 0 {
			break
		}
		mitmRecord := a.MitmDatabase.RecordMap[mitmRecordIds[0]]
		r.ActualGrade = r.ActualGrade.Merge(mitmRecord.MitmInfo.Grade)
		r.MatchedMitmName = mitmRecord.MitmInfo.NameList.String()
		r.MatchedMitmType = mitmRecord.MitmInfo.Type
		r.MatchedMitmSignature = mitmRecord.RequestSignature.String()
	}

	return r
}
