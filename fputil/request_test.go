package fp_test

import (
	"crypto/tls"
	"net/http"
	"strings"
	"testing"

	fp "github.com/cloudflare/mitmengine/fputil"
	"github.com/cloudflare/mitmengine/testutil"
)

var (
	emptyVersionSig = fp.VersionSignature{}
	emptyIntSig     = fp.IntSignature{fp.IntList{}, &fp.IntSet{}, &fp.IntSet{}, &fp.IntSet{}, &fp.IntSet{}}
	emptyStringSig  = fp.StringSignature{
		OrderedList: fp.StringList{},
		OptionalSet: make(fp.StringSet),
		UnlikelySet: make(fp.StringSet),
		ExcludedSet: make(fp.StringSet),
		RequiredSet: make(fp.StringSet),
	}
	anyStringSig = fp.StringSignature{
		OrderedList: nil,
		OptionalSet: nil,
		UnlikelySet: make(fp.StringSet),
		ExcludedSet: make(fp.StringSet),
		RequiredSet: make(fp.StringSet),
	}
)

func TestNewRequestFingerprint(t *testing.T) {
	var tests = []struct {
		in  string
		out fp.RequestFingerprint
	}{
		{"::::::", fp.RequestFingerprint{}},
	}
	for _, test := range tests {
		fingerprint, err := fp.NewRequestFingerprint(test.in)
		testutil.Ok(t, err)
		testutil.Equals(t, test.out, fingerprint)
	}
}

func TestRequestFingerprintString(t *testing.T) {
	var tests = []struct {
		in  fp.RequestFingerprint
		out string
	}{
		{fp.RequestFingerprint{}, "::::::"},
	}
	for _, test := range tests {
		testutil.Equals(t, test.out, test.in.String())
	}
}

func TestNewRequestSignature(t *testing.T) {
	var tests = []struct {
		str string
		sig fp.RequestSignature
	}{
		{"::::::", fp.RequestSignature{
			Version:    emptyVersionSig,
			Cipher:     emptyIntSig,
			Extension:  emptyIntSig,
			Curve:      emptyIntSig,
			EcPointFmt: emptyIntSig,
			Header:     emptyStringSig,
			Quirk:      emptyStringSig,
		}},
	}
	for _, test := range tests {
		sig, err := fp.NewRequestSignature(test.str)
		testutil.Ok(t, err)
		testutil.Equals(t, test.sig, sig)
	}
}

func TestRequestSignatureString(t *testing.T) {
	var tests = []struct {
		in  fp.RequestSignature
		out string
	}{
		{fp.RequestSignature{
			Version:    emptyVersionSig,
			Cipher:     emptyIntSig,
			Extension:  emptyIntSig,
			Curve:      emptyIntSig,
			EcPointFmt: emptyIntSig,
			Header:     emptyStringSig,
			Quirk:      emptyStringSig,
		}, "::::::"},
	}
	for _, test := range tests {
		testutil.Equals(t, test.out, test.in.String())
	}
}

func TestRequestSignatureMerge(t *testing.T) {
	var tests = []struct {
		in1 string
		in2 string
		out string
	}{
		{"::::::", "::::::", "::::::"},
		{":*:*:*:*:*:*", ":*:*:*:*:*:*", ":*:*:*:*:*:*"},
	}
	for _, test := range tests {
		signature1, err := fp.NewRequestSignature(test.in1)
		testutil.Equals(t, nil, err)
		signature2, err := fp.NewRequestSignature(test.in2)
		testutil.Equals(t, nil, err)
		testutil.Equals(t, test.out, signature1.Merge(signature2).String())
	}
}

// todo fill this function out
func TestVersionSignatureMerge(t *testing.T) {
	var tests = []struct {
		in1 string
		in2 string
		out string
	}{}
	for _, test := range tests {
		signature1, err := fp.NewIntSignature(test.in1)
		testutil.Ok(t, err)
		signature2, err := fp.NewIntSignature(test.in2)
		testutil.Ok(t, err)
		testutil.Equals(t, test.out, signature1.Merge(signature2).String())
	}
}

func TestIntSignatureMerge(t *testing.T) {
	var tests = []struct {
		in1 string
		in2 string
		out string
	}{
		{"", "", ""},
		{"*", "1", "*"},
		{"*", "1,^2", "*"},
		{"*^2", "1,^2", "*^2"},
		{"1,2", "2,1", "~1,2"},
		{"1,2", "1,2,3", "1,2,?3"},
		{"1,4", "2,3", "?1,?4,?2,?3"},
		{"1,2", "3,2,1", "~1,2,?3"},
		{"1,2", "3,1,2", "?3,1,2"},
	}
	for _, test := range tests {
		signature1, err := fp.NewIntSignature(test.in1)
		testutil.Ok(t, err)
		signature2, err := fp.NewIntSignature(test.in2)
		testutil.Ok(t, err)
		testutil.Equals(t, test.out, signature1.Merge(signature2).String())
	}
}

func TestStringSignatureMerge(t *testing.T) {
	var tests = []struct {
		in1 string
		in2 string
		out string
	}{
		{"", "", ""},
		{"*", "1", "*"},
		{"*", "1,^2", "*"},
		{"*^2", "1,^2", "*^2"},
		{"1,2", "2,1", "~1,2"},
		{"1,2", "1,2,3", "1,2,?3"},
		{"1,4", "2,3", "?1,?4,?2,?3"},
		{"1,2", "3,2,1", "~1,2,?3"},
		{"1,2", "3,1,2", "?3,1,2"},
	}
	for _, test := range tests {
		signature1, err := fp.NewStringSignature(test.in1)
		testutil.Ok(t, err)
		signature2, err := fp.NewStringSignature(test.in2)
		testutil.Ok(t, err)
		testutil.Equals(t, test.out, signature1.Merge(signature2).String())
	}
}

func TestRequestSignatureMatch(t *testing.T) {
	var tests = []struct {
		in1 string
		in2 string
		out fp.Match
	}{
		{"::::::", "::::::", fp.MatchPossible},
		{":*:*:*:*:*:*", "::::::", fp.MatchPossible},
	}
	for _, test := range tests {
		signature, err := fp.NewRequestSignature(test.in1)
		testutil.Ok(t, err)
		fingerprint, err := fp.NewRequestFingerprint(test.in2)
		testutil.Ok(t, err)
		signatureMatch, _ := signature.Match(fingerprint)
		testutil.Equals(t, signatureMatch, test.out)
	}
}

func TestVersionSignatureMatch(t *testing.T) {
	var tests = []struct {
		in1 string
		in2 string
		out fp.Match
	}{
		{"", "303", fp.MatchPossible},   // match anything
		{",,", "303", fp.MatchPossible}, // long version, match anything
		{"0200", "200", fp.MatchPossible},
		{"2", "200", fp.MatchPossible},
		{"200,200,302", "301", fp.MatchPossible},
		{"200,302,302", "301", fp.MatchUnlikely},
		{"302,302,302", "301", fp.MatchImpossible},
		{"200,200,301", "302", fp.MatchImpossible},
	}
	for _, test := range tests {
		signature, err := fp.NewVersionSignature(test.in1)
		testutil.Ok(t, err)
		fingerprint, err := fp.NewVersion(test.in2)
		testutil.Ok(t, err)
		testutil.Equals(t, signature.Match(fingerprint), test.out)
	}
}

func TestIntSignatureMatch(t *testing.T) {
	var tests = []struct {
		in1 string
		in2 string
		out fp.Match
	}{
		{"", "", fp.MatchPossible},
		{"*", "1", fp.MatchPossible},
		{"*", "1,2", fp.MatchPossible},
		{"*1,^2", "1,2", fp.MatchImpossible},
		{"*1,^2", "1", fp.MatchPossible},
		{"~1,2", "2,1", fp.MatchPossible},
		{"~1,^2", "1,2", fp.MatchImpossible},
		{"1,2", "2,1", fp.MatchImpossible},
		{"1,?2", "2,1", fp.MatchImpossible},
		{"~1,?2", "2,1", fp.MatchPossible},
		{"1,2", "1,2,3", fp.MatchImpossible},
		{"1,2,?3", "1,2,3", fp.MatchPossible},
		{"*1,2", "1,2,3", fp.MatchPossible},
		{"*1,2", "3,2,1", fp.MatchPossible},
		{"?1,2,?3", "1,2", fp.MatchPossible},
		{"?1,2,?3", "2,3", fp.MatchPossible},
		{"?1,2,?3", "1,3", fp.MatchImpossible},
	}
	for _, test := range tests {
		signature, err := fp.NewIntSignature(test.in1)
		testutil.Ok(t, err)
		fingerprint, err := fp.NewIntList(test.in2)
		testutil.Ok(t, err)
		match, _ := signature.Match(fingerprint)
		testutil.Equals(t, test.out, match)
	}
}

func TestStringSignatureMatch(t *testing.T) {
	var tests = []struct {
		in1 string
		in2 string
		out fp.Match
	}{
		{"", "", fp.MatchPossible},
		{"*", "1", fp.MatchPossible},
		{"*", "1,2", fp.MatchPossible},
		{"*1,^2", "1,2", fp.MatchImpossible},
		{"*1,^2", "1", fp.MatchPossible},
		{"~1,2", "2,1", fp.MatchPossible},
		{"~1,^2", "1,2", fp.MatchImpossible},
		{"1,2", "2,1", fp.MatchImpossible},
		{"1,?2", "2,1", fp.MatchImpossible},
		{"~1,?2", "2,1", fp.MatchPossible},
		{"1,2", "1,2,3", fp.MatchImpossible},
		{"1,2,?3", "1,2,3", fp.MatchPossible},
		{"*1,2", "1,2,3", fp.MatchPossible},
		{"*1,2", "3,2,1", fp.MatchPossible},
		{"?1,2,?3", "1,2", fp.MatchPossible},
		{"?1,2,?3", "2,3", fp.MatchPossible},
		{"?1,2,?3", "1,3", fp.MatchImpossible},
		{"!1", "1", fp.MatchUnlikely},
		{"*!1", "1", fp.MatchUnlikely},
		{"!1,2,?3", "1,2", fp.MatchUnlikely},
	}
	for _, test := range tests {
		signature1, err := fp.NewStringSignature(test.in1)
		testutil.Ok(t, err)
		signature2, err := fp.NewStringList(test.in2)
		testutil.Ok(t, err)
		testutil.Equals(t, test.out, signature1.Match(signature2))
	}
}

func TestGrade(t *testing.T) {
	requestFingerprint := "0303:1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,9c,9d,2f,35,0a:~00,17,ff01,0a,0b,23,10,05,0d,12,33,2d,2b,1b,15:1d,17,18:00:*:grease"
	requestSignature, err := fp.NewRequestSignature(requestFingerprint)
	if err != nil {
		t.Fatal("request signature could not be parsed")
	}
	grade := requestSignature.Grade()
	testutil.Equals(t, fp.GradeA, grade)
}


func parseReqFingerprintString(t *testing.T, s string) fp.RequestFingerprint {
	parsed, err := fp.NewRequestFingerprint(s)
	testutil.Ok(t, err)
	return parsed
}

func populateClientHelloInfo(tlsVersions []uint16, ecPoints []uint8, ciphers []uint16, curves []tls.CurveID) (*tls.ClientHelloInfo) {
	var chi tls.ClientHelloInfo
	chi.SupportedPoints = ecPoints
	chi.CipherSuites = ciphers
	chi.SupportedCurves = curves
	chi.SupportedVersions = tlsVersions
	return &chi
}

func populateRequest(headers []string) (*http.Request) {
	r, _ := http.NewRequest("GET", "https://example.com", nil)
	for _, header := range headers{
		r.Header.Set(strings.Split(header, "|")[0],strings.Split(header, "|")[1])
	}
	return r
}

func TestFingerprintClientHello(t *testing.T) {
	var tests = []struct{
		chi 	*tls.ClientHelloInfo
		r 		*http.Request
		out 	fp.RequestFingerprint
	}{
		{
			//Normal
			populateClientHelloInfo(
				[]uint16{uint16(0x0200), uint16(0x0300), uint16(0x0301), uint16(0x0302), uint16(0x0303), uint16(0x0304), uint16(0x0A0A), uint16(0x7f14)},
				[]uint8{uint8(0x01)},
				[]uint16{uint16(0x1301),uint16(0x1302),uint16(0x1303),uint16(0xc02b),uint16(0x35)},
				[]tls.CurveID{tls.CurveID(0x1d),tls.CurveID(0x17),tls.CurveID(0x18)},
			), 
			populateRequest([]string{
				"User-Agent|blah (blah) blah",
			}),
			parseReqFingerprintString(t, "0304:1301,1302,1303,c02b,35:0a,0b:1d,17,18:01:user-agent:"),
		},
		{
			//Missing field
			populateClientHelloInfo(
				[]uint16{uint16(0x0200), uint16(0x0300), uint16(0x0301), uint16(0x0302), uint16(0x0303), uint16(0x0A0A), uint16(0x7f14)},
				[]uint8{},
				[]uint16{uint16(0x1301),uint16(0x1302),uint16(0x1303),uint16(0xc02b),uint16(0x35)},
				[]tls.CurveID{tls.CurveID(0x1d),tls.CurveID(0x17),tls.CurveID(0x18)},
			), 
			populateRequest([]string{
				"User-Agent|blah (blah) blah",
			}),
			parseReqFingerprintString(t, "0303:1301,1302,1303,c02b,35:0a:1d,17,18::user-agent:"),
		},
		{
			//Missing most fields
			populateClientHelloInfo(
				[]uint16{uint16(0x0200)},
				[]uint8{},
				[]uint16{},
				[]tls.CurveID{},
			), 
			populateRequest([]string{}),
			parseReqFingerprintString(t, "0200::::::"),
		},
	}
	var invalids = []struct{
		chi 	*tls.ClientHelloInfo
		r 		*http.Request
		err 	string
	}{ 
		{
			//Nil chi
			nil, 
			populateRequest([]string{
				"User-Agent|blah (blah) blah",
			}),
			"clientHello was nil",
		},
		{
			//Nil r
			populateClientHelloInfo(
				[]uint16{uint16(0x0200)},
				[]uint8{},
				[]uint16{},
				[]tls.CurveID{},
			), 
			nil,
			"httpRequest was nil",
		},
	}
	for _, test := range tests {
		fingerprint, err := fp.FingerprintClientHello(test.chi, test.r)
		testutil.Ok(t, err)
		testutil.Equals(t, fingerprint.String(), test.out.String())
	}
	for _, invalid := range invalids {
		_, err := fp.FingerprintClientHello(invalid.chi, invalid.r)
		testutil.Equals(t, err.Error(), invalid.err)
	}
}