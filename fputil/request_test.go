package fp_test

import (
	"testing"

	fp "github.com/cloudflare/mitmengine/fputil"
	"github.com/cloudflare/mitmengine/testutil"
)

var (
	emptyVersionSig = fp.VersionSignature{}
	emptyIntSig     = fp.IntSignature{fp.IntList{}, make(fp.IntSet), make(fp.IntSet), make(fp.IntSet), make(fp.IntSet)}
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
