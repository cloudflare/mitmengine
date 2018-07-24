package fp_test

import (
	"testing"

	fp "github.com/cloudflare/mitmengine/fputil"
	"github.com/cloudflare/mitmengine/testutil"
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
			Version:    fp.VersionSignature{},
			Cipher:     fp.IntSignature{fp.IntList{}, make(fp.IntSet), make(fp.IntSet), make(fp.IntSet), make(fp.IntSet)},
			Extension:  fp.IntSignature{fp.IntList{}, make(fp.IntSet), make(fp.IntSet), make(fp.IntSet), make(fp.IntSet)},
			Curve:      fp.IntSignature{fp.IntList{}, make(fp.IntSet), make(fp.IntSet), make(fp.IntSet), make(fp.IntSet)},
			EcPointFmt: fp.IntSignature{fp.IntList{}, make(fp.IntSet), make(fp.IntSet), make(fp.IntSet), make(fp.IntSet)},
			Header:     fp.StringSignature{fp.StringList{}, make(fp.StringSet), make(fp.StringSet), make(fp.StringSet), make(fp.StringSet)},
			Quirk:      fp.StringSignature{fp.StringList{}, make(fp.StringSet), make(fp.StringSet), make(fp.StringSet), make(fp.StringSet)},
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
			Version:    fp.VersionSignature{},
			Cipher:     fp.IntSignature{fp.IntList{}, make(fp.IntSet), make(fp.IntSet), make(fp.IntSet), make(fp.IntSet)},
			Extension:  fp.IntSignature{fp.IntList{}, make(fp.IntSet), make(fp.IntSet), make(fp.IntSet), make(fp.IntSet)},
			Curve:      fp.IntSignature{fp.IntList{}, make(fp.IntSet), make(fp.IntSet), make(fp.IntSet), make(fp.IntSet)},
			EcPointFmt: fp.IntSignature{fp.IntList{}, make(fp.IntSet), make(fp.IntSet), make(fp.IntSet), make(fp.IntSet)},
			Header:     fp.StringSignature{fp.StringList{}, make(fp.StringSet), make(fp.StringSet), make(fp.StringSet), make(fp.StringSet)},
			Quirk:      fp.StringSignature{fp.StringList{}, make(fp.StringSet), make(fp.StringSet), make(fp.StringSet), make(fp.StringSet)},
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
		testutil.Equals(t, test.out, signature.Match(fingerprint))
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
