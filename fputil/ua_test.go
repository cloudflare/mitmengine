package fp_test

import (
	"testing"

	fp "github.com/cloudflare/mitmengine/fputil"
	"github.com/cloudflare/mitmengine/testutil"
)

func TestNewUAFingerprint(t *testing.T) {
	var tests = []struct {
		in  string
		out fp.UAFingerprint
	}{
		{"0:0.0.0:0:0:0.0.0:0:", fp.UAFingerprint{}},
		{"0::0:0::0:", fp.UAFingerprint{BrowserVersion: fp.UAVersion{-1, -1, -1}, OSVersion: fp.UAVersion{-1, -1, -1}}},
	}
	for _, test := range tests {
		fingerprint, err := fp.NewUAFingerprint(test.in)
		testutil.Ok(t, err)
		testutil.Equals(t, test.out, fingerprint)
	}
}

func TestUAFingerprintString(t *testing.T) {
	var tests = []struct {
		in  fp.UAFingerprint
		out string
	}{
		{fp.UAFingerprint{}, "0:0.0.0:0:0:0.0.0:0:"},
		{fp.UAFingerprint{BrowserVersion: fp.UAVersion{-1, -1, -1}, OSVersion: fp.UAVersion{-1, -1, -1}}, "0::0:0::0:"},
	}
	for _, test := range tests {
		testutil.Equals(t, test.out, test.in.String())
	}
}

func TestNewUASignature(t *testing.T) {
	var tests = []struct {
		in  string
		out fp.UASignature
	}{
		{"0:0.0.0:0:0:0.0.0:0:", fp.UASignature{}},
		{"0::0:0::0:", fp.UASignature{BrowserVersion: fp.UAVersionSignature{Min: fp.UAVersion{-1, -1, -1}, Max: fp.UAVersion{-1, -1, -1}}, OSVersion: fp.UAVersionSignature{Min: fp.UAVersion{-1, -1, -1}, Max: fp.UAVersion{-1, -1, -1}}}},
	}
	for _, test := range tests {
		uaSignature, err := fp.NewUASignature(test.in)
		testutil.Ok(t, err)
		testutil.Equals(t, test.out, uaSignature)
	}
}

func TestUASignatureString(t *testing.T) {
	var tests = []struct {
		in  fp.UASignature
		out string
	}{
		{fp.UASignature{}, "0:0.0.0:0:0:0.0.0:0:"},
		{fp.UASignature{BrowserVersion: fp.UAVersionSignature{Min: fp.UAVersion{-1, -1, -1}, Max: fp.UAVersion{-1, -1, -1}}, OSVersion: fp.UAVersionSignature{Min: fp.UAVersion{-1, -1, -1}, Max: fp.UAVersion{-1, -1, -1}}}, "0::0:0::0:"},
	}
	for _, test := range tests {
		testutil.Equals(t, test.out, test.in.String())
	}
}

func TestUASignatureMerge(t *testing.T) {
	var tests = []struct {
		in1 fp.UASignature
		in2 fp.UASignature
		out fp.UASignature
	}{
		{fp.UASignature{}, fp.UASignature{}, fp.UASignature{}},
	}
	for _, test := range tests {
		testutil.Equals(t, test.out, test.in1.Merge(test.in2))
	}
}

func TestUAVersionSignatureMerge(t *testing.T) {
	var tests = []struct {
		in1 fp.UAVersionSignature
		in2 fp.UAVersionSignature
		out fp.UAVersionSignature
	}{
		{fp.UAVersionSignature{}, fp.UAVersionSignature{}, fp.UAVersionSignature{}},
		{
			fp.UAVersionSignature{Min: fp.UAVersion{6, 1, 0}, Max: fp.UAVersion{6, 3, 0}},
			fp.UAVersionSignature{Min: fp.UAVersion{10, 0, 0}, Max: fp.UAVersion{10, 0, 0}},
			fp.UAVersionSignature{Min: fp.UAVersion{6, 1, 0}, Max: fp.UAVersion{10, 0, 0}},
		},
	}
	for _, test := range tests {
		testutil.Equals(t, test.out, test.in1.Merge(test.in2))
	}
}

func TestUASignatureMatch(t *testing.T) {
	var tests = []struct {
		in1 fp.UASignature
		in2 fp.UAFingerprint
		out fp.Match
	}{
		{fp.UASignature{}, fp.UAFingerprint{}, fp.MatchPossible},
	}
	for _, test := range tests {
		testutil.Equals(t, test.out, test.in1.Match(test.in2))
	}
}

func TestUAVersionSignatureMatch(t *testing.T) {
	var tests = []struct {
		in1 fp.UAVersionSignature
		in2 fp.UAVersion
		out fp.Match
	}{
		{fp.UAVersionSignature{}, fp.UAVersion{}, fp.MatchPossible},
		{
			fp.UAVersionSignature{Min: fp.UAVersion{6, 1, 0}, Max: fp.UAVersion{10, 0, 0}},
			fp.UAVersion{6, 1, 0},
			fp.MatchPossible,
		},
	}
	for _, test := range tests {
		testutil.Equals(t, test.out, test.in1.Match(test.in2))
	}
}
