package fp_test

import (
	"testing"

	fp "github.com/cloudflare/mitmengine/fputil"
	"github.com/cloudflare/mitmengine/testutil"
)

var (
	anyUAVersionFin = fp.UAVersion{-1, -1, -1}
	anyUAVersionSig = fp.UAVersionSignature{Min: anyUAVersionFin, Max: anyUAVersionFin}
)

func TestNewUAFingerprint(t *testing.T) {
	var tests = []struct {
		in  string
		out fp.UAFingerprint
	}{
		{"0:0.0.0:0:0:0.0.0:0:", fp.UAFingerprint{}},
		{"0::0:0::0:", fp.UAFingerprint{BrowserVersion: anyUAVersionFin, OSVersion: anyUAVersionFin}},
	}
	for _, test := range tests {
		fingerprint, err := fp.NewUAFingerprint(test.in)
		testutil.Ok(t, err)
		testutil.Equals(t, test.out, fingerprint)
	}
}

func parseUAFingerprintString(t *testing.T, s string) fp.UAFingerprint {
	parsed, err := fp.NewUAFingerprint(s)
	testutil.Ok(t, err)
	return parsed
}

func TestUAFingerprintFromUserAgentString(t *testing.T) {
	var tests = []struct {
		out  fp.UAFingerprint
		in string
		desc string
	}{
		//real useragents from https://deviceatlas.com/blog/list-of-user-agent-strings
		{parseUAFingerprintString(t,"0:0.0.0:0:0:0.0.0:0:"), "", "Empty string"},
		{parseUAFingerprintString(t,"0:0.0.0:0:0:0.0.0:0:"), "Mozzarella?()();;/%^$@!~^`'\"|\\-_%2e><:", "Gibberish UA"},
		{parseUAFingerprintString(t,"0:0.0.0:3:10:0.0.0:1:"), "Mozilla/5.0 (X11; Ubuntu; Plan-9 x86_128; rv:15.0) Lizard/20100101 Firefox/15.0.1", "Odd"},
		{parseUAFingerprintString(t,"4:15.0.1:3:10:0.0.0:1:"), "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:15.0) Gecko/20100101 Firefox/15.0.1", "Firefox on Linux"},
		{parseUAFingerprintString(t,"1:47.0.2526:1:2:6.1.0:1:"), "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36", "Chrome on Win7"},
		{parseUAFingerprintString(t,"2:12.246.0:1:2:10.0.0:1:"), "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246", "Edge on Win10"},
		{parseUAFingerprintString(t,"1:51.0.2704:3:7:0.0.0:1:"), "Mozilla/5.0 (X11; CrOS x86_64 8172.45.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.64 Safari/537.36", "Chromebook"},
		{parseUAFingerprintString(t,"3:9.0.2:2:3:10.11.2:1:"), "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/601.3.9 (KHTML, like Gecko) Version/9.0.2 Safari/601.3.9", "Safari on OSX"},
		{parseUAFingerprintString(t,"1:58.0.3029:3:5:7.0.0:3:"), "Mozilla/5.0 (Linux; Android 7.0; SM-G930VC Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/58.0.3029.83 Mobile Safari/537.36", "Android"},
	}
	for _, test := range tests {
		parsedUA := fp.UAFingerprintFromUserAgentString(test.in)
		if test.out.String() != parsedUA.String() {
			t.Error("Expected", test.out.String(), "got", parsedUA.String(), "when parsing:", test.desc)
		}
		testutil.Equals(t, test.out.String(), parsedUA.String())
	}
}

func TestUAFingerprintString(t *testing.T) {
	var tests = []struct {
		in  fp.UAFingerprint
		out string
	}{
		{fp.UAFingerprint{}, "0:0.0.0:0:0:0.0.0:0:"},
		{fp.UAFingerprint{BrowserVersion: anyUAVersionFin, OSVersion: anyUAVersionFin}, "0::0:0::0:"},
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
		{"0:0.0.0:0:0:0.0.0:0:*", fp.UASignature{Quirk: anyStringSig}},
		{"0::0:0::0:*", fp.UASignature{BrowserVersion: anyUAVersionSig, OSVersion: anyUAVersionSig, Quirk: anyStringSig}},
		{"0:0.0.0:0:0:0.0.0:0:", fp.UASignature{Quirk: emptyStringSig}},
		{"0::0:0::0:", fp.UASignature{BrowserVersion: anyUAVersionSig, OSVersion: anyUAVersionSig, Quirk: emptyStringSig}},
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
		{fp.UASignature{}, "0:0.0.0:0:0:0.0.0:0:*"},
		{fp.UASignature{BrowserVersion: anyUAVersionSig, OSVersion: anyUAVersionSig}, "0::0:0::0:*"},
		{fp.UASignature{Quirk: emptyStringSig}, "0:0.0.0:0:0:0.0.0:0:"},
		{fp.UASignature{BrowserVersion: anyUAVersionSig, OSVersion: anyUAVersionSig, Quirk: emptyStringSig}, "0::0:0::0:"},
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
