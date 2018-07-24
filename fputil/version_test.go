package fp_test

import (
	"testing"

	fp "github.com/cloudflare/mitmengine/fputil"
	"github.com/cloudflare/mitmengine/testutil"
)

func TestVersionString(t *testing.T) {
	var tests = []struct {
		in  fp.Version
		out string
	}{
		{fp.VersionEmpty, ""},
		{fp.VersionSSL2, "2.0"},
		{fp.VersionSSL3, "3.0"},
		{fp.VersionTLS10, "3.1"},
		{fp.VersionTLS11, "3.2"},
		{fp.VersionTLS12, "3.3"},
		{fp.VersionTLS13, "3.4"},
		{fp.Version(255), "Version(255)"},
	}

	for _, test := range tests {
		actual := test.in.String()
		testutil.Equals(t, test.out, actual)
	}
}

func TestVersionGrade(t *testing.T) {
	var tests = []struct {
		in  fp.Version
		out fp.Grade
	}{
		{fp.VersionEmpty, fp.GradeEmpty},
		{fp.VersionSSL2, fp.GradeF},
		{fp.VersionSSL3, fp.GradeC},
		{fp.VersionTLS10, fp.GradeB},
		{fp.VersionTLS11, fp.GradeB},
		{fp.VersionTLS12, fp.GradeA},
		{fp.VersionTLS13, fp.GradeA},
		{fp.Version(255), fp.GradeF},
	}

	for _, test := range tests {
		actual := test.in.Grade()
		testutil.Equals(t, test.out, actual)
	}
}
