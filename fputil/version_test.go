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
		{fp.VersionSSL2, "200"},
		{fp.VersionSSL3, "300"},
		{fp.VersionTLS10, "301"},
		{fp.VersionTLS11, "302"},
		{fp.VersionTLS12, "303"},
		{fp.VersionTLS13, "304"},
		{fp.Version(255), "ff"},
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
