package fp_test

import (
	"testing"

	fp "github.com/cloudflare/mitmengine/fputil"
	"github.com/cloudflare/mitmengine/testutil"
)

func TestNewMitmInfo(t *testing.T) {
	var tests = []struct {
		in  string
		out fp.MitmInfo
	}{
		{":0:0", fp.MitmInfo{}},
		{"test:1:1", fp.MitmInfo{NameList: fp.StringList{"test"}, Type: fp.TypeAntivirus, Grade: fp.GradeA}},
		{"test1,test2:1:1", fp.MitmInfo{NameList: fp.StringList{"test1", "test2"}, Type: fp.TypeAntivirus, Grade: fp.GradeA}},
	}
	for _, test := range tests {
		info, err := fp.NewMitmInfo(test.in)
		testutil.Ok(t, err)
		testutil.Equals(t, test.out, info)
	}
}

func TestMitmInfoString(t *testing.T) {
	var tests = []struct {
		in  fp.MitmInfo
		out string
	}{
		{fp.MitmInfo{}, ":0:0"},
		{fp.MitmInfo{NameList: fp.StringList{"test"}, Type: fp.TypeAntivirus, Grade: fp.GradeA}, "test:1:1"},
		{fp.MitmInfo{NameList: fp.StringList{"test1", "test2"}, Type: fp.TypeAntivirus, Grade: fp.GradeA}, "test1,test2:1:1"},
	}
	for _, test := range tests {
		testutil.Equals(t, test.out, test.in.String())
	}
}

func TestMitmInfoMerge(t *testing.T) {
	var tests = []struct {
		in1 fp.MitmInfo
		in2 fp.MitmInfo
		out fp.MitmInfo
	}{
		{fp.MitmInfo{}, fp.MitmInfo{}, fp.MitmInfo{}},
	}
	for _, test := range tests {
		testutil.Equals(t, test.out, test.in1.Merge(test.in2))
	}
}

func TestMitmInfoMatch(t *testing.T) {
	var tests = []struct {
		in1 fp.MitmInfo
		in2 fp.MitmInfo
		out fp.Match
	}{
		{fp.MitmInfo{}, fp.MitmInfo{}, fp.MatchPossible},
	}
	for _, test := range tests {
		testutil.Equals(t, test.out, test.in1.Match(test.in2))
	}
}
