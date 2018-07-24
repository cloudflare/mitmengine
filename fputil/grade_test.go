package fp_test

import (
	"testing"

	fp "github.com/cloudflare/mitmengine/fputil"
	"github.com/cloudflare/mitmengine/testutil"
)

func TestGradeString(t *testing.T) {
	var tests = []struct {
		in  fp.Grade
		out string
	}{
		{fp.GradeEmpty, "empty"},
		{fp.GradeA, "A"},
		{fp.GradeB, "B"},
		{fp.GradeC, "C"},
		{fp.GradeF, "F"},
		{fp.Grade(255), "Grade(255)"},
	}

	for _, test := range tests {
		actual := test.in.String()
		testutil.Equals(t, test.out, actual)
	}
}

func TestGradeMerge(t *testing.T) {
	var tests = []struct {
		in1 fp.Grade
		in2 fp.Grade
		out fp.Grade
	}{
		{fp.GradeEmpty, fp.GradeEmpty, fp.GradeEmpty},
		{fp.GradeA, fp.GradeEmpty, fp.GradeA},
		{fp.GradeA, fp.GradeB, fp.GradeB},
		{fp.GradeB, fp.GradeA, fp.GradeB},
		{fp.GradeF, fp.GradeC, fp.GradeF},
		{fp.GradeF, fp.GradeF, fp.GradeF},
	}

	for _, test := range tests {
		actual := test.in1.Merge(test.in2)
		testutil.Equals(t, test.out, actual)
	}
}
