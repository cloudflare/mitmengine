package fp_test

import (
	"testing"

	fp "github.com/cloudflare/mitmengine/fputil"
	"github.com/cloudflare/mitmengine/testutil"
)

func TestCipherCheckAnyTriviallyBroken(t *testing.T) {
	var tests = []struct {
		in  fp.IntList
		out bool
	}{
		{fp.IntList{}, false},
		{fp.IntList{0x00FF}, false},
		{fp.IntList{0x0000}, true},
		{fp.IntList{0x0003}, true},
		{fp.IntList{0x0004}, false},
		{fp.IntList{0xC02B}, false},
		{fp.IntList{0x00FF, 0xC02B}, false},
		{fp.IntList{0xC02B, 0x0004, 0x00FF}, false},
		{fp.IntList{0x00FF, 0xC02B, 0x0004}, false},
		{fp.IntList{0x0004, 0xC02B, 0x0003}, true},
	}

	check := fp.NewCipherCheck()
	for _, test := range tests {
		actual := check.AnyTriviallyBroken(test.in)
		testutil.Equals(t, test.out, actual)
	}
}

func TestCipherCheckAnyKnownAttack(t *testing.T) {
	var tests = []struct {
		in  fp.IntList
		out bool
	}{
		{fp.IntList{}, false},
		{fp.IntList{0x00FF}, false},
		{fp.IntList{0x0000}, true},
		{fp.IntList{0x0003}, true},
		{fp.IntList{0x0004}, true},
		{fp.IntList{0xC02B}, false},
		{fp.IntList{0x00FF, 0xC02B}, false},
		{fp.IntList{0xC02B, 0x0004, 0x00FF}, true},
		{fp.IntList{0x00FF, 0xC02B, 0x0004}, true},
		{fp.IntList{0x0004, 0xC02B, 0x0003}, true},
	}

	check := fp.NewCipherCheck()
	for _, test := range tests {
		actual := check.AnyKnownAttack(test.in)
		testutil.Equals(t, test.out, actual)
	}
}

func TestCipherCheckGrade(t *testing.T) {
	var tests = []struct {
		in  fp.IntList
		out fp.Grade
	}{
		{fp.IntList{}, fp.GradeEmpty},
		{fp.IntList{0x00FF}, fp.GradeEmpty},
		{fp.IntList{0x0000}, fp.GradeF},
		{fp.IntList{0x0003}, fp.GradeF},
		{fp.IntList{0x0004}, fp.GradeC},
		{fp.IntList{0xC02B}, fp.GradeA},
		{fp.IntList{0x00FF, 0xC02B}, fp.GradeA},
		{fp.IntList{0xC02B, 0x0004, 0x00FF}, fp.GradeC},
		{fp.IntList{0x00FF, 0xC02B, 0x0004}, fp.GradeC},
		{fp.IntList{0x0004, 0xC02B, 0x0003}, fp.GradeF},
	}

	check := fp.NewCipherCheck()
	for _, test := range tests {
		actual := check.Grade(test.in)
		testutil.Equals(t, test.out, actual)
	}
}

func TestCipherCheckIsFirstPfs(t *testing.T) {
	var tests = []struct {
		in  fp.IntList
		out bool
	}{
		{fp.IntList{}, false},
		{fp.IntList{0x00FF}, false},
		{fp.IntList{0x0000}, false},
		{fp.IntList{0x0003}, false},
		{fp.IntList{0x0004}, false},
		{fp.IntList{0xC02B}, true},
		{fp.IntList{0x00FF, 0xC02B}, true},
		{fp.IntList{0xC02B, 0x0004, 0x00FF}, true},
		{fp.IntList{0x00FF, 0xC02B, 0x0004}, true},
		{fp.IntList{0x0004, 0xC02B, 0x0003}, false},
	}

	check := fp.NewCipherCheck()
	for _, test := range tests {
		actual := check.IsFirstPfs(test.in)
		testutil.Equals(t, test.out, actual)
	}
}
