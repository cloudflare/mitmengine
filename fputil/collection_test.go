package fp_test

import (
	"testing"

	fp "github.com/cloudflare/mitmengine/fputil"
	"github.com/cloudflare/mitmengine/testutil"
)

// Test IntList
func TestIntListParse(t *testing.T) {
	var tests = []struct {
		in  string
		out fp.IntList
	}{
		{"0", fp.IntList{0}},
		{"1,2,3", fp.IntList{1, 2, 3}},
	}

	for _, test := range tests {
		var actual fp.IntList
		err := actual.Parse(test.in)
		testutil.Ok(t, err)
		testutil.Equals(t, test.out, actual)
	}
}

func TestIntListString(t *testing.T) {
	var tests = []struct {
		in  fp.IntList
		out string
	}{
		{fp.IntList{0}, "0"},
		{fp.IntList{1, 2, 3}, "1,2,3"},
	}

	for _, test := range tests {
		actual := test.in.String()
		testutil.Equals(t, test.out, actual)
	}
}

func TestIntListContains(t *testing.T) {
	var tests = []struct {
		a   fp.IntList
		b   fp.IntList
		out bool
	}{
		{fp.IntList{0}, fp.IntList{0}, true},
		{fp.IntList{0}, fp.IntList{}, true},
		{fp.IntList{}, fp.IntList{}, true},
		{fp.IntList{0}, fp.IntList{1}, false},
		{fp.IntList{}, fp.IntList{1}, false},
		{fp.IntList{1, 2, 3}, fp.IntList{1, 3}, true},
		{fp.IntList{1, 2, 3}, fp.IntList{3, 1}, false},
		{fp.IntList{1, 2, 3}, fp.IntList{2, 3}, true},
		{fp.IntList{1, 2, 3}, fp.IntList{3, 2}, false},
		{fp.IntList{1, 2, 3}, fp.IntList{1, 2, 3}, true},
		{fp.IntList{1, 2, 3}, fp.IntList{1, 2, 3, 4}, false},
		{fp.IntList{1, 2, 3}, fp.IntList{1, 3, 2}, false},
	}

	for _, test := range tests {
		actual := test.a.Contains(test.b)
		testutil.Equals(t, test.out, actual)
	}
}

func TestIntListEquals(t *testing.T) {
	var tests = []struct {
		a   fp.IntList
		b   fp.IntList
		out bool
	}{
		{fp.IntList{0}, fp.IntList{0}, true},
		{fp.IntList{0}, fp.IntList{}, false},
		{fp.IntList{}, fp.IntList{}, true},
		{fp.IntList{0}, fp.IntList{1}, false},
		{fp.IntList{}, fp.IntList{1}, false},
		{fp.IntList{1, 2, 3}, fp.IntList{1, 3}, false},
		{fp.IntList{1, 2, 3}, fp.IntList{3, 1}, false},
		{fp.IntList{1, 2, 3}, fp.IntList{2, 3}, false},
		{fp.IntList{1, 2, 3}, fp.IntList{3, 2}, false},
		{fp.IntList{1, 2, 3}, fp.IntList{1, 2, 3}, true},
		{fp.IntList{1, 2, 3}, fp.IntList{1, 2, 3, 4}, false},
		{fp.IntList{1, 2, 3}, fp.IntList{1, 3, 2}, false},
	}

	for _, test := range tests {
		actual := test.a.Equals(test.b)
		testutil.Equals(t, test.out, actual)
	}
}

func TestIntListSet(t *testing.T) {
	var tests = []struct {
		in  fp.IntList
		out *fp.IntSet
	}{
		{fp.IntList{0}, fp.IntList{0}.Set()},
		{fp.IntList{1, 2, 3}, fp.IntList{1, 2, 3}.Set()},
	}

	for _, test := range tests {
		actual := test.in.Set()
		testutil.Equals(t, test.out, actual)
	}
}

// Test IntSet
func TestIntSetList(t *testing.T) {
	var tests = []struct {
		in  *fp.IntSet
		out fp.IntList
	}{
		{fp.IntList{}.Set(),fp.IntList{}},
		{fp.IntList{0}.Set(), fp.IntList{0}},
		{fp.IntList{1, 2, 3}.Set(), fp.IntList{1, 2, 3}},
	}

	for _, test := range tests {
		actual := test.in.List()
		testutil.Equals(t, test.out, actual)
	}
}

func TestIntSetInter(t *testing.T) {
	var tests = []struct {
		a   *fp.IntSet
		b   *fp.IntSet
		out *fp.IntSet
	}{
		{fp.IntList{}.Set(), fp.IntList{}.Set(), fp.IntList{}.Set()},
		{fp.IntList{0}.Set(), fp.IntList{0}.Set(), fp.IntList{0}.Set()},
		{fp.IntList{1, 2, 3}.Set(), fp.IntList{2, 3, 4}.Set(), fp.IntList{2, 3}.Set()},
	}

	for _, test := range tests {
		actual := test.a.Inter(test.b)
		// Use Equal function for sets, defined for intset.Sparse; deep equals (as defined in package testutil)
		// does not handle intset.Sparse correctly
		test.out.Equals(&actual.Sparse)
	}
}

func TestIntSetDiff(t *testing.T) {
	var tests = []struct {
		a   *fp.IntSet
		b   *fp.IntSet
		out *fp.IntSet
	}{
		{fp.IntList{}.Set(), fp.IntList{}.Set(), fp.IntList{}.Set()},
		{fp.IntList{0}.Set(), fp.IntList{0}.Set(), fp.IntList{}.Set()},
		{fp.IntList{1, 2, 3}.Set(), fp.IntList{2, 3, 4}.Set(), fp.IntList{1}.Set()},
	}

	for _, test := range tests {
		actual := test.a.Diff(test.b)
		// Use Equal function for sets, defined for intset.Sparse; deep equals (as defined in package testutil)
		// does not handle intset.Sparse correctly
		test.out.Equals(&actual.Sparse)
	}
}

func TestIntSetUnion(t *testing.T) {
	var tests = []struct {
		a   *fp.IntSet
		b   *fp.IntSet
		out *fp.IntSet
	}{
		{fp.IntList{}.Set(), fp.IntList{}.Set(), fp.IntList{}.Set()},
		{fp.IntList{0}.Set(), fp.IntList{0}.Set(), fp.IntList{0}.Set()},
		{fp.IntList{1, 2, 3}.Set(), fp.IntList{2, 3, 4}.Set(), fp.IntList{1, 2, 3, 4}.Set()},
	}

	for _, test := range tests {
		actual := test.a.Union(test.b)
		// Use Equal function for sets, defined for intset.Sparse; deep equals (as defined in package testutil)
		// does not handle intset.Sparse correctly
		test.out.Equals(&actual.Sparse)
	}
}

// Test StringList
func TestStringListParse(t *testing.T) {
	var tests = []struct {
		in  string
		out fp.StringList
	}{
		{"0", fp.StringList{"0"}},
		{"1,2,3", fp.StringList{"1", "2", "3"}},
	}

	for _, test := range tests {
		var actual fp.StringList
		err := actual.Parse(test.in)
		testutil.Ok(t, err)
		testutil.Equals(t, test.out, actual)
	}
}

func TestStringListString(t *testing.T) {
	var tests = []struct {
		in  fp.StringList
		out string
	}{
		{fp.StringList{"0"}, "0"},
		{fp.StringList{"1", "2", "3"}, "1,2,3"},
	}

	for _, test := range tests {
		actual := test.in.String()
		testutil.Equals(t, test.out, actual)
	}
}

func TestStringListContains(t *testing.T) {
	var tests = []struct {
		a   fp.StringList
		b   fp.StringList
		out bool
	}{
		{fp.StringList{"0"}, fp.StringList{"0"}, true},
		{fp.StringList{"0"}, fp.StringList{}, true},
		{fp.StringList{}, fp.StringList{}, true},
		{fp.StringList{"0"}, fp.StringList{"1"}, false},
		{fp.StringList{}, fp.StringList{"1"}, false},
		{fp.StringList{"1", "2", "3"}, fp.StringList{"1", "3"}, true},
		{fp.StringList{"1", "2", "3"}, fp.StringList{"3", "1"}, false},
		{fp.StringList{"1", "2", "3"}, fp.StringList{"2", "3"}, true},
		{fp.StringList{"1", "2", "3"}, fp.StringList{"3", "2"}, false},
		{fp.StringList{"1", "2", "3"}, fp.StringList{"1", "2", "3"}, true},
		{fp.StringList{"1", "2", "3"}, fp.StringList{"1", "2", "3", "4"}, false},
		{fp.StringList{"1", "2", "3"}, fp.StringList{"1", "3", "2"}, false},
	}

	for _, test := range tests {
		actual := test.a.Contains(test.b)
		testutil.Equals(t, test.out, actual)
	}
}

func TestStringListEquals(t *testing.T) {
	var tests = []struct {
		a   fp.StringList
		b   fp.StringList
		out bool
	}{
		{fp.StringList{"0"}, fp.StringList{"0"}, true},
		{fp.StringList{"0"}, fp.StringList{}, false},
		{fp.StringList{}, fp.StringList{}, true},
		{fp.StringList{"0"}, fp.StringList{"1"}, false},
		{fp.StringList{}, fp.StringList{"1"}, false},
		{fp.StringList{"1", "2", "3"}, fp.StringList{"1", "3"}, false},
		{fp.StringList{"1", "2", "3"}, fp.StringList{"3", "1"}, false},
		{fp.StringList{"1", "2", "3"}, fp.StringList{"2", "3"}, false},
		{fp.StringList{"1", "2", "3"}, fp.StringList{"3", "2"}, false},
		{fp.StringList{"1", "2", "3"}, fp.StringList{"1", "2", "3"}, true},
		{fp.StringList{"1", "2", "3"}, fp.StringList{"1", "2", "3", "4"}, false},
		{fp.StringList{"1", "2", "3"}, fp.StringList{"1", "3", "2"}, false},
	}

	for _, test := range tests {
		actual := test.a.Equals(test.b)
		testutil.Equals(t, test.out, actual)
	}
}

func TestStringListSet(t *testing.T) {
	var tests = []struct {
		in  fp.StringList
		out fp.StringSet
	}{
		{fp.StringList{"0"}, fp.StringSet{"0": true}},
		{fp.StringList{"1", "2", "3"}, fp.StringSet{"1": true, "2": true, "3": true}},
	}

	for _, test := range tests {
		actual := test.in.Set()
		testutil.Equals(t, test.out, actual)
	}
}

// Test StringSet
func TestStringSetList(t *testing.T) {
	var tests = []struct {
		in  fp.StringSet
		out fp.StringList
	}{
		{fp.StringSet{"0": true}, fp.StringList{"0"}},
		{fp.StringSet{"1": true, "2": true, "3": true}, fp.StringList{"1", "2", "3"}},
	}

	for _, test := range tests {
		actual := test.in.List()
		testutil.Equals(t, test.out, actual)
	}
}

func TestStringSetInter(t *testing.T) {
	var tests = []struct {
		a   fp.StringSet
		b   fp.StringSet
		out fp.StringSet
	}{
		{fp.StringSet{"0": true}, fp.StringSet{"0": true}, fp.StringSet{"0": true}},
		{fp.StringSet{"1": true, "2": true, "3": true}, fp.StringSet{"2": true, "3": true, "4": true}, fp.StringSet{"2": true, "3": true}},
	}

	for _, test := range tests {
		actual := test.a.Inter(test.b)
		testutil.Equals(t, test.out, actual)
	}
}

func TestStringSetDiff(t *testing.T) {
	var tests = []struct {
		a   fp.StringSet
		b   fp.StringSet
		out fp.StringSet
	}{
		{fp.StringSet{"0": true}, fp.StringSet{"0": true}, fp.StringSet{}},
		{fp.StringSet{"1": true, "2": true, "3": true}, fp.StringSet{"2": true, "3": true, "4": true}, fp.StringSet{"1": true}},
	}

	for _, test := range tests {
		actual := test.a.Diff(test.b)
		testutil.Equals(t, test.out, actual)
	}
}

func TestStringSetUnion(t *testing.T) {
	var tests = []struct {
		a   fp.StringSet
		b   fp.StringSet
		out fp.StringSet
	}{
		{fp.StringSet{"0": true}, fp.StringSet{"0": true}, fp.StringSet{"0": true}},
		{fp.StringSet{"1": true, "2": true, "3": true}, fp.StringSet{"2": true, "3": true, "4": true}, fp.StringSet{"1": true, "2": true, "3": true, "4": true}},
	}

	for _, test := range tests {
		actual := test.a.Union(test.b)
		testutil.Equals(t, test.out, actual)
	}
}
