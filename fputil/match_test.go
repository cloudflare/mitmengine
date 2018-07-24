package fp_test

import (
	"testing"

	fp "github.com/cloudflare/mitmengine/fputil"
	"github.com/cloudflare/mitmengine/testutil"
)

func TestMatchString(t *testing.T) {
	var tests = []struct {
		in  fp.Match
		out string
	}{
		{fp.MatchEmpty, "empty"},
		{fp.MatchImpossible, "impossible"},
		{fp.MatchUnlikely, "unlikely"},
		{fp.MatchPossible, "possible"},
		{fp.Match(255), "Match(255)"},
	}

	for _, test := range tests {
		actual := test.in.String()
		testutil.Equals(t, test.out, actual)
	}
}
