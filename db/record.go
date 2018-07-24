package db

import (
	"fmt"
	"strings"

	fp "github.com/cloudflare/mitmengine/fputil"
)

// A Record is represents a software signature.
type Record struct {
	RequestSignature fp.RequestSignature
	UASignature      fp.UASignature
	MitmInfo         fp.MitmInfo
}

// Parse a record from a string, returning an error on failure.
func (a *Record) Parse(s string) error {
	split := strings.Split(s, "|")
	if len(split) != 3 {
		return fmt.Errorf("invalid record format: '%s'", s)
	}
	if err := a.UASignature.Parse(split[0]); err != nil {
		return err
	}
	if err := a.RequestSignature.Parse(split[1]); err != nil {
		return err
	}
	if err := a.MitmInfo.Parse(split[2]); err != nil {
		return err
	}
	return nil
}

// Return a string representation of a record.
func (a Record) String() string {
	return fmt.Sprintf("%s|%s|%s", a.UASignature, a.RequestSignature, a.MitmInfo)
}

// Merge two records into one.
func (a Record) Merge(b Record) (merged Record) {
	merged.RequestSignature = a.RequestSignature.Merge(b.RequestSignature)
	merged.UASignature = a.UASignature.Merge(b.UASignature)
	merged.MitmInfo = a.MitmInfo.Merge(b.MitmInfo)
	return merged
}
