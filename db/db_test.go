package db_test

import (
	"bytes"
	"testing"

	"github.com/cloudflare/mitmengine/db"
	fp "github.com/cloudflare/mitmengine/fputil"
	"github.com/cloudflare/mitmengine/testutil"
)

func TestNewDatabase(t *testing.T) {
	_, err := db.NewDatabase(bytes.NewReader(nil))
	testutil.Ok(t, err)
}

func TestDatabaseLoad(t *testing.T) {
	a, _ := db.NewDatabase(bytes.NewReader(nil))
	err := a.Load(bytes.NewReader(nil))
	testutil.Ok(t, err)
}

func TestDatabaseAdd(t *testing.T) {
	a, _ := db.NewDatabase(bytes.NewReader(nil))
	testutil.Equals(t, 0, a.Len())
	a.Add(db.Record{})
	testutil.Equals(t, 1, a.Len())
	a.Add(db.Record{})
	testutil.Equals(t, 2, a.Len())
}

func TestDatabaseClear(t *testing.T) {
	a, _ := db.NewDatabase(bytes.NewReader(nil))
	a.Add(db.Record{})
	a.Clear()
	testutil.Equals(t, 0, a.Len())
	a.Add(db.Record{})
	testutil.Equals(t, 1, a.Len())
}

func TestDatabaseGetByUAFingerprint(t *testing.T) {
	var tests = []struct {
		in  fp.UAFingerprint
		out []int
	}{
		{fp.UAFingerprint{}, []int(nil)},
		{fp.UAFingerprint{BrowserName: 1}, []int{0}},
		{fp.UAFingerprint{BrowserName: 2}, []int(nil)},
	}
	a, _ := db.NewDatabase(bytes.NewReader(nil))
	var record db.Record
	record.Parse("1:0:0:0:0:0:|::::::|::")
	a.Add(record)
	for _, test := range tests {
		testutil.Equals(t, test.out, a.GetByUAFingerprint(test.in))
	}
}

func TestDatabaseGetByRequestFingerprint(t *testing.T) {
	var tests = []struct {
		in  fp.RequestFingerprint
		out []int
	}{
		{fp.RequestFingerprint{}, []int(nil)},
		{fp.RequestFingerprint{Version: fp.VersionTLS12}, []int{0}},
		{fp.RequestFingerprint{Version: 2}, []int(nil)},
	}
	a, _ := db.NewDatabase(bytes.NewReader(nil))
	var record db.Record
	record.Parse("1:0:0:0:0:0:|303::::::|::")
	a.Add(record)
	for _, test := range tests {
		testutil.Equals(t, test.out, a.GetByRequestFingerprint(test.in))
	}
}
