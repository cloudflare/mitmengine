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
	testutil.Equals(t, 0, len(a.RecordMap))
	a.Add(db.Record{})
	testutil.Equals(t, 1, len(a.RecordMap))
	a.Add(db.Record{})
	testutil.Equals(t, 2, len(a.RecordMap))
}

func TestDatabaseClear(t *testing.T) {
	a, _ := db.NewDatabase(bytes.NewReader(nil))
	a.Add(db.Record{})
	a.Clear()
	testutil.Equals(t, 0, len(a.RecordMap))
	a.Add(db.Record{})
	testutil.Equals(t, 1, len(a.RecordMap))
}

func TestDatabaseGetByUAFingerprint(t *testing.T) {
	var tests = []struct {
		in  fp.UAFingerprint
		out []uint64
	}{
		{fp.UAFingerprint{}, []uint64(nil)},
		{fp.UAFingerprint{BrowserName: 1}, []uint64{0}},
		{fp.UAFingerprint{BrowserName: 2}, []uint64(nil)},
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
		out []uint64
	}{
		{fp.RequestFingerprint{}, []uint64(nil)},
		{fp.RequestFingerprint{Version: fp.VersionTLS12}, []uint64{0}},
		{fp.RequestFingerprint{Version: 2}, []uint64(nil)},
	}
	a, _ := db.NewDatabase(bytes.NewReader(nil))
	var record db.Record
	record.Parse("1:0:0:0:0:0:|303::::::|::")
	a.Add(record)
	for _, test := range tests {
		testutil.Equals(t, test.out, a.GetByRequestFingerprint(test.in))
	}
}
