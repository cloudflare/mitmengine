package db

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	fp "github.com/cloudflare/mitmengine/fputil"
)

// A Database contains a collection of records containing software signatures.
type Database struct {
	CurrID    uint64
	RecordMap map[uint64]Record
}

// NewDatabase returns a new Database initialized from the configuration.
func NewDatabase(input io.Reader) (Database, error) {
	var a Database
	a.RecordMap = make(map[uint64]Record)
	err := a.Load(input)
	return a, err
}

// Load records from input into the database, and return an error on bad records.
func (a *Database) Load(input io.Reader) error {
	var record Record
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		recordString := scanner.Text()
		if idx := strings.IndexRune(recordString, '\t'); idx != -1 {
			// remove anything before a tab
			recordString = recordString[idx+1:]
		}
		if idx := strings.IndexRune(recordString, '#'); idx != -1 {
			// remove comments at end of lines
			recordString = recordString[:idx]
		}
		// remove any whitespace or quotes
		recordString = strings.Trim(strings.TrimSpace(recordString), "\"")
		if len(recordString) == 0 {
			continue // skip empty lines
		}
		if err := record.Parse(recordString); err != nil {
			return fmt.Errorf("unable to parse record: %s, %s", recordString, err)
		}
		a.Add(record)
	}
	return nil
}

// Add a single record to the database.
func (a *Database) Add(record Record) uint64 {
	a.RecordMap[a.CurrID] = record
	a.CurrID++
	return a.CurrID - 1
}

// Clear all records from the database.
func (a *Database) Clear() {
	for id := range a.RecordMap {
		delete(a.RecordMap, id)
	}
}

// Dump records in the database to output.
func (a Database) Dump(output io.Writer) error {
	for _, record := range a.RecordMap {
		_, err := fmt.Fprintln(output, record)
		if err != nil {
			return err
		}
	}
	return nil
}

// GetByRequestFingerprint returns all records in the database matching the
// request fingerprint.
func (a Database) GetByRequestFingerprint(requestFingerprint fp.RequestFingerprint) []uint64 {
	return a.GetBy(func(r Record) bool { return r.RequestSignature.Match(requestFingerprint) != fp.MatchImpossible })
}

// GetByUAFingerprint returns all records in the database matching the
// user agent fingerprint.
func (a Database) GetByUAFingerprint(uaFingerprint fp.UAFingerprint) []uint64 {
	return a.GetBy(func(r Record) bool { return r.UASignature.Match(uaFingerprint) != fp.MatchImpossible })
}

// GetBy returns a list of records for which GetBy returns true.
func (a Database) GetBy(getFunc func(Record) bool) []uint64 {
	var recordIds []uint64
	for id, record := range a.RecordMap {
		if getFunc(record) {
			recordIds = append(recordIds, id)
		}
	}
	return recordIds
}

// DeleteBy deletes records for which rmFunc returns true.
func (a *Database) DeleteBy(deleteFunc func(Record) bool) {
	recordIds := a.GetBy(deleteFunc)
	for _, id := range recordIds {
		delete(a.RecordMap, id)
	}
}

// MergeBy merges records for which mergeFunc returns true.
func (a *Database) MergeBy(mergeFunc func(Record, Record) bool) (int, int) {
	before := len(a.RecordMap)
	for id1 := range a.RecordMap {
		for id2 := range a.RecordMap {
			if id1 == id2 {
				continue
			}
			// retrieve record1 in each loop iteration in case it changed
			record1 := a.RecordMap[id1]
			record2 := a.RecordMap[id2]
			if mergeFunc(record1, record2) {
				a.RecordMap[id1] = record1.Merge(record2)
				// If elements are deleted from the map during the iteration, they will not be produced.
				// https://golang.org/ref/spec#For_statements
				delete(a.RecordMap, id2)
			}
		}
	}
	return before, len(a.RecordMap)
}
