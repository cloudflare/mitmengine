package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/cloudflare/mitmengine"
	"github.com/cloudflare/mitmengine/db"
)

var outDir = filepath.Join("mergedb")
var mitmConfig = mitmengine.Config{
	BrowserFileName:   filepath.Join("testdata", "mitmengine", "browser.txt"),
	MitmFileName:      filepath.Join("testdata", "mitmengine", "mitm.txt"),
	BadHeaderFileName: filepath.Join("testdata", "mitmengine", "badheader.txt"),
}

func askUser(scanner *bufio.Scanner, message string) bool {
	fmt.Println(message)
	if !scanner.Scan() {
		log.Fatal("Aborting...")
	}
	switch scanner.Text() {
	case "y", "Y", "Yes", "yes":
		return true
	}
	return false
}

func main() {
	var err error
	var file *os.File
	mitmProcessor, err := mitmengine.NewProcessor(&mitmConfig)
	if err != nil {
		log.Fatal(err)
	}
	os.MkdirAll(outDir, 0777)

	scanner := bufio.NewScanner(os.Stdin)

	var before, after int
	if askUser(scanner, "Automatically merge browser database?") {
		size := len(mitmProcessor.BrowserDatabase.Records)
		total := size * size
		count := 0
		before, after = mitmProcessor.BrowserDatabase.MergeBy(func(r1, r2 db.Record) bool {
			count++
			if count%size == 0 {
				fmt.Printf("(%.2f)\r", (float32(count*100))/float32(total))
			}
			// Don't automatically merge across these values
			if !(r1.UASignature.BrowserName == r2.UASignature.BrowserName &&
				r1.UASignature.OSName == r2.UASignature.OSName &&
				r1.UASignature.OSVersion == r2.UASignature.OSVersion &&
				r1.UASignature.DeviceType == r2.UASignature.DeviceType &&
				r1.UASignature.Quirk.String() == r2.UASignature.Quirk.String() &&
				r1.RequestSignature.Version.String() == r2.RequestSignature.Version.String() &&
				r1.RequestSignature.Curve.String() == r2.RequestSignature.Curve.String() &&
				r1.RequestSignature.EcPointFmt.String() == r2.RequestSignature.EcPointFmt.String() &&
				r1.RequestSignature.Quirk.String() == r2.RequestSignature.Quirk.String()) {
				return false
			}
			merged := r1.RequestSignature.Merge(r2.RequestSignature)
			// Merge if one of the request signatures already contains the other.
			if r1.RequestSignature.String() == merged.String() || r2.RequestSignature.String() == merged.String() {
				return true
			}
			// Do not merge if the merged signature is too lenient
			if merged.Cipher.OrderedList == nil && merged.Cipher.OptionalSet.Len() > 10 {
				return false
			}
			if merged.Extension.OrderedList == nil && merged.Extension.OptionalSet.Len() > 10 {
				return false
			}
			return true
		})
		fmt.Printf("Before: %d, After: %d\n", before, after)
	}
	if askUser(scanner, "Manually merge browser database?") {
		before, after = mitmProcessor.BrowserDatabase.MergeBy(func(r1, r2 db.Record) bool {
			return askUser(scanner, fmt.Sprintf("in1: %s\nin2: %s\nout: %s\nMerge? ", r1, r2, r1.Merge(r2)))
		})
		fmt.Printf("Before: %d, After: %d\n", before, after)
	}
	fmt.Println("Dumping browser database")
	// dump browser database
	file, err = os.Create(filepath.Join(outDir, "browser.txt"))
	if err != nil {
		log.Fatal(err)
	}
	mitmProcessor.BrowserDatabase.Dump(file)

	if askUser(scanner, "Automatically merge mitm database?") {
		mitmProcessor.MitmDatabase.MergeBy(func(r1, r2 db.Record) bool { return r1.RequestSignature.String() == r2.RequestSignature.String() })
		mitmProcessor.MitmDatabase.MergeBy(func(r1, r2 db.Record) bool {
			return r1.RequestSignature.String() == r2.RequestSignature.String()
		})
	}
	if askUser(scanner, "Manually merge mitm database?") {
		mitmProcessor.MitmDatabase.MergeBy(func(r1, r2 db.Record) bool { return r1.RequestSignature.String() == r2.RequestSignature.String() })
		mitmProcessor.MitmDatabase.MergeBy(func(r1, r2 db.Record) bool {
			return askUser(scanner, fmt.Sprintf("in1: %s\nin2: %s\nout: %s\nMerge? ", r1, r2, r1.Merge(r2)))
		})
	}
	fmt.Println("Dumping mitm database")
	// dump mitm database
	file, err = os.Create(filepath.Join(outDir, "mitm.txt"))
	if err != nil {
		log.Fatal(err)
	}
	mitmProcessor.MitmDatabase.Dump(file)
	fmt.Println("Finished")
}
