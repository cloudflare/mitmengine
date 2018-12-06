package fp

import (
	"fmt"
	"strconv"
	"strings"

	ua "github.com/avct/uasurfer"
)

// User agent signature and fingerprint strings have the format
// 	<br-name>:<br-vers>:<os-plat>:<os-name>:<os-vers>:<dev-type>:<quirk>
//
// For fingerprints the parts have the formats
// <br-name>, <os-plat>, <os-name>, <dev-type>:
//	<int>
// <browser-vers>, <os-vers>:
//      <major>[.<minor>[.<patch>]]
// <quirk>:
//	<str-list>
// where <int> is a decimal-encoded int using constants defined in uasurfer, and
// <str-list> is a comma-separated list of strings.
//
// and for signatures the parts have the formats
// <br-name>, <os-plat>, <os-name>, <dev-type>:
//      <int>
// <browser-vers>, <os-vers>:
//      [<major>[.<minor>[.<patch>]]][-[<major>[.<minor>[.<patch>]]]]
// <quirk>:
//	same as in request.go
// where items in enclosed in square brackets are optional,

const anyVersion int = -1

const (
	uaFieldCount      int    = 7
	uaFieldSep        string = ":"
	uaVersionFieldSep string = "."
	uaVersionRangeSep string = "-"
)

// UAFingerprint is a fingerprint for a user agent
type UAFingerprint struct {
	BrowserName    int
	BrowserVersion UAVersion
	OSPlatform     int
	OSName         int
	OSVersion      UAVersion
	DeviceType     int
	Quirk          StringList
}

// NewUAFingerprint returns a new user agent fingerprint parsed from a string
func NewUAFingerprint(s string) (UAFingerprint, error) {
	var a UAFingerprint
	err := a.Parse(s)
	return a, err
}

// Parse a user agent fingerprint from a string and return an error on failure
func (a *UAFingerprint) Parse(s string) error {
	var err error
	fields := strings.Split(s, uaFieldSep)
	if len(fields) != uaFieldCount {
		return fmt.Errorf("bad ua field count '%s': exp %d, got %d", s, uaFieldCount, len(fields))
	}
	fieldIdx := 0
	if a.BrowserName, err = strconv.Atoi(fields[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++
	if err = a.BrowserVersion.Parse(fields[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++
	if a.OSPlatform, err = strconv.Atoi(fields[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++
	if a.OSName, err = strconv.Atoi(fields[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++
	if err = a.OSVersion.Parse(fields[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++
	if a.DeviceType, err = strconv.Atoi(fields[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++
	if err = a.Quirk.Parse(fields[fieldIdx]); err != nil {
		return err
	}
	return nil
}

// String returns a string representation of a fingerprint
func (a UAFingerprint) String() string {
	return strings.Join([]string{strconv.Itoa(a.BrowserName), a.BrowserVersion.String(), strconv.Itoa(a.OSPlatform), strconv.Itoa(a.OSName), a.OSVersion.String(), strconv.Itoa(a.DeviceType), a.Quirk.String()}, uaFieldSep)
}

// UAVersion represents a user agent browser or OS version.
type UAVersion ua.Version

// Parse a user agent version from a string and return an error on failure.
func (a *UAVersion) Parse(s string) error {
	var i int
	var err error
	a.Major = anyVersion
	a.Minor = anyVersion
	a.Patch = anyVersion
	if len(s) == 0 {
		return nil
	}
	fields := strings.Split(s, uaVersionFieldSep)
	switch len(fields) {
	case 3:
		if len(fields[2]) > 0 {
			i, err = strconv.Atoi(fields[2])
			if err != nil {
				return err
			}
			a.Patch = i
		}
		fallthrough
	case 2:
		if len(fields[1]) > 0 {
			i, err := strconv.Atoi(fields[1])
			if err != nil {
				return err
			}
			a.Minor = i
		}
		fallthrough
	case 1:
		if len(fields[0]) > 0 {
			i, err := strconv.Atoi(fields[0])
			if err != nil {
				return err
			}
			a.Major = i
		}
		return nil
	default:
		return fmt.Errorf("invalid user agent version format: '%s'", s)
	}
}

func (a UAVersion) String() string {
	var fields []string
	if a.Major != anyVersion {
		fields = append(fields, strconv.Itoa(a.Major))
		if a.Minor != anyVersion {
			fields = append(fields, strconv.Itoa(a.Minor))
			if a.Patch != anyVersion {
				fields = append(fields, strconv.Itoa(a.Patch))
			}
		}
	}
	return strings.Join(fields, uaVersionFieldSep)
}

// A UAVersionSignature matches a range of possible user agent versions
type UAVersionSignature struct {
	Min UAVersion
	Max UAVersion
}

func (a UAVersionSignature) String() string {
	if a.Min == a.Max {
		return a.Min.String()
	}
	return strings.Join([]string{a.Min.String(), a.Max.String()}, uaVersionRangeSep)
}

// Parse a user agent version signature from a string and return an error on failure.
func (a *UAVersionSignature) Parse(s string) error {
	fields := strings.SplitN(s, uaVersionRangeSep, 2)
	if err := a.Min.Parse(fields[0]); err != nil {
		return err
	}
	switch len(fields) {
	case 2:
		if err := a.Max.Parse(fields[1]); err != nil {
			return err
		}
	case 1:
		a.Max = a.Min
	}
	return nil
}

// minMatch returns true if fingerprint matches the min value
func (a UAVersion) minMatch(fingerprint UAVersion) bool {
	if a.Major == anyVersion || a.Major <= fingerprint.Major {
		return true
	}
	if a.Major > fingerprint.Major {
		return false
	}
	if a.Minor == anyVersion || a.Minor <= fingerprint.Minor {
		return true
	}
	if a.Minor > fingerprint.Minor {
		return false
	}
	if a.Patch == anyVersion || a.Patch <= fingerprint.Patch {
		return true
	}
	if a.Patch > fingerprint.Patch {
		return false
	}
	return true
}

// maxMatch returns true if fingerprint matches the max value
func (a UAVersion) maxMatch(fingerprint UAVersion) bool {
	if a.Major == anyVersion || a.Major >= fingerprint.Major {
		return true
	}
	if a.Major < fingerprint.Major {
		return false
	}
	if a.Minor == anyVersion || a.Minor >= fingerprint.Minor {
		return true
	}
	if a.Minor < fingerprint.Minor {
		return false
	}
	if a.Patch == anyVersion || a.Patch >= fingerprint.Patch {
		return true
	}
	if a.Patch < fingerprint.Patch {
		return false
	}
	return true
}

// Match a user agent fingerprint against the signature.
// Returns MatchImpossible if no match is possible, MatchUnlikely if the match
// is possible with an unlikely configuration, and MatchPossible otherwise.
func (a UAVersionSignature) Match(fingerprint UAVersion) Match {
	if a.Min.minMatch(fingerprint) && a.Max.maxMatch(fingerprint) {
		return MatchPossible
	}
	return MatchImpossible
}

// minMerge returns the min value of two versions.
func (a UAVersion) minMerge(b UAVersion) UAVersion {
	if a.Major == anyVersion || b.Major == anyVersion {
		return UAVersion{anyVersion, anyVersion, anyVersion}
	}
	if a.Major < b.Major {
		return a
	}
	if a.Major > b.Major {
		return b
	}
	if a.Minor == anyVersion || b.Minor == anyVersion {
		return UAVersion{a.Major, anyVersion, anyVersion}
	}
	if a.Minor < b.Minor {
		return a
	}
	if a.Minor > b.Minor {
		return b
	}
	if a.Patch == anyVersion || b.Patch == anyVersion {
		return UAVersion{a.Major, a.Minor, anyVersion}
	}
	if a.Patch < b.Patch {
		return a
	}
	if a.Patch > b.Patch {
		return b
	}
	return a
}

// maxMerge returns the max value of two versions.
func (a UAVersion) maxMerge(b UAVersion) UAVersion {
	if a.Major == anyVersion || b.Major == anyVersion {
		return UAVersion{anyVersion, anyVersion, anyVersion}
	}
	if a.Major > b.Major {
		return a
	}
	if a.Major < b.Major {
		return b
	}
	if a.Minor == anyVersion || b.Minor == anyVersion {
		return UAVersion{a.Major, anyVersion, anyVersion}
	}
	if a.Minor > b.Minor {
		return a
	}
	if a.Minor < b.Minor {
		return b
	}
	if a.Patch == anyVersion || b.Patch == anyVersion {
		return UAVersion{a.Major, a.Minor, anyVersion}
	}
	if a.Patch > b.Patch {
		return a
	}
	if a.Patch < b.Patch {
		return b
	}
	return a
}

// Merge signatures a and b to match fingerprints from both.
func (a UAVersionSignature) Merge(b UAVersionSignature) UAVersionSignature {
	return UAVersionSignature{Min: a.Min.minMerge(b.Min), Max: a.Max.maxMerge(b.Max)}
}

// A UASignature represents a set of user agents
type UASignature struct {
	BrowserName    int
	BrowserVersion UAVersionSignature
	OSPlatform     int
	OSName         int
	OSVersion      UAVersionSignature
	DeviceType     int
	Quirk          StringSignature
}

// Parse a user agent signature from a string and return an error on failure
func (a *UASignature) Parse(s string) error {
	var err error
	fields := strings.Split(s, uaFieldSep)
	if len(fields) != uaFieldCount {
		return fmt.Errorf("bad ua field count '%s': exp %d, got %d", s, uaFieldCount, len(fields))
	}
	fieldIdx := 0
	if a.BrowserName, err = strconv.Atoi(fields[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++
	if err = a.BrowserVersion.Parse(fields[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++
	if a.OSPlatform, err = strconv.Atoi(fields[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++
	if a.OSName, err = strconv.Atoi(fields[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++
	if err = a.OSVersion.Parse(fields[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++
	if a.DeviceType, err = strconv.Atoi(fields[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++
	if err = a.Quirk.Parse(fields[fieldIdx]); err != nil {
		return err
	}
	return nil
}

// NewUASignature returns a new user agent signature parsed from a string
func NewUASignature(s string) (UASignature, error) {
	var a UASignature
	err := a.Parse(s)
	return a, err
}

// String returns a string representation of a signature
func (a UASignature) String() string {
	return strings.Join([]string{strconv.Itoa(a.BrowserName), a.BrowserVersion.String(), strconv.Itoa(a.OSPlatform), strconv.Itoa(a.OSName), a.OSVersion.String(), strconv.Itoa(a.DeviceType), a.Quirk.String()}, uaFieldSep)
}

// Merge user agent signatures a and b to match fingerprints from both.
func (a UASignature) Merge(b UASignature) UASignature {
	var merged UASignature
	if a.BrowserName != b.BrowserName {
		merged.BrowserName = 0
		merged.BrowserVersion.Min = UAVersion{anyVersion, anyVersion, anyVersion}
		merged.BrowserVersion.Max = UAVersion{anyVersion, anyVersion, anyVersion}
	} else {
		merged.BrowserName = a.BrowserName
		merged.BrowserVersion = a.BrowserVersion.Merge(b.BrowserVersion)
	}
	if a.OSPlatform != b.OSPlatform {
		merged.OSPlatform = 0
	} else {
		merged.OSPlatform = a.OSPlatform
	}
	if a.OSName != b.OSName {
		merged.OSName = 0
		merged.OSVersion.Min = UAVersion{anyVersion, anyVersion, anyVersion}
		merged.OSVersion.Max = UAVersion{anyVersion, anyVersion, anyVersion}
	} else {
		merged.OSName = a.OSName
		merged.OSVersion = a.OSVersion.Merge(b.OSVersion)
	}
	if a.DeviceType != b.DeviceType {
		merged.DeviceType = 0
	} else {
		merged.DeviceType = a.DeviceType
	}
	merged.Quirk = a.Quirk.Merge(b.Quirk)
	return merged
}

// Match a user agent against the user agent signature.
// Returns MatchImpossible if no match is possible, MatchUnlikely if the match
// is possible with an unlikely configuration, and MatchPossible otherwise.
func (a UASignature) Match(fingerprint UAFingerprint) Match {
	if a.BrowserName != 0 && a.BrowserName != fingerprint.BrowserName {
		//fmt.Println("1", fingerprint)
		return MatchImpossible
	}
	if a.OSPlatform != 0 && a.OSPlatform != fingerprint.OSPlatform {
		//fmt.Println("2", fingerprint)
		return MatchImpossible
	}
	if a.OSName != 0 && a.OSName != fingerprint.OSName {
		//fmt.Println("3", fingerprint)
		return MatchImpossible
	}
	if a.DeviceType != 0 && a.DeviceType != fingerprint.DeviceType {
		//fmt.Println("4", fingerprint)
		return MatchImpossible
	}

	matchBrowserVersion := a.BrowserVersion.Match(fingerprint.BrowserVersion)
	matchOSVersion := a.OSVersion.Match(fingerprint.OSVersion)
	matchQuirk := a.Quirk.Match(fingerprint.Quirk)
	if matchBrowserVersion == MatchImpossible || matchOSVersion == MatchImpossible || matchQuirk == MatchImpossible {
		//fmt.Println("5", fingerprint)
		return MatchImpossible
	}
	if matchBrowserVersion == MatchUnlikely || matchOSVersion == MatchUnlikely || matchQuirk == MatchUnlikely {
		return MatchUnlikely
	}
	return MatchPossible
}
