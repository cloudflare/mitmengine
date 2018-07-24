package fp

import (
	"fmt"
	"strconv"
	"strings"
)

// Sources:
//  - https://jhalderm.com/pub/papers/interception-ndss17.pdf
const (
	TypeEmpty uint8 = iota
	TypeAntivirus
	TypeFakeBrowser
	TypeMalware
	TypeParental
	TypeProxy
)

// MitmInfo contains information about mitm software.
type MitmInfo struct {
	NameList StringList
	Type     uint8
	Grade    Grade
}

// String returns a string representation of the mitm info.
func (a MitmInfo) String() string {
	return fmt.Sprintf("%s:%d:%d", a.NameList, a.Type, a.Grade)
}

// NewMitmInfo returns a new MitmInfo struct parsed from a string.
func NewMitmInfo(s string) (MitmInfo, error) {
	var a MitmInfo
	err := a.Parse(s)
	return a, err
}

// Parse info from a string and return an error on failure.
func (a *MitmInfo) Parse(s string) error {
	var i int
	var err error
	fields := strings.Split(s, ":")
	if len(fields) != 3 {
		return fmt.Errorf("invalid mitm info: '%s'", s)
	}
	if err := a.NameList.Parse(fields[0]); err != nil {
		return err
	}
	// simplify mitm names
	for idx, elem := range a.NameList {
		elem = strings.ToLower(strings.Replace(elem, "-", "", -1))
		for _, mitmName := range mitmNames {
			if strings.Contains(elem, mitmName) {
				elem = mitmName
				break
			}
		}
		a.NameList[idx] = elem
	}
	i, err = strconv.Atoi(fields[1])
	if err != nil {
		return err
	}
	a.Type = uint8(i)
	i, err = strconv.Atoi(fields[2])
	if err != nil {
		return err
	}
	a.Grade = Grade(i)
	return nil
}

// Merge mitm info a and b.
func (a MitmInfo) Merge(b MitmInfo) MitmInfo {
	var merged MitmInfo
	if a.NameList == nil && b.NameList == nil {
		merged.NameList = nil
	} else {
		merged.NameList = (a.NameList.Set().Union(b.NameList.Set())).List()
	}
	if a.Type == b.Type {
		merged.Type = a.Type
	} else {
		merged.Type = TypeEmpty
	}
	merged.Grade = a.Grade.Merge(b.Grade)
	return merged
}

// Match returns MatchPossible if the lists of mitm names are exactly the same
// or share a common mitm name, and returns MatchImpossible otherwise.
func (a MitmInfo) Match(b MitmInfo) Match {
	if a.NameList.String() == b.NameList.String() || len(a.NameList.Set().Inter(b.NameList.Set())) > 0 {
		return MatchPossible
	}
	return MatchImpossible
}

// known HTTPS interception software vendors
var mitmNames = []string{
	"avast",
	"avg",
	"barracuda",
	"bitdefender",
	"bluecoat",
	"bullguard",
	"chromodo",
	"ciscows",
	"citrix",
	"cybersitter",
	"drweb",
	"eset",
	"forcepoint",
	"fortigate",
	"gdata",
	"hidemyip",
	"junipersrx",
	"kaspersky",
	"keepmyfamilysecure",
	"hidemyip",
	"kindergate",
	"komodiasuperfish",
	"microsofttmg",
	"netnanny",
	"pcpandora",
	"privdog",
	"qustodio",
	"sophos",
	"staffcop",
	"untangle",
	"wajam",
	"webtitan",
	"adguard",
}
