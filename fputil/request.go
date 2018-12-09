package fp

import (
	"bytes"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Client request signature and fingerprint strings have the format
// 	<version>:<cipher>:<extension>:<curve>:<ecpointfmt>:<header>:<quirk>
//
// For fingerprints the parts have the formats
// <version>:
//	<vers>
// <cipher>, <extension>, <curve>, <ecpointfmt>:
//	<int-list>
// <header>, <quirk>:
//	<str-list>
// where <vers> is a TLS version ('', '2.0', '3.0', '3.1', '3.2', '3.3', '3.4')
// <int-list> is a comma-separated list of hex-encoded ints, and <str-list> is
// a comma-separated list of strings.
//
// and for signatures the parts have the formats
// <version>:
//      [<exp>|<min>,<exp>,<max>]
// <cipher>, <extension>, <curve>, <ecpointfmt>:
//	[*~][<[!?+]int-list>]
// <header>, <quirk>:
//	[*~][<[!?+]str-list>]
// where items in enclosed in square brackets are optional,
// <exp> is the expected TLS version, <min> is the minimum TLS version, <max> is the maximum TLS version,
// '*' and '~' are optional list prefixes, and '!' and '?' are optional list element prefixes.
//
// A list prefix can be one of the following options:
//         '*' means to allow extra items and any ordering of items
//         '~' means to allow any ordering of items
//         ''  means to enforce ordering of items (default)
//
// An item prefix can be one of the following options:
//	   '!' means the item is possible, but not expected (unlikely)
//	   '?' means the item is expected, but not required (optional)
//	   '^' means the item is excluded, and not possible (excluded)
//	   ''  means the item is required (default)

const (
	requestFieldCount int    = 7
	requestFieldSep   string = ":"
	fieldElemSep      string = ","
)
const (
	flagAnyItems byte = '*'
	flagAnyOrder byte = '~'
	flagUnlikely byte = '!'
	flagOptional byte = '?'
	flagExcluded byte = '^'
)

// A RequestFingerprint represents the features of a client request, including client
// hello features, http headers, and any additional quirks.
type RequestFingerprint struct {
	Version    Version
	Cipher     IntList
	Extension  IntList
	Curve      IntList
	EcPointFmt IntList
	Header     StringList
	Quirk      StringList
}

// NewRequestFingerprint is a wrapper around RequestFingerprint.Parse
func NewRequestFingerprint(s string) (RequestFingerprint, error) {
	var a RequestFingerprint
	err := a.Parse(s)
	return a, err
}

// Parse a fingerprint from a string and return an error on failure.
func (a *RequestFingerprint) Parse(s string) error {
	fields := strings.Split(s, requestFieldSep)
	if len(fields) != requestFieldCount {
		return fmt.Errorf("bad request field count '%s': exp %d, got %d", s, requestFieldCount, len(fields))
	}
	fieldIdx := 0
	if err := a.Version.Parse(fields[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++
	if err := a.Cipher.Parse(fields[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++
	if err := a.Extension.Parse(fields[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++
	if err := a.Curve.Parse(fields[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++
	if err := a.EcPointFmt.Parse(fields[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++
	if err := a.Header.Parse(fields[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++
	if err := a.Quirk.Parse(fields[fieldIdx]); err != nil {
		return err
	}
	return nil
}

// String returns a string representation of the fingerprint.
func (a RequestFingerprint) String() string {
	return strings.Join([]string{a.Version.String(), a.Cipher.String(), a.Extension.String(), a.Curve.String(), a.EcPointFmt.String(), a.Header.String(), a.Quirk.String()}, requestFieldSep)
}

// A RequestSignature represents a set of client request fingerprints. Many TLS/HTTPS
// implementations can be uniquely identified by their signatures.
type RequestSignature struct {
	Version    VersionSignature
	Cipher     IntSignature
	Extension  IntSignature
	Curve      IntSignature
	EcPointFmt IntSignature
	Header     StringSignature
	Quirk      StringSignature

	// non-exported fields
	pfs         bool
	pfsCached   bool
	grade       Grade
	gradeCached bool
}

// A VersionSignature is a signature for a TLS version.
type VersionSignature struct {
	Min Version
	Exp Version
	Max Version
}

// An IntSignature is a signature on a list of integers.
type IntSignature struct {
	OrderedList IntList
	RequiredSet *IntSet
	OptionalSet *IntSet
	UnlikelySet *IntSet
	ExcludedSet *IntSet
}

// A StringSignature is a signature on a list of strings.
type StringSignature struct {
	OrderedList StringList
	RequiredSet StringSet
	OptionalSet StringSet
	UnlikelySet StringSet
	ExcludedSet StringSet
}

// NewRequestSignature is a wrapper around RequestSignature.Parse
func NewRequestSignature(s string) (RequestSignature, error) {
	var a RequestSignature
	err := a.Parse(s)
	return a, err
}

// Parse a signature from a string and return an error on failure.
func (a *RequestSignature) Parse(s string) error {
	fields := strings.Split(s, requestFieldSep)
	if len(fields) != requestFieldCount {
		return fmt.Errorf("bad request field count '%s': exp %d, got %d", s, requestFieldCount, len(fields))
	}
	fieldIdx := 0
	if err := a.Version.Parse(fields[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++
	if err := a.Cipher.Parse(fields[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++
	if err := a.Extension.Parse(fields[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++
	if err := a.Curve.Parse(fields[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++
	if err := a.EcPointFmt.Parse(fields[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++
	if err := a.Header.Parse(fields[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++
	if err := a.Quirk.Parse(fields[fieldIdx]); err != nil {
		return err
	}
	return nil
}

// Grade returns the security grade for the request signature.
func (a *RequestSignature) Grade() Grade {
	if !a.gradeCached {
		a.grade = GlobalCipherCheck.Grade(a.Cipher.OrderedList)
		a.gradeCached = true
	}
	return a.grade
}

// IsPfs returns true if the request signature has perfect forward secrecy.
func (a *RequestSignature) IsPfs() bool {
	if !a.pfsCached {
		a.pfs = GlobalCipherCheck.IsFirstPfs(a.Cipher.OrderedList)
		a.pfsCached = true
	}
	return a.pfs
}

// Parse a version signature from a string and return an error on failure.
func (a *VersionSignature) Parse(s string) error {
	a.Min, a.Exp, a.Max = VersionEmpty, VersionEmpty, VersionEmpty
	if len(s) == 0 {
		return nil
	}
	fields := strings.Split(s, fieldElemSep)
	var err error
	switch len(fields) {
	case 1:
		if err = a.Min.Parse(fields[0]); err != nil {
			return err
		}
		a.Exp = a.Min
		a.Max = a.Min
	case 3:
		if err = a.Min.Parse(fields[0]); err != nil {
			return err
		}
		if err = a.Exp.Parse(fields[1]); err != nil {
			return err
		}
		if err = a.Max.Parse(fields[2]); err != nil {
			return err
		}
	default:
		return fmt.Errorf("invalid version format: '%s'", s)
	}
	// sanity check
	if a.Min != VersionEmpty {
		if a.Exp != VersionEmpty && a.Min > a.Exp {
			return fmt.Errorf("version: Min > Exp")
		}
		if a.Max != VersionEmpty && a.Min > a.Max {
			return fmt.Errorf("version: Min > Max")
		}
	}
	if a.Exp != VersionEmpty {
		if a.Max != VersionEmpty && a.Exp > a.Max {
			return fmt.Errorf("version: Exp > Max")
		}
	}
	return nil
}

// NewVersionSignature returns a new int signature parsed from a string.
func NewVersionSignature(s string) (VersionSignature, error) {
	var a VersionSignature
	err := a.Parse(s)
	return a, err
}

// NewIntSignature returns a new int signature parsed from a string.
func NewIntSignature(s string) (IntSignature, error) {
	var a IntSignature
	err := a.Parse(s)
	return a, err
}

// NewStringSignature returns a new string signature parsed from a string.
func NewStringSignature(s string) (StringSignature, error) {
	var a StringSignature
	err := a.Parse(s)
	return a, err
}

// Parse an int signature from a string and return an error on failure.
func (a *IntSignature) Parse(s string) error {
	a.OrderedList = IntList{}
	a.ExcludedSet = new(IntSet)
	a.UnlikelySet = new(IntSet)
	a.OptionalSet = new(IntSet)
	a.RequiredSet = new(IntSet)
	if len(s) == 0 {
		return nil
	}
	anyItems, anyOrder := false, false
	switch s[0] {
	case flagAnyItems:
		anyItems = true
		s = s[1:]
	case flagAnyOrder:
		anyOrder = true
		s = s[1:]
	}
	var split []string
	if len(s) > 0 {
		split = strings.Split(s, fieldElemSep)
	}
	for _, v := range split {
		if len(v) == 0 {
			return fmt.Errorf("invalid int signature format: '%s'", s)
		}
		flag := v[0]
		switch flag {
		case flagOptional, flagUnlikely, flagExcluded:
			v = v[1:]
		}
		elem64bit, err := strconv.ParseUint(v, 16, 16)
		elem := int(elem64bit)
		if err != nil {
			return err
		}
		switch flag {
		case flagOptional:
			a.OptionalSet.Insert(elem)
		case flagUnlikely:
			a.UnlikelySet.Insert(elem)
		case flagExcluded:
			a.ExcludedSet.Insert(elem)
			continue // do not add to ordered list
		default:
			a.RequiredSet.Insert(elem)
		}
		a.OrderedList = append(a.OrderedList, elem)
	}
	if anyItems {
		// allow any order and any optional items
		// still check for required, unlikely, and excluded items
		a.OrderedList = nil
		a.OptionalSet = new(IntSet) // todo can replace with clear?
	}
	if anyOrder {
		// allow any order
		a.OrderedList = nil
	}
	return nil
}

// Parse a string signature from a string and return an error on failure.
func (a *StringSignature) Parse(s string) error {
	a.OrderedList = StringList{}
	a.UnlikelySet = make(StringSet)
	a.OptionalSet = make(StringSet)
	a.ExcludedSet = make(StringSet)
	a.RequiredSet = make(StringSet)
	if len(s) == 0 {
		return nil
	}
	anyItems, anyOrder := false, false
	switch s[0] {
	case flagAnyItems:
		anyItems = true
		s = s[1:]
	case flagAnyOrder:
		anyOrder = true
		s = s[1:]
	}
	var split []string
	if len(s) > 0 {
		split = strings.Split(s, fieldElemSep)
	}
	for _, v := range split {
		if len(v) == 0 {
			return fmt.Errorf("invalid int signature format: '%s'", s)
		}
		flag := v[0]
		switch flag {
		case flagOptional, flagUnlikely, flagExcluded:
			v = v[1:]
		}
		switch flag {
		case flagOptional:
			a.OptionalSet[v] = true
		case flagUnlikely:
			a.UnlikelySet[v] = true
		case flagExcluded:
			a.ExcludedSet[v] = true
			continue // do not add to ordered list
		default:
			a.RequiredSet[v] = true
		}
		a.OrderedList = append(a.OrderedList, v)
	}
	if anyItems {
		// allow any order and any optional items
		// still check for required, unlikely, and excluded items
		a.OrderedList = nil
		a.OptionalSet = nil
	}
	if anyOrder {
		// allow any order
		a.OrderedList = nil
	}
	return nil
}

// Returns a string representation of the signature.
func (a RequestSignature) String() string {
	return strings.Join([]string{a.Version.String(), a.Cipher.String(), a.Extension.String(), a.Curve.String(), a.EcPointFmt.String(), a.Header.String(), a.Quirk.String()}, requestFieldSep)
}

// Return a string representation of the version signature.
func (a VersionSignature) String() string {
	if a.Min == a.Exp && a.Max == a.Exp {
		return a.Exp.String()
	}
	return strings.Join([]string{a.Exp.String(), a.Min.String(), a.Max.String()}, fieldElemSep)
}

// String returns a string representation of the int signature.
func (a IntSignature) String() string {
	var buf bytes.Buffer
	var list IntList

	if a.OrderedList != nil {
		// element ordering is strict
		list = a.OrderedList
	} else {
		if a.RequiredSet.Len() == 0 {
			buf.WriteByte(flagAnyItems)
		} else {
			buf.WriteByte(flagAnyOrder)
		}
		list = append(list, a.RequiredSet.List()...)
		list = append(list, a.OptionalSet.List()...)
		list = append(list, a.UnlikelySet.List()...)
	}
	list = append(list, a.ExcludedSet.List()...)
	if a.OrderedList == nil {
		sort.Slice(list, func(a, b int) bool { return list[a] < list[b] })
	}
	for idx, elem := range list {
		if idx != 0 {
			buf.WriteString(fieldElemSep)
		}
		switch {
		case a.OptionalSet.Has(elem):
			buf.WriteByte(flagOptional)
		case a.UnlikelySet.Has(elem):
			buf.WriteByte(flagUnlikely)
		case a.ExcludedSet.Has(elem):
			buf.WriteByte(flagExcluded)
		}
		buf.WriteString(fmt.Sprintf("%x", elem))
	}
	return buf.String()
}

// String returns a string representation of the string signature.
func (a StringSignature) String() string {
	var buf bytes.Buffer
	var list StringList

	if a.OrderedList != nil {
		// element ordering is strict
		list = a.OrderedList
	} else {
		if a.OptionalSet == nil {
			buf.WriteByte(flagAnyItems)
		} else {
			buf.WriteByte(flagAnyOrder)
		}
		list = append(list, a.RequiredSet.List()...)
		list = append(list, a.OptionalSet.List()...)
		list = append(list, a.UnlikelySet.List()...)
	}
	list = append(list, a.ExcludedSet.List()...)
	if a.OrderedList == nil {
		sort.Slice(list, func(a, b int) bool { return list[a] < list[b] })
	}
	for idx, elem := range list {
		if idx != 0 {
			buf.WriteString(fieldElemSep)
		}
		switch {
		case a.OptionalSet[elem]:
			buf.WriteByte(flagOptional)
		case a.UnlikelySet[elem]:
			buf.WriteByte(flagUnlikely)
		case a.ExcludedSet[elem]:
			buf.WriteByte(flagExcluded)
		}
		buf.WriteString(elem)
	}
	return buf.String()
}

// Merge signatures a and b to match fingerprints from both.
func (a RequestSignature) Merge(b RequestSignature) (merged RequestSignature) {
	merged.Version = a.Version.Merge(b.Version)
	merged.Cipher = a.Cipher.Merge(b.Cipher)
	merged.Extension = a.Extension.Merge(b.Extension)
	merged.Curve = a.Curve.Merge(b.Curve)
	merged.EcPointFmt = a.EcPointFmt.Merge(b.EcPointFmt)
	merged.Header = a.Header.Merge(b.Header)
	merged.Quirk = a.Quirk.Merge(b.Quirk)
	merged.pfsCached = false
	merged.gradeCached = false
	return
}

// Merge version signatures a and b to match fingerprints from both.
func (a VersionSignature) Merge(b VersionSignature) (merged VersionSignature) {
	merged = a
	if a.Exp != VersionEmpty {
		if b.Exp == VersionEmpty || b.Exp < a.Exp {
			merged.Exp = b.Exp
		}
	}
	if a.Min != VersionEmpty {
		if b.Min == VersionEmpty || b.Min < a.Min {
			merged.Min = b.Min
		}
	}
	if a.Max != VersionEmpty {
		if b.Max == VersionEmpty || b.Max > a.Max {
			merged.Max = b.Max
		}
	}
	return
}

// Merge int signatures a and b to match fingerprints from both.
func (a IntSignature) Merge(b IntSignature) (merged IntSignature) {
	// Merge lists according to the following rules:
	// 1) The merged list should not have any duplicate elements.
	// 2) The order of elements in a and b must remain the same.
	// 3) If there exists elements e1, e2 that appear in different orders
	// in a and b, the merged list should be nil (accept any ordering).
	fmt.Println("BEFORE MERGE A'S REQUIRED SET IS", a.RequiredSet.String())
	fmt.Println("BEFORE MERGE A'S OPTIONAL SET IS", a.OptionalSet.String())
	fmt.Println("BEFORE MERGE A'S EXCLUDED SET IS", a.ExcludedSet.String())
	fmt.Println("BEFORE MERGE A'S UNLIKELY SET IS", a.UnlikelySet.String())
	fmt.Println("BEFORE MERGE A'S ORDERED LIST IS", a.OrderedList)

	fmt.Println("BEFORE MERGE B'S REQUIRED SET IS", b.RequiredSet.String())
	fmt.Println("BEFORE MERGE B'S OPTIONAL SET IS", b.OptionalSet.String())
	fmt.Println("BEFORE MERGE B'S EXCLUDED SET IS", b.ExcludedSet.String())
	fmt.Println("BEFORE MERGE B'S UNLIKELY SET IS", b.UnlikelySet.String())
	fmt.Println("BEFORE MERGE B'S ORDERED LIST IS", b.OrderedList)

	merged = IntSignature{
		IntList{},
		new(IntSet),
		new(IntSet),
		new(IntSet),
		new(IntSet),
	}

	anyOrder := false
	if a.OrderedList == nil || b.OrderedList == nil {
		anyOrder = true
	} else {
		var mergedSet IntSet
		var bSet IntSet
		bSet.Copy(b.RequiredSet.Union(b.OptionalSet).Union(b.UnlikelySet))
		bIdx := 0
		bLen := len(b.OrderedList)
		for _, elem := range a.OrderedList {
			fmt.Println(elem)
			// check if elem is already merged
			if mergedSet.Has(elem) {
				// elem is already merged, so abort and accept any ordering
				fmt.Println("ANY ORDER TRUE")
				anyOrder = true
				break
			}
			// check if b contains elem
			if bSet.Has(elem) {
				fmt.Println("bSet has elem!!")
				// add all elems of b up to elem
				for ; bIdx < bLen && b.OrderedList[bIdx] != elem; bIdx++ {
					merged.OrderedList = append(merged.OrderedList, b.OrderedList[bIdx])
					mergedSet.Insert(b.OrderedList[bIdx])
				}
				// skip past elem since it is added below
				bIdx++
			}
			// add elem to merged list and set
			merged.OrderedList = append(merged.OrderedList, elem)
			mergedSet.Insert(elem)
		}
		// add remaining elems of b to merged list
		merged.OrderedList = append(merged.OrderedList, b.OrderedList[bIdx:bLen]...)
	}

	// Clear ordered list if any ordering is accepted
	if anyOrder {
		merged.OrderedList = nil
		fmt.Println(merged.OrderedList)
	}

	// Take intersection of required elems
	if a.RequiredSet.Len() != 0 || b.RequiredSet.Len() != 0 {
		merged.RequiredSet.Copy(a.RequiredSet.Inter(b.RequiredSet))
	}

	// Take intersection of excluded elems
	if a.ExcludedSet.Len() != 0 || b.ExcludedSet.Len() != 0 {
		merged.ExcludedSet.Copy(a.ExcludedSet.Inter(b.ExcludedSet))
	}

	// Take union of optional elems
	//if anyOrder && (a.OptionalSet.Len() == 0 || b.OptionalSet.Len() == 0) {
	//	merged.OptionalSet = new(IntSet)
	//} else {
	//	merged.OptionalSet.Copy(a.OptionalSet.Union(b.OptionalSet).Union(a.RequiredSet).Union(b.RequiredSet).Diff(merged.RequiredSet))
	//}
	// todo... think about new optional set merging rules
	if a.RequiredSet.Len() != 0 && b.RequiredSet.Len() != 0 {
		merged.OptionalSet.Copy(a.OptionalSet.Union(b.OptionalSet).Union(a.RequiredSet).Union(b.RequiredSet).Diff(merged.RequiredSet))
	}

	// Take union of unlikely elems
	//if a.UnlikelySet.Len() == 0 || b.UnlikelySet.Len() == 0 {
	//	merged.UnlikelySet = new(IntSet)
	//} else {
	//	merged.UnlikelySet.Copy(a.UnlikelySet.Union(b.UnlikelySet).Union(a.OptionalSet).Union(b.OptionalSet).Diff(merged.OptionalSet))
	//}
	// todo... think about new unlikely set merging rules
	if a.OptionalSet.Len() != 0 && b.OptionalSet.Len() != 0 {
		merged.UnlikelySet.Copy(a.UnlikelySet.Union(b.UnlikelySet).Union(a.OptionalSet).Union(b.OptionalSet).Diff(merged.OptionalSet))
	}

	fmt.Println("AFTER MERGE REQUIRED SET IS", merged.RequiredSet.String())
	fmt.Println("AFTER MERGE OPTIONAL SET IS", merged.OptionalSet.String())
	fmt.Println("AFTER MERGE EXCLUDED SET IS", merged.ExcludedSet.String())
	fmt.Println("AFTER MERGE UNLIKELY SET IS", merged.UnlikelySet.String())
	fmt.Println("AFTER MERGE ORDERED LIST IS", merged.OrderedList)
	return
}

// Merge string signatures a and b to match fingerprints from both.
func (a StringSignature) Merge(b StringSignature) (merged StringSignature) {
	// Merge lists according to the following rules:
	// 1) The merged list should not have any duplicate elements.
	// 2) The order of elements in a and b must remain the same.
	// 3) If there exists elements e1, e2 that appear in different orders
	// in a and b, the merged list should be nil (accept any ordering).
	anyOrder := false
	if a.OrderedList == nil || b.OrderedList == nil {
		anyOrder = true
	} else {
		mergedSet := make(StringSet)
		merged.OrderedList = StringList{}
		bSet := b.RequiredSet.Union(b.OptionalSet).Union(b.UnlikelySet)
		bIdx := 0
		bLen := len(b.OrderedList)
		for _, elem := range a.OrderedList {
			// check if elem is already merged
			if mergedSet[elem] {
				// elem is already merged, so abort and accept any ordering
				anyOrder = true
				break
			}
			// check if b contains elem
			if bSet[elem] {
				// add all elems of b up to elem
				for ; bIdx < bLen && b.OrderedList[bIdx] != elem; bIdx++ {
					merged.OrderedList = append(merged.OrderedList, b.OrderedList[bIdx])
					mergedSet[b.OrderedList[bIdx]] = true
				}
				// skip past elem since it is added below
				bIdx++
			}
			// add elem to merged list/set
			merged.OrderedList = append(merged.OrderedList, elem)
			mergedSet[elem] = true
		}
		// add remaining elems of b to merged list
		merged.OrderedList = append(merged.OrderedList, b.OrderedList[bIdx:bLen]...)
	}

	// Clear ordered list if any ordering is accepted
	if anyOrder {
		merged.OrderedList = nil
	}

	// Take intersection of required elems
	if a.RequiredSet != nil || b.RequiredSet != nil {
		merged.RequiredSet = a.RequiredSet.Inter(b.RequiredSet)
	}

	// Take intersection of excluded elems
	if a.ExcludedSet != nil || b.ExcludedSet != nil {
		merged.ExcludedSet = a.ExcludedSet.Inter(b.ExcludedSet)
	}

	// Take union of optional elems
	if a.OptionalSet == nil || b.OptionalSet == nil {
		merged.OptionalSet = nil
	} else {
		merged.OptionalSet = a.OptionalSet.Union(b.OptionalSet).Union(a.RequiredSet).Union(b.RequiredSet).Diff(merged.RequiredSet)
	}

	// Take union of unlikely elems
	if a.UnlikelySet == nil || b.UnlikelySet == nil {
		merged.UnlikelySet = nil
	} else {
		merged.UnlikelySet = a.UnlikelySet.Union(b.UnlikelySet).Union(a.OptionalSet).Union(b.OptionalSet).Diff(merged.OptionalSet)
	}

	return
}

// Match a fingerprint against the signature.
// Returns MatchImpossible if no match is possible, MatchUnlikely if the match
// is possible with an unlikely configuration, and MatchPossible otherwise.
func (a RequestSignature) Match(fingerprint RequestFingerprint) (Match, int) {
	matchMap, similarity := a.MatchMap(fingerprint)
	for _, v := range matchMap {
		if v == MatchImpossible {
			return MatchImpossible, similarity
		}
	}
	for _, v := range matchMap {
		if v == MatchUnlikely {
			return MatchUnlikely, similarity
		}
	}
	return MatchPossible, similarity
}

// MatchMap returns (1) a map of the match results of the fingerprint against the signature,
// and (2) the count of overlapping cipher, extension, curve, and ecpointfmt values.
// The second value helps a caller deduce the closest matching record in the case there is no "MatchPossible" match.
func (a RequestSignature) MatchMap(fingerprint RequestFingerprint) (map[string]Match, int) {
	matchMap := make(map[string]Match)
	var similarity int
	var matchcount int
	matchMap["version"] = a.Version.Match(fingerprint.Version)
	matchMap["cipher"], matchcount = a.Cipher.Match(fingerprint.Cipher)
	similarity += matchcount
	matchMap["extension"], matchcount = a.Extension.Match(fingerprint.Extension)
	similarity += matchcount
	matchMap["curve"], matchcount = a.Curve.Match(fingerprint.Curve)
	similarity += matchcount
	matchMap["ecpointfmt"], matchcount = a.EcPointFmt.Match(fingerprint.EcPointFmt)
	similarity += matchcount
	matchMap["header"] = a.Header.Match(fingerprint.Header)
	matchMap["quirk"] = a.Quirk.Match(fingerprint.Quirk)
	return matchMap, similarity
}

// Match a version against the version signature.
// Returns MatchImpossible if no match is possible, MatchUnlikely if the match
// is possible with an unlikely configuration, and MatchPossible otherwise.
func (a VersionSignature) Match(version Version) Match {
	if a.Min != VersionEmpty && version < a.Min {
		return MatchImpossible
	}
	if a.Max != VersionEmpty && version > a.Max {
		return MatchImpossible
	}
	if a.Exp != VersionEmpty && version < a.Exp {
		return MatchUnlikely
	}
	return MatchPossible
}

// Match an int list against the int signature.
// Returns MatchImpossible if no match is possible, MatchUnlikely if the match
// is possible with an unlikely configuration, and MatchPossible otherwise.
func (a IntSignature) Match(list IntList) (Match, int) {
	set := list.Set()
	similarity := len(set.Inter(a.RequiredSet)) + len(set.Inter(a.OptionalSet))

	// check if the ordered list matches
	if a.OrderedList != nil && !a.OrderedList.Contains(list) {
		return MatchImpossible, similarity
	}
	// check that the set does not contain any excluded items
	if len(set.Inter(a.ExcludedSet)) > 0 {
		return MatchImpossible, similarity
	}
	// check that the set has all required items
	if len(a.RequiredSet.Diff(set)) > 0 {
		return MatchImpossible, similarity
	}
	// see if there's anything left after removing required and optional items
	set = set.Diff(a.RequiredSet).Diff(a.OptionalSet)
	if a.OptionalSet != nil && len(set) > 0 {
		// check if the remaining items are unlikely or impossible
		if a.UnlikelySet != nil && len(set.Diff(a.UnlikelySet)) > 0 {
			return MatchImpossible, similarity
		}
		return MatchUnlikely, similarity
	}
	// check if the set has any unlikely items
	if len(set.Inter(a.UnlikelySet)) > 0 {
		return MatchUnlikely, similarity
	}
	return MatchPossible, similarity
}

// Match a string list against the string signature.
// Returns MatchImpossible if no match is possible, MatchUnlikely if the match
// is possible with an unlikely configuration, and MatchPossible otherwise.
func (a StringSignature) Match(list StringList) Match {
	set := list.Set()
	// check if the ordered list matches
	if a.OrderedList != nil && !a.OrderedList.Contains(list) {
		return MatchImpossible
	}
	// check that the set does not contain any excluded items
	if set.Inter(a.ExcludedSet).Len() > 0 {
		return MatchImpossible
	}
	// check that the set has all required items
	if a.RequiredSet.Diff(set).Len() > 0 {
		return MatchImpossible
	}
	// see if there's anything left after removing required and optional items
	set.Copy(set.Diff(a.RequiredSet).Diff(a.OptionalSet))
	if a.OptionalSet.Len() != 0 && set.Len() > 0 {
		// check if the remaining items are unlikely or impossible
		if a.UnlikelySet.Len() != 0 && set.Diff(a.UnlikelySet).Len() > 0 {
			return MatchImpossible
		}
		return MatchUnlikely
	}
	// check if the set has any unlikely items
	if set.Inter(a.UnlikelySet).Len() > 0 {
		return MatchUnlikely
	}
	return MatchPossible
}
