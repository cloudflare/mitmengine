package fp

import (
	"bytes"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// IntList is a list of integers
type IntList []uint64

// IntSet is a set of integers
type IntSet map[uint64]bool

// NewIntList returns a string list parsed from a string.
func NewIntList(s string) (IntList, error) {
	var a IntList
	err := a.Parse(s)
	return a, err
}

// Parse an int list from a string and return an error on failure
func (a *IntList) Parse(s string) error {
	*a = nil
	var split []string
	if len(s) > 0 {
		split = strings.Split(s, ",")
	}
	for _, v := range split {
		if len(v) == 0 {
			return fmt.Errorf("invalid int list format: '%s'", s)
		}
		elem, err := strconv.ParseUint(v, 16, 16)
		if err != nil {
			return err
		}
		*a = append(*a, elem)
	}
	return nil
}

// String returns a comma-separated string of list elements
func (a IntList) String() string {
	var buf bytes.Buffer
	for idx, elem := range a {
		if idx != 0 {
			buf.WriteString(",")
		}
		buf.WriteString(fmt.Sprintf("%x", elem))
	}
	return buf.String()
}

// Contains returns true if b is an ordered subsequence of a
func (a IntList) Contains(b IntList) bool {
	bIdx := 0
	bLen := len(b)
	if bLen == 0 {
		return true
	}
	for _, elem := range a {
		if elem == b[bIdx] {
			bIdx++
			if bIdx == bLen {
				return true
			}
		}
	}
	return false
}

// Equals returns true if a and b are equal
func (a IntList) Equals(b IntList) bool {
	if len(a) != len(b) {
		return false
	}
	for idx := range a {
		if a[idx] != b[idx] {
			return false
		}
	}
	return true
}

// Set returns a set representation of a list
func (a IntList) Set() IntSet {
	set := make(IntSet, len(a))
	for _, elem := range a {
		set[elem] = true
	}
	return set
}

// List returns a list representation of a set in sorted order
func (a IntSet) List() IntList {
	list := make(IntList, len(a))
	idx := 0
	for elem := range a {
		list[idx] = elem
		idx++
	}
	sort.Slice(list, func(i, j int) bool { return list[i] < list[j] })
	return list
}

// Inter returns the set intersection (a & b)
func (a IntSet) Inter(b IntSet) IntSet {
	inter := make(IntSet, len(a))
	for elem := range a {
		if b[elem] {
			inter[elem] = true
		}
	}
	return inter
}

// Diff returns the set difference (a - b)
func (a IntSet) Diff(b IntSet) IntSet {
	diff := make(IntSet, len(a))
	for elem := range a {
		if !b[elem] {
			diff[elem] = true
		}
	}
	return diff
}

// Union returns the set union (a | b)
func (a IntSet) Union(b IntSet) IntSet {
	union := make(IntSet, len(a)+len(b))
	for elem := range a {
		union[elem] = true
	}
	for elem := range b {
		union[elem] = true
	}
	return union
}

// StringList is a list of strings
type StringList []string

// StringSet is a set of strings
type StringSet map[string]bool

// NewStringList returns a string list parsed from a string.
func NewStringList(s string) (StringList, error) {
	var a StringList
	err := a.Parse(s)
	return a, err
}

// Parse a stringlist from a string and return an error on failure
func (a *StringList) Parse(s string) error {
	*a = nil
	if len(s) > 0 {
		*a = strings.Split(s, ",")
	}
	return nil
}

// String returns a comma-separated string of list elements
func (a StringList) String() string {
	var buf bytes.Buffer
	for idx, elem := range a {
		if idx != 0 {
			buf.WriteString(",")
		}
		buf.WriteString(elem)
	}
	return buf.String()
}

// Contains returns true if b is an ordered subsequence of a
func (a StringList) Contains(b StringList) bool {
	bIdx := 0
	bLen := len(b)
	if bLen == 0 {
		return true
	}
	for _, elem := range a {
		if elem == b[bIdx] {
			bIdx++
			if bIdx == bLen {
				return true
			}
		}
	}
	return false
}

// Equals returns true if a and b are equal
func (a StringList) Equals(b StringList) bool {
	if len(a) != len(b) {
		return false
	}
	for idx := range a {
		if a[idx] != b[idx] {
			return false
		}
	}
	return true
}

// Set returns a set representation of a list
func (a StringList) Set() StringSet {
	set := make(StringSet, len(a))
	for _, elem := range a {
		set[elem] = true
	}
	return set
}

// List returns a list representation of a set in sorted order
func (a StringSet) List() StringList {
	list := make(StringList, len(a))
	idx := 0
	for elem := range a {
		list[idx] = elem
		idx++
	}
	sort.Slice(list, func(i, j int) bool { return list[i] < list[j] })
	return list
}

// Inter returns the set intersection (a & b)
func (a StringSet) Inter(b StringSet) StringSet {
	inter := make(StringSet, len(a))
	for elem := range a {
		if b[elem] {
			inter[elem] = true
		}
	}
	return inter
}

// Diff returns the set difference (a - b)
func (a StringSet) Diff(b StringSet) StringSet {
	diff := make(StringSet, len(a))
	for elem := range a {
		if !b[elem] {
			diff[elem] = true
		}
	}
	return diff
}

// Union returns the set union (a | b)
func (a StringSet) Union(b StringSet) StringSet {
	union := make(StringSet, len(a)+len(b))
	for elem := range a {
		union[elem] = true
	}
	for elem := range b {
		union[elem] = true
	}
	return union
}
