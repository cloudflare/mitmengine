package fp

import "fmt"

// Grade represents a TLS client security grade
type Grade uint8

// String returns a string representation of the grade
func (a Grade) String() string {
	switch a {
	case GradeEmpty:
		return "empty"
	case GradeA:
		return "A"
	case GradeB:
		return "B"
	case GradeC:
		return "C"
	case GradeF:
		return "F"
	default:
		return fmt.Sprintf("Grade(%d)", uint8(a))
	}
}

// Merge returns the weakest of two security grades
func (a Grade) Merge(b Grade) Grade {
	if a > b {
		return a
	}
	return b
}

// Sources:
//  - https://jhalderm.com/pub/papers/interception-ndss17.pdf
const (
	GradeEmpty Grade = iota // no grade assigned
	GradeA                  // optimal
	GradeB                  // suboptimal
	GradeC                  // known attack
	GradeF                  // trivially broken
)
