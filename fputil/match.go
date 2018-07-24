package fp

import "fmt"

// Match gives the match result for a comparison of a fingerprint to a
// signature.
type Match uint8

// String returns a string represenation of a Match type
func (a Match) String() string {
	switch a {
	case MatchEmpty:
		return "empty"
	case MatchImpossible:
		return "impossible"
	case MatchUnlikely:
		return "unlikely"
	case MatchPossible:
		return "possible"
	default:
		return fmt.Sprintf("Match(%d)", uint8(a))
	}
}

const (
	// MatchEmpty is the uninitialized value for a match
	MatchEmpty Match = iota

	// MatchImpossible means that a match is not possible.
	MatchImpossible

	// MatchUnlikely means that a match is possible but unlikely.
	MatchUnlikely

	// MatchPossible means that a match is possible.
	MatchPossible
)
