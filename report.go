package mitmengine

import (
	fp "github.com/cloudflare/mitmengine/fputil"
)

// A Report contains mitm detection results for a request.
type Report struct {

	// MatchedUASignature is the matched browser user agent signature
	MatchedUASignature string

	// BrowserSignature is the signature of the matched browser
	BrowserSignature string

	// BrowserSignatureMatch is the match result of the actual fingerprint
	// versus the browser signature
	BrowserSignatureMatch fp.Match

	// Reason for mismatch between actual fingerprint and expected signature
	Reason string

	// ReasonDetails supplied additional details for the above reason
	ReasonDetails string

	// BrowserGrade is the expected security grade for the browser without interference
	BrowserGrade fp.Grade

	// Actual security grade of the request
	ActualGrade fp.Grade

	// WeakCiphers is true if the request contains weak ciphers
	WeakCiphers bool

	// LosesPfs is true if a MITM causes the request to lose perfect
	// forward secrecy
	LosesPfs bool

	// MatchedMitmSignature is the signature of the MITM software if matched
	MatchedMitmSignature string

	// MatchedMitmName is the name of the MITM software if matched
	MatchedMitmName string

	// MatchedMitmType classification of the MITM software if matched
	MatchedMitmType uint8

	// Error is set if the user agent does not indicate a supported browser, or
	// does not match any known user agent signature
	Error error
}
