package fp

import "fmt"

// Version represents a TLS Version
type Version uint16

// NewVersion parses a version from a string, returning VersionEmpty if not recognized
func NewVersion(s string) (Version, error) {
	var a Version
	err := a.Parse(s)
	return a, err
}

// Parse initializes a version from a string
func (a *Version) Parse(s string) error {
	switch s {
	case "":
		*a = VersionEmpty
	case "2.0":
		*a = VersionSSL2
	case "3.0":
		*a = VersionSSL3
	case "3.1":
		*a = VersionTLS10
	case "3.2":
		*a = VersionTLS11
	case "3.3":
		*a = VersionTLS12
	case "3.4":
		*a = VersionTLS13
	default:
		return fmt.Errorf("invalid version: '%s'", s)
	}
	return nil
}

// String returns a string representation of the version
func (a Version) String() string {
	switch a {
	case VersionEmpty:
		return ""
	case VersionSSL2:
		return "2.0"
	case VersionSSL3:
		return "3.0"
	case VersionTLS10:
		return "3.1"
	case VersionTLS11:
		return "3.2"
	case VersionTLS12:
		return "3.3"
	case VersionTLS13:
		return "3.4"
	default:
		return fmt.Sprintf("Version(%d)", a)
	}
}

// Grade returns a security grade for the version
func (a Version) Grade() Grade {
	switch a {
	case VersionEmpty:
		return GradeEmpty
	case VersionTLS13, VersionTLS12:
		return GradeA
	case VersionTLS11, VersionTLS10:
		return GradeB
	case VersionSSL3:
		return GradeC
	default:
		return GradeF
	}
}

// Source:
//  - SSL0.2: https://www-archive.mozilla.org/projects/security/pki/nss/ssl/draft02.html
//  - SSL3.0: https://tools.ietf.org/html/draft-ietf-tls-ssl-version3-00#appendix-A.1.1
//  - TLS1.0: https://tools.ietf.org/html/draft-ietf-tls-protocol-01#appendix-A.2
//  - TLS1.1: https://www.ietf.org/rfc/rfc4346.txt
//  - TLS1.2: https://www.ietf.org/rfc/rfc5246.txt
//  - TLS1.3: https://tools.ietf.org/html/draft-ietf-tls-tls13-28#section-4.2.1
const (
	VersionEmpty Version = 0
	VersionSSL2  Version = 0x0002
	VersionSSL3  Version = 0x0300
	VersionTLS10 Version = 0x0301
	VersionTLS11 Version = 0x0302
	VersionTLS12 Version = 0x0303
	VersionTLS13 Version = 0x0304
)
