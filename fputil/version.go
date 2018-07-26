package fp

import (
	"fmt"
	"strconv"
)

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
	if len(s) == 0 {
		*a = VersionEmpty
		return nil
	}
	u, err := strconv.ParseUint(s, 16, 16)
	if err != nil {
		return err
	}
	switch u {
	case 2, 0x0200: // version 2 is 0x0002 on the wire
		*a = VersionSSL2
	case 0x0300:
		*a = VersionSSL3
	case 0x0301:
		*a = VersionTLS10
	case 0x0302:
		*a = VersionTLS11
	case 0x0303:
		*a = VersionTLS12
	case 0x0304:
		*a = VersionTLS13
	default:
		return fmt.Errorf("invalid tls version: %s", s)
	}
	return nil
}

// String returns a string representation of the version
func (a Version) String() string {
	if a == VersionEmpty {
		return ""
	}
	return fmt.Sprintf("%x", uint16(a))
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
	VersionSSL2  Version = 0x0200 // 0x0002 on the wire, so let's swap here
	VersionSSL3  Version = 0x0300
	VersionTLS10 Version = 0x0301
	VersionTLS11 Version = 0x0302
	VersionTLS12 Version = 0x0303
	VersionTLS13 Version = 0x0304
)
