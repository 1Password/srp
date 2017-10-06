package srp

import (
	"crypto/sha256"
	"encoding/base32"
	"strings"
)

// prehash is kept for compatibility with legacy implementations
func prehash(s string) string {
	if s == "" {
		return ""
	}

	hasher := sha256.New()
	hasher.Write([]byte(s))
	bits := hasher.Sum(nil)

	return strings.TrimRight(base32.StdEncoding.EncodeToString(bits), "=")
}
