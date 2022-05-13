package srp

import (
	"crypto/sha1" //nolint:gosec // SHA1 is wired into too many standards and test data
	"crypto/sha256"
	"errors"
	"hash"
)

// We need a way to select a cryptographic hash that is
// used for computing u and k. We also need a way to make this just
// sha256 unless someone really, really needs to use sha1 to run against
// standards, test vectors, and the like

// See
//  https://www.reddit.com/r/golang/comments/hocwje/just_found_out_that_we_can_namespace_functions_in/
// for this use of type and var

type srpHash struct{
}

// Hash is thingy hang functions off of.
var Hash srpHash

const (
	sha256Name string = "sha256"
	sha1Name string = "sha1-if-really-needed"
)

func (srpHash) IsValid(hn string) error {
	switch hn {
	case sha256Name, sha1Name:
		return nil
	}
	return errors.New("invalid hash choice")
}

// New returns the default (sha256 hash.Hash function).
// The caller should check for a nil result.
func (srpHash) New() hash.Hash {
	defaultHash := string(sha256Name)
	return (Hash).NewWith(defaultHash)
}

// NewWith returns the appropriate hash.Hash function or nil if you didn't
// guess what hashes we allow.
func (srpHash) NewWith(hashName string) hash.Hash {
	switch hashName {
	case "sha256":
		return sha256.New()
	case "sha1-if-really-needed":
		return sha1.New() //nolint:gosec // We have to leave this as a backwards option
	default:
		return nil
	}
}
