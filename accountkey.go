package srp

import (
	"crypto/sha256"
	"errors"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/hkdf"
)

// AccountKey represents user account key that is used in authentication and key derivation
// Format is Format Version; it is usually format will be `A2` or `A3`
// ID is a randomly string used to distinguish account keys.
// Key is the account key in hex. non-hex characters are stripped.
type AccountKey struct {
	Format string
	ID     string
	Key    string
}

// ValidAccountKeyChars contains all valid Account Key characters
var ValidAccountKeyChars = "23456789ABCDEFGHJKLMNPQRSTVWXYZ"

// NewAccountKeyFromString parses an Account Key string into
// an AccountKey struct
func NewAccountKeyFromString(keyString string) (*AccountKey, error) {
	keyStr := ""
	keyString = strings.ToUpper(keyString)
	for i := range keyString {
		if strings.Index(ValidAccountKeyChars, string(keyString[i])) >= 0 {
			keyStr = keyStr + string(keyString[i])
		}
	}
	if len(keyStr) != 34 {
		return nil, errors.New("invalid account key. len was " + strconv.Itoa(len(keyStr)))
	}
	ak := AccountKey{
		Format: keyStr[0:2],
	}
	switch ak.Format {
	case "A2", "A3":
		ak.ID = keyStr[2:8]
		ak.Key = keyStr[8:34]
	default:
		return nil, errors.New("invalid account key format")
	}
	return &ak, nil
}

// CombineWithBytes combines account key data with the given set of bytes
func (k *AccountKey) CombineWithBytes(b []byte) []byte {
	//
	// HKDF
	//
	kdf := hkdf.New(sha256.New, []byte(k.Key), []byte(k.ID), []byte(k.Format))

	personal := make([]byte, len(b))
	io.ReadFull(kdf, personal)

	//
	// combined = b ^ personal
	//
	combined := make([]byte, len(b))
	for i := 0; i < len(b); i++ {
		combined[i] = b[i] ^ personal[i]
	}

	return combined
}
