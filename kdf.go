package srp

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"io"
	"math/big"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

/* The derivation of the SRP x, particularly the KDF specific to 1Password,
 * shouldn't be part of the srp package. Well, it is. But let's at least move
 * it to a separate file. */

// CalculateX compute X value used in SRP authentication.
func CalculateX(method, alg, email, password string, salt []byte, iterations int, accountKey *AccountKey) (*big.Int, error) {
	if iterations == 0 { // Using SRP Test Vectors
		h1 := sha1.New()
		h1.Write(salt)

		h2 := sha1.New()
		h2.Write([]byte(email + ":" + password))
		h1.Write(h2.Sum(nil))

		return NumberFromBytes(h1.Sum(nil)), nil
	}

	if accountKey == nil {
		return nil, errors.New("missing AccountKey in CalculateX")
	}

	var h func() hash.Hash
	var keyLen int
	var err error
	salt, err = base64.RawURLEncoding.DecodeString(string(salt))
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode salt")
	}

	if alg == "PBES2-HS512" || alg == "PBES2g-HS512" {
		keyLen = 512 / 8
		h = sha512.New
	} else if alg == "PBES2-HS256" || alg == "PBES2g-HS256" {
		keyLen = 256 / 8
		h = sha256.New
	} else {
		return nil, fmt.Errorf("invalid SRP alg: %q", alg)
	}

	if strings.HasPrefix(method, "SRP-") {
		derivedBits := pbkdf2.Key([]byte(prehash(password)), salt, iterations, keyLen, h)
		combined := accountKey.CombineWithBytes(derivedBits)

		hasher := sha1.New()

		hasher.Write(salt)
		hasher.Write([]byte(email + ":" + bytesToHex(combined)))
		return NumberFromBytes(hasher.Sum(nil)), nil
	}

	if strings.HasPrefix(method, "SRPg-") {
		emailSalt := []byte(email)
		info := []byte(method)
		bigSalt := make([]byte, 32)
		if _, err := io.ReadFull(hkdf.New(sha256.New, salt, emailSalt, info), bigSalt); err != nil {
			return nil, errors.Wrap(err, "HKDF failed")
		}

		derivedBits := pbkdf2.Key([]byte(password), bigSalt, iterations, keyLen, h)
		combined := accountKey.CombineWithBytes(derivedBits)

		return NumberFromBytes(combined), nil
	}

	return nil, fmt.Errorf("invalid SRP method: %q", method)
}
