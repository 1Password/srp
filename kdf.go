package srp

import (

	// #nosec See docs for KDFRFC5054 for warnings.
	"crypto/sha1"
	"fmt"
	"math/big"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

/*
 * Best to use KDF from github/agilebits/op/crypto
 * I will import at some point
 */

/*
KDFRFC5054 is *NOT* recommended. Instead use a key derivation function (KDF) that
involves a hashing scheme designed for password hashing.
The SRP verifier that is stored by the server is like
a password hash with respect to crackability. Choose a KDF
that that makes the server stored verifiers hard to crack.

This computes the client's long term secret, x
from  a username, password, and salt as described
in RFC 5054 §2.6, which says
    x = SHA1(s | SHA1(I | ":" | P))
*/
func KDFRFC5054(salt []byte, username string, password string) (*big.Int, error) {
	p := []byte(PreparePassword(password))
	u := []byte(PreparePassword(username))
	sep := []byte(":")

	innerHasher := sha1.New() // #nosec

	if n, err := innerHasher.Write(u); err != nil {
		return nil, fmt.Errorf("writing username: %w", err)
	} else if n != len(u) {
		return nil, fmt.Errorf("could only write %d out of the %d username bytes", n, len(u))
	}

	if n, err := innerHasher.Write(sep); err != nil {
		return nil, fmt.Errorf("writing separator: %w", err)
	} else if n != len(sep) {
		return nil, fmt.Errorf("could only write %d out of the %d separator bytes", n, len(sep))
	}

	if n, err := innerHasher.Write(p); err != nil {
		return nil, fmt.Errorf("writing password: %w", err)
	} else if n != len(p) {
		return nil, fmt.Errorf("could only write %d out of the %d password bytes", n, len(p))
	}

	ih := innerHasher.Sum(nil)

	oHasher := sha1.New() // #nosec

	if n, err := oHasher.Write(salt); err != nil {
		return nil, fmt.Errorf("writing salt: %w", err)
	} else if n != len(salt) {
		return nil, fmt.Errorf("could only write %d out of the %d salt bytes", n, len(salt))
	}

	if n, err := oHasher.Write(ih); err != nil {
		return nil, fmt.Errorf("writing inner hash: %w", err)
	} else if n != len(ih) {
		return nil, fmt.Errorf("could only write %d out of the %d inner hash bytes", n, len(ih))
	}

	h := oHasher.Sum(nil)

	return bigIntFromBytes(h), nil
}

// PreparePassword strips leading and trailing white space
// and normalizes to unicode NFKD.
func PreparePassword(s string) string {
	var out string
	out = string(norm.NFKD.Bytes([]byte(s)))
	out = strings.TrimLeftFunc(out, unicode.IsSpace)
	out = strings.TrimRightFunc(out, unicode.IsSpace)
	return out
}

/**
 ** Copyright 2017 AgileBits, Inc.
 ** Licensed under the Apache License, Version 2.0 (the "License").
 **/
