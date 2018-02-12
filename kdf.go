package srp

import (
	"crypto/sha1"
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
KDFRFC5054 is *not* recommended. Instead use a key derivation function (KDF) that
involves a hashing scheme designed for password hashing.
The SRP verifier that is stored by the server is like
a password hash with respect to crackability. Choose a KDF
that that makes the server stored verifiers hard to crack.

This computes the client's long term secret, x
from  a username, password, and salt as described
in RFC 5054 §2.6, which says
    x = SHA1(s | SHA1(I | ":" | P))
*/
func KDFRFC5054(salt []byte, username string, password string) (x *big.Int) {

	p := []byte(PreparePassword(password))

	u := []byte(PreparePassword(username))

	innerHasher := sha1.New()
	innerHasher.Write(u)
	innerHasher.Write([]byte(":"))
	innerHasher.Write(p)
	ih := innerHasher.Sum(nil)

	oHasher := sha1.New()
	oHasher.Write(salt)
	oHasher.Write(ih)

	h := oHasher.Sum(nil)
	x = bigIntFromBytes(h)
	return x
}

// PreparePassword strips leading and trailing white space
// and normalizes to unicode NFKD
func PreparePassword(s string) string {
	var out string
	// step #1: normalize `NFKD`
	out = string(norm.NFKD.Bytes([]byte(s)))
	// step #2: trim left
	out = strings.TrimLeftFunc(out, unicode.IsSpace)
	// step #3: trim right
	out = strings.TrimRightFunc(out, unicode.IsSpace)
	// step #4: return the result
	return out
}

/**
 ** Copyright 2017 AgileBits, Inc.
 ** Licensed under the Apache License, Version 2.0 (the "License").
 **/
