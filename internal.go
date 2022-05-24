package srp

import (
	rand "crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

/*
The principle srp.go file was getting too long, so I'm putting the non-exported
methods in here.
*/

// generateMySecret creates the little a or b
// According to RFC 5054, this should be at least 32 bytes
// According to RFC 2631 this should be uniform in the range
// [2, q-2], where q is the Sophie Germain prime from which
// N was created.
// According to RFC 3526 §8 there are some specific sizes depending
// on the group. We go with RFC 3526 values if available, otherwise
// a minimum of 32 bytes.
func (s *SRP) generateMySecret() *big.Int {
	eSize := maxInt(s.group.ExponentSize, MinExponentSize)
	bytes := make([]byte, eSize)
	_, err := rand.Read(bytes)
	if err != nil {
		// If we can't get random bytes from the system, then we have no business doing anything crypto related.
		panic(fmt.Sprintf("Failed to get random bytes: %v", err))
	}
	ephemeralPrivate := &big.Int{}
	ephemeralPrivate.SetBytes(bytes)
	s.ephemeralPrivate = ephemeralPrivate
	return s.ephemeralPrivate
}

// setHashName allows set something other than "sha256". Please don't.
// TODO(jpg) Find a way that this can be called before k is computed.
//nolint:unused
func (s *SRP) setHashName(hn string) {
	s.hashName = hn
}

// makeLittleK is a wrapper for standard and non-standard variants.
func (s *SRP) makeLittleK() (*big.Int, error) {
	if err := Hash.IsValid(s.hashName); err != nil {
		return nil, fmt.Errorf("cannot make k: %w", err)
	}
	if s.stdPadding {
		k := s.group.LittleK(s.hashName)
		if k == nil {
			return nil, fmt.Errorf("failed to get little k")
		}
		return k, nil
	}
	return s.makeLittleKNonStd()
}

// makeLittleKNonStd initializes multiplier based on group parameters
// k = H(N, g)
// This does _not_ conform to RFC 5054 padding.
// If you want standard padding use s.group.LittleK().
func (s *SRP) makeLittleKNonStd() (*big.Int, error) {
	if s.group == nil {
		return nil, fmt.Errorf("group not set")
	}

	// We will remake k, even if already created, as server needs to
	// remake it after manually setting k

	h := Hash.NewWith(s.hashName)
	if h == nil {
		return nil, fmt.Errorf("failed to get hash function")
	}
	_, err := h.Write(s.group.n.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to write N to hasher: %w", err)
	}
	_, err = h.Write(s.group.g.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to write g to hasher: %w", err)
	}
	k := &big.Int{}
	s.k = k.SetBytes(h.Sum(nil))

	return s.k, nil
}

// makeA calculates A (if necessary) and returns it.
func (s *SRP) makeA() (*big.Int, error) {
	if s.group == nil {
		return nil, fmt.Errorf("group not set")
	}
	if s.isServer {
		return nil, fmt.Errorf("only the client can make A")
	}
	if s.group.IsZero(s.ephemeralPrivate) {
		s.ephemeralPrivate = s.generateMySecret()
	}

	s.ephemeralPublicA = &big.Int{}
	result := s.ephemeralPublicA.Exp(s.group.g, s.ephemeralPrivate, s.group.n)
	return result, nil
}

// makeB calculates B and returns it.
func (s *SRP) makeB() (*big.Int, error) {
	term1 := &big.Int{}
	term2 := &big.Int{}

	// Absolute Prerequisites: Group, isServer, v
	if s.group == nil {
		return nil, fmt.Errorf("group not set")
	}
	if !s.isServer {
		return nil, fmt.Errorf("only the server can make B")
	}
	if s.group.IsZero(s.v) {
		return nil, fmt.Errorf("v must be known before B can be calculated")
	}
	// This test is so I'm not lying to gosec wrt to G105
	if s.group.n.Cmp(bigZero) == 0 {
		return nil, fmt.Errorf("something is wrong if modulus is zero")
	}

	// Generatable prerequisites: k, b if needed
	if s.group.IsZero(s.k) {
		var err error
		if s.k, err = s.makeLittleK(); err != nil {
			return nil, err
		}
	}
	if s.group.IsZero(s.ephemeralPrivate) {
		s.ephemeralPrivate = s.generateMySecret()
	}

	// B = kv + g^b  (term1 is kv, term2 is g^b)
	// We also do some modular reduction on some of our intermediate values
	term2.Exp(s.group.g, s.ephemeralPrivate, s.group.n) // #nosec G105
	term1.Mul(s.k, s.v)
	term1 = s.group.Reduce(term1)
	s.ephemeralPublicB.Add(term1, term2)
	s.ephemeralPublicB = s.group.Reduce(s.ephemeralPublicB)

	return s.ephemeralPublicB, nil
}

func (s *SRP) isUValid() bool {
	if s.u == nil || s.badState {
		s.u = nil
		return false
	}
	if s.group.IsZero(s.u) {
		return false
	}
	return true
}

// makeVerifier creates to the verifier from x and parameters.
func (s *SRP) makeVerifier() (*big.Int, error) {
	if s.group == nil {
		return nil, fmt.Errorf("group not set")
	}
	if s.badState {
		return nil, fmt.Errorf("we have bad data")
	}
	if s.group.IsZero(s.x) {
		return nil, fmt.Errorf("x must be known to calculate v")
	}

	result := s.v.Exp(s.group.g, s.x, s.group.n)

	return result, nil
}

// calculateU creates a hash of A and B.
// It does this the 1Password way or the Standard way depending on s.stdPadding.
func (s *SRP) calculateU() (*big.Int, error) {
	if s.stdPadding {
		return s.calculateUStd()
	}
	return s.calculateUNonStd()
}

// calculateUNonStd creates a hash A and B
// BUG(jpg): Calculation of u does not use RFC 5054 compatable padding/hashing
// The scheme we use (see source) is to use SHA256 of the concatenation of A and B
// each represented as a lowercase hexadecimal string.
// Additionally those hex strings have leading "0" removed even if that makes them of odd length.
// use calculateUStd() for a standard compliant version.
func (s *SRP) calculateUNonStd() (*big.Int, error) {
	if !s.IsPublicValid(s.ephemeralPublicA) || !s.IsPublicValid(s.ephemeralPublicB) {
		s.u = nil
		return nil, fmt.Errorf("both A and B must be known to calculate u")
	}

	h := Hash.NewWith(s.hashName)
	if h == nil {
		return nil, fmt.Errorf("failed to set up hash function")
	}

	trimmedHexPublicA := serverStyleHexFromBigInt(s.ephemeralPublicA)
	trimmedHexPublicB := serverStyleHexFromBigInt(s.ephemeralPublicB)

	_, err := h.Write([]byte(fmt.Sprintf("%s%s", trimmedHexPublicA, trimmedHexPublicB)))
	if err != nil {
		return nil, fmt.Errorf("failed to write to hasher: %w", err)
	}

	u := &big.Int{}
	s.u = u.SetBytes(h.Sum(nil))
	if s.group.IsZero(s.u) {
		return nil, fmt.Errorf("u == 0, which is a bad thing")
	}
	return s.u, nil
}

// calculateU creates a hash A and B as specified in RFC5054 using SHA256.
func (s *SRP) calculateUStd() (*big.Int, error) {
	if !s.IsPublicValid(s.ephemeralPublicA) || !s.IsPublicValid(s.ephemeralPublicB) {
		s.u = nil
		return nil, fmt.Errorf("both A and B must be known to calculate u")
	}

	// A and B will be big-endian byte arrays padded to byte length of N
	grp := s.group
	lenN := len(grp.N().Bytes())
	A := grp.PaddedBytes(s.ephemeralPublicA)
	B := grp.PaddedBytes(s.ephemeralPublicB)

	h := Hash.NewWith(s.hashName)
	if h == nil {
		return nil, fmt.Errorf("failed to set up hash function")
	}

	b, err := h.Write(A)
	if err != nil || b != lenN {
		return nil, fmt.Errorf("failed to write A to hasher: %w", err)
	}

	b, err = h.Write(B)
	if err != nil || b != lenN {
		return nil, fmt.Errorf("failed to write B to hasher: %w", err)
	}
	u := &big.Int{}
	s.u = u.SetBytes(h.Sum(nil))
	if s.group.IsZero(s.u) {
		return nil, fmt.Errorf("u == 0, which is a bad thing")
	}
	return s.u, nil
}

// Convert a bigInt to a lowercase hex string with leading "0"s removed.
// We do this explicitly instead of as an artifact of fmt.Sprintf.
func serverStyleHexFromBigInt(bn *big.Int) string {
	// Don't worry. The compiler will build things the same even if we didn't create
	// all of the intermediate variables below. And this better communicates all these
	// things we are doing to construct these strings
	b := bn.Bytes()
	h := hex.EncodeToString(b)
	l := strings.ToLower(h)
	res := strings.TrimLeft(l, "0")

	return res
}

/**
 ** Copyright 2017, 2022 AgileBits, Inc.
 ** Licensed under the Apache License, Version 2.0 (the "License").
 **/
